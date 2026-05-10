"""Robust NFT CSV decoder — with cache.

Reads NFT contract rows from a CSV, extracts token information from on-chain
Transfer logs (ERC-721 + ERC-1155), resolves tokenURI (IPFS / data URI /
HTTP), fetches metadata with multi-gateway fallback, and writes a normalised
output CSV.

Results are stored in a local SQLite cache keyed on contract address.
On subsequent runs, already-processed addresses are skipped entirely — only
new rows from the daily CSV update are fetched.  Use --force to reprocess
everything (e.g. after fixing a bug).

Required environment variables:
  BSC_RPC          RPC endpoint for BSC/EVM chain
  NFT_CSV_PATH     Path to input CSV
  BSCSCAN_API_KEY  BscScan API key (fallback when logs miss the Transfer event)

Optional environment variables:
  NFT_OUTPUT_PATH   Output CSV path      (default: data/output/nft_metadata_robust.csv)
  NFT_CACHE_PATH    SQLite cache path    (default: data/cache/nft_cache.db)
  NFT_HTTP_TIMEOUT  Request timeout sec  (default: 12)
  NFT_MAX_ROWS      Limit rows for testing  (default: all)
  NFT_RUN_ALL       "1" = process all rows; "0" = only has_url==True  (default: 1)
  NFT_FORCE         "1" = ignore cache, reprocess everything  (default: 0)

Usage:
  python decode_nft_csv_robust.py
  NFT_FORCE=1 python decode_nft_csv_robust.py   # reprocess all
  NFT_MAX_ROWS=100 python decode_nft_csv_robust.py  # test run
"""

from __future__ import annotations

import base64
import json
import os
import re
import sqlite3
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import pandas as pd
import requests
from dotenv import load_dotenv
from web3 import Web3

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# ERC-721  Transfer(address indexed from, address indexed to, uint256 indexed tokenId)
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

# ERC-1155 TransferSingle(address indexed operator, address indexed from,
#                         address indexed to, uint256 id, uint256 value)
TRANSFER_SINGLE_TOPIC = "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62"

ERC721_TOKEN_URI_ABI = [
    {
        "inputs": [{"name": "tokenId", "type": "uint256"}],
        "name": "tokenURI",
        "outputs": [{"name": "", "type": "string"}],
        "stateMutability": "view",
        "type": "function",
    }
]

# When tokenURI(id) reverts or returns empty, try these IDs in order.
# Many contracts start at 1, some at 0.
TOKENURI_FALLBACK_IDS = [1, 0, 2]

# Bare IPFS CIDv0 (Qm...) or CIDv1 (bafy...) without ipfs:// prefix
_BARE_CID_RE = re.compile(
    r"^(Qm[1-9A-HJ-NP-Za-km-z]{44}|bafy[a-z2-7]{52,})(/.*)?$"
)

DEFAULT_GATEWAYS = [
    "https://cloudflare-ipfs.com/ipfs/{cid_path}",
    "https://ipfs.io/ipfs/{cid_path}",
    "https://gateway.pinata.cloud/ipfs/{cid_path}",
]

# Output columns — order matters for the CSV
OUTPUT_COLUMNS = [
    "address",
    "name",
    "known_url",
    "first_seen_txhash",
    "token_id",
    "token_standard",
    "transfer_from",
    "transfer_to",
    "token_uri_raw",
    "token_uri_resolved",
    "token_uri_source",
    "meta_name",
    "meta_desc",
    "meta_image",
    "meta_image_resolved",
    "meta_ext_url",
    "meta_website",
    "metadata_http_status",
    "metadata_content_type",
    "scam_type",
    "error",
]


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

@dataclass
class Settings:
    bsc_rpc: str
    bscscan_key: str
    input_csv: str
    output_csv: str
    cache_path: str
    timeout_sec: int
    max_rows: Optional[int]
    run_all: bool
    force: bool


def load_settings() -> Settings:
    load_dotenv()

    bsc_rpc = os.getenv("BSC_RPC")
    bscscan_key = os.getenv("BSCSCAN_API_KEY", "")
    input_csv = os.getenv("NFT_CSV_PATH")
    output_csv = os.getenv(
        "NFT_OUTPUT_PATH", "data/output/nft_metadata_robust.csv")
    cache_path = os.getenv("NFT_CACHE_PATH", "data/cache/nft_cache.db")
    timeout_sec = int(os.getenv("NFT_HTTP_TIMEOUT", "12"))
    max_rows_raw = os.getenv("NFT_MAX_ROWS", "").strip()
    max_rows = int(max_rows_raw) if max_rows_raw else None
    run_all = os.getenv("NFT_RUN_ALL", "1").strip() == "1"
    force = os.getenv("NFT_FORCE", "0").strip() == "1"

    if not bsc_rpc:
        raise ValueError("Missing BSC_RPC in .env/environment")
    if not input_csv:
        raise ValueError("Missing NFT_CSV_PATH in .env/environment")
    if not bscscan_key:
        print("WARNING: BSCSCAN_API_KEY not set — BscScan fallback disabled")

    return Settings(
        bsc_rpc=bsc_rpc,
        bscscan_key=bscscan_key,
        input_csv=input_csv,
        output_csv=output_csv,
        cache_path=cache_path,
        timeout_sec=timeout_sec,
        max_rows=max_rows,
        run_all=run_all,
        force=force,
    )


# ---------------------------------------------------------------------------
# SQLite cache
# ---------------------------------------------------------------------------

# Every output column is stored as TEXT; None becomes SQL NULL.
# The cache is keyed on lowercase contract address.

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS nft_results (
    address              TEXT PRIMARY KEY,
    name                 TEXT,
    known_url            TEXT,
    first_seen_txhash    TEXT,
    token_id             TEXT,
    token_standard       TEXT,
    transfer_from        TEXT,
    transfer_to          TEXT,
    token_uri_raw        TEXT,
    token_uri_resolved   TEXT,
    token_uri_source     TEXT,
    meta_name            TEXT,
    meta_desc            TEXT,
    meta_image           TEXT,
    meta_image_resolved  TEXT,
    meta_ext_url         TEXT,
    meta_website         TEXT,
    metadata_http_status TEXT,
    metadata_content_type TEXT,
    scam_type            TEXT,
    error                TEXT,
    cached_at            TEXT DEFAULT (datetime('now'))
);
"""


def open_cache(path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # safe for concurrent reads
    conn.execute(_CREATE_TABLE)
    conn.commit()
    return conn


def cache_get(conn: sqlite3.Connection, address: str) -> Optional[Dict[str, Any]]:
    """Return cached result for address, or None if not cached."""
    row = conn.execute(
        "SELECT * FROM nft_results WHERE address = ?",
        (address.lower(),),
    ).fetchone()
    return dict(row) if row else None


def cache_set(conn: sqlite3.Connection, result: Dict[str, Any]) -> None:
    """Upsert one result row into the cache."""
    address = str(result.get("address", "")).lower()
    cols = ["address"] + [c for c in OUTPUT_COLUMNS if c != "address"]
    placeholders = ", ".join("?" * len(cols))
    col_names = ", ".join(cols)
    update_clause = ", ".join(
        f"{c} = excluded.{c}" for c in cols if c != "address"
    )
    # Coerce all values to str/None — prevents SQLite INTEGER overflow on
    # large ERC-1155 token IDs (e.g. 256-bit values used by some contracts)

    def _safe(v: Any) -> Any:
        if v is None:
            return None
        return str(v)

    values = [address] + [_safe(result.get(c)) for c in cols if c != "address"]
    conn.execute(
        f"""
        INSERT INTO nft_results ({col_names}) VALUES ({placeholders})
        ON CONFLICT(address) DO UPDATE SET {update_clause},
            cached_at = datetime('now')
        """.replace("{col_name}", col_names),
        values,
    )
    conn.commit()


def cache_get_all(conn: sqlite3.Connection) -> Dict[str, Dict[str, Any]]:
    """Load entire cache into a dict keyed by lowercase address."""
    rows = conn.execute("SELECT * FROM nft_results").fetchall()
    return {row["address"]: dict(row) for row in rows}


# ---------------------------------------------------------------------------
# Output row template
# ---------------------------------------------------------------------------

def make_result_row(row: pd.Series) -> Dict[str, Any]:
    return {col: None for col in OUTPUT_COLUMNS} | {
        "address": row.get("address"),
        "name": row.get("name"),
        "known_url": row.get("extracted_urls"),
        "first_seen_txhash": row.get("first_seen_txhash"),
    }


# ---------------------------------------------------------------------------
# Topic / address helpers
# ---------------------------------------------------------------------------

def normalize_topic(hex_value: str) -> str:
    h = hex_value.lower()
    return h if h.startswith("0x") else "0x" + h


def topic_to_address(topic_hex: str) -> str:
    return "0x" + topic_hex.lower().replace("0x", "")[-40:]


# ---------------------------------------------------------------------------
# Token ID extraction
# ---------------------------------------------------------------------------

def get_token_id_from_logs(
    receipt: Any,
    contract_address: str,
) -> Tuple[Optional[int], Optional[str], Optional[str], Optional[str]]:
    """
    Scan receipt logs for the target contract's first Transfer event.
    Supports ERC-721 and ERC-1155.

    Returns (token_id, token_standard, from_addr, to_addr).
    """
    target = contract_address.lower()

    for log in receipt["logs"]:
        if log["address"].lower() != target:
            continue
        if not log.get("topics"):
            continue

        topic0 = normalize_topic(log["topics"][0].hex())

        # ERC-721: Transfer(from, to, tokenId) — tokenId is topics[3]
        if topic0 == TRANSFER_TOPIC and len(log["topics"]) >= 4:
            token_id = int(log["topics"][3].hex(), 16)
            return (
                token_id,
                "ERC-721",
                topic_to_address(log["topics"][1].hex()),
                topic_to_address(log["topics"][2].hex()),
            )

        # ERC-1155: TransferSingle — token ID is first word of data
        if topic0 == TRANSFER_SINGLE_TOPIC and len(log["topics"]) >= 4:
            data_hex = log["data"].hex()
            clean = data_hex[2:] if data_hex.startswith("0x") else data_hex
            token_id = int(clean[:64], 16)
            return (
                token_id,
                "ERC-1155",
                topic_to_address(log["topics"][2].hex()),
                topic_to_address(log["topics"][3].hex()) if len(
                    log["topics"]) > 3 else None,
            )

    return None, None, None, None


def get_token_id_from_bscscan(
    contract_address: str,
    bscscan_key: str,
    timeout_sec: int,
) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    """
    BscScan fallback when receipt logs don't contain a Transfer event.
    Returns (token_id, token_standard, to_address).
    """
    if not bscscan_key:
        return None, None, None

    for action, standard in [("tokennfttx", "ERC-721"), ("token1155tx", "ERC-1155")]:
        try:
            r = requests.get(
                "https://api.bscscan.com/api",
                params={
                    "module": "account",
                    "action": action,
                    "contractaddress": contract_address,
                    "page": 1,
                    "offset": 1,
                    "sort": "asc",
                    "apikey": bscscan_key,
                },
                timeout=timeout_sec,
            ).json()
            if r.get("status") == "1" and r.get("result"):
                first = r["result"][0]
                return int(first["tokenID"]), standard, first.get("to")
        except Exception:
            continue

    return None, None, None


# ---------------------------------------------------------------------------
# URI helpers
# ---------------------------------------------------------------------------

def ipfs_to_cid_path(uri: str) -> Optional[str]:
    if not isinstance(uri, str) or not uri.lower().startswith("ipfs://"):
        return None
    payload = uri[7:].strip().lstrip("/")
    if payload.startswith("ipfs/"):
        payload = payload[5:]
    return payload or None


def token_uri_candidates(uri: str, token_id: int) -> List[Tuple[str, str]]:
    """
    Build an ordered list of (url, source_label) fetch candidates.

    Handles:
      - data URIs (base64 and plain JSON)
      - ipfs:// URIs (via multiple public gateways)
      - bare CIDs without ipfs:// prefix (Qm... / bafy...)
      - HTTP/HTTPS with optional IPFS gateway fallback
      - {id} placeholder substitution (ERC-1155)
      - unresolvable strings (bare numbers, garbage) → returns []
    """
    if not isinstance(uri, str) or not uri.strip():
        return []

    raw = uri.strip()

    if "{id}" in raw:
        raw = raw.replace("{id}", format(token_id, "x").zfill(64))

    if raw.startswith("data:application/json"):
        return [(raw, "data_uri")]

    cid_path = ipfs_to_cid_path(raw)
    if cid_path:
        encoded = quote(cid_path)
        return [(t.format(cid_path=encoded), "ipfs_gateway") for t in DEFAULT_GATEWAYS]

    if _BARE_CID_RE.match(raw):
        encoded = quote(raw)
        return [(t.format(cid_path=encoded), "ipfs_bare_cid") for t in DEFAULT_GATEWAYS]

    if raw.startswith("http://") or raw.startswith("https://"):
        candidates = [(raw, "http")]
        if "/ipfs/" in raw:
            cid_part = raw.split("/ipfs/", 1)[1].strip("/")
            if cid_part:
                encoded = quote(cid_part)
                for t in DEFAULT_GATEWAYS:
                    fallback = t.format(cid_path=encoded)
                    if fallback != raw:
                        candidates.append((fallback, "ipfs_gateway_fallback"))
        return candidates

    # Bare number, relative path, garbage — not fetchable
    return []


def parse_data_uri_json(data_uri: str) -> Dict[str, Any]:
    header, payload = data_uri.split(",", 1)
    if ";base64" in header.lower():
        decoded = base64.b64decode(payload).decode("utf-8", errors="replace")
    else:
        decoded = requests.utils.unquote(payload)
    return json.loads(decoded)


# ---------------------------------------------------------------------------
# Metadata fetching
# ---------------------------------------------------------------------------

def fetch_metadata(
    session: requests.Session,
    candidates: List[Tuple[str, str]],
    timeout_sec: int,
) -> Tuple[Optional[Dict], Optional[str], Optional[int], Optional[str], Optional[str]]:
    """Try candidates in order until one returns valid JSON. Returns
    (metadata, resolved_uri, http_status, content_type, source_label)."""
    for candidate, source in candidates:
        try:
            if candidate.startswith("data:application/json"):
                return parse_data_uri_json(candidate), candidate, None, "application/json", source

            resp = session.get(candidate, timeout=timeout_sec)
            if resp.status_code >= 400:
                continue
            return (
                resp.json(),
                candidate,
                resp.status_code,
                resp.headers.get("content-type"),
                source,
            )
        except Exception:
            continue

    return None, None, None, None, None


def extract_metadata_fields(metadata: Dict[str, Any]) -> Dict[str, Optional[str]]:
    website: Optional[str] = None
    for attr in metadata.get("attributes", []) or []:
        if isinstance(attr, dict):
            if str(attr.get("trait_type", "")).strip().lower() == "website":
                website = attr.get("value")
                break

    return {
        "meta_name": metadata.get("name"),
        "meta_desc": metadata.get("description"),
        "meta_image": metadata.get("image"),
        "meta_ext_url": metadata.get("external_url"),
        "meta_website": website,
    }


def resolve_image_uri(image_uri: Any) -> Optional[str]:
    if not isinstance(image_uri, str) or not image_uri.strip():
        return None
    image_uri = image_uri.strip()
    cid_path = ipfs_to_cid_path(image_uri)
    if cid_path:
        return DEFAULT_GATEWAYS[0].format(cid_path=quote(cid_path))
    if image_uri.startswith("http://") or image_uri.startswith("https://"):
        return image_uri
    return None


# ---------------------------------------------------------------------------
# Per-row decoder
# ---------------------------------------------------------------------------

def decode_row(
    row: pd.Series,
    w3: Web3,
    session: requests.Session,
    settings: Settings,
) -> Dict[str, Any]:
    result = make_result_row(row)

    try:
        tx_hash = row.get("first_seen_txhash")
        address = row.get("address")

        if not isinstance(tx_hash, str) or not tx_hash.strip():
            result["error"] = "missing_txhash"
            return result
        if not isinstance(address, str) or not address.strip():
            result["error"] = "missing_address"
            return result

        # Step 1 — token ID from receipt logs
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        token_id, standard, from_addr, to_addr = get_token_id_from_logs(
            receipt, address)

        # Step 1b — BscScan fallback (ERC-721 + ERC-1155)
        if token_id is None:
            token_id, standard, to_addr = get_token_id_from_bscscan(
                address, settings.bscscan_key, settings.timeout_sec
            )

        if token_id is None:
            result["error"] = "no_tokens_minted"
            result["scam_type"] = "name_symbol_only"
            return result

        result["token_standard"] = standard
        result["transfer_from"] = from_addr
        result["transfer_to"] = to_addr

        # Step 2 — tokenURI with fallback ID retry
        # Some contracts revert on ID 0 but work on ID 1 (and vice versa).
        contract = w3.eth.contract(
            address=w3.to_checksum_address(address),
            abi=ERC721_TOKEN_URI_ABI,
        )
        ids_to_try = [token_id] + \
            [i for i in TOKENURI_FALLBACK_IDS if i != token_id]
        token_uri_raw: Optional[str] = None
        used_token_id = token_id
        last_uri_error: Optional[str] = None

        for try_id in ids_to_try:
            try:
                uri = contract.functions.tokenURI(try_id).call()
                if isinstance(uri, str) and uri.strip():
                    token_uri_raw = uri.strip()
                    used_token_id = try_id
                    break
                last_uri_error = "empty_uri"
            except Exception as exc:
                last_uri_error = str(exc)

        result["token_id"] = used_token_id

        if not token_uri_raw:
            result["error"] = last_uri_error or "empty_uri"
            return result

        result["token_uri_raw"] = token_uri_raw

        # Step 3 — resolve URI into fetch candidates
        candidates = token_uri_candidates(token_uri_raw, used_token_id)
        if not candidates:
            result["error"] = "unsupported_token_uri"
            return result

        # Step 4 — fetch metadata
        metadata, resolved_uri, status, content_type, source = fetch_metadata(
            session, candidates, settings.timeout_sec
        )

        result["token_uri_resolved"] = resolved_uri
        result["token_uri_source"] = source
        result["metadata_http_status"] = status
        result["metadata_content_type"] = content_type

        if metadata is None:
            result["error"] = "metadata_fetch_failed"
            return result

        result.update(extract_metadata_fields(metadata))
        result["meta_image_resolved"] = resolve_image_uri(
            result.get("meta_image"))

    except Exception as exc:
        result["error"] = str(exc)

    return result


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run_pipeline(settings: Settings) -> None:
    df = pd.read_csv(settings.input_csv, on_bad_lines="skip")

    required_cols = {"address", "first_seen_txhash"}
    missing = required_cols - set(df.columns)
    if missing:
        raise ValueError(f"CSV missing required columns: {sorted(missing)}")

    # Optional row filter
    if not settings.run_all and "has_url" in df.columns:
        df = df[df["has_url"] == True].copy()

    if settings.max_rows is not None:
        df = df.head(settings.max_rows)

    # Normalise addresses for consistent cache lookups
    df["address"] = df["address"].astype(str).str.lower().str.strip()

    # ---- Cache setup --------------------------------------------------------
    conn = open_cache(settings.cache_path)

    if settings.force:
        print("--force: ignoring cache, reprocessing all rows")
        cached = {}
    else:
        cached = cache_get_all(conn)
        print(f"Cache: {len(cached)} addresses already processed")

    # Split into cached vs new
    is_cached = df["address"].isin(cached)
    new_df = df[~is_cached].copy()
    cached_df = df[is_cached].copy()

    print(f"Total rows    : {len(df)}")
    print(f"  From cache  : {len(cached_df)}")
    print(f"  To fetch    : {len(new_df)}")

    # ---- Process new rows ---------------------------------------------------
    results: List[Dict[str, Any]] = []

    if not new_df.empty:
        w3 = Web3(Web3.HTTPProvider(settings.bsc_rpc))
        if not w3.is_connected():
            raise ConnectionError("Could not connect to BSC RPC")

        session = requests.Session()
        total_new = len(new_df)

        for i, (_, row) in enumerate(new_df.iterrows(), start=1):
            result = decode_row(row, w3, session, settings)
            cache_set(conn, result)        # persist immediately
            results.append(result)

            if i % 50 == 0 or i == total_new:
                print(f"  Fetched: {i}/{total_new}")

    # ---- Merge cached results back in ---------------------------------------
    for _, row in cached_df.iterrows():
        hit = cached[row["address"]]
        # Refresh name/known_url from today's CSV (may have been updated)
        hit["name"] = row.get("name")
        hit["known_url"] = row.get("extracted_urls")
        results.append(hit)

    conn.close()

    # ---- Save output CSV ----------------------------------------------------
    out_df = pd.DataFrame(results, columns=OUTPUT_COLUMNS +
                          ["cached_at"] if "cached_at" in results[0] else OUTPUT_COLUMNS)
    # Drop internal cache column if present
    out_df = out_df[[c for c in OUTPUT_COLUMNS if c in out_df.columns]]
    # Preserve original CSV row order
    out_df = out_df.set_index("address").reindex(df["address"]).reset_index()

    os.makedirs(os.path.dirname(settings.output_csv) or ".", exist_ok=True)
    out_df.to_csv(settings.output_csv, index=False)

    # ---- Summary ------------------------------------------------------------
    n = len(out_df)
    got_uri = out_df["token_uri_raw"].notna().sum()
    got_meta = out_df["meta_name"].notna().sum()
    errors = out_df["error"].notna().sum()

    print(f"\nDone. Saved to {settings.output_csv}")
    print(f"  Total      : {n}")
    print(f"  Got URI    : {got_uri}  ({round(got_uri / n * 100, 1)}%)")
    print(f"  Got meta   : {got_meta}  ({round(got_meta / n * 100, 1)}%)")
    print(f"  Errors     : {errors}  ({round(errors / n * 100, 1)}%)")
    print("\nError breakdown:")
    print(out_df["error"].value_counts(dropna=False).head(10).to_string())
    if "token_standard" in out_df.columns:
        print("\nToken standard breakdown:")
        print(out_df["token_standard"].value_counts(dropna=False).to_string())


if __name__ == "__main__":
    run_pipeline(load_settings())
