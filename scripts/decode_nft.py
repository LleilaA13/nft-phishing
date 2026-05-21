"""Blazing Fast NFT CSV decoder — Multithreaded with SQLite Cache.

Chain: BNB Chain (BSC) mainnet.

FIXES vs decode_nft1.py
-----------------------
1. BSC RPC restored correctly; sensible public default so script runs without .env.
2. Token ID discovery no longer bails if receipt has no Transfer log:
   falls back to a wide sweep of token IDs [0,1,2,3,4,5,10,100,1000].
3. Removed POA middleware — causes issues on newer web3.py versions.
4. BscScan API key now clearly documented (see .env section below).
5. IPFS gateway timeout raised to 12 s (was 4 s — caused most IPFS URIs to fail).
6. Local IPFS gateway removed from defaults; only enabled via NFT_LOCAL_IPFS=1.


.env file setup
---------------
Create a file named .env in the same directory as this script:

    BSC_RPC=https://bsc-dataseed1.binance.org        # or your private RPC
    BSCSCAN_API_KEY=YOUR_KEY_HERE                     # from bscscan.com/myapikey
    NFTSCAN_API_KEY=YOUR_KEY_HERE                     # from developer.nftscan.com (optional)
    NFT_CSV_PATH=retry_errors.csv
    NFT_OUTPUT_PATH=nft_output.csv
    NFT_MAX_WORKERS=20
    # NFT_FORCE=1       # uncomment to ignore cache and re-fetch everything
    # NFT_DEBUG=1       # uncomment for verbose logging
    # NFT_LOCAL_IPFS=1  # uncomment if you run a local IPFS node on port 8080
"""

from __future__ import annotations

import base64
import mimetypes
import json
import os
import re
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote
import logging

import pandas as pd
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dotenv import load_dotenv
from web3 import Web3
from web3.exceptions import BadFunctionCallOutput
from requests.exceptions import RequestException
from json import JSONDecodeError

# ---------------------------------------------------------------------------
# Constants & ABIs
# ---------------------------------------------------------------------------

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
TRANSFER_SINGLE_TOPIC = "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62"

COMBINED_URI_ABI = [
    {"inputs": [{"name": "tokenId", "type": "uint256"}], "name": "tokenURI",
     "outputs": [{"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"name": "id", "type": "uint256"}], "name": "uri",
     "outputs": [{"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
]

# FIX 8: Wider sweep — many collections start at 0 or skip early IDs
TOKENURI_FALLBACK_IDS = [0, 1, 2, 3, 4, 5, 10, 100, 1000]

_BARE_CID_RE = re.compile(
    r"^(Qm[1-9A-HJ-NP-Za-km-z]{44}|bafy[a-z2-7]{52,})(/.*)?$")

# FIX 6: Local IPFS node removed from defaults — only add it if explicitly set
DEFAULT_GATEWAYS = [
    "https://ipfs.io/ipfs/{cid_path}",
    "https://dweb.link/ipfs/{cid_path}",
    "https://gateway.pinata.cloud/ipfs/{cid_path}",
]

ARWEAVE_GATEWAYS = ["https://arweave.net/{txid_path}"]

# FIX 4: Raised from 4 s → 12 s so IPFS gateways have time to resolve
GATEWAY_RACE_TIMEOUT = 12

OUTPUT_COLUMNS = [
    "address", "name", "known_url", "first_seen_txhash", "token_id",
    "token_standard", "transfer_from", "transfer_to", "token_uri_raw",
    "token_uri_resolved", "token_uri_source", "meta_name", "meta_desc",
    "meta_image", "meta_image_resolved", "meta_ext_url", "meta_website",
    "metadata_http_status", "metadata_content_type", "scam_type", "error",
    "error_class",
]

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


@dataclass
class Settings:
    bsc_rpc: str
    bscscan_key: str
    nftscan_key: str
    input_csv: str
    output_csv: str
    cache_path: str
    timeout_sec: int
    max_rows: Optional[int]
    run_all: bool
    force: bool
    max_workers: int
    local_ipfs: bool


def load_settings() -> Settings:
    load_dotenv()
    bsc_rpc = os.getenv("BSC_RPC", "https://bsc-dataseed1.binance.org")
    input_csv = os.getenv(
        "NFT_CSV_PATH", "/home/leyla/blockchain-phishing/data/nft_tokens.csv")
    if not input_csv:
        raise ValueError("Set NFT_CSV_PATH in your .env file")

    return Settings(
        bsc_rpc=bsc_rpc,
        bscscan_key=os.getenv("BSCSCAN_API_KEY", ""),
        nftscan_key=os.getenv("NFTSCAN_API_KEY", ""),
        input_csv=input_csv,
        output_csv=os.getenv("NFT_OUTPUT_PATH", "data/output/nft_rerun.csv"),
        cache_path=os.getenv("NFT_CACHE_PATH", "data/cache/nft_cache_errors.db"),
        timeout_sec=int(os.getenv("NFT_HTTP_TIMEOUT", "15")),
        max_rows=int(os.getenv("NFT_MAX_ROWS", "0")) or None,
        run_all=os.getenv("NFT_RUN_ALL", "1") == "1",
        force=os.getenv("NFT_FORCE", "0") == "1",
        max_workers=int(os.getenv("NFT_MAX_WORKERS", "8")),
        local_ipfs=os.getenv("NFT_LOCAL_IPFS", "0") == "1",
    )


thread_local = threading.local()


def get_thread_resources(settings: Settings) -> Tuple[Web3, requests.Session]:
    if not hasattr(thread_local, "w3"):
        # No POA middleware — causes issues on web3.py v6+ and is unnecessary
        thread_local.w3 = Web3(Web3.HTTPProvider(
            settings.bsc_rpc, request_kwargs={"timeout": settings.timeout_sec}))

    if not hasattr(thread_local, "session"):
        session = requests.Session()
        session.headers.update({
            "Accept": "application/json, text/plain, */*",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Cache-Control": "no-cache",
        })
        retry = Retry(total=2, backoff_factor=0.5,
                      status_forcelist=[429, 500, 502, 503, 504])
        pool_size = max(10, settings.max_workers)
        adapter = HTTPAdapter(pool_connections=pool_size,
                              pool_maxsize=pool_size, max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        thread_local.session = session
    return thread_local.w3, thread_local.session


log = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.DEBUG if os.getenv("NFT_DEBUG", "0") == "1" else logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

# ---------------------------------------------------------------------------
# SQLite Cache (unchanged from original)
# ---------------------------------------------------------------------------

db_lock = threading.Lock()

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS nft_results (
    address TEXT PRIMARY KEY, name TEXT, known_url TEXT, first_seen_txhash TEXT,
    token_id TEXT, token_standard TEXT, transfer_from TEXT, transfer_to TEXT,
    token_uri_raw TEXT, token_uri_resolved TEXT, token_uri_source TEXT,
    meta_name TEXT, meta_desc TEXT, meta_image TEXT, meta_image_resolved TEXT,
    meta_ext_url TEXT, meta_website TEXT, metadata_http_status TEXT,
    metadata_content_type TEXT, scam_type TEXT, error TEXT,
    error_class TEXT,
    cached_at TEXT DEFAULT (datetime('now'))
);
"""


def open_cache(path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(_CREATE_TABLE)
    conn.commit()
    return conn


def cache_get_all(conn: sqlite3.Connection) -> Dict[str, Dict[str, Any]]:
    rows = conn.execute("SELECT * FROM nft_results").fetchall()
    return {row["address"]: dict(row) for row in rows}


def cache_set(conn: sqlite3.Connection, result: Dict[str, Any]) -> None:
    address = str(result.get("address", "")).lower()
    cols = ["address"] + [c for c in OUTPUT_COLUMNS if c != "address"]
    placeholders = ", ".join("?" * len(cols))
    col_names = ", ".join(cols)
    update_clause = ", ".join(
        f"{c} = excluded.{c}" for c in cols if c != "address")

    def _safe(v): return None if v is None else str(v)
    values = [address] + [_safe(result.get(c)) for c in cols if c != "address"]

    with db_lock:
        conn.execute(
            f"INSERT INTO nft_results ({col_names}) VALUES ({placeholders}) "
            f"ON CONFLICT(address) DO UPDATE SET {update_clause}, cached_at = datetime('now')",
            values,
        )
        conn.commit()


def make_result_row(row: pd.Series) -> Dict[str, Any]:
    return {col: None for col in OUTPUT_COLUMNS} | {
        "address": row.get("address"),
        "name": row.get("name"),
        "known_url": row.get("extracted_urls"),
        "first_seen_txhash": row.get("first_seen_txhash"),
    }

# ---------------------------------------------------------------------------
# Log parsing helpers
# ---------------------------------------------------------------------------


def normalize_topic(hex_value: str) -> str:
    h = hex_value.lower()
    return h if h.startswith("0x") else "0x" + h


def topic_to_address(topic_hex: str) -> str:
    return "0x" + topic_hex.lower().replace("0x", "")[-40:]


def get_token_id_from_logs(receipt: Any, contract_address: str):
    if not receipt:
        return None, None, None, None
    target = contract_address.lower()
    for log_item in receipt["logs"]:
        if log_item["address"].lower() != target or not log_item.get("topics"):
            continue
        topic0 = normalize_topic(log_item["topics"][0].hex())
        if topic0 == TRANSFER_TOPIC and len(log_item["topics"]) >= 4:
            return (int(log_item["topics"][3].hex(), 16), "ERC-721",
                    topic_to_address(log_item["topics"][1].hex()),
                    topic_to_address(log_item["topics"][2].hex()))
        if topic0 == TRANSFER_SINGLE_TOPIC and len(log_item["topics"]) >= 4:
            data_hex = log_item["data"].hex()
            clean = data_hex[2:] if data_hex.startswith("0x") else data_hex
            return (int(clean[:64], 16), "ERC-1155",
                    topic_to_address(log_item["topics"][2].hex()),
                    topic_to_address(log_item["topics"][3].hex()) if len(log_item["topics"]) > 3 else None)
    return None, None, None, None

# ---------------------------------------------------------------------------
# BscScan — find a valid token ID for a contract
# ---------------------------------------------------------------------------


def get_token_id_from_bscscan(contract_address: str, bscscan_key: str, timeout_sec: int):
    """Query BscScan NFT transfer API to find a valid token ID."""
    if not bscscan_key:
        return None, None, None

    for action, standard in [("tokennfttx", "ERC-721"), ("token1155tx", "ERC-1155")]:
        time.sleep(0.25)  # stay within 5 req/s free-tier limit
        try:
            resp = requests.get(
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
            )
            if "text/html" in resp.headers.get("Content-Type", ""):
                time.sleep(1.5)
                continue
            r = resp.json()
            if r.get("status") == "1" and r.get("result"):
                try:
                    return int(r["result"][0]["tokenID"]), standard, r["result"][0].get("to")
                except (KeyError, ValueError):
                    continue
        except Exception as e:
            log.debug("BscScan request failed for %s: %s", contract_address, e)
    return None, None, None


# ---------------------------------------------------------------------------
# URI resolution helpers
# ---------------------------------------------------------------------------


def ipfs_to_cid_path(uri: str) -> Optional[str]:
    if not isinstance(uri, str) or not uri.lower().startswith("ipfs://"):
        return None
    payload = uri[7:].strip().lstrip("/")
    if payload.startswith("ipfs/"):
        payload = payload[5:]
    return payload or None


def token_uri_candidates(uri: str, token_id: int) -> List[Tuple[str, str]]:
    if not isinstance(uri, str) or not uri.strip():
        return []
    raw = uri.strip()
    if "{id}" in raw:
        raw = raw.replace("{id}", format(token_id, "x").zfill(64))
    if raw.startswith("data:application/json"):
        return [(raw, "data_uri")]

    cid_path = ipfs_to_cid_path(raw)
    if cid_path:
        candidates = []
        for t in DEFAULT_GATEWAYS:
            candidates.append((t.format(cid_path=quote(cid_path)), "ipfs_gateway"))
            if not cid_path.endswith(".json"):
                candidates.append((t.format(cid_path=quote(f"{cid_path}.json")), "ipfs_gateway_json"))
        return candidates

    if raw.startswith("ar://"):
        txid_path = raw[5:].strip().lstrip("/")
        if txid_path:
            return [(t.format(txid_path=quote(txid_path)), "arweave_gateway")
                    for t in ARWEAVE_GATEWAYS]

    if raw.startswith("https://arweave.net/"):
        candidates = [(raw, "http")]
        if not raw.endswith(".json"):
            candidates.append((f"{raw}.json", "arweave_gateway_json"))
        return candidates

    if _BARE_CID_RE.match(raw):
        candidates = []
        for t in DEFAULT_GATEWAYS:
            candidates.append((t.format(cid_path=quote(raw)), "ipfs_bare_cid"))
            candidates.append((t.format(cid_path=quote(f"{raw}.json")), "ipfs_bare_cid_json"))
        return candidates

    if raw.startswith("http://") or raw.startswith("https://"):
        candidates = [(raw, "http")]
        if "/ipfs/" in raw:
            cid_part = raw.split("/ipfs/", 1)[1].strip("/")
            if cid_part:
                for t in DEFAULT_GATEWAYS:
                    fallback = t.format(cid_path=quote(cid_part))
                    if fallback != raw:
                        candidates.append((fallback, "ipfs_gateway_fallback"))
        return candidates
    return []


def is_direct_asset_uri(uri: Optional[str]) -> bool:
    if not isinstance(uri, str) or not uri.strip():
        return False
    path = uri.split("?", 1)[0].split("#", 1)[0].lower().strip()
    return path.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg",
                          ".mp4", ".webm", ".mp3", ".wav", ".glb", ".gltf"))


def guess_content_type(uri: Optional[str]) -> Optional[str]:
    if not isinstance(uri, str):
        return None
    guessed, _ = mimetypes.guess_type(uri.split("?", 1)[0].split("#", 1)[0])
    return guessed


def _parse_json_text(text: str) -> Dict[str, Any]:
    cleaned = text.strip().lstrip("\ufeff")
    if cleaned and cleaned[0] in "[{":
        return json.loads(cleaned)
    raise ValueError("response body is not JSON")


def fetch_metadata(session: requests.Session, candidates: List[Tuple[str, str]], timeout_sec: int):
    for candidate, source in candidates:
        try:
            if candidate.startswith("data:application/json"):
                header, payload = candidate.split(",", 1)
                decoded = (base64.b64decode(payload).decode("utf-8")
                           if ";base64" in header.lower()
                           else requests.utils.unquote(payload))
                return _parse_json_text(decoded), candidate, None, "application/json", source

            try:
                # FIX 4: Use per-gateway timeout (raised to 12 s)
                resp = session.get(candidate, timeout=GATEWAY_RACE_TIMEOUT)
            except RequestException as e:
                log.debug("HTTP request failed for %s: %s", candidate, e)
                continue

            try:
                if resp.status_code >= 400:
                    log.debug("HTTP status %s for %s", resp.status_code, candidate)
                    continue
                content_type = resp.headers.get("content-type", "")
                try:
                    metadata = resp.json()
                except JSONDecodeError:
                    try:
                        metadata = _parse_json_text(resp.text)
                    except Exception:
                        continue
                return metadata, candidate, resp.status_code, content_type, source
            finally:
                resp.close()
        except Exception as e:
            log.debug("Unexpected error fetching %s: %s", candidate, e)
    return None, None, None, None, None


def extract_metadata_fields(metadata: Dict[str, Any]) -> Dict[str, Optional[str]]:
    website = next(
        (attr.get("value") for attr in metadata.get("attributes", [])
         if isinstance(attr, dict) and str(attr.get("trait_type", "")).strip().lower() == "website"),
        None,
    )
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
    cid_path = ipfs_to_cid_path(image_uri.strip())
    if cid_path:
        return DEFAULT_GATEWAYS[0].format(cid_path=quote(cid_path))
    return image_uri if image_uri.startswith("http") else None

# ---------------------------------------------------------------------------
# Per-Row Task
# ---------------------------------------------------------------------------


def process_row_task(row: pd.Series, settings: Settings, conn: sqlite3.Connection) -> Dict[str, Any]:
    w3, session = get_thread_resources(settings)
    result = make_result_row(row)
    result["error_class"] = None

    try:
        tx_hash = row.get("first_seen_txhash")
        address = row.get("address")

        if not tx_hash or not str(tx_hash).strip():
            result["error"] = "missing_txhash"
            cache_set(conn, result)
            return result
        if not address or not str(address).strip():
            result["error"] = "missing_address"
            cache_set(conn, result)
            return result

        # ── Step 1: Get a token ID ────────────────────────────────────────────
        receipt = None
        try:
            receipt = w3.eth.get_transaction_receipt(tx_hash)
        except Exception as e:
            log.debug("Receipt fetch failed %s: %s", tx_hash, e)
            result["error_class"] = "network_transient"

        token_id, standard, from_addr, to_addr = get_token_id_from_logs(receipt, address)

        # FIX: BscScan fallback with correct API
        if token_id is None:
            log.debug("Falling back to BscScan for %s", address)
            token_id, standard, to_addr = get_token_id_from_bscscan(
                address, settings.bscscan_key, settings.timeout_sec)

        # FIX 2: Don't bail — sweep a range of token IDs via tokenURI directly
        nft_type = row.get("detected_type", "ERC721")
        sweep_ids = TOKENURI_FALLBACK_IDS if token_id is None else [token_id] + [
            i for i in TOKENURI_FALLBACK_IDS if i != token_id]

        result.update({"token_standard": standard or nft_type,
                        "transfer_from": from_addr, "transfer_to": to_addr})

        checksum_addr = w3.to_checksum_address(address)
        contract = w3.eth.contract(address=checksum_addr, abi=COMBINED_URI_ABI)

        token_uri_raw, used_token_id, last_uri_error = None, None, None

        for try_id in sweep_ids:
            try:
                # FIX 3: Try both uri() and tokenURI() for any contract type
                if nft_type == "ERC1155":
                    uri = contract.functions.uri(try_id).call()
                else:
                    try:
                        uri = contract.functions.tokenURI(try_id).call()
                    except Exception:
                        uri = contract.functions.uri(try_id).call()

                if isinstance(uri, str) and uri.strip():
                    token_uri_raw, used_token_id = uri.strip(), try_id
                    break
            except Exception as exc:
                err_str = str(exc)
                if "execution reverted" in err_str:
                    last_uri_error = "Reverted"
                    result["error_class"] = "contract_revert"
                else:
                    last_uri_error = err_str
                    result["error_class"] = "contract_error"

        result["token_id"] = used_token_id


        result["token_uri_raw"] = token_uri_raw

        candidates = token_uri_candidates(token_uri_raw, used_token_id)
        if not candidates:
            result["error"] = "unsupported_token_uri"
            cache_set(conn, result)
            return result

        metadata, resolved_uri, status, content_type, source = fetch_metadata(
            session, candidates, settings.timeout_sec)

        result.update({"token_uri_resolved": resolved_uri, "token_uri_source": source,
                        "metadata_http_status": status, "metadata_content_type": content_type})

        if metadata is None:
            if is_direct_asset_uri(token_uri_raw):
                result["token_uri_resolved"] = resolve_image_uri(token_uri_raw) or token_uri_raw
                result["token_uri_source"] = "direct_asset_fallback"
                result["meta_image"] = token_uri_raw
                result["meta_image_resolved"] = resolve_image_uri(token_uri_raw)
                result["metadata_content_type"] = guess_content_type(token_uri_raw)
                result["error"] = None
                result["error_class"] = "direct_asset_fallback"
                cache_set(conn, result)
                return result

            result["error"] = "metadata_fetch_failed"
            result["error_class"] = "network"
            cache_set(conn, result)
            return result

        result.update(extract_metadata_fields(metadata))
        result["meta_image_resolved"] = resolve_image_uri(result.get("meta_image"))

    except Exception as exc:
        log.debug("Unhandled exception %s: %s", row.get("address"), exc, exc_info=True)
        result["error"] = str(exc)
        if not result.get("error_class"):
            result["error_class"] = "unexpected"

    cache_set(conn, result)
    return result

# ---------------------------------------------------------------------------
# Main Pipeline
# ---------------------------------------------------------------------------


def run_pipeline(settings: Settings) -> None:
    global DEFAULT_GATEWAYS

    # FIX 6: Add local IPFS only if explicitly configured
    if settings.local_ipfs:
        DEFAULT_GATEWAYS = ["http://127.0.0.1:8080/ipfs/{cid_path}"] + DEFAULT_GATEWAYS
        print("✅ Local IPFS node enabled.")
    else:
        print("ℹ️  Using public IPFS gateways (set NFT_LOCAL_IPFS=1 to use local node).")

    df = pd.read_csv(settings.input_csv, on_bad_lines="skip")
    if not {"address", "first_seen_txhash"}.issubset(df.columns):
        raise ValueError("CSV missing required columns: address, first_seen_txhash")

    if not settings.run_all and "has_url" in df.columns:
        df = df[df["has_url"] == True]
    if settings.max_rows:
        df = df.head(settings.max_rows)

    df["address"] = df["address"].astype(str).str.lower().str.strip()
    conn = open_cache(settings.cache_path)
    cached = {} if settings.force else cache_get_all(conn)

    is_cached = df["address"].isin(cached)
    new_df, cached_df = df[~is_cached], df[is_cached]
    print(f"Total: {len(df):,} | Cached: {len(cached_df):,} | To fetch: {len(new_df):,}")

    os.makedirs(os.path.dirname(settings.output_csv) or ".", exist_ok=True)
    write_header = True

    def _flush(rows: list) -> None:
        nonlocal write_header
        if not rows:
            return
        chunk_df = pd.DataFrame(rows)
        chunk_df = chunk_df[[c for c in OUTPUT_COLUMNS if c in chunk_df.columns]]
        chunk_df.to_csv(settings.output_csv, mode="a" if not write_header else "w",
                        header=write_header, index=False)
        write_header = False
        rows.clear()

    # Write cached rows first
    cached_rows = []
    for _, row in cached_df.iterrows():
        hit = cached[row["address"]]
        hit.update({"name": row.get("name"), "known_url": row.get("extracted_urls")})
        cached_rows.append(hit)
    _flush(cached_rows)

    CHUNK_SIZE = 50
    n_workers = min(settings.max_workers, 30)
    total = len(new_df)
    processed = 0

    if not new_df.empty:
        print(f"🚀 Processing {total:,} rows with {n_workers} workers...")
        with ThreadPoolExecutor(max_workers=n_workers) as executor:
            executor = ThreadPoolExecutor(max_workers=n_workers)

            for chunk_start in range(0, total, CHUNK_SIZE):
                chunk = new_df.iloc[chunk_start: chunk_start + CHUNK_SIZE]
                chunk_results = []

                futures = {executor.submit(process_row_task, row, settings, conn): row
                        for _, row in chunk.iterrows()}

                # THE FIX: We wrap the ENTIRE for loop in the try/except block
                try:
                    for future in as_completed(futures, timeout=180):
                        try:
                            chunk_results.append(future.result())
                        except Exception as e:
                            row = futures[future]
                            chunk_results.append(make_result_row(
                                row) | {"error": f"thread_exception: {e}", "error_class": "unexpected"})
                except TimeoutError:
                    # If the 180 seconds expire before all 50 finish, this catches it safely!
                    log.warning(
                        f"Chunk hit the 180-second timeout! Force-cancelling {len([f for f in futures if not f.done()])} stuck threads.")
                    for f in futures:
                        f.cancel()  # Tell the pool to drop the pending ones

                    # For the ones that timed out, we still want to log them as errors in the CSV
                    for f, row in futures.items():
                        if not f.done():
                            chunk_results.append(make_result_row(
                                row) | {"error": "row_timeout_in_pool", "error_class": "network"})

                _flush(chunk_results)
                processed += len(chunk)
                print(f"  Processed: {processed}/{total}")

            executor.shutdown(wait=False, cancel_futures=True)
    conn.close()

    out_df = pd.read_csv(settings.output_csv)
    n = len(out_df)
    got_uri = out_df.get("token_uri_raw", pd.Series()).notna().sum()
    got_meta = out_df.get("meta_name", pd.Series()).notna().sum()
    errors = out_df.get("error", pd.Series()).notna().sum()
    print(f"\n✅ Done → {settings.output_csv}")
    print(f"   Total: {n:,} | URIs resolved: {got_uri:,} | Metadata: {got_meta:,} | Errors: {errors:,}")


if __name__ == "__main__":
    run_pipeline(load_settings())
