import os
import re
import gzip
import logging
from urllib.parse import urlparse, unquote, quote
import pandas as pd
import requests
from web3 import Web3
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED, as_completed
import time
import base64
import json
import json5
import urllib.parse
import threading
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- LOGGING ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("decode_tid.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)


# --- CONFIGURATION ---
INPUT_CSV = "/home/leyla/blockchain-phishing/data/nft_tokens.csv"
SUCCESS_CSV = "../data/output/success_nfts.csv"
ERROR_CSV = "../data/output/error_nfts.csv"
BSC_RPC = "https://bsc-rpc.publicnode.com"
IPFS_GATEWAY = "http://127.0.0.1:8080/ipfs/"
MAX_WORKERS = 15
FLUSH_EVERY = 200


# hardcoded blocklist of hostnames that are placeholders, mock, internal. If a contract's URI points to one of these,
# #skip instead of making a uselless HTTP request:
SKIP_HOSTS = {
    'localhost', '0.0.0.0', 'example.com',
    'api.example.com', 'cdn.example.com', 'agora.example',
    'api.triplec.example', 'placeholder-uri', 'nothing.mock1',
    'api.node.com'
}

# different timeouts per lble:
TIMEOUT_BY_SOURCE = {
    "http":                  8,   # regular HTTP servers should be fast
    "ipfs_gateway":          5,   # local node — should be fast if pinned
    "ipfs_gateway_json":     5,
    "ipfs_gateway_fallback": 10,  # public gateways can be slow
    "arweave":               10,  # arweave.net can be slow
    "arweave_json":          10,
}
# fallback timeout for any sources not explicitly listed in TIMEOUT_BY_SOURCE
DEFAULT_TIMEOUT = 8

# Expanded ABI to include evasion methods (getURI, metadataURI)
URI_ABI = [
    {"inputs": [{"name": "tokenId", "type": "uint256"}], "name": "tokenURI",    "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"name": "id",      "type": "uint256"}], "name": "uri",         "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"name": "tokenId", "type": "uint256"}], "name": "getURI",      "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"name": "id",      "type": "uint256"}], "name": "metadataURI", "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "tokenURI",    "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "uri",         "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "baseURI",     "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "contractURI", "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "getURI",      "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "metadataURI", "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
]


# ERC-721 and ERC-20 standard Transfer event
TRANSFER_TOPIC = "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
# ERC-1155 standard TransferSingle event
TRANSFER_SINGLE_TOPIC = "c3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62"

# Matches bare IPFS CIDs returned without the ipfs:// scheme
_BARE_CID_RE = re.compile(
    r"^(Qm[1-9A-HJ-NP-Za-km-z]{44}|bafy[a-z2-7]{52,})(/.*)?$")


# ---------------------------------------------------------------------------
# THREAD-LOCAL RESOURCES: Web3 connections and HTTP sessions are not thread-safe, so each worker thread gets its own instance.
# ---------------------------------------------------------------------------

_thread_local = threading.local()


def _get_thread_w3() -> Web3:
    """Each worker thread gets its own Web3 connection."""
    if not hasattr(_thread_local, "w3"):
        _thread_local.w3 = Web3(Web3.HTTPProvider(BSC_RPC))
    return _thread_local.w3


def _get_thread_session() -> requests.Session:
    """Each worker thread gets its own requests Session."""
    if not hasattr(_thread_local, "session"):
        s = requests.Session()
        s.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
        })

        adapter = requests.adapters.HTTPAdapter(
            # Keep a small pool of connections for efficiency, but not too many to overwhelm the local node
            pool_connections=4, pool_maxsize=4)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        s.max_redirects = 10  # quindi 1 o 10?
        _thread_local.session = s
    return _thread_local.session


# ---------------------------------------------------------------------------
# STAGE 1: URI EXTRACTION (Web3 / RPC)
# ---------------------------------------------------------------------------

def get_exact_token_id(w3, tx_hash: str, address: str):
    if pd.isna(tx_hash) or not str(tx_hash).startswith("0x"):
        return None
    try:
        # fetch the transaction receipt to access logs from the RPC, which may contain the exact token ID in Transfer events
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        for log in receipt.get('logs', []):
            if log['address'].lower() == address.lower() and log['topics']:
                topic0 = log['topics'][0].hex()
                if topic0 == TRANSFER_TOPIC:
                    # ERC-721: TokenID is usually indexed (topic 3)
                    if len(log['topics']) >= 4:
                        return int(log['topics'][3].hex(), 16)
                    # Non-standard: TokenID is NOT indexed, falls into the data field
                    else:
                        data_hex = log['data'].hex()
                        clean = data_hex[2:] if data_hex.startswith(
                            "0x") else data_hex
                        if len(clean) >= 64:
                            return int(clean[:64], 16)

                elif topic0 == TRANSFER_SINGLE_TOPIC:
                    data_hex = log['data'].hex()
                    clean = data_hex[2:] if data_hex.startswith(
                        "0x") else data_hex
                    if len(clean) >= 64:
                        return int(clean[:64], 16)
    except Exception:
        pass
    return None


def is_rpc_rate_limited(exc: Exception) -> bool:
    """Detects if an RPC error is likely due to rate limiting."""
    msg = str(exc).lower()
    # this is a heuristic and may not catch all cases, but it looks for common indicators of rate limiting in the error message
    return "429" in msg or "rate limit" in msg or "too many requests" in msg


def extract_uri_from_contract(w3, address: str, tx_hash: str) -> tuple[str | None, int | None, str | None]:
    """
    Returns (uri, token_id, error_message). 
    On success, token_id is the ID used (or None for no-arg functions). 
    On error, uri and token_id are None.
    """
    try:
        checksum_addr = w3.to_checksum_address(address)
    except Exception as e:
        return None, None, f"RPC Error: Invalid address — {e}"

    try:
        code = w3.eth.get_code(checksum_addr)
        if code in (b'', b'\x00'):
            return None, None, "True Negative: No contract code (EOA or self-destructed)"
    except Exception as e:
        if is_rpc_rate_limited(e):
            return None, None, f"RPC Error: Rate limited — {e}"
        return None, None, f"RPC Error: Could not fetch bytecode — {e}"

    try:
        contract = w3.eth.contract(address=checksum_addr, abi=URI_ABI)
    except Exception as e:
        return None, None, f"RPC Error: Could not instantiate contract — {e}"

    uri = None
    resolved_token_id = None
    last_err = None

    # 1. Token-ID-based functions first (most reliable for ERC-721/1155)
    for token_id in [1, 0, 2, 1000, 10000]:
        for func_name in ['tokenURI', 'uri', 'getURI', 'metadataURI']:
            try:
                candidate = getattr(contract.functions,
                                    func_name)(token_id).call()
                if candidate and candidate.strip():
                    if "{id}" in candidate:
                        candidate = candidate.replace(
                            "{id}", format(token_id, "x").zfill(64))
                    uri = candidate
                    resolved_token_id = token_id
                    break
            except Exception as e:
                if is_rpc_rate_limited(e):
                    return None, None, f"RPC Error: Rate limited — {e}"
                last_err = e
                continue
        if uri:
            break

    # 2. No-argument evasion functions — only if step 1 found nothing
    if not uri:
        for func_name in ['baseURI', 'contractURI', 'tokenURI', 'uri', 'getURI', 'metadataURI']:
            try:
                candidate = getattr(contract.functions, func_name)().call()
                if isinstance(candidate, str) and candidate.strip():
                    uri = candidate
                    break
            except Exception as e:
                if is_rpc_rate_limited(e):
                    return None, None, f"RPC Error: Rate limited — {e}"
                last_err = e
                continue

    # 3. Exact token ID extracted from transaction logs — only if steps 1 and 2 found nothing
    if not uri:
        exact_id = get_exact_token_id(w3, tx_hash, address)
        if exact_id is not None:
            for func_name in ['tokenURI', 'uri', 'getURI', 'metadataURI']:
                try:
                    candidate = getattr(contract.functions,
                                        func_name)(exact_id).call()
                    if candidate and candidate.strip():
                        if "{id}" in candidate:
                            candidate = candidate.replace(
                                "{id}", format(exact_id, "x").zfill(64))
                        uri = candidate
                        resolved_token_id = exact_id
                        break
                except Exception as e:
                    if is_rpc_rate_limited(e):
                        return None, None, f"RPC Error: Rate limited — {e}"
                    last_err = e
                    continue

    if not uri:
        error_msg = "No URI found on contract (even with exact ID)"
        if last_err:
            err_str = str(last_err).replace('\n', ' ')[:200]
            error_msg += f" — Last revert/error: {err_str}"
        return None, None, error_msg

    # Sanitise the raw URI string
    uri = uri.split('\x00')[0].strip()
    if not uri:
        return None, None, "Invalid URI: contained only null bytes"

    # Fix malformed port+path (e.g. ":7777contract/" → ":7777/contract/")
    uri = re.sub(r'(:\d{2,5})([a-zA-Z])', r'\1/\2', uri)

    # Reject unfilled template literals ({address}, {contract}, {id})
    if re.search(r'\{(address|contract|id)\}', unquote(uri), re.IGNORECASE):
        return None, None, f"Invalid URI: unfilled template literal in '{uri}'"

    return uri, resolved_token_id, None


# ---------------------------------------------------------------------------
# STAGE 2: METADATA FETCH (HTTP / IPFS / on-chain data: URI)
# ---------------------------------------------------------------------------

# Known gateway prefixes to normalise to the local node
_IPFS_GATEWAY_PREFIXES = [
    "ipfs://",
    "https://ipfs.io/ipfs/",
    "https://dweb.link/ipfs/",
    "https://gateway.pinata.cloud/ipfs/",
    # decommissioned Aug 2024, kept for stored URIs
    "https://cloudflare-ipfs.com/ipfs/",
    "https://cf-ipfs.com/ipfs/",
]

# Public fallback gateways tried in order when the local node fails
_PUBLIC_GATEWAYS = [
    "https://ipfs.io/ipfs/{cid_path}",
    "https://dweb.link/ipfs/{cid_path}",
    "https://gateway.pinata.cloud/ipfs/{cid_path}",
]

_ARWEAVE_GATEWAYS = ["https://arweave.net/{txid_path}"]


def _ipfs_cid_path(uri: str) -> str | None:
    """Extract the CID+path portion from any recognised IPFS URI form."""
    for prefix in _IPFS_GATEWAY_PREFIXES:
        if uri.startswith(prefix):
            # Remove the prefix and any leading slashes
            payload = uri[len(prefix):].lstrip("/")
            if payload.startswith("ipfs/"):
                # Remove redundant "ipfs/" if present after the prefix
                payload = payload[5:]
            return payload or None  # Return None if the payload is empty after stripping
    # If it's a bare CID (with optional path), treat the whole thing as the CID path
    if _BARE_CID_RE.match(uri):
        return uri
    return None


def format_ipfs_url(uri: str | None) -> str | None:
    """Normalise any IPFS URI to the local gateway. Non-IPFS URIs pass through."""
    if not uri:
        return uri
    cid_path = _ipfs_cid_path(uri)
    if cid_path:
        return f"{IPFS_GATEWAY}{cid_path}"
    return uri


def uri_fetch_candidates(uri: str, token_id: int | None) -> list[tuple[str, str]]:
    """
    Expand a raw token URI into an ordered list of (url, source_label) pairs to try.

    Handles: ipfs://, bare CIDs, ar://, arweave.net, http/https, data: URIs.
    For IPFS URIs, also tries appending .json for contracts that omit the extension.
    Falls back to public gateways automatically when the local node is listed first.
    """
    if not isinstance(uri, str) or not uri.strip():
        return []

    raw = uri.strip()  # Remove leading/trailing whitespace

    # Substitute ERC-1155 {id} placeholder with the actual token ID in hex, zero-padded to 64 chars, if available. This is a common pattern in ERC-1155 contracts where the URI is a template that needs the token ID filled in. If token_id is None, we leave the placeholder as-is, which may still resolve correctly for some contracts that handle it on their end, but in many cases it will lead to an invalid URL.
    if "{id}" in raw and token_id is not None:
        raw = raw.replace("{id}", format(token_id, "x").zfill(64))

    # on-chain data: URI — no network needed
    # If the URI is a data URI, we can decode it directly without making an HTTP request. We return it as a candidate with a special label so that the orchestrator knows to handle it differently.
    if raw.startswith("data:"):
        return [(raw, "data_uri")]

    # IPFS (ipfs://, gateway URLs, bare CIDs)
    cid_path = _ipfs_cid_path(raw)
    if cid_path:
        candidates = []
        encoded = quote(cid_path)
        # Local node first, then public gateways
        all_gateways = [
            "http://127.0.0.1:8080/ipfs/{cid_path}"] + _PUBLIC_GATEWAYS
        for tpl in all_gateways:
            url = tpl.format(cid_path=encoded)
            candidates.append((url, "ipfs_gateway"))
            # Try with .json suffix in case the contract omits it
            if not cid_path.split("/")[-1].endswith(".json"):
                candidates.append(
                    (tpl.format(cid_path=encoded + ".json"), "ipfs_gateway_json"))
        return candidates

    # Arweave
    if raw.startswith("ar://"):
        txid_path = raw[5:].strip().lstrip("/")
        if txid_path:
            return [(tpl.format(txid_path=quote(txid_path)), "arweave")
                    for tpl in _ARWEAVE_GATEWAYS]

    if raw.startswith("https://arweave.net/"):
        candidates = [(raw, "arweave")]
        if not raw.split("?")[0].endswith(".json"):
            candidates.append((raw + ".json", "arweave_json"))
        return candidates

    # Plain HTTP/HTTPS — also try re-routing through public IPFS gateways if /ipfs/ is in the path
    if raw.startswith("http://") or raw.startswith("https://"):
        candidates = [(raw, "http")]
        if "/ipfs/" in raw:
            cid_part = raw.split("/ipfs/", 1)[1].strip("/")
            if cid_part:
                for tpl in _PUBLIC_GATEWAYS:
                    fallback = tpl.format(cid_path=quote(cid_part))
                    if fallback != raw:
                        candidates.append((fallback, "ipfs_gateway_fallback"))
        return candidates

    return []


def safe_json_loads(text: str) -> dict:
    try:
        result = json.loads(text)
    except json.JSONDecodeError:
        result = json5.loads(text)
    if not isinstance(result, dict):
        raise ValueError(
            f"Expected a JSON object, got {type(result).__name__}")
    return result


def fetch_metadata_from_data_uri(uri: str) -> tuple[dict | None, str | None]:
    try:
        header, payload = uri.split(",", 1)
        if "base64" in header.lower():
            padding_needed = (4 - len(payload) % 4) % 4
            raw_bytes = base64.b64decode(payload + "=" * padding_needed)
            try:
                data_str = raw_bytes.decode('utf-8', errors='ignore')
            except Exception:
                data_str = raw_bytes.decode('latin-1', errors='ignore')
        else:  # if not base64, the payload is URL-encoded, so we decode it using unquote
            data_str = urllib.parse.unquote(payload)
        # Some metadata JSONs contain unescaped newlines, which are technically invalid but we want to handle them gracefully. We replace unescaped newlines with the literal \n sequence before parsing, so that they are preserved in the resulting string values without causing a JSON parse error.
        # regex to replace unescaped newlines with \n
        data_str = re.sub(r'(?<!\\)\n', r'\\n', data_str)
        return safe_json_loads(data_str), None

    except Exception as e:
        # generic error message for any failure in parsing the data URI, which could be due to malformed structure, decoding issues, or JSON parsing errors. The specific exception message is included for debugging purposes.
        return None, f"On-Chain Parse Error: {e}"


'''
this function fetches the metadata from a given URL using the provided HTTP session. 
It handles various edge cases such as invalid URLs, network errors, unexpected content types (like HTML or binary data), gzip-compressed responses, and JSON parsing errors. 
It returns either the parsed metadata as a dictionary or an error message describing what went wrong. 
'''


def fetch_metadata_over_http(session: requests.Session, source_label: str, fetch_url: str) -> tuple[dict | None, str | None]:
    # Reject relative paths to avoid SSRF and clearly invalid URLs. We require absolute URLs with a scheme (http/https) to ensure we know where we're fetching from and can apply appropriate handling and security checks.
    if fetch_url.startswith('/'):
        return None, f"Invalid URI: relative path '{fetch_url}'"
    if not fetch_url.startswith("http"):
        # bc it doesn't start with http, it's not a valid URL we can fetch. This is a quick check to filter out clearly invalid URIs before attempting to parse them, which would likely fail or be more complex to handle. We only support http and https schemes for off-chain metadata fetching in this function; data: URIs are handled separately in the orchestrator.
        return None, f"Invalid URI: unsupported scheme in '{fetch_url}'"

    try:
        # Parse the URL to extract the hostname for blocklisting. If the URL is malformed, urlparse may raise an exception, which we catch and return as an error message.
        parsed_host = urlparse(fetch_url).hostname or ""
    except Exception as e:
        return None, f"Invalid URI: could not parse host — {e}"

    if parsed_host in SKIP_HOSTS:
        return None, f"Invalid URI: skipped host '{parsed_host}'"

    timeout = TIMEOUT_BY_SOURCE.get(source_label, DEFAULT_TIMEOUT)
    final_url = fetch_url

    try:
        # Use source-specific timeout if available, otherwise default to 8 seconds
        response = session.get(fetch_url, timeout=timeout, verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as primary_err:
        # Public gateway fallbacks are handled by uri_fetch_candidates in the
        # orchestrator — each gateway is a separate candidate, so we just
        # report this URL's failure and let the caller try the next one.
        return None, f"Network Error: {primary_err}"

    final_url = response.url  # after redirects
    content_type = response.headers.get('Content-Type', '')

    if 'text/html' in content_type.lower():
        snippet = response.text[:300].strip().replace('\n', ' ')
        return None, f"Server returned HTML instead of JSON (from {final_url}): '{snippet}'"

    # if the uri points to a media file, treat the URL as the image
    if any(t in content_type for t in ('image/', 'video/', 'audio/')):
        return {"image": final_url}, None

    raw_body = response.content.strip()
    if not raw_body:
        return None, f"Server returned an empty body (HTTP {response.status_code}, from {final_url})"

    # Check for gzip magic number to detect compressed responses, which some servers use to save bandwidth. If we detect gzip compression, we attempt to decompress it before further processing. If decompression fails, we return an error message indicating that the response was gzip-compressed but could not be decompressed, which may suggest an issue with the server's response or an incorrect Content-Encoding header.
    if raw_body[:2] == b'\x1f\x8b':
        try:
            raw_body = gzip.decompress(raw_body)
        except Exception as gz_err:
            return None, f"Gzip decompression failed (from {final_url}): {gz_err}"

    # If the first byte is a control character (except for common whitespace), it's likely not valid JSON. We check this to catch cases where the server returns binary data or an error message that isn't JSON, which would cause the JSON parser to fail with a less clear error. By checking for control characters early, we can provide a more specific error message about the response being non-textual.
    if raw_body[0] < 0x20 and raw_body[0] not in (0x09, 0x0a, 0x0d):
        snippet = raw_body[:16].hex()
        return None, f"Server returned binary/non-text response (from {final_url}): first bytes 0x{snippet}"

    try:
        try:
            text_content = raw_body.decode('utf-8-sig')
        except UnicodeDecodeError:
            text_content = raw_body.decode('utf-8', errors='ignore')

        metadata = safe_json_loads(text_content)
        return metadata, None

    except Exception as e:
        snippet = raw_body[:300].decode(
            'utf-8', errors='replace').strip().replace('\n', ' ')
        return None, f"JSON parse failed (from {final_url}): {e} — server returned: '{snippet}'"


# ---------------------------------------------------------------------------
# STAGE 3: SET UP, called by each worker thread for each address
# ---------------------------------------------------------------------------

def get_nft_data(address: str, tx_hash: str) -> dict:
    result = {
        "address": address,
        "token_id": None,
        "token_uri": None,
        "meta_name": None,
        "meta_description": None,
        "meta_image": None,
        "error": None,
    }

    w3 = _get_thread_w3()
    session = _get_thread_session()

    uri, resolved_token_id, rpc_error = extract_uri_from_contract(
        w3, address, tx_hash)
    if rpc_error:
        result["error"] = rpc_error
        return result

    result["token_id"] = str(
        resolved_token_id) if resolved_token_id is not None else None
    result["token_uri"] = uri

    # Build ordered list of URLs to try for this URI
    # takes raw URI and token ID, and returns a list of (fetch_url, source_label) pairs to try in order. This handles all the logic of normalising IPFS URIs, substituting token IDs into templates, and generating fallback URLs for public gateways. If the URI is invalid or unsupported, this may return an empty list, which we check for before proceeding to fetch metadata.
    candidates = uri_fetch_candidates(uri, resolved_token_id)
    if not candidates:  # if no valid list of candidates:
        result["error"] = f"Invalid URI: unsupported scheme in '{uri}'"
        return result

    # data: URI — decode on-chain, no HTTP needed
    if candidates[0][1] == "data_uri":
        metadata, parse_error = fetch_metadata_from_data_uri(uri)
        if parse_error:
            result["error"] = parse_error
            return result
        result["meta_name"] = metadata.get("name")
        result["meta_description"] = metadata.get("description")
        result["meta_image"] = format_ipfs_url(
            metadata.get("image") or metadata.get("image_url"))
        return result

    # Off-chain: try each candidate URL in order
    all_errors = []
    for fetch_url, source_label in candidates:
        metadata, http_error = fetch_metadata_over_http(
            session, source_label, fetch_url)
        if metadata is not None:
            result["meta_name"] = metadata.get("name")
            result["meta_description"] = metadata.get("description")
            result["meta_image"] = format_ipfs_url(
                metadata.get("image") or metadata.get("image_url"))
            return result
        all_errors.append(f"[{source_label}] {http_error}")

    result["error"] = " | ".join(all_errors)
    return result


# ---------------------------------------------------------------------------
# SAVE HELPER
# ---------------------------------------------------------------------------

def _flush_results(
    results: list[dict],
    pending_df: pd.DataFrame,
    success_csv: str,
    error_csv: str,
) -> None:
    """Write a batch of results to the success/error CSVs."""
    if not results:
        return

    results_df = pd.DataFrame(results)
    src = pending_df.drop(columns=["error"], errors="ignore")
    merged = pd.merge(src, results_df, on="address", how="inner")
    new_success_df = merged[merged["error"].isna()]
    new_error_df = merged[merged["error"].notna()]

    os.makedirs(os.path.dirname(success_csv), exist_ok=True)
    os.makedirs(os.path.dirname(error_csv),   exist_ok=True)

    if not new_success_df.empty:
        write_header = not os.path.exists(success_csv)
        new_success_df.to_csv(success_csv, mode="a",
                              index=False, header=write_header)
        log.info(f"Flushed {len(new_success_df)} successes to {success_csv}")

    if not new_error_df.empty:
        if os.path.exists(error_csv):
            existing = pd.read_csv(error_csv, dtype={"token_id": str})
            combined = pd.concat([existing, new_error_df])
            deduped = combined.drop_duplicates(subset=["address"], keep="last")
            deduped.to_csv(error_csv, index=False)
            log.info(
                f"Updated {error_csv} with {len(new_error_df)} failures (duplicates removed).")
        else:
            new_error_df.to_csv(error_csv, index=False)
            log.info(f"Created {error_csv} with {len(new_error_df)} failures.")


# ---------------------------------------------------------------------------
# MAIN PIPELINE
#  ---------------------------------------------------------------------------

def main():
    log.info(f"Loading {INPUT_CSV}...")
    try:
        df = pd.read_csv(INPUT_CSV)
        df['address'] = df['address'].astype(str).str.lower().str.strip()
    except FileNotFoundError:
        log.error(f"{INPUT_CSV} not found.")
        return

    successful_addresses: set[str] = set()
    if os.path.exists(SUCCESS_CSV):
        try:
            success_df = pd.read_csv(SUCCESS_CSV, dtype={"token_id": str})
            successful_addresses = set(
                success_df['address'].astype(str).str.lower().str.strip())
            log.info(
                f"  {len(successful_addresses)} previously successful addresses — skipping.")
        except Exception as e:
            log.warning(f"Could not read {SUCCESS_CSV}: {e}")

    pending_df = df[~df['address'].isin(
        successful_addresses)].drop_duplicates(subset=['address'])
    total = len(pending_df)

    if total == 0:
        log.info("No new addresses to process. Everything is up to date!")
        return

    log.info(
        f"Need to process {total} addresses with {MAX_WORKERS} workers...")

    rows = list(pending_df.iterrows())
    results = []
    count = 0
    interrupted = False
    start_time = time.time()

    executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    futures: dict = {}

    def _submit_batch():
        """Fill the pool up to MAX_WORKERS * 4 in-flight futures."""
        while rows and len(futures) < MAX_WORKERS * 4:
            _, row = rows.pop(0)
            addr = row['address']
            tx = row.get('first_seen_txhash', None)
            f = executor.submit(get_nft_data, addr, tx)
            futures[f] = addr

    try:
        _submit_batch()
        while futures:
            done, _ = wait(futures, return_when=FIRST_COMPLETED)
            for f in done:
                try:
                    results.append(f.result())
                except Exception as exc:
                    addr = futures[f]
                    results.append({"address": addr, "token_id": None, "token_uri": None,
                                    "meta_name": None, "meta_description": None,
                                    "meta_image": None, "error": f"Unhandled exception: {exc}"})
                del futures[f]
                count += 1
                if count % 50 == 0 or count == total:
                    log.info(f"  Processed {count}/{total}...")
                # Periodic flush to disk
                if count % FLUSH_EVERY == 0:
                    _flush_results(results, pending_df, SUCCESS_CSV, ERROR_CSV)
                    results.clear()
            # Keep the pool topped up
            _submit_batch()

    except KeyboardInterrupt:
        interrupted = True
        log.warning(
            f"\nInterrupted — cancelling pending work, saving {len(results)} results so far...")
        executor.shutdown(wait=False, cancel_futures=True)
    else:
        executor.shutdown(wait=False)

    if interrupted and not results:
        log.info("No results to save.")
        return

    # Final flush
    _flush_results(results, pending_df, SUCCESS_CSV, ERROR_CSV)



    elapsed = time.time() - start_time
    log.info(
        f"\n{'Interrupted' if interrupted else 'Finished'} after {elapsed:.2f} seconds.")


if __name__ == "__main__":
    main()
