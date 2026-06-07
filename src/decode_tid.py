import os
import re
import gzip
from urllib.parse import urlparse, unquote, quote
import pandas as pd
import requests
from web3 import Web3
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import base64
import json
import json5
import urllib.parse
import threading
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURATION ---
INPUT_CSV = "/home/leyla/blockchain-phishing/data/nft_tokens.csv"
SUCCESS_CSV = "../data/output/success_nfts.csv"
ERROR_CSV = "../data/output/error_nfts.csv"
BSC_RPC = "https://bsc-rpc.publicnode.com"
IPFS_GATEWAY = "http://127.0.0.1:8080/ipfs/"
MAX_WORKERS = 5

SKIP_HOSTS = {
    'localhost', '0.0.0.0', 'example.com',
    'api.example.com', 'cdn.example.com', 'agora.example',
    'api.triplec.example', 'placeholder-uri', 'nothing.mock1',
    'api.node.com'
}

# Expanded ABI to include evasion methods (getURI, metadataURI)
URI_ABI = [
    {"inputs": [{"name": "tokenId", "type": "uint256"}], "name": "tokenURI", "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"name": "id", "type": "uint256"}], "name": "uri", "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"name": "tokenId", "type": "uint256"}], "name": "getURI", "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"name": "id", "type": "uint256"}], "name": "metadataURI", "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "tokenURI", "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "uri", "outputs": [{"name": "", "type": "string"}],
        "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "baseURI", "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "contractURI", "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "getURI", "outputs": [{"name": "", "type": "string"}],
        "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "metadataURI", "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
]

TRANSFER_TOPIC = "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
TRANSFER_SINGLE_TOPIC = "c3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62"

# Matches bare IPFS CIDs returned without the ipfs:// scheme
_BARE_CID_RE = re.compile(r"^(Qm[1-9A-HJ-NP-Za-km-z]{44}|bafy[a-z2-7]{52,})(/.*)?$")


# ---------------------------------------------------------------------------
# THREAD-LOCAL RESOURCES
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
            pool_connections=4, pool_maxsize=4, max_retries=1)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        s.max_redirects = 10
        _thread_local.session = s
    return _thread_local.session


# ---------------------------------------------------------------------------
# STAGE 1: URI EXTRACTION (Web3 / RPC)
# ---------------------------------------------------------------------------

def get_exact_token_id(w3, tx_hash: str, address: str):
    if pd.isna(tx_hash) or not str(tx_hash).startswith("0x"):
        return None
    try:
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


def extract_uri_from_contract(w3, address: str, tx_hash: str) -> tuple[str | None, int | None, str | None]:
    """
    Returns (uri, token_id, error_message). On success, token_id is the ID used (or None for no-arg functions). On error, uri and token_id are None.
    """
    try:
        checksum_addr = w3.to_checksum_address(address)
    except Exception as e:
        return None, None, f"RPC Error: Invalid address — {e}"

    try:
        if w3.eth.get_code(checksum_addr) in (b'', b'\x00'):
            return None, None, "True Negative: Contract is Dead / Self-Destructed"
    except Exception as e:
        return None, None, f"RPC Error: Could not fetch bytecode — {e}"

    try:
        contract = w3.eth.contract(address=checksum_addr, abi=URI_ABI)
    except Exception as e:
        return None, None, f"RPC Error: Could not instantiate contract — {e}"

    uri = None
    resolved_token_id = None
    last_err = None

    # 1. No-argument evasion functions
    for func_name in ['baseURI', 'contractURI', 'tokenURI', 'uri', 'getURI', 'metadataURI']:
        try:
            candidate = getattr(contract.functions, func_name)().call()
            if isinstance(candidate, str) and candidate.strip():
                uri = candidate
                break
        except Exception as e:
            last_err = e
            continue

    # 2. Fast sweep with common token IDs + offset IDs
    if not uri:
        for token_id in [1, 0, 2, 1000, 10000]:
            # Standard functions
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
                    last_err = e
                    continue
            if uri:
                break

    # 3. Exact token ID extracted from transaction logs
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
    "https://cloudflare-ipfs.com/ipfs/",  # decommissioned Aug 2024, kept for stored URIs
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
            payload = uri[len(prefix):].lstrip("/")
            if payload.startswith("ipfs/"):
                payload = payload[5:]
            return payload or None
    if _BARE_CID_RE.match(uri):
        return uri
    return None


def format_ipfs_url(uri: str | None) -> str | None:
    """Normalise any IPFS URI to the local gateway. Non-IPFS URIs pass through."""
    if not uri:
        return uri
    cid_path = _ipfs_cid_path(uri)
    if cid_path:
        return f"http://127.0.0.1:8080/ipfs/{cid_path}"
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

    raw = uri.strip()

    # Substitute ERC-1155 {id} placeholder
    if "{id}" in raw and token_id is not None:
        raw = raw.replace("{id}", format(token_id, "x").zfill(64))

    # on-chain data: URI — no network needed
    if raw.startswith("data:"):
        return [(raw, "data_uri")]

    # IPFS (ipfs://, gateway URLs, bare CIDs)
    cid_path = _ipfs_cid_path(raw)
    if cid_path:
        candidates = []
        encoded = quote(cid_path)
        # Local node first, then public gateways
        all_gateways = ["http://127.0.0.1:8080/ipfs/{cid_path}"] + _PUBLIC_GATEWAYS
        for tpl in all_gateways:
            url = tpl.format(cid_path=encoded)
            candidates.append((url, "ipfs_gateway"))
            # Try with .json suffix in case the contract omits it
            if not cid_path.split("/")[-1].endswith(".json"):
                candidates.append((tpl.format(cid_path=encoded + ".json"), "ipfs_gateway_json"))
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
        else:
            data_str = urllib.parse.unquote(payload)

        data_str = re.sub(r'(?<!\\)\n', r'\\n', data_str)
        return safe_json_loads(data_str), None

    except Exception as e:
        return None, f"On-Chain Parse Error: {e}"


def fetch_metadata_over_http(session: requests.Session, fetch_url: str) -> tuple[dict | None, str | None]:
    if fetch_url.startswith('/'):
        return None, f"Invalid URI: relative path '{fetch_url}'"
    if not fetch_url.startswith("http"):
        return None, f"Invalid URI: unsupported scheme in '{fetch_url}'"

    try:
        parsed_host = urlparse(fetch_url).hostname or ""
    except Exception as e:
        return None, f"Invalid URI: could not parse host — {e}"

    if parsed_host in SKIP_HOSTS:
        return None, f"Invalid URI: skipped host '{parsed_host}'"

    response = None
    final_url = fetch_url

    try:
        response = session.get(fetch_url, timeout=15, verify=False)
        # Some servers (User-Agent filters, rate limiters) return 403 spuriously.
        # Retry once after a short delay before treating it as a hard failure.
        if response.status_code == 403:
            time.sleep(2)
            response = session.get(fetch_url, timeout=15, verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as primary_err:
        # Public gateway fallbacks are handled by uri_fetch_candidates in the
        # orchestrator — each gateway is a separate candidate, so we just
        # report this URL's failure and let the caller try the next one.
        return None, f"Network Error: {primary_err}"

    content_type = response.headers.get('Content-Type', '')

    if 'text/html' in content_type.lower():
        snippet = response.text[:300].strip().replace('\n', ' ')
        return None, f"Server returned HTML instead of JSON (from {final_url}): '{snippet}'"

    if any(t in content_type for t in ('image/', 'video/', 'audio/')):
        return {"image": final_url}, None

    raw_body = response.content.strip()
    if not raw_body:
        return None, f"Server returned an empty body (HTTP {response.status_code}, from {final_url})"

    if raw_body[:2] == b'\x1f\x8b':
        try:
            raw_body = gzip.decompress(raw_body)
        except Exception as gz_err:
            return None, f"Gzip decompression failed (from {final_url}): {gz_err}"

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
# STAGE 3: ORCHESTRATION
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

    uri, resolved_token_id, rpc_error = extract_uri_from_contract(w3, address, tx_hash)
    if rpc_error:
        result["error"] = rpc_error
        return result

    result["token_id"] = resolved_token_id
    result["token_uri"] = uri

    # Build ordered list of URLs to try for this URI
    candidates = uri_fetch_candidates(uri, resolved_token_id)
    if not candidates:
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
    last_error = None
    for fetch_url, source_label in candidates:
        metadata, http_error = fetch_metadata_over_http(session, fetch_url)
        if metadata is not None:
            result["meta_name"] = metadata.get("name")
            result["meta_description"] = metadata.get("description")
            result["meta_image"] = format_ipfs_url(
                metadata.get("image") or metadata.get("image_url"))
            return result
        last_error = f"[{source_label}] {http_error}"

    result["error"] = last_error
    return result


# ---------------------------------------------------------------------------
# MAIN PIPELINE
# ---------------------------------------------------------------------------

def main():
    print(f"Loading {INPUT_CSV}...")
    try:
        df = pd.read_csv(INPUT_CSV)
        df['address'] = df['address'].astype(str).str.lower().str.strip()
    except FileNotFoundError:
        print(f"Error: {INPUT_CSV} not found.")
        return

    successful_addresses = set()
    if os.path.exists(SUCCESS_CSV):
        try:
            success_df = pd.read_csv(SUCCESS_CSV)
            successful_addresses = set(
                success_df['address'].astype(str).str.lower().str.strip())
            print(
                f"  {len(successful_addresses)} previously successful addresses — skipping.")
        except Exception as e:
            print(f"Could not read {SUCCESS_CSV}: {e}")

    pending_df = df[~df['address'].isin(
        successful_addresses)].drop_duplicates(subset=['address'])
    addresses_to_process = pending_df['address'].tolist()

    if not addresses_to_process:
        print("No new addresses to process. Everything is up to date!")
        return

    print(f"Need to process {len(addresses_to_process)} addresses...")

    results = []
    start_time = time.time()
    interrupted = False

    executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    try:
        futures = {}
        for _, row in pending_df.iterrows():
            addr = row['address']
            tx = row.get('first_seen_txhash', None)
            futures[executor.submit(get_nft_data, addr, tx)] = addr

        for count, future in enumerate(as_completed(futures), 1):
            results.append(future.result())
            if count % 50 == 0 or count == len(addresses_to_process):
                print(f"  Processed {count}/{len(addresses_to_process)}...")

    except KeyboardInterrupt:
        interrupted = True
        print(
            f"\nInterrupted — cancelling pending work, saving {len(results)} results so far...")
        executor.shutdown(wait=False, cancel_futures=True)
    else:
        executor.shutdown(wait=False)

    if interrupted and not results:
        print("No results to save.")
        return

    results_df = pd.DataFrame(results)

    if 'error' in pending_df.columns:
        pending_df = pending_df.drop(columns=['error'])

    final_df = pd.merge(pending_df, results_df, on="address", how="left")

    new_success_df = final_df[final_df['error'].isna()]
    new_error_df = final_df[final_df['error'].notna()]

    os.makedirs(os.path.dirname(SUCCESS_CSV), exist_ok=True)
    os.makedirs(os.path.dirname(ERROR_CSV), exist_ok=True)

    if not new_success_df.empty:
        write_header = not os.path.exists(SUCCESS_CSV)
        new_success_df.to_csv(SUCCESS_CSV, mode='a',
                              index=False, header=write_header)
        print(f"Appended {len(new_success_df)} new successes to {SUCCESS_CSV}")


    if not new_error_df.empty:
        if os.path.exists(ERROR_CSV):
                # Load the old errors, add the new ones, and remove duplicates based on the address
                existing_errors = pd.read_csv(ERROR_CSV)
                combined_errors = pd.concat([existing_errors, new_error_df])
                # keep='last' ensures we keep the most recent error message from this run
                clean_errors = combined_errors.drop_duplicates(
                    subset=['address'], keep='last')
                clean_errors.to_csv(ERROR_CSV, index=False)
                print(
                    f"Updated {ERROR_CSV} with {len(new_error_df)} failures (Duplicates removed!).")
        else:
                new_error_df.to_csv(ERROR_CSV, index=False)
                print(f"Created {ERROR_CSV} with {len(new_error_df)} failures.")
    else:
        if os.path.exists(ERROR_CSV):
            os.remove(ERROR_CSV)
            print("Cleared error file — zero errors!")

    print(f"\n{'Interrupted' if interrupted else 'Finished'} after {time.time() - start_time:.2f} seconds.")


if __name__ == "__main__":
    main()
