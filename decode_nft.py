import os
import re
import gzip
from urllib.parse import urlparse, unquote
import pandas as pd
import requests
from web3 import Web3
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import base64
import json
import json5
import urllib.parse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURATION ---
INPUT_CSV = "/home/leyla/blockchain-phishing/data/nft_tokens.csv"
SUCCESS_CSV = "../data/output/success_nfts.csv"
ERROR_CSV = "../data/output/error_nfts.csv"
BSC_RPC = "https://bsc-rpc.publicnode.com"
IPFS_GATEWAY = "http://127.0.0.1:8080/ipfs/"
MAX_WORKERS = 5

SKIP_HOSTS = {'localhost', '127.0.0.1', '0.0.0.0', 'example.com',
              'api.example.com', 'cdn.example.com', 'agora.example',
              'api.triplec.example', 'placeholder-uri', 'nothing.mock1',
              'api.node.com'}

URI_ABI = [
    {"inputs": [{"name": "tokenId", "type": "uint256"}], "name": "tokenURI", "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"name": "id", "type": "uint256"}], "name": "uri", "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "tokenURI", "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "uri", "outputs": [{"name": "", "type": "string"}],
        "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "baseURI", "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "contractURI", "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "name", "outputs": [{"name": "", "type": "string"}],
        "stateMutability": "view", "type": "function"}
]

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
TRANSFER_SINGLE_TOPIC = "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62"


def get_exact_token_id(w3, tx_hash: str, address: str):
    if pd.isna(tx_hash) or not str(tx_hash).startswith("0x"):
        return None
    try:
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        for log in receipt.get('logs', []):
            if log['address'].lower() == address.lower() and log['topics']:
                topic0 = log['topics'][0].hex()
                if topic0 == TRANSFER_TOPIC and len(log['topics']) >= 4:
                    return int(log['topics'][3].hex(), 16)
                elif topic0 == TRANSFER_SINGLE_TOPIC:
                    data_hex = log['data'].hex()
                    clean = data_hex[2:] if data_hex.startswith("0x") else data_hex
                    return int(clean[:64], 16)
    except Exception:
        pass
    return None


def format_ipfs_url(uri):
    if not uri:
        return uri
    ipfs_prefixes = [
        "ipfs://",
        "https://ipfs.io/ipfs/",
        "https://cloudflare-ipfs.com/ipfs/",
        "https://gateway.pinata.cloud/ipfs/"
    ]
    for prefix in ipfs_prefixes:
        if uri.startswith(prefix):
            cid_and_path = uri[len(prefix):]
            return f"http://127.0.0.1:8080/ipfs/{cid_and_path}"
    return uri


def safe_json_loads(text: str) -> dict:
    """Parse JSON strictly; fall back to json5 for trailing commas, comments, etc."""
    try:
        result = json.loads(text)
    except json.JSONDecodeError:
        result = json5.loads(text)
    if not isinstance(result, dict):
        raise ValueError(f"Expected a JSON object, got {type(result).__name__}")
    return result


def get_nft_data(w3, session, address: str, tx_hash: str) -> dict:
    result = {"address": address, "token_uri": None, "meta_name": None,
              "meta_description": None, "meta_image": None, "error": None}

    try:
        checksum_addr = w3.to_checksum_address(address)

        if w3.eth.get_code(checksum_addr) in (b'', b'\x00'):
            result["error"] = "Contract is Dead / Self-Destructed"
            return result

        contract = w3.eth.contract(address=checksum_addr, abi=URI_ABI)

        try:
            contract.functions.name().call()
        except Exception:
            pass

        uri = None

        # 1. Check no-argument functions first (baseURI, contractURI, etc.)
        for func_name in ['baseURI', 'contractURI', 'tokenURI', 'uri']:
            try:
                uri_candidate = getattr(contract.functions, func_name)().call()
                if isinstance(uri_candidate, str) and uri_candidate.strip():
                    uri = uri_candidate
                    break
            except Exception:
                continue

        # 2. Fast sweep (Standard ERC-721/1155)
        if not uri:
            for token_id in [1, 0, 2]:
                try:
                    candidate = contract.functions.tokenURI(token_id).call()
                    if candidate and candidate.strip():
                        uri = candidate
                        break
                except Exception:
                    try:
                        candidate = contract.functions.uri(token_id).call()
                        if candidate and candidate.strip():
                            if "{id}" in candidate:
                                candidate = candidate.replace("{id}", format(token_id, "x").zfill(64))
                            uri = candidate
                            break
                    except Exception:
                        continue

        # 3. Exact token ID from tx logs
        if not uri:
            exact_id = get_exact_token_id(w3, tx_hash, address)
            if exact_id is not None:
                try:
                    candidate = contract.functions.tokenURI(exact_id).call()
                    if candidate and candidate.strip():
                        uri = candidate
                except Exception:
                    try:
                        candidate = contract.functions.uri(exact_id).call()
                        if candidate and candidate.strip():
                            if "{id}" in candidate:
                                candidate = candidate.replace("{id}", format(exact_id, "x").zfill(64))
                            uri = candidate
                    except Exception:
                        pass

        if not uri:
            result["error"] = "No URI found on contract (even with exact ID)"
            return result

        # Strip null bytes
        uri = uri.split('\x00')[0].strip()

        if not uri:
            result["error"] = "Invalid URI format: URI was only null bytes"
            return result

        # Fix malformed port+path (e.g. ":7777contract/" → ":7777/contract/")
        uri = re.sub(r'(:\d{2,5})([a-zA-Z])', r'\1/\2', uri)

        # Reject unfilled template literals ({address}, {contract}, {id})
        if re.search(r'\{(address|contract|id)\}', unquote(uri), re.IGNORECASE):
            result["error"] = "Invalid URI format: unfilled template literal"
            return result

        result["token_uri"] = uri

        # --- ON-CHAIN BASE64/UTF8 DATA ---
        if uri.startswith("data:"):
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

                # Normalise bare newlines inside string values
                data_str = re.sub(r'(?<!\\)\n', r'\\n', data_str)

                metadata = safe_json_loads(data_str)

                result["meta_name"] = metadata.get("name")
                result["meta_description"] = metadata.get("description")
                result["meta_image"] = format_ipfs_url(
                    metadata.get("image") or metadata.get("image_url"))
                return result

            except Exception as e:
                result["error"] = f"On-Chain Parse Error: {str(e)}"
                return result

        # --- STANDARD HTTP/IPFS URLS ---
        fetch_url = format_ipfs_url(uri)

        if fetch_url and fetch_url.startswith('/'):
            result["error"] = "Invalid URI format: relative path"
            return result

        if not fetch_url or not fetch_url.startswith("http"):
            result["error"] = "Invalid URI format"
            return result

        try:
            parsed_host = urlparse(fetch_url).hostname or ""
        except Exception:
            parsed_host = ""

        if parsed_host in SKIP_HOSTS or parsed_host in ('localhost', '127.0.0.1', '0.0.0.0'):
            result["error"] = f"Invalid URI format: skipped host ({parsed_host})"
            return result

        try:
            response = session.get(fetch_url, timeout=15, verify=False)
            response.raise_for_status()
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError,
                requests.exceptions.HTTPError) as e:
            if "127.0.0.1:8080/ipfs/" in fetch_url:
                public_url = fetch_url.replace(
                    "http://127.0.0.1:8080/ipfs/", "https://cloudflare-ipfs.com/ipfs/")
                try:
                    response = session.get(public_url, timeout=15, verify=False)
                    response.raise_for_status()
                except Exception as e2:
                    raise e2
            else:
                raise e

        if 'text/html' in response.headers.get('Content-Type', '').lower():
            result["error"] = "Contract/Parse Error: Returned HTML/CAPTCHA instead of JSON"
            return result

        raw_body = response.content.strip()
        if not raw_body:
            result["error"] = "Contract/Parse Error: Empty response body"
            return result

        # Decompress unlabelled gzip bodies (magic bytes \x1f\x8b)
        if raw_body[:2] == b'\x1f\x8b':
            try:
                raw_body = gzip.decompress(raw_body)
            except Exception as gz_err:
                result["error"] = f"Contract/Parse Error: Gzip decompression failed ({gz_err})"
                return result

        # Reject binary/control-character responses
        if raw_body and raw_body[0] < 0x20 and raw_body[0] not in (0x09, 0x0a, 0x0d):
            result["error"] = "Contract/Parse Error: Binary/non-text response"
            return result

        # If server returned an image directly, treat it as the NFT image
        content_type = response.headers.get('Content-Type', '')
        if any(t in content_type for t in ('image/', 'video/', 'audio/')):
            result["meta_image"] = fetch_url
            return result

        try:
            if "json" in response.headers.get('Content-Type', ''):
                parsed = response.json()
                if not isinstance(parsed, dict):
                    raise ValueError(f"Expected JSON object, got {type(parsed).__name__}")
                metadata = parsed
            else:
                try:
                    text_content = raw_body.decode('utf-8-sig')
                except UnicodeDecodeError:
                    text_content = raw_body.decode('utf-8', errors='ignore')
                metadata = safe_json_loads(text_content)

        except (json.JSONDecodeError, ValueError) as e:
            result["error"] = f"Contract/Parse Error: {str(e)}"
            return result

        result["meta_name"] = metadata.get("name")
        result["meta_description"] = metadata.get("description")
        result["meta_image"] = format_ipfs_url(
            metadata.get("image") or metadata.get("image_url"))

    except requests.exceptions.RequestException as e:
        result["error"] = f"Network Error: {str(e)}"
    except Exception as e:
        result["error"] = f"Contract/Parse Error: {str(e)}"

    return result


# --- MAIN PIPELINE ---
def main():
    print(f"Loading {INPUT_CSV}...")
    try:
        df = pd.read_csv(INPUT_CSV)
        df['address'] = df['address'].astype(str).str.lower().str.strip()
    except FileNotFoundError:
        print(f"Error: {INPUT_CSV} not found.")
        return

    # 1. Skip already successful addresses
    successful_addresses = set()
    if os.path.exists(SUCCESS_CSV):
        try:
            success_df = pd.read_csv(SUCCESS_CSV)
            successful_addresses = set(
                success_df['address'].astype(str).str.lower().str.strip())
            print(f"  {len(successful_addresses)} previously successful addresses — skipping.")
        except Exception as e:
            print(f"Could not read {SUCCESS_CSV}: {e}")

    # 2. Filter to only addresses we need to process
    pending_df = df[~df['address'].isin(
        successful_addresses)].drop_duplicates(subset=['address'])
    addresses_to_process = pending_df['address'].tolist()

    if not addresses_to_process:
        print("No new or failed addresses to process. Everything is up to date!")
        return

    print(f"Need to process {len(addresses_to_process)} addresses...")

    w3 = Web3(Web3.HTTPProvider(BSC_RPC))
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=MAX_WORKERS, pool_maxsize=MAX_WORKERS,
        max_retries=1, max_redirects=10)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    results = []
    start_time = time.time()

    # 3. Fetch data
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {}
        for _, row in pending_df.iterrows():
            addr = row['address']
            tx = row.get('first_seen_txhash', None)
            futures[executor.submit(get_nft_data, w3, session, addr, tx)] = addr

        for count, future in enumerate(as_completed(futures), 1):
            results.append(future.result())
            if count % 50 == 0 or count == len(addresses_to_process):
                print(f"  Processed {count}/{len(addresses_to_process)}...")

    # 4. Merge fetched data back with original CSV columns
    results_df = pd.DataFrame(results)

    if 'error' in pending_df.columns:
        pending_df = pending_df.drop(columns=['error'])

    final_df = pd.merge(pending_df, results_df, on="address", how="left")

    # 5. Split into success and errors
    new_success_df = final_df[final_df['error'].isna()]
    new_error_df = final_df[final_df['error'].notna()]

    # 6. Save files
    os.makedirs(os.path.dirname(SUCCESS_CSV), exist_ok=True)
    os.makedirs(os.path.dirname(ERROR_CSV), exist_ok=True)

    if not new_success_df.empty:
        write_header = not os.path.exists(SUCCESS_CSV)
        new_success_df.to_csv(SUCCESS_CSV, mode='a', index=False, header=write_header)
        print(f"Appended {len(new_success_df)} new successes to {SUCCESS_CSV}")

    if not new_error_df.empty:
        new_error_df.to_csv(ERROR_CSV, index=False)
        print(f"Saved {len(new_error_df)} failures to {ERROR_CSV} (will be retried next run)")
    else:
        if os.path.exists(ERROR_CSV):
            os.remove(ERROR_CSV)
            print("Cleared error file - zero errors!")

    print(f"\nFinished in {time.time() - start_time:.2f} seconds.")


if __name__ == "__main__":
    main()
