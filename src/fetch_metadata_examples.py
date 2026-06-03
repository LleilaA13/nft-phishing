import os
import csv
import pandas as pd
import requests
from web3 import Web3
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import base64
import json
import urllib.parse
import urllib3

# --- NEW: Disable annoying SSL Warnings ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURATION ---
INPUT_CSV = "../data/shared_nfts/NFT examples - Sheet1.csv"
OUTPUT_CSV = "../data/output/examples_decoded_metadata.csv"
BSC_RPC = "https://bsc-dataseed1.binance.org"
IPFS_GATEWAY = "http://127.0.0.1:8080/ipfs/"
MAX_WORKERS = 5
LOG_LOOKBACK_BLOCKS = 250000
LOG_CHUNK_SIZE = 50000

TRANSFER_TOPIC = Web3.keccak(text="Transfer(address,address,uint256)").hex()
TRANSFER_SINGLE_TOPIC = Web3.keccak(
    text="TransferSingle(address,address,address,uint256,uint256)").hex()
ZERO_TOPIC = "0x" + ("00" * 32)

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


def format_ipfs_url(uri: str) -> str:
    if not isinstance(uri, str):
        return None

    # 1. Handle standard ipfs:// links
    if uri.startswith("ipfs://"):
        return uri.replace("ipfs://", IPFS_GATEWAY).replace("ipfs/ipfs/", "ipfs/")

    # 2. Intercept hardcoded public gateways and force them to local Docker node
    if "/ipfs/" in uri and ("ipfs.io" in uri or "pinata.cloud" in uri or "nftstorage.link" in uri):
        hash_part = uri.split("/ipfs/")[-1]
        return IPFS_GATEWAY + hash_part

    return uri


def parse_token_id(value):
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)

    text = str(value).strip()
    if not text:
        return None

    if text.startswith("0x"):
        try:
            return int(text, 16)
        except Exception:
            return None

    try:
        return int(text)
    except Exception:
        return None


def normalize_header(name: str) -> str:
    return str(name).strip().lower().replace(" ", "_")


def load_rows_with_optional_token_ids(input_csv: str):
    rows = []

    with open(input_csv, "r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.reader(f)
        raw_rows = [row for row in reader if row]

    if not raw_rows:
        return rows

    header_map = None
    first_row = raw_rows[0]
    first_cell = first_row[0].strip().lower() if first_row else ""

    if not first_cell.startswith("0x"):
        normalized = [normalize_header(cell) for cell in first_row]
        if any(name in ("address", "contract", "contract_address") for name in normalized):
            header_map = {name: idx for idx, name in enumerate(normalized)}
            data_rows = raw_rows[1:]
        else:
            data_rows = raw_rows
    else:
        data_rows = raw_rows

    def pick_index(names, default_index=None):
        if header_map:
            for name in names:
                if name in header_map:
                    return header_map[name]
        return default_index

    address_index = pick_index(["address", "contract", "contract_address"], 0)
    lure_index = pick_index(
        ["description_lure", "description", "lure", "notes"], 1)
    token_index = pick_index(["token_id", "tokenid", "id"], 2)

    for row in data_rows:
        if address_index is None or address_index >= len(row):
            continue

        address = row[address_index].strip()
        if not address.startswith("0x"):
            continue

        lure = row[lure_index].strip(
        ) if lure_index is not None and lure_index < len(row) else ""
        token_ids = []
        if token_index is not None and token_index < len(row):
            token_value = row[token_index].strip()
            if token_value:
                for piece in token_value.replace(";", ",").replace("|", ",").split(","):
                    token_id = parse_token_id(piece)
                    if token_id is not None:
                        token_ids.append(token_id)

        rows.append((address, lure, token_ids))

    return rows


def discover_token_ids_from_logs(w3, address: str, max_ids: int = 5):
    checksum_addr = w3.to_checksum_address(address)
    latest_block = w3.eth.block_number
    start_block = max(0, latest_block - LOG_LOOKBACK_BLOCKS)
    discovered = []
    seen = set()

    filters = [
        {"topics": [TRANSFER_TOPIC, ZERO_TOPIC]},
        {"topics": [TRANSFER_SINGLE_TOPIC, None, ZERO_TOPIC]},
    ]

    for filter_args in filters:
        for from_block in range(start_block, latest_block + 1, LOG_CHUNK_SIZE):
            to_block = min(from_block + LOG_CHUNK_SIZE - 1, latest_block)
            try:
                logs = w3.eth.get_logs({
                    "fromBlock": from_block,
                    "toBlock": to_block,
                    "address": checksum_addr,
                    **filter_args,
                })
            except Exception:
                continue

            for log in logs:
                try:
                    token_id = int(log["data"].hex(), 16)
                except Exception:
                    try:
                        token_id = int(log["data"], 16)
                    except Exception:
                        continue

                if token_id in seen:
                    continue

                seen.add(token_id)
                discovered.append(token_id)
                if len(discovered) >= max_ids:
                    return discovered

    return discovered


def build_token_id_candidates(explicit_token_ids, discovered_token_ids):
    ordered = []
    seen = set()

    for token_id in list(explicit_token_ids or []) + [1, 0, 2] + list(discovered_token_ids or []):
        try:
            normalized = int(token_id)
        except Exception:
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(normalized)

    return ordered


def get_nft_data(w3, session, address: str, original_lure: str, explicit_token_ids=None) -> dict:
    result = {"address": address, "description_lure": original_lure, "token_uri": None,
              "meta_name": None, "meta_description": None, "meta_image": None, "error": None}

    try:
        checksum_addr = w3.to_checksum_address(address)

        # Diagnostic 1: Is it dead?
        if w3.eth.get_code(checksum_addr) in (b'', b'\x00'):
            result["error"] = "True Negative: Contract is Dead"
            return result

        contract = w3.eth.contract(address=checksum_addr, abi=URI_ABI)

        contract_name = None
        try:
            contract_name = contract.functions.name().call()
        except:
            pass

        uri = None
        discovered_token_ids = []

        # 1. Evasion Sweep
        for func_name in ['baseURI', 'contractURI', 'tokenURI', 'uri']:
            try:
                uri_candidate = getattr(contract.functions, func_name)().call()
                if isinstance(uri_candidate, str) and uri_candidate.strip():
                    uri = uri_candidate
                    break
            except Exception:
                continue

        # 2. Fast Sweep
        if not uri:
            if not explicit_token_ids:
                try:
                    discovered_token_ids = discover_token_ids_from_logs(
                        w3, checksum_addr)
                except Exception:
                    discovered_token_ids = []

            for token_id in build_token_id_candidates(explicit_token_ids, discovered_token_ids):
                try:
                    uri = contract.functions.tokenURI(token_id).call()
                    break
                except Exception:
                    try:
                        uri = contract.functions.uri(token_id).call()
                        if "{id}" in uri:
                            uri = uri.replace("{id}", format(
                                token_id, "x").zfill(64))
                        break
                    except Exception:
                        continue

        if not uri:
            result["error"] = f"True Negative: Name-Only Scam (Name: {contract_name})" if contract_name else "True Negative: No URI function found"
            return result

        result["token_uri"] = uri

        # --- Decode Base64/IPFS ---
        if uri.startswith("data:application/json"):
            try:
                header, payload = uri.split(",", 1)
                if "base64" in header.lower():
                    data_str = base64.b64decode(payload).decode('utf-8')
                    metadata = json.loads(data_str)
                else:
                    metadata = json.loads(urllib.parse.unquote(payload))
                result["meta_name"] = metadata.get("name")
                result["meta_description"] = metadata.get("description")
                result["meta_image"] = format_ipfs_url(
                    metadata.get("image") or metadata.get("image_url"))
                return result
            except Exception as e:
                result["error"] = f"On-Chain Parse Error: {str(e)}"
                return result

        fetch_url = format_ipfs_url(uri)
        if not fetch_url or not fetch_url.startswith("http"):
            result["error"] = "Invalid URI format"
            return result

        # --- NEW: verify=False forces Python to ignore SSL errors ---
        response = session.get(fetch_url, timeout=45, verify=False)
        response.raise_for_status()

        try:
            metadata = response.json()
        except json.JSONDecodeError:
            metadata = json.loads(response.content.decode('utf-8-sig'))

        result["meta_name"] = metadata.get("name")
        result["meta_description"] = metadata.get("description")
        result["meta_image"] = format_ipfs_url(
            metadata.get("image") or metadata.get("image_url"))

    except requests.exceptions.RequestException as e:
        result["error"] = f"Network Error: {str(e)}"
    except Exception as e:
        result["error"] = f"Contract Error: {str(e)}"

    return result


def main():
    print(f"Loading {INPUT_CSV} targeting 0x addresses...")

    addresses_to_process = load_rows_with_optional_token_ids(INPUT_CSV)

    print(f"Found {len(addresses_to_process)} valid contracts to query.")

    w3 = Web3(Web3.HTTPProvider(BSC_RPC))
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=MAX_WORKERS, pool_maxsize=MAX_WORKERS)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    results = []
    start_time = time.time()

    # 2. Multithreaded Web3 Extraction
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(
            get_nft_data, w3, session, addr, desc, token_ids): addr for addr, desc, token_ids in addresses_to_process}

        for count, future in enumerate(as_completed(futures), 1):
            results.append(future.result())
            if count % 10 == 0 or count == len(addresses_to_process):
                print(
                    f"  Queried {count}/{len(addresses_to_process)} contracts...")

    # 3. Save Results
    results_df = pd.DataFrame(results)
    results_df.to_csv(OUTPUT_CSV, index=False)

    successes = len(results_df[results_df['error'].isna()])
    print(f"\nFinished in {time.time() - start_time:.2f} seconds.")
    print(
        f"Successfully decoded {successes} out of {len(addresses_to_process)} contracts.")
    print(f"Results saved to {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
