import os
from unittest import result
import pandas as pd
import requests
from web3 import Web3
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import base64
import json
import urllib.parse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURATION ---
# Your daily updated file
INPUT_CSV = "/home/leyla/blockchain-phishing/data/nft_tokens.csv"
# The growing database of good results
SUCCESS_CSV = "../data/output/success_nfts.csv"
ERROR_CSV = "../data/output/error_nfts.csv"        # The current list of failures
BSC_RPC = "https://bsc-rpc.publicnode.com"
# Use "http://127.0.0.1:8080/ipfs/" if using Docker
IPFS_GATEWAY = "http://127.0.0.1:8080/ipfs/"
MAX_WORKERS = 5

URI_ABI = [
    # Standard Functions
    {"inputs": [{"name": "tokenId", "type": "uint256"}], "name": "tokenURI", "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"name": "id", "type": "uint256"}], "name": "uri", "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    # Scammer Evasion Functions
    {"inputs": [], "name": "tokenURI", "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "uri", "outputs": [{"name": "", "type": "string"}],
        "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "baseURI", "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "contractURI", "outputs": [
        {"name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
    # --- NEW: Diagnostic Functions ---
    {"inputs": [], "name": "name", "outputs": [{"name": "", "type": "string"}],
        "stateMutability": "view", "type": "function"}
]

# --- HELPER FUNCTIONS ---
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
TRANSFER_SINGLE_TOPIC = "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62"


def get_exact_token_id(w3, tx_hash: str, address: str):
    """Extracts the exact Token ID from the blockchain transaction logs."""
    if pd.isna(tx_hash) or not str(tx_hash).startswith("0x"):
        return None
    try:
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        for log in receipt.get('logs', []):
            if log['address'].lower() == address.lower() and log['topics']:
                topic0 = log['topics'][0].hex()
                # ERC-721
                if topic0 == TRANSFER_TOPIC and len(log['topics']) >= 4:
                    return int(log['topics'][3].hex(), 16)
                # ERC-1155
                elif topic0 == TRANSFER_SINGLE_TOPIC:
                    data_hex = log['data'].hex()
                    clean = data_hex[2:] if data_hex.startswith(
                        "0x") else data_hex
                    return int(clean[:64], 16)
    except Exception:
        pass
    return None


def format_ipfs_url(uri: str) -> str:
    if not isinstance(uri, str):
        return None
    if uri.startswith("ipfs://"):
        return uri.replace("ipfs://", IPFS_GATEWAY).replace("ipfs/ipfs/", "ipfs/")
    if "/ipfs/" in uri and any(gateway in uri for gateway in ["ipfs.io", "pinata.cloud", "cloudflare-ipfs.com"]):
        hash_part = uri.split("/ipfs/")[-1]
        return IPFS_GATEWAY + hash_part
    return uri

def get_nft_data(w3, session, address: str, tx_hash: str) -> dict:
    result = {"address": address, "token_uri": None, "meta_name": None,
              "meta_description": None, "meta_image": None, "error": None}


    try:
        checksum_addr = w3.to_checksum_address(address)

        # --- DIAGNOSTIC 1: Is the contract dead? ---
        if w3.eth.get_code(checksum_addr) in (b'', b'\x00'):
                result["error"] = "True Negative: Contract is Dead / Self-Destructed"
                return result

        contract = w3.eth.contract(address=checksum_addr, abi=URI_ABI)

            # --- DIAGNOSTIC 2: Is it a Name-Only Scam? ---
            # We test this by asking for a name, but if we later fail to find a URI,
            # we know it was just a fake token, not a real NFT.
        contract_name = None
        try:
            contract_name = contract.functions.name().call()
        except Exception:
                pass

        uri = None

        # 1. NEW: Check evasive NO-ARGUMENT functions first (baseURI, contractURI)
        for func_name in ['baseURI', 'contractURI', 'tokenURI', 'uri']:
            try:
                uri_candidate = getattr(contract.functions, func_name)().call()
                if isinstance(uri_candidate, str) and uri_candidate.strip():
                    uri = uri_candidate
                    break
            except Exception:
                continue

        # 2. EXISTING: Fast Sweep (Standard ERC-721/1155)
        if not uri:
            for token_id in [1, 0, 2]:
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
            exact_id = get_exact_token_id(w3, tx_hash, address)
            if exact_id is not None:
                try:
                    uri = contract.functions.tokenURI(exact_id).call()
                except Exception:
                    try:
                        uri = contract.functions.uri(exact_id).call()
                        if "{id}" in uri:
                            uri = uri.replace(
                                "{id}", format(exact_id, "x").zfill(64))
                    except Exception:
                        pass

        if not uri:
            result["error"] = "No URI found on contract (even with exact ID)"
            return result

        result["token_uri"] = uri

        # --- NEW: HANDLE ON-CHAIN BASE64/UTF8 DATA ---
        if uri.startswith("data:"):
            try:
                # Split exactly ONCE at the first comma to separate header from payload
                header, payload = uri.split(",", 1)

                if "base64" in header.lower():
                    data_str = base64.b64decode(payload).decode('utf-8')
                    metadata = json.loads(data_str)
                else:
                    # If it's not base64, it's url-encoded or raw text
                    data_str = urllib.parse.unquote(payload)
                    metadata = json.loads(data_str)

                result["meta_name"] = metadata.get("name")
                result["meta_description"] = metadata.get("description")
                result["meta_image"] = format_ipfs_url(
                    metadata.get("image") or metadata.get("image_url"))
                return result
            except Exception as e:
                result["error"] = f"On-Chain Parse Error: {str(e)}"
                return result

        # --- EXISTING: HANDLE STANDARD HTTP/IPFS URLS ---
        fetch_url = format_ipfs_url(uri)
        if not fetch_url or not fetch_url.startswith("http"):
            result["error"] = "Invalid URI format"
            return result

        try:
            # Try your local Docker IPFS or the standard HTTP url (shorter timeout)
            response = session.get(fetch_url, timeout=15, verify=False)
            response.raise_for_status()
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.HTTPError) as e:
            # FALLBACK: If local IPFS times out or 504s, try a public gateway
            if "127.0.0.1:8080/ipfs/" in fetch_url:
                public_url = fetch_url.replace("http://127.0.0.1:8080/ipfs/", "https://cloudflare-ipfs.com/ipfs/")
                response = requests.sessions.session.get(public_url, timeout=15, verify=False)
                response.raise_for_status()
            else:
                raise e # Re-raise if it wasn't an IPFS issue
            
        if 'text/html' in response.headers.get('Content-Type', '').lower():
            result["error"] = "Contract/Parse Error: Returned HTML/CAPTCHA instead of JSON"
            return result
        # --- NEW: HANDLE MALFORMED UTF-8 BOM JSONS ---
        try:
            # If the server politely says it's JSON, use the built-in parser
            if "json" in response.headers.get('Content-Type', ''):
                metadata = response.json()
            else:
                # If it's raw text, try standard UTF-8 first
                try:
                    text_content = response.content.decode('utf-8-sig')
                except UnicodeDecodeError:
                    # FALLBACK: If scammers used bad emojis or weird text formatting, ignore the broken characters
                    text_content = response.content.decode(
                        'utf-8', errors='ignore')

                metadata = json.loads(text_content)

        except json.JSONDecodeError:
            result["error"] = "Contract/Parse Error: Expecting value: line 1 column 1 (char 0)"
            return result

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
        # Ensure addresses are clean for merging later
        df['address'] = df['address'].astype(str).str.lower().str.strip()
    except FileNotFoundError:
        print(f"Error: {INPUT_CSV} not found.")
        return

    # 1. Identify already successful addresses to skip
    successful_addresses = set()
    if os.path.exists(SUCCESS_CSV):
        try:
            success_df = pd.read_csv(SUCCESS_CSV)
            successful_addresses = set(
                success_df['address'].astype(str).str.lower().str.strip())
            print(
                f"Found {len(successful_addresses)} previously successful addresses. Skipping them.")
        except Exception as e:
            print(f"Could not read {SUCCESS_CSV}: {e}")

    # 2. Filter input df to only addresses we need to process
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
        pool_connections=MAX_WORKERS, pool_maxsize=MAX_WORKERS, max_retries=1)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    results = []
    start_time = time.time()

    # 3. Fetch Data
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # We need to iterate over the dataframe rows to pass both address and txhash
        futures = {}
        for _, row in pending_df.iterrows():
            addr = row['address']
            tx = row.get('first_seen_txhash', None)
            futures[executor.submit(
                get_nft_data, w3, session, addr, tx)] = addr

        for count, future in enumerate(as_completed(futures), 1):
            results.append(future.result())
            if count % 50 == 0 or count == len(addresses_to_process):
                print(f"  Processed {count}/{len(addresses_to_process)}...")

    # 4. Merge fetched data back with original CSV columns
    results_df = pd.DataFrame(results)

    # FIX: Drop the old 'error' column from the input CSV if it exists to prevent suffixing (error_x, error_y)
    if 'error' in pending_df.columns:
        pending_df = pending_df.drop(columns=['error'])

    final_df = pd.merge(pending_df, results_df, on="address", how="left")

    # 5. Split into Success and Errors
    new_success_df = final_df[final_df['error'].isna()]
    new_error_df = final_df[final_df['error'].notna()]

    # 6. Save Files
    # Automatically create the folder if it doesn't exist
    os.makedirs(os.path.dirname(SUCCESS_CSV), exist_ok=True)
    os.makedirs(os.path.dirname(ERROR_CSV), exist_ok=True)

    if not new_success_df.empty:
        # Append to success file (write header only if file doesn't exist)
        write_header = not os.path.exists(SUCCESS_CSV)
        new_success_df.to_csv(SUCCESS_CSV, mode='a',
                              index=False, header=write_header)
        print(f"Appended {len(new_success_df)} new successes to {SUCCESS_CSV}")

    if not new_error_df.empty:
        # Overwrite error file so it acts as a fresh "to-do" list
        new_error_df.to_csv(ERROR_CSV, index=False)
        print(
            f"Saved {len(new_error_df)} failures to {ERROR_CSV} (These will be retried next run)")
    else:
        # If there are no errors, we can safely clear the error file if it exists
        if os.path.exists(ERROR_CSV):
            os.remove(ERROR_CSV)
            print("Cleared error file - zero errors!")

    print(f"\nFinished in {time.time() - start_time:.2f} seconds.")


if __name__ == "__main__":
    main()
