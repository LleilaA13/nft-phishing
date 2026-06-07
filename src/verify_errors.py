import os
import pandas as pd
import re
import requests
from bs4 import BeautifulSoup
import time
import urllib3
import json
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURATION ---
ERROR_CSV = "../data/output/error_nfts.csv"
SUCCESS_CSV = "../data/output/success_nfts.csv"
IPFS_GATEWAY = "http://127.0.0.1:8080/ipfs/"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*"
}

# --- RECOVERY FUNCTIONS ---


def recover_html(url: str) -> dict:
    """Visits HTML pages and attempts to scrape OpenGraph metadata."""
    try:
        response = requests.get(url, headers=HEADERS, timeout=10, verify=False)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        metadata = {}

        # FIXED: Using attrs={} prevents the "multiple values for argument 'name'" bug
        og_title = soup.find('meta', attrs={'property': 'og:title'}) or soup.find(
            'meta', attrs={'name': 'twitter:title'})
        og_desc = soup.find('meta', attrs={'property': 'og:description'}) or soup.find(
            'meta', attrs={'name': 'twitter:description'})
        og_image = soup.find('meta', attrs={'property': 'og:image'}) or soup.find(
            'meta', attrs={'name': 'twitter:image'})

        if og_title and og_title.get('content'):
            metadata['meta_name'] = og_title.get('content')
        elif soup.title:
            metadata['meta_name'] = soup.title.string

        if og_desc and og_desc.get('content'):
            metadata['meta_description'] = og_desc.get('content')
        if og_image and og_image.get('content'):
            metadata['meta_image'] = og_image.get('content')

        if metadata:
            metadata['recovery_method'] = "Scraped from HTML"
            return metadata

        return {"error": f"Scrape failed: Server returned HTTP {response.status_code}, but no OpenGraph metadata tags were found."}

    except requests.exceptions.RequestException as e:
        return {"error": f"Server request failed during HTML scrape: {str(e)}"}
    except Exception as e:
        return {"error": f"HTML Parsing Exception: {str(e)}"}


def recover_ipfs_typo(raw_string: str) -> dict:
    """Fixes broken IPFS hashes, and catches raw JSON pasted into the URI."""
    raw_string = raw_string.strip()

    # 1. Catch developers who pasted raw JSON directly into the contract
    if raw_string.startswith('{') and raw_string.endswith('}'):
        try:
            data = json.loads(raw_string)
            return {
                "meta_name": data.get("name"),
                "meta_description": data.get("description"),
                "meta_image": data.get("image") or data.get("image_url"),
                "token_uri": "Raw JSON stored on contract",
                "recovery_method": "Parsed Raw JSON Typo"
            }
        except json.JSONDecodeError:
            pass  # Not valid JSON, continue to IPFS checks

    # 2. Extract the actual IPFS Hash using Regex (catches hashes hidden inside strings)
    match = re.search(
        r'(Qm[1-9A-HJ-NP-Za-km-z]{44,}|baf[a-zA-Z0-9]{40,})', raw_string)
    if not match:
        return {"error": "Garbage Data: Value is not a recognizable IPFS CID or JSON."}

    clean_hash = match.group(1)

    # If the hash has a path attached (e.g. Qm.../1.json), grab the path too
    path_match = re.search(rf'{clean_hash}(/[a-zA-Z0-9._-]+)*', raw_string)
    if path_match:
        clean_hash = path_match.group(0)

    fixed_url = f"{IPFS_GATEWAY}{clean_hash}"

    try:
        response = requests.get(
            fixed_url, headers=HEADERS, timeout=15, verify=False)
        response.raise_for_status()
        data = response.json()
        return {
            "meta_name": data.get("name"),
            "meta_description": data.get("description"),
            "meta_image": data.get("image") or data.get("image_url"),
            "token_uri": fixed_url,
            "recovery_method": "Fixed IPFS Typo"
        }
    except requests.exceptions.RequestException as e:
        return {"error": f"Fixed IPFS URL ({fixed_url}), but server rejected it: {str(e)}"}
    except ValueError as e:
        return {"error": f"Fixed IPFS URL, but payload was not valid JSON: {str(e)}"}


def verify_network_error(error_str: str) -> dict:
    """Extracts the URL from a network error and tests the server's exact response."""
    url = None
    match_url = re.search(r"url: (https?://[^\s\)]+)", error_str)
    if match_url:
        url = match_url.group(1)
    else:
        match_host = re.search(r"host='([^']+)'", error_str)
        match_path = re.search(r"url: ([^\s\)]+)", error_str)
        if match_host and match_path:
            url = f"https://{match_host.group(1)}{match_path.group(1)}"

    if not url:
        return {"error": "Regex Failed: Could not extract a valid URL from the raw error string."}

    try:
        response = requests.get(url, headers=HEADERS, timeout=15, verify=False)
        response.raise_for_status()

        try:
            data = response.json()
            return {
                "meta_name": data.get("name"),
                "meta_description": data.get("description"),
                "meta_image": data.get("image") or data.get("image_url"),
                "token_uri": url,
                "recovery_method": "Network Retry Success"
            }
        except ValueError as e:
            return {"error": f"Network Retry Success (HTTP {response.status_code}), but data is not JSON: {str(e)}"}

    except requests.exceptions.ConnectionError as e:
        return {"error": f"VERIFIED DEAD (Connection/DNS): {str(e)}", "dead": True}

    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "Unknown"
        if status in [404, 410]:
            return {"error": f"VERIFIED DEAD (HTTP {status}): {str(e)}", "dead": True}
        return {"error": f"Server Rejected Request: {str(e)}"}

    except requests.exceptions.Timeout as e:
        return {"error": f"Server Timeout: {str(e)}"}

    except Exception as e:
        return {"error": f"Unexpected Failure: {str(e)}"}


# --- MAIN PIPELINE ---

def main():
    try:
        df = pd.read_csv(ERROR_CSV)
    except FileNotFoundError:
        print(f"Error: Could not find {ERROR_CSV}.")
        return

    recovered_data = []
    dead_data = []

    print(f"Scanning {len(df)} errors for recovery opportunities...\n")

    for index, row in df.iterrows():
        err = str(row['error'])
        address = row['address']
        result = None

        if "Server returned HTML" in err:
            match = re.search(r"\(from (https?://[^\)]+)\)", err)
            if match:
                url = match.group(1)
                print(f"[HTML] Scraping: {url}")
                result = recover_html(url)
                if not result.get("error"):
                    result["token_uri"] = url

        elif "unsupported scheme in" in err:
            match = re.search(r"unsupported scheme in '([^']+)'", err)
            if match:
                raw_val = match.group(1)
                print(f"[IPFS] Fixing Typo: {raw_val}")
                result = recover_ipfs_typo(raw_val)

        elif "Network Error:" in err:
            print(f"[NET]  Verifying if dead: {address}")
            result = verify_network_error(err)

        if result:
            base_row = row.to_dict()
            if "error" not in result:
                # SUCCESS
                base_row.update(result)
                recovered_data.append(base_row)
                print(
                    f"       -> RECOVERED! Found: '{result.get('meta_name', 'Unnamed')}'")
            else:
                # FAILED
                print(f"       -> {result['error']}")
                if result.get("dead"):
                    # Update error message directly in dataframe so it stays in error_nfts.csv
                    df.at[index, 'error'] = result['error']
            time.sleep(0.5)  # Polite delay so we don't spam servers

    # --- CLEANUP LOGIC ---
    print("\n--- Finalizing Data ---")

    recovered_addresses = [r['address'] for r in recovered_data]

    # 1. Append recovered data directly to success_nfts.csv
    if recovered_data:
        recovered_df = pd.DataFrame(recovered_data)
        # Drop the 'error' column before appending so it matches the success schema perfectly
        if 'error' in recovered_df.columns:
            recovered_df = recovered_df.drop(columns=['error'])

        write_header = not os.path.exists(SUCCESS_CSV)
        recovered_df.to_csv(SUCCESS_CSV, mode='a',
                            index=False, header=write_header)
        print(
            f"✅ Appended {len(recovered_df)} recovered NFTs directly to {SUCCESS_CSV}")


    # 3. Save the error CSV (removes recovered, keeps dead ones with updated error message)
    addresses_to_remove = set(recovered_addresses)
    remaining_errors = df[~df['address'].isin(addresses_to_remove)]
    remaining_errors.to_csv(ERROR_CSV, index=False)
    print(
        f"🧹 Updated {ERROR_CSV}: Removed {len(addresses_to_remove)} recovered addresses and preserved dead targets.")


if __name__ == "__main__":
    main()
