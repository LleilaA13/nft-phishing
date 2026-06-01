import os
import json
import time
import asyncio
import pandas as pd
import datetime
from urllib.parse import urlparse
from aiohttp.client_exceptions import InvalidURL, ClientPayloadError, ClientConnectorError, ServerDisconnectedError, ClientOSError, TooManyRedirects, ClientResponseError
from aiohttp import request, ClientTimeout
from aiomultiprocess import Pool

# Import your custom utility file
import utility as utils

# --- HELPER FUNCTIONS ---

def get_proper_url(url):
    local_gateway = "http://127.0.0.1:8080/"
    # local_gateway = "http://ipfs:8080/" # Use this if running inside a specific Docker setup
    # local_gateway = "https://ipfs.io/"  # Use this if you don't have a local node (slower)

    # Safety Check: Ensure url is a string (handles NaN/None)
    if not url or not isinstance(url, str):
        return url, -1

    try:
        if 'ipfs://' in url:
            start = url.index('ipfs://')
            url = local_gateway + 'ipfs/' + url[start+7:]
            return url, True
        if 'ipfs/' in url:
            start = url.index('ipfs/')
            url = local_gateway + url[start:]
            return url, True
    except Exception:
        return {url: 'NoneType uri'}, -1
    
    return url, False


def is_potential_url(url_string):
    try:
        result = urlparse(url_string)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False


# --- CORE LOGIC ---

async def get_uri_info_asy_mult_csv(arguments):
    out_file, url = arguments

    # Handle non-string URLs early
    if not isinstance(url, str):
         return {'uri': str(url), 'error': 'Invalid URL Type'}

    if len(url) > 2083:
        return {'uri': url, 'error': 'Too long uri'}

    reformatted_url, is_ipfs = get_proper_url(url)

    if is_ipfs == -1:
        return {'uri': url, 'error': 'NoneType uri'}

    err = None
    info = {'uri': url, 'is_ipfs_url': is_ipfs}

    metadata_retries = 3 if is_ipfs else 1
    
    response_content_bytes = None
    response_headers = None

    timeout_time = 60 if is_ipfs else 30

    # Request the Metadata
    for attempt in range(metadata_retries): 
        try:
            start_response_1 = time.time()
            async with request('GET', reformatted_url, timeout=ClientTimeout(total=timeout_time)) as response:
                response_content_bytes = await response.read() 
                info['response_status'] = response.status
                response_headers = response.headers
                info['response_time'] = time.time() - start_response_1
                break 
        except (asyncio.TimeoutError, ClientConnectorError, ServerDisconnectedError, ClientOSError) as e:
            if attempt == metadata_retries-1: 
                err = f'timeout_or_conn_err: {str(e)}'
            else: 
                await asyncio.sleep(0.5)
        except Exception as e:
            err = str(e)
            break 

    if err:
        info['error'] = err
        return info

    if response_headers is None:
        info['metadata_error'] = 'response_headers missing'
        return info

    content_type = response_headers.get('content-type', '').lower()
    info['content_type'] = content_type

    # Parse and Save JSON
    try:
        # Try to parse the downloaded bytes as JSON
        json_response = json.loads(response_content_bytes)
        if json_response:
            info['metadata'] = True
            # Dump the JSON back into a string to save it safely in the CSV
            info['raw_json'] = json.dumps(json_response) 
        else:
            info['metadata_error'] = 'empty json content'
            
    except (json.JSONDecodeError, UnicodeDecodeError):
        info['metadata_error'] = 'Not valid JSON or decoding failed'
    except Exception as e:
        info['metadata_error'] = f'json parse error: {str(e)}'

    # Return the dictionary safely to the pool
    return info


# --- STATISTICS & MAIN ---

def get_token_statistics(token_uris_list):
    print(f"Input type: {type(token_uris_list)}")

    # Filter out NaNs immediately
    token_uris_list = [t for t in token_uris_list if isinstance(t, str)]
    
    print('total token uris: ', len(token_uris_list))
    token_uris_list = set(token_uris_list)
    print('total unique token uris: ', len(token_uris_list))
    
    callable_token_uris_list = [t for t in token_uris_list if not any(domain in t for domain in ['api.immutable.com'])]
    print('total callable token uris: ',  len(callable_token_uris_list))
    
    to_search_token_uris = [t for t in callable_token_uris_list if len(t) < 2083]
    print('total token uris longer than 2083 chars: ', len(callable_token_uris_list) - len(to_search_token_uris))


async def main(input_dir='../data/output/error_nfts.csv', out_file='metadata_snapshot_{}.csv'):
    datetime_now = datetime.datetime.now()
    print('#### {}: starting metadata scraper ###'.format(datetime_now))

    # Read Pandas CSV Correctly
    try:
        df = pd.read_csv(input_dir)
        token_uris = df['token_uri'].dropna().astype(str).tolist()
    except Exception as e:
        print(f"Error loading CSV: {e}")
        return

    # Print stats
    get_token_statistics(token_uris)

    # Prepare snapshot file name
    out_file = out_file.format(str(datetime_now.date().year))
    print('Snapshot file name is: ', out_file)

    # Setup CSV Headers for Metadata scraping
    headers = ['uri', 'error', 'response_status', 'content_type', 'is_ipfs_url', 
               'metadata', 'metadata_error', 'response_time', 'raw_json']

    if not os.path.exists('data/' + out_file):
        print('file not found, creating new...')
        os.makedirs('data', exist_ok=True)
        utils.update_csv(out_file, [headers])
    else:
        print('file already exists. Exploring remaining token uris...')
        token_uris_explored = set(pd.read_csv('data/'+out_file, usecols=['uri'])['uri'].dropna().astype(str).tolist())
        print('Total token uris already explored are: ', len(token_uris_explored))
        
        token_uris_set = set(token_uris)
        token_uris = list(token_uris_set.difference(token_uris_explored))
        
        del token_uris_explored
        print('Remaining token uris to catch are: ', len(token_uris))

    # Limit processes to CPU count or explicit number
    n_processes = 8
    
    batches = [(out_file, item) for item in token_uris]
    
    # Safety check if empty
    if not batches:
        print("No URIs to process.")
        return

    print(f"Starting processing of {len(batches)} items with {n_processes} processes...")
    
    # Run the multiprocessing pool
    async with Pool(n_processes) as pool:
        # 1. Gather all the dictionaries returned by the workers
        results = await pool.map(get_uri_info_asy_mult_csv, batches)

    # 2. Write them to the CSV safely after all downloads finish
    if results:
        rows_to_write = []
        for r in results:
            if r is not None:
                rows_to_write.append([
                    r.get('uri'), r.get('error'), r.get('response_status'), 
                    r.get('content_type'), r.get('is_ipfs_url'), r.get('metadata'), 
                    r.get('metadata_error'), r.get('response_time'), r.get('raw_json')
                ])
        
        utils.update_csv(out_file, rows_to_write)
        print(f"Successfully saved {len(rows_to_write)} rows to CSV.")

    print('Finished!')

if __name__ == "__main__":
    # Ensure this matches your actual input file name and desired output name
    asyncio.run(main('../data/output/success_nfts.csv', 'metadata_snapshot_{}.csv'))