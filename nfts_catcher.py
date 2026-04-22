import os
from PIL import Image, UnidentifiedImageError
import imagehash
from tqdm import tqdm
import utility as utils
import io
import time
import asyncio
from aiohttp.client_exceptions import InvalidURL, ClientPayloadError, ClientConnectorError, ServerDisconnectedError, ClientOSError, TooManyRedirects, ClientResponseError
from aiohttp import request, ClientTimeout
from aiomultiprocess import Pool
from aiomultiprocess.types import ProxyException
import datetime
import aioschedule as schedule
import pandas as pd
import json
from urllib.parse import urlparse



# --- HELPER FUNCTIONS ---

def get_proper_url(url):
    local_gateway = "http://127.0.0.1:8080/"
    #local_gateway = "http://ipfs:8080/"

    # 1. Safety Check: Ensure url is a string (handles NaN/None)
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
    except Exception as e:
        return {url: 'NoneType uri'}, -1
    
    return url, False


def is_potential_url(url_string):
    try:
        result = urlparse(url_string)
        # Check if scheme (http/https) and netloc (domain) are present
        return all([result.scheme, result.netloc])
    except ValueError:
        return False


def dict_to_csv_form(out_file, info):
    keys = ['uri', 'error', 'response_status', 'content_type', 'is_ipfs_url', 'metadata', 'metadata_error', 'extra_fields', 'second_url',
        'is_ipfs_second_url', 'img_field', 'second_response_status', 'perc_hash_32', 'perc_hash_64', 'image_error', 'response_time', 'response_2_time']

    dict_to_store = {k: None for k in keys}
    dict_to_store.update(info)

    # WARNING: Writing to the same file from multiple processes concurrently 
    # without a lock can cause data corruption. Ensure utils.update_csv handles locking.
    utils.update_csv(out_file, [[dict_to_store['uri'], dict_to_store['error'], dict_to_store['response_status'],
        dict_to_store['content_type'], dict_to_store['is_ipfs_url'], dict_to_store['metadata'], dict_to_store['is_ipfs_second_url'], 
        dict_to_store['img_field'], dict_to_store['second_response_status'], dict_to_store['perc_hash_32'], dict_to_store['perc_hash_64'], 
        dict_to_store['image_error'], dict_to_store['metadata_error'], dict_to_store['extra_fields'],  dict_to_store['response_time'], 
        dict_to_store['second_url'], dict_to_store['response_2_time']]])

    return 0

# --- CORE LOGIC ---

@utils.timeout(60*60)
async def get_uri_info_asy_mult_csv(arguments):
    out_file, url = arguments

    # Handle non-string URLs early
    if not isinstance(url, str):
         return dict_to_csv_form(out_file, {'uri': str(url), 'error': 'Invalid URL Type'})

    if len(url) > 2083:
        return dict_to_csv_form(out_file, {'uri': url, 'error': 'Too long uri'})

    reformatted_url, is_ipfs = get_proper_url(url)

    if is_ipfs == -1:
        return dict_to_csv_form(out_file, {'uri': url, 'error': 'NoneType uri'})

    image_url = None
    err = None
    info = {'uri': url}

    metadata_retries = 3 if is_ipfs else 1
    
    response_content_bytes = None
    response_headers = None
    response_status = None

    timeout_time = 60 if is_ipfs else 30

    # Retry Logic for Initial Request
    for attempt in range(metadata_retries): 
        try:
            start_response_1 = time.time()
            async with request('GET', reformatted_url, timeout=ClientTimeout(total=timeout_time)) as response:
                response_content_bytes = await response.read() 
                response_status = response.status
                response_headers = response.headers
                time_response_1 = time.time() - start_response_1
                info.update({'response_time': time_response_1, 'response_status': response_status, 'is_ipfs_url': is_ipfs})
                break 
        except (asyncio.TimeoutError, ClientConnectorError, ServerDisconnectedError, ClientOSError) as e:
            if attempt == metadata_retries-1: err = f'timeout_or_conn_err: {str(e)}'
            else: await asyncio.sleep(0.5)
        except Exception as e:
            err = str(e)
            break 

    if err:
        return dict_to_csv_form(out_file, {'uri': url, 'error': err})
    

    if response_headers is None:
        info.update({'metadata_error': 'response_headers missing'})
        return dict_to_csv_form(out_file, info)

    # Content Type Handling
    content_type = response_headers.get('content-type', '').lower()
    info.update({'content_type': content_type})

    is_json_flow = False
    is_image_flow = False

    if 'application/json' in content_type:
        is_json_flow = True
    elif 'image' in content_type:
        is_image_flow = True
    else:
        # Sniffing
        try:
            json_response = json.loads(response_content_bytes)
            is_json_flow = True 
        except (json.JSONDecodeError, UnicodeDecodeError):
            try:
                buffer_check = io.BytesIO(response_content_bytes)
                img_check = Image.open(buffer_check)
                img_check.verify() 
                is_image_flow = True
            except Exception:
                info.update({'metadata_error': 'other content/parsing failed'})
                return dict_to_csv_form(out_file, info)

    # JSON Processing
    if is_json_flow:
        try:
            if 'json_response' not in locals():
                json_response = json.loads(response_content_bytes)
            
            if json_response:
                info['metadata'] = True
                # Handle variants of image keys
                image_url = json_response.get('image') or json_response.get('image_url') or json_response.get('img')
                
                if image_url:
                    #if len(image_url) > 2083:
                    if not is_potential_url(image_url):
                        info.update({'image_error': 'Not a valid URL'})
                        return dict_to_csv_form(out_file, info)
                        
                    image_url, is_ipfs_ = get_proper_url(image_url)
                    if is_ipfs_ == -1:
                        info.update({'image_error': 'NoneType second url'})
                        return dict_to_csv_form(out_file, info)
                    
                    info.update({'img_field': True, 'is_ipfs_second_url': is_ipfs_})
                else:
                     info.update({'img_field': False, 'extra_fields': list(json_response.keys())})
            else:
                info.update({'metadata_error': 'empty json content'})
                return dict_to_csv_form(out_file, info)
        except Exception as e:
             info.update({'metadata_error': f'json parse error: {str(e)}'})
             return dict_to_csv_form(out_file, info)

    # Image Processing
    elif is_image_flow:
        image_url = url
        info.update({'metadata': False})

    # Second Request (Image)
    if image_url and isinstance(image_url, str):
        info.update({'second_url': image_url})
        img_bytes = None

        reformatted_second_url, is_ipfs_second_url = get_proper_url(image_url)
        metadata_retries_second_url = 3 if is_ipfs_second_url else 1
        timeout_time_second_url = 60 if is_ipfs_second_url else 30
        
        for attempt in range(metadata_retries_second_url):
            try:
                start_response_2 = time.time()
                async with request('GET', reformatted_second_url, timeout=ClientTimeout(total=timeout_time_second_url)) as response:
                    img_bytes = await response.read()
                    info.update({'second_response_status': response.status})
                    info.update({'response_2_time': time.time() - start_response_2})
                    break
            except (asyncio.TimeoutError, ClientConnectorError, ServerDisconnectedError) as e:
                if attempt == metadata_retries_second_url-1:
                     info.update({'image_error': 'timeout/conn error on image'})
                     return dict_to_csv_form(out_file, info)
                await asyncio.sleep(0.5)
            except Exception as e:
                info.update({'image_error': str(e)})
                return dict_to_csv_form(out_file, info)

        if img_bytes:
            try:
                buffer = io.BytesIO(img_bytes)
                im = Image.open(buffer)
                avg_hash_32 = str(imagehash.phash(im, hash_size=32))
                avg_hash_64 = str(imagehash.phash(im, hash_size=64))
                info.update({'perc_hash_32': avg_hash_32, 'perc_hash_64': avg_hash_64})
            except UnidentifiedImageError:
                info.update({'image_error': 'unidentified_image_err'})
            except Image.DecompressionBombError:
                info.update({'image_error': 'DecompressionBomb_err'})
            except Exception as e:
                info.update({'image_error': f'processing error: {str(e)}'})

    return dict_to_csv_form(out_file, info)

# --- STATISTICS & MAIN ---

def get_token_statistics(token_uris_list):
    print(f"Input type: {type(token_uris_list)}")

    # Filter out NaNs immediately to avoid crashes
    token_uris_list = [t for t in token_uris_list if isinstance(t, str)]
    
    print('total token uris: ', len(token_uris_list))
    token_uris_list = set(token_uris_list)
    print('total unique token uris: ', len(token_uris_list))
    
    # Logic: strings are safe to iterate now
    callable_token_uris_list = [t for t in token_uris_list if not any(domain in t for domain in ['api.immutable.com'])]
    print('total callable token uris: ',  len(callable_token_uris_list))
    
    to_search_token_uris = [t for t in callable_token_uris_list if len(t) < 2083]
    print('total token uris longer than 2083 chars: ', len(callable_token_uris_list) - len(to_search_token_uris))


async def main(input_dir='data/all_token_uris_to_explore.csv.zst', out_file='token_uri_details_token_uri_details_{}_snapshot.csv'):
    #out_file = 'token_uri_details_token_uri_details_{}_snapshot.csv'
    datetime_now = datetime.datetime.now()
    print('#### {}: starting nft catcher ###'.format(datetime_now))

    # --- FIX 1: Read Pandas CSV Correctly ---
    try:
        df = pd.read_csv(input_dir)
        # Select column, drop NAs, convert to list
        token_uris = df['token_uris'].dropna().astype(str).tolist()
    except Exception as e:
        print(f"Error loading CSV: {e}")
        return

    # Print stats
    get_token_statistics(token_uris)

    # Prepare snapshot file
    out_file = out_file.format(str(datetime_now.date().year))
    print('Snapshot file name is: ', out_file)

    if not os.path.exists('data/' + out_file):
        print('file not found, creating new...')
        # Ensure directory exists
        os.makedirs('data', exist_ok=True)
        utils.update_csv(out_file, [['uri', 'error', 'response_status', 'content_type', 'is_ipfs_url',
                'metadata', 'is_ipfs_second_url', 'img_field', 'second_response_status', 'perc_hash_32', 'perc_hash_64','image_error',
                'metadata_error', 'extra_fields', 'response_time', 'second_url', 'response_2_time']])
    else:
        print('file already exists. Exploring remaining token uris...')
        # Optimize reading already explored files (only read required column)
        token_uris_explored = set(pd.read_csv('data/'+out_file, usecols=['uri'])['uri'].dropna().astype(str).tolist())
        
        print('Total token uris already explored are: ', len(token_uris_explored))
        
        # Convert input list to set for O(1) difference operation
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
    
    async with Pool(n_processes) as pool:
        await pool.map(get_uri_info_asy_mult_csv, batches)

    print('Finished!')

if __name__ == "__main__":
    
    # Run once
    asyncio.run(main('data/unreachable_ipfs_token_uris.csv', 'output_check_on_ipfs_uris.csv'))

    # If you want to use the schedule, remove asyncio.run(main()) above
    # and uncomment the lines below:
    
    # loop = asyncio.new_event_loop()
    # schedule.every().day.at("12:23").do(main)
    # while True:
    #     loop.run_until_complete(schedule.run_pending())
    #     time.sleep(5)