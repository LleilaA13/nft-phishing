import multiprocessing.pool
import functools
from multiprocessing import TimeoutError
import os
import logging
import pickle
import csv


# create a directory named id_channel at target base_path
def create_dir(base_path, id_channel):
    path = base_path + str(id_channel)

    try:
        os.mkdir(path)
    except:
        logging.info("Creation of the directory %s failed " % path)
    else:
        logging.info("Successfully created the directory %s " % path)

    return path + '/'

# return the higher n numbers from a dictionary


def get_n_greater_elements_from_dict_fast(my_dict, n):
    from operator import itemgetter
    return dict(sorted(my_dict.items(), key=itemgetter(1), reverse=True)[:n])


# save preprocess docs in pickle
def save_as_pickle(text_list, outfile_name):
    with open('data/'+outfile_name, 'wb') as fp:
        pickle.dump(text_list, fp)


def update_csv(csv_filename, data):
    if len(data) > 0:
        with open('data/'+csv_filename, 'a', encoding='UTF8', newline='') as f:
            writer = csv.writer(f, escapechar='\\')
            writer.writerows(data)


# open a pickle file
def open_pickle(filename, creation_type=dict, verbose=False):
    try:
        with open('data/'+filename, 'rb') as fp:
            saved_file = pickle.load(fp)
    except:
        if verbose:
            print(
                f'File {filename} not found. Empty {str(creation_type)} initialized')
        return creation_type()

    return saved_file


def timeout(max_timeout):
    """Timeout decorator, parameter in seconds."""
    def timeout_decorator(item):
        """Wrap the original function."""
        @functools.wraps(item)
        def func_wrapper(*args, **kwargs):
            """Closure for function."""
            pool = multiprocessing.pool.ThreadPool(processes=1)
            async_result = pool.apply_async(item, args, kwargs)
            # raises a TimeoutError if execution exceeds max_timeout
            try:
                return async_result.get(max_timeout)
            except TimeoutError:
                return {args[0]: 'Timeout Error downloading file'}

        return func_wrapper
    return timeout_decorator
