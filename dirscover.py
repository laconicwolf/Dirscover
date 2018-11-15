#!/usr/bin/env python3


__author__ = "Jake Miller (@LaconicWolf)"
__date__ = "20181109"
__version__ = "0.01"
__description__ = """A multi-processed, multi-threaded scanner to discover web directories on multiple URLs."""

from sys import version

if not version.startswith('3'):
    print('\n[-] This script will only work with Python3. Sorry!\n')
    exit()

import os
import argparse
import time
import threading
import queue
from multiprocessing import Pool, cpu_count
from random import randrange
from urllib.parse import urlparse

# Third party modules
try:
    import requests
    import tqdm
    from requests_ntlm import HttpNtlmAuth
except ImportError as error:
    missing_module = str(error).split(' ')[-1]
    print('[-] Missing module: {}'.format(missing_module))
    print('[*] Try running "pip install {}", or do an Internet search for installation instructions.'.format(missing_module.strip("'")))
    exit()
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.auth import HTTPBasicAuth
from requests.auth import HTTPDigestAuth


def get_random_useragent():
    """Returns a randomly chosen User-Agent string."""
    win_edge = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'
    win_firefox = 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/43.0'
    win_chrome = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36"
    lin_firefox = 'Mozilla/5.0 (X11; Linux i686; rv:30.0) Gecko/20100101 Firefox/42.0'
    mac_chrome = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.38 Safari/537.36'
    ie = 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)'
    ua_dict = {
        1: win_edge,
        2: win_firefox,
        3: win_chrome,
        4: lin_firefox,
        5: mac_chrome,
        6: ie
    }
    rand_num = randrange(1, (len(ua_dict) + 1))
    return ua_dict[rand_num]


def normalize_urls(urls):
    """Accepts a list of urls and formats them to the proto://address:port format.
    Returns a new list of the processed urls.
    """
    url_list = []
    http_port_list = ['80', '280', '81', '591', '593', '2080', '2480', '3080', 
                  '4080', '4567', '5080', '5104', '5800', '6080',
                  '7001', '7080', '7777', '8000', '8008', '8042', '8080',
                  '8081', '8082', '8088', '8180', '8222', '8280', '8281',
                  '8530', '8887', '9000', '9080', '9090', '16080']                    
    https_port_list = ['832', '981', '1311', '7002', '7021', '7023', '7025',
                   '7777', '8333', '8531', '8888']
    for url in urls:
        u = urlparse(url)
        if u.scheme == 'http':
            if ':' in u.netloc:
                url_list.append(url)
            else:
                url = u.scheme + '://' + u.netloc + ':80'
                if u.path:
                    url += u.path
                    url_list.append(url)
                else:
                    url_list.append(url)
        elif u.scheme == 'https':
            if ':' in u.netloc:
                url_list.append(url)
                continue
            else:
                url = u.scheme + '://' + u.netloc + ':443'
                if u.path:
                    url += u.path
                    url_list.append(url)
                else:
                    url_list.append(url)
        else:
            if ':' in u.netloc:
                port = u.netloc.split(':')[-1]
                if port in https_port_list:
                    url = 'http://' + url
                    url_list.append(url)
                if port in https_port_list or port.endswith('43'):
                    url = 'https://' + url
                    url_list.append(url)
            while True: 
                scheme = input('[*] Please specify http or https for the site {}, or type exit to quit: '.format(url)).lower()
                if scheme == 'exit':
                    exit()
                if scheme == 'http' or 'https':
                    break
            if scheme == 'http':
                url = scheme + '://' + url
                u = urlparse(url)
                url = u.scheme + '://' + u.netloc + ':80'
                if u.path:
                    url += u.path
                    url_list.append(url)
            if scheme == 'https':
                url = scheme + '://' + url
                u = urlparse(url)
                url = u.scheme + '://' + u.netloc + ':443'
                if u.path:
                    url += u.path
                    url_list.append(url)
            continue
    return url_list


def make_request(url):
    """Builds a requests object, makes a request, and returns 
    a tuple of response attributes.
    """

    # Initialize a session object
    s = requests.Session()
    
    # Add a user agent from commandline options or select
    # a random user agent.
    user_agent = args.useragent if args.useragent else get_random_useragent()
    s.headers['User-Agent'] = user_agent
    
    # Parse and add cookies specified from commandline options
    if args.cookies:
        for item in cookie_list:
            if item[0] not in url:
                continue
            domain_cookies = item[1]
            cookies = domain_cookies.split(';')
            for cookie in cookies:
                cookie_name = cookie.split('=')[0].lstrip()
                cookie_value = '='.join(cookie.split('=')[1:]).lstrip()
                s.cookies[cookie_name] = cookie_value
    
    # Add referer if specified by commandline options
    if args.referer:
        s.headers['Referer'] = args.referer
    
    # Add a proxy if specified by commandline options
    if args.proxy:
        s.proxies['http'] = args.proxy
        s.proxies['https'] = args.proxy

    # Add an authrization header if specified by commandline
    # options. Handle basic, digest, and ntlm
    if args.auth:
        for item in auth_list:
            if item[0] not in url:
                continue
            auth_addr = item[0]
            auth_method = item[1]
            auth_uname = item[2]
            auth_passw = item[3]
            if auth_method.lower() == 'basic':
                try:
                    resp = s.get(url, auth=(auth_uname, auth_passw), verify=False, timeout=int(args.timeout))
                except Exception as e:
                    if args.verbose:
                        with lock:
                            print('[-] Experiencing network connectivity issues. Waiting 30 seconds and retrying the request...')
                    time.sleep(30)
                    try:
                        resp = s.get(url, auth=(auth_uname, auth_passw), verify=False, timeout=int(args.timeout))
                    except Exception as e:
                        with lock:
                            print('[-] The request to {} failed with the following error:\n{}'.format(url, e))
                            return (url, 'FAIL', 'FAIL', 'FAIL')
            if auth_method.lower() == 'digest':
                try:
                    resp = s.get(url, auth=HTTPDigestAuth(auth_uname, auth_passw), verify=False, timeout=int(args.timeout))
                except Exception as e:
                    if args.verbose:
                        with lock:
                            print('[-] Experiencing network connectivity issues. Waiting 30 seconds and retrying the request...')
                    time.sleep(30)
                    try:
                        resp = s.get(url, auth=HTTPDigestAuth(auth_uname, auth_passw), verify=False, timeout=int(args.timeout))
                    except Exception as e:
                        with lock:
                            print('[-] The request to {} failed with the following error:\n{}'.format(url, e))
                            return (url, 'FAIL', 'FAIL', 'FAIL')
            if auth_method.lower() == 'ntlm':
                nt_auth_dom = auth_uname.split('/')[0]
                nt_auth_uname = auth_uname.split('/')[1]
                s.auth = HttpNtlmAuth(nt_auth_dom + '\\' + nt_auth_uname, auth_passw)
                try:
                    resp = s.get(url, verify=False, timeout=int(args.timeout))
                except Exception as e:
                    if args.verbose:
                        with lock:
                            print('[-] Experiencing network connectivity issues. Waiting 30 seconds and retrying the request...')
                    time.sleep(30)
                    try:
                        resp = s.get(url, verify=False, timeout=int(args.timeout))
                    except Exception as e:
                        with lock:
                            print('[-] The request to {} failed with the following error:\n{}'.format(url, e))
                            return (url, 'FAIL', 'FAIL', 'FAIL')
    
    # Unless Auth is specified, send the request
    # with no authorization header.
    else:
        try:
            resp = s.get(url, verify=False, timeout=int(args.timeout))
        except Exception as e:
            if args.verbose:
                with lock:
                    print('[-] Experiencing network connectivity issues. Waiting 30 seconds and retrying the request...')
            time.sleep(30)
            try:
                resp = s.get(url, verify=False, timeout=int(args.timeout))
            except Exception as e:
                with lock:
                    print('[-] The request to {} failed with the following error:\n{}'.format(url, e))
                    return (url, 'FAIL', 'FAIL', 'FAIL')
    
    # Update the status bar
    with lock:
        p_bar.update(counter + 1)
    
    # Determine the response length and 
    # whether a redirect occurred
    resp_len = len(resp.text)
    redir_url = resp.url if resp.url.strip('/') != url.strip('/') else ""
    
    # Print data to screen if verbose and return the data.
    if args.verbose:
        if redir_url:
            try:
                redirect_url = redir_url[:35] + '...'
            except IndexError:
                redirect_url = redir_url
        else:
            redirect_url = redir_url
        with lock:
            print("{} : {} : {} : {}".format(resp.status_code, url, resp_len, redirect_url))
    resp_data = (url, resp.status_code, resp_len, redir_url)
    return resp_data


def manage_queue(url, dir_queue, dirscover_data):
    """Manages the dir_queue and calls the make_request function"""
    while True:
        directory = dir_queue.get()
        resource = url.strip('/') + '/' + directory
        dirscover_data.append(make_request(resource))
        dir_queue.task_done()


def format_results(results):
    """Provides output formatting"""

    # Create a directory to put the results files
    dirname = 'dirscover_results'
    if dirname not in os.listdir():
        os.mkdir(dirname) 

    # Name the file based on the domain name
    filename = results[1][0].split('/')[2].replace('.', '_').replace(':','-') + '.csv'
    
    # Write the file
    filepath = dirname + os.sep + filename
    with lock:
        with open(filepath, 'w') as outfile:
            for item in results:
                item = [str(i) for i in item]
                outfile.write(','.join(item) + '\n')
        outfile.close()
        print("\n[*] Results file written to {}.".format(filepath))

    # Print the results to the screen
    with lock:
        print()
        for item in results:
            url_path, resp_code, resp_len, redirect_url = item

            # Truncate the redirect url string
            if redirect_url and redirect_url != 'Redirect URL':
                try:
                    redirect_url = redirect_url[:35] + '...'
                except IndexError:
                    pass
            print("{} : {} : {} : {}".format(resp_code, url_path, resp_len, redirect_url))


def dirscover_multithreader(url):
    """Starts the multithreading and sends the returned data to
    a specified output format.
    """

    # Initializes the queue.
    dir_queue = queue.Queue()

    # Initializes a variable to hold all the request data per process. 
    dirscover_data = [('URL','Response Code','Response Length','Redirect URL')]

    # Starts the multithreading
    for i in range(args.threads):
        t = threading.Thread(target=manage_queue, args=[url, dir_queue, dirscover_data])
        t.daemon = True
        t.start()    

    for directory in wordlist:
        dir_queue.put(directory)
    dir_queue.join()

    # Provides output formatting
    format_results(dirscover_data)
    

def main():
    start = time.time()

    # Starts multiprocessing
    with Pool(cores) as p:
        p.map(dirscover_multithreader, urls)

    print("\nTime taken = {0:.5f}".format(time.time() - start))


# Commandline arguments
parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose",
                    help="increase output verbosity",
                    action="store_true")
parser.add_argument("-pr", "--proxy", 
                    help="specify a proxy to use (-p 127.0.0.1:8080)")
parser.add_argument("-a", "--auth",
                    nargs="*",
                    help='specify an address, auth type, username, and password for authentication delimited with ~~~. Example: -a "https://example.com:8443~~~ntlm~~~domain/jmiller~~~S3Cr37P@ssW0rd"')
parser.add_argument("-c", "--cookies",
                    nargs="*",
                    help='specify a domain(s) and cookie(s) data delimited with ~~~. Example: -c "https://example.com:8443~~~C1=IlV0ZXh0L2h; C2=AHWqTUmF8I;" "http://example2.com:80~~~Token=19005936-1"')
parser.add_argument("-ua", "--useragent", 
                    help="specify a User Agent string to use. Default is a random User Agent string.")
parser.add_argument("-r", "--referer", 
                    help="specify a referer string to use.")
parser.add_argument("-w", "--wordlist",
                    help="specify a file containing urls formatted http(s)://addr:port.")
parser.add_argument("-uf", "--url_file",
                    help="specify a file containing urls formatted http(s)://addr:port.")
parser.add_argument("-u", "--url",
                    help="specify a single url formatted http(s)://addr:port.")
parser.add_argument("-p", "--processes",
                    nargs="?",
                    type=int,
                    help="specify number of processes (default will utilize 1 process per cpu core)")
parser.add_argument("-t", "--threads",
                    nargs="?",
                    type=int,
                    const=5,
                    default=5,
                    help="specify number of threads (default=5)")
parser.add_argument("-to", "--timeout",
                    nargs="?", 
                    type=int, 
                    default=10, 
                    help="specify number of seconds until a connection timeout (default=10)")
args = parser.parse_args()

# Suppress SSL warnings in the terminal
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Number of cores. Will launch a process for each core.
if args.processes:
    cores = args.processes
else:
    cores = cpu_count()
# Parse the urls
if not args.url and not args.url_file:
    parser.print_help()
    print("\n[-] Please specify a URL (-u) or an input file containing URLs (-uf).\n")
    exit()
if args.url and args.url_file:
    parser.print_help()
    print("\n[-] Please specify a URL (-u) or an input file containing URLs (-uf). Not both\n")
    exit()
if args.url_file:
    url_file = args.url_file
    if not os.path.exists(url_file):
        print("\n[-] The file cannot be found or you do not have permission to open the file. Please check the path and try again\n")
        exit()
    urls = open(url_file).read().splitlines()
if args.url:
    if not args.url.startswith('http'):
        parser.print_help()
        print("\n[-] Please specify a URL in the format proto://address:port (https://example.com:80).\n")
        exit()
    urls = [args.url]

# Normalizes URLs to the proto://address:port format
urls = normalize_urls(urls)

# Parse the wordlist
if not args.wordlist:
    parser.print_help()
    print("\n[-] Please specify an input file containing a wordlist (-w).\n")
    exit()
if not os.path.exists(args.wordlist):
    print("\n[-] The file {} cannot be found or you do not have permission to open the file. Please check the path and try again\n".format(args.wordlist))
    exit()
with open(args.wordlist) as fh:
    wordlist = fh.read().splitlines()

# Parses cookies
if args.cookies:
    cookie_list = []
    for item in args.cookies:
        if '~~~' not in item:
            print('\n[-] Please specify the domain with the cookies using 3 tildes as a delimiter to separate the domain the cookie (-c "https://example.com:8443~~~C1=IlV0ZXh0L2h; C2=AHWqTUmF8I; Token=19005936-1").\n')
            exit()
        cookie_domain = item.split('~~~')[0]
        cookies = item.split('~~~')[1]
        if cookie_domain.strip('/') not in [u.strip('/') for u in urls]:
            print('\n[-] Could not find {} in the URL list. Exiting.\n'.format('cookie_domain'))
            exit()
        else:
            cookie_list.append((cookie_domain, cookies))

# Parses the authorization options
if args.auth:
    auth_list = []
    for item in args.auth:
        if '~~~' not in item:
            print('\n[-] Please specify an address, auth type, username, and password for authentication delimited with ~~~. Example: -a "https://example.com:8443~~~ntlm~~~domain/jmiller~~~S3Cr37P@ssW0rd"\n')
            exit()
        auth_domain = item.split('~~~')[0]
        if auth_domain.strip('/') not in [u.strip('/') for u in urls]:
            print('\n[-] Could not find {} in the URL list. Exiting\n'.format('auth_domain'))
            exit()
        auth_type = item.split('~~~')[1]
        possible_auth_types = ['basic', 'digest', 'ntlm']
        if auth_type.lower() not in possible_auth_types:
            print("\n[-] Authorization type {} not supported. Only Basic, Digest, or NTLM are supported.\n".format(auth_type))
            exit()
        username = item.split('~~~')[2]
        if auth_type.lower() == 'ntlm' and '/' not in username:
            print('\n[-] NTLM auth requres a domain with a username, delimited by /. Example: -a "https://example.com:8443~~~ntlm~~~example.domain/jmiller~~~S3Cr37P@ssW0rd"\n')
            exit()
        password = item.split('~~~')[3]
        auth_list.append((auth_domain, auth_type, username, password))

# Initializes progress bar. Not 100% accourate but 
# better than nothing...
p_bar = tqdm.tqdm(range(len(wordlist)))
counter = 0

# Initilizes the lock for thread-safe operations
lock = threading.Lock()

if __name__ == '__main__':
    main()
