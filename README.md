# Dirscover
A multi-processed, multi-threaded scanner to perform forced browsing on multiple URLs. Feed it a wordlist (of files/directory names) and a URL (or file containing multiple URLs) and Dirscover will send web requests to discover files or directories specified in the wordlist. For each request Dirscover returns the URL, response code, response length, and redirect url (if applicable). The results will also be written to a CSV file for each URL provided.

Dirscover is meant to be fast. By default it will detect the amount of CPU cores available and launch that many processes. Each URL that you pass will be spawned as a new process, and each process is multi-threaded.

This script requires Python3 and does not work with previous versions.

## Usage

### Attempts forced browsing against each site specified in urls.txt using the wordlist filenames.txt
`python3 dirscover.py --wordlist filenames.txt --url_file urls.txt`

### Additional options
```
-v, --verbose       increase output verbosity.
-pr, --proxy        specify a proxy to use (-pr 127.0.0.1:8080).
-a, --auth          specify an address, auth type, username, and password
                    for authentication delimited with ~~~. 
                    Example: -a "https://example.com:8443~~~ntlm~~~domain/jmiller~~~S3Cr37P@ssW0rd"
-c, --cookies       specify a domain(s) and cookie(s) data delimited with ~~~. 
                    Example: -c "https://example.com:8443~~~C1=IlV0ZXh0L2h; C2=AHWqTUmF8I;" "http://example2.com:80~~~Token=19005936-1"
-ua, --useragent    specify a User-Agent string to use. Default is a random browser User-Agent string.
-r, --referer       specify a referer string to use.
-w, --wordlist      specify a file containing urls formatted http(s)://addr:port.
-uf, --url_file     specify a file containing urls formatted http(s)://addr:port.
-u, --url           specify a single url formatted http(s)://addr:port.
-p, --processes     specify number of processes (default will utilize 1 process per cpu core).
-t, --threads       specify number of threads (default=5) per process.
-to, --timeout      specify number of seconds until a connection timeout (default=10).
```
