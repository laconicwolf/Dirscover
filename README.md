# Dirscover
A multi-processed, multi-threaded scanner to perform forced browsing on multiple URLs. Feed it a wordlist (of files/directory names) and a URL (or file containing multiple URLs) and Dirscover will send web requests to discover files or directories specified in the wordlist. For each request Dirscover returns the URL, response code, response length, and redirect url (if applicable). The results will also be written to a CSV file for each URL provided.

Dirscover is meant to be fast. By default it will detect the amount of CPU cores available and launch that many processes. Each URL that you pass will be spawned as a new process, and each process is multi-threaded with a default of 5 threads. Feel free to increase the threads if you want each site to be forced browse more quickly.

A progress bar will appear, however it will only give you a general idea of your progress if you are forced browsing multiple sites, because it will refresh itself with the data from each process.

This script requires Python3 and does not work with previous versions.

## Usage

### Attempts forced browsing against each site specified in urls.txt using the wordlist filenames.txt
`python3 dirscover.py --wordlist filenames.txt --url_file urls.txt`

### Additional options
```
-v, --verbose                                 increase output verbosity.
-pr <proxy url>, --proxy                      specify a proxy to use (-pr 127.0.0.1:8080).
-a, --auth [auth info [auth info ...]]        specify an address, auth type, username, and password
                                              for authentication delimited with ~~~. 
                                              Example: -a "https://example.com:8443~~~ntlm~~~domain/jmiller~~~S3Cr37P@ssW0rd"
-c, --cookies [cookie info [cookie info ...]] specify a domain(s) and cookie(s) data delimited with ~~~. 
                                              Example: -c "https://example.com:8443~~~C1=IlV0ZXh0L2h; C2=AHWqTUmF8I;" "http://example2.com:80~~~Token=19005936-1"
-ua, --useragent <user-agent>                 specify a User-Agent string to use. Default is a random browser User-Agent string.
-r, --referer <referer>                       specify a referer string to use.
-w, --wordlist <filename>                     specify a file containing urls formatted http(s)://addr:port.
-uf, --url_file <filename>                    specify a file containing urls formatted http(s)://addr:port.
-u, --url <url>                               specify a single url formatted http(s)://addr:port.
-s, --status_code_filter [code [code ...]]    specify the status code(s) to be displayed to the terminal (-s 200 403 201). 
                                              You can also include a wildcard (-s 2*) to include all response codes that 
                                              start with a number. All response codes will still be written to a file.
-p, --processes <int>                         specify number of processes (default will utilize 1 process per cpu core).
-t, --threads <int>                           specify number of threads (default=5) per process.
-to, --timeout <int>                          specify number of seconds until a connection timeout (default=10).
```
