#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: cbk914
import argparse
import requests
import sys

def check_url(url, debug):
    try:
        # Send a GET request and get the response headers
        response = requests.get(url)
        response.raise_for_status()
        headers = response.headers

        # If debug flag is set, print the response content and headers
        if debug:
            print(response.status_code)
            print(response.content)
            print(headers)

        # Check for client-side desync vulnerabilities
        if 'Transfer-Encoding' in headers and 'Content-Length' in headers:
            print('Client-side desync vulnerability found!')
        else:
            print('No client-side desync vulnerability found.')
    except requests.exceptions.RequestException as e:
        print('Error:', e)
        sys.exit(1)

if __name__ == '__main__':
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Check for client-side desync vulnerabilities')
    parser.add_argument('-u', '--url', type=str, required=True, help='URL to check')
    parser.add_argument('-d', '--debug', action='store_true', help='Print debugging information')
    args = parser.parse_args()

    # Call the check_url function with the provided URL and debug flag
    check_url(args.url, args.debug)
