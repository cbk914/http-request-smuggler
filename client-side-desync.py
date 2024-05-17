#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: cbk914

import argparse
import requests
import sys
import logging
import re

def validate_url(url):
    # Simple regex for validating a URL
    regex = re.compile(
        r'^(?:http|https)://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

def check_url(url, debug):
    if not validate_url(url):
        logging.error('Invalid URL format.')
        sys.exit(1)

    try:
        # Send a GET request and get the response headers with a timeout
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        headers = response.headers

        # If debug flag is set, print the response content and headers
        if debug:
            logging.debug(f'Status Code: {response.status_code}')
            logging.debug(f'Content: {response.content}')
            logging.debug(f'Headers: {headers}')

        # Check for client-side desync vulnerabilities
        if 'Transfer-Encoding' in headers and 'Content-Length' in headers:
            print('Client-side desync vulnerability found!')
        else:
            print('No client-side desync vulnerability found.')
    except requests.exceptions.RequestException as e:
        logging.error(f'Error: {e}')
        sys.exit(1)

if __name__ == '__main__':
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Check for client-side desync vulnerabilities')
    parser.add_argument('-u', '--url', type=str, required=True, help='URL to check')
    parser.add_argument('-d', '--debug', action='store_true', help='Print debugging information')
    args = parser.parse_args()

    # Configure logging level
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)

    # Call the check_url function with the provided URL and debug flag
    check_url(args.url, args.debug)
