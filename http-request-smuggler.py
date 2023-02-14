#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# Author:
import argparse
import requests

parser = argparse.ArgumentParser(description='Check a URL for request smuggling vulnerabilities')
parser.add_argument('-u', '--url', required=True, help='The URL to test')
parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')
args = parser.parse_args()

url = args.url
debug = args.debug

# Test 1: Splitting headers with whitespace
headers = {
    'Transfer-Encoding': 'chunked',
    'Content-Length': '0\r\n',
    'X:': 'X\r\n'
}

try:
    response = requests.post(url, headers=headers, timeout=5)
    response.raise_for_status()
except requests.exceptions.RequestException as e:
    if debug:
        print(f'Request error: {e}')
    else:
        print('Error: Could not connect to the URL')
    exit()
except ValueError as e:
    if debug:
        print(f'Value error: {e}')
    else:
        print('Error: Invalid response from the server')
    exit()

if response.status_code == 400:
    print('Possible request smuggling vulnerability detected (Splitting headers with whitespace)')
else:
    print('No request smuggling vulnerability detected')

# Test 2: Splitting headers with a new line
headers = {
    'Transfer-Encoding': 'chunked',
    'Content-Length': '0',
    'X': ': X',
    '\r\n': '\r\n',
    'Y': ': Y\r\n'
}

try:
    response = requests.post(url, headers=headers, timeout=5)
    response.raise_for_status()
except requests.exceptions.RequestException as e:
    if debug:
        print(f'Request error: {e}')
    else:
        print('Error: Could not connect to the URL')
    exit()
except ValueError as e:
    if debug:
        print(f'Value error: {e}')
    else:
        print('Error: Invalid response from the server')
    exit()

if response.status_code == 400:
    print('Possible request smuggling vulnerability detected (Splitting headers with a new line)')
else:
    print('No request smuggling vulnerability detected')

# Test 3: Combining headers with a comma
headers = {
    'Transfer-Encoding': 'chunked',
    'Content-Length': '0',
    'X': 'X, Y'
}

try:
    response = requests.post(url, headers=headers, timeout=5)
    response.raise_for_status()
except requests.exceptions.RequestException as e:
    if debug:
        print(f'Request error: {e}')
    else:
        print('Error: Could not connect to the URL')
    exit()
except ValueError as e:
    if debug:
        print(f'Value error: {e}')
    else:
        print('Error: Invalid response from the server')
    exit()

if response.status_code == 400:
    print('Possible request smuggling vulnerability detected (Combining headers with a comma)')
else:
    print('No request smuggling vulnerability detected')
