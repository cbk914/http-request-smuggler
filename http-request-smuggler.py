
import argparse
import requests

parser = argparse.ArgumentParser(description='Check a URL for request smuggling vulnerabilities')
parser.add_argument('-u', '--url', required=True, help='The URL to test')
args = parser.parse_args()

url = args.url

# Test 1: Splitting headers with whitespace
headers = {
    'Transfer-Encoding': 'chunked',
    'Content-Length': '0\r\n',
    'X:': 'X\r\n'
}

response = requests.post(url, headers=headers)

if response.status_code == 400:
    print('Possible request smuggling vulnerability detected (Splitting headers with whitespace)')
else:
    print('No request smuggling vulnerability detected')

# Test 2: Splitting headers with a new line
headers = {
    'Transfer-Encoding': 'chunked',
    'Content-Length': '0',
    '\nX': ':X'
}

response = requests.post(url, headers=headers)

if response.status_code == 400:
    print('Possible request smuggling vulnerability detected (Splitting headers with a new line)')
else:
    print('No request smuggling vulnerability detected')

# Test 3: Combining headers with a comma
headers = {
    'Transfer-Encoding': 'chunked',
    'Content-Length': '0',
    'X': 'X',
    'Y': 'Y'
}

response = requests.post(url, headers=headers)

if response.status_code == 400:
    print('Possible request smuggling vulnerability detected (Combining headers with a comma)')
else:
    print('No request smuggling vulnerability detected')
