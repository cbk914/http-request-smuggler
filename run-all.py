#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: cbk914

import subprocess
from termcolor import colored
import logging

# List of techniques
techniques = ["CLTE", "CL0", "SLRE", "TECL", "TESI"]

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def read_urls(file_path):
    """Read URLs from a file."""
    try:
        with open(file_path, 'r') as file:
            urls = file.read().splitlines()
        return urls
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return []

def run_command(url, tech):
    """Run the HTTP request smuggling test command."""
    command = f"python3 http-request-smuggler.py -t {tech} -u https://{url}"
    logging.info(f"Scanning {url} with technique {tech}...")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    return stdout.decode(), stderr.decode()

def print_output(stdout, stderr):
    """Print the output of the command in color."""
    color = 'green' if 'error' not in stdout.lower() and 'error' not in stderr.lower() else 'red'
    print(colored(stdout, color))
    print(colored(stderr, color))

def main():
    urls = read_urls('targets.txt')
    if not urls:
        logging.error("No URLs to scan.")
        return

    for url in urls:
        for tech in techniques:
            stdout, stderr = run_command(url, tech)
            print_output(stdout, stderr)

if __name__ == "__main__":
    main()
