#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: cbk914

import logging
import re
import subprocess
import sys
from pathlib import Path

from termcolor import colored

# List of techniques
techniques = ["CLTE", "CL0", "SLRE", "TECL", "TESI"]

# Default per-probe wall-clock budget. The original code waited forever, so a
# hung target could wedge a whole scan run.
PROBE_TIMEOUT = 60

# Path to the scanner invoked as a child process. Resolved relative to this
# file so the runner works regardless of the current working directory.
SCANNER = Path(__file__).resolve().with_name("http-request-smuggler.py")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# A DNS label, or a bare numeric IPv4 octet.
_LABEL_RE = re.compile(r'^[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?$')
# An IPv6 literal must arrive bracketed, e.g. [::1].
_IPV6_RE = re.compile(r'^\[[0-9A-Fa-f:.%]+\]$')
_SCHEME_RE = re.compile(r'^(?P<scheme>https?)://', re.IGNORECASE)

MAX_HOST_LEN = 253


def validate_target(raw):
    """Normalise one line of targets.txt into a host plus an optional scheme.

    A target is *data*. This function is the trust boundary: it accepts only a
    DNS name, an IPv4 literal, or a bracketed IPv6 literal, and raises
    ValueError on anything else. Because the allowlist is built from a strict
    character class, shell metacharacters (``;``, ``&``, ``|``, ``$``,
    backtick, quotes, whitespace, newlines) can never survive this function.

    Returns a ``(scheme, host)`` tuple, defaulting the scheme to https.
    """
    if raw is None:
        raise ValueError('target is empty')

    candidate = raw.strip()
    if not candidate:
        raise ValueError('target is empty')

    scheme = 'https'
    match = _SCHEME_RE.match(candidate)
    if match:
        scheme = match.group('scheme').lower()
        candidate = candidate[match.end():]

    # Drop any path, query, fragment or userinfo component.
    candidate = candidate.split('/', 1)[0]
    if '@' in candidate:
        candidate = candidate.rsplit('@', 1)[1]

    if not candidate:
        raise ValueError('target has no host component')

    if _IPV6_RE.match(candidate):
        return scheme, candidate

    if len(candidate) > MAX_HOST_LEN:
        raise ValueError(f'target exceeds {MAX_HOST_LEN} characters: {candidate!r}')

    labels = candidate.split('.')
    for label in labels:
        if not _LABEL_RE.match(label):
            raise ValueError(f'invalid target: {raw!r}')

    return scheme, candidate


def build_command(target, tech):
    """Build the argv for a single probe.

    List form, ``shell=False``: the target occupies exactly one argv element,
    so no part of it is ever parsed by a shell. ``sys.executable`` replaces the
    hardcoded ``python3``, which does not exist under that name on Windows.
    """
    if tech not in techniques:
        raise ValueError(f'unknown technique: {tech!r}')

    scheme, host = validate_target(target)
    return [
        sys.executable,
        str(SCANNER),
        '-t',
        tech,
        '-u',
        f'{scheme}://{host}',
    ]


def read_urls(file_path):
    """Read candidate targets from a file, skipping blanks and comments."""
    try:
        with open(file_path, 'r') as file:
            lines = file.read().splitlines()
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return []

    targets = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        targets.append(stripped)
    return targets


def run_command(target, tech, timeout=PROBE_TIMEOUT):
    """Run the HTTP request smuggling probe for one target/technique pair."""
    command = build_command(target, tech)
    logging.info("Scanning %s with technique %s...", command[-1], tech)
    process = subprocess.Popen(
        command,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        logging.error("Probe for %s (%s) timed out after %ss", target, tech, timeout)
    return stdout.decode(errors='replace'), stderr.decode(errors='replace')


def print_output(stdout, stderr):
    """Print the output of the command in color."""
    color = 'green' if 'error' not in stdout.lower() and 'error' not in stderr.lower() else 'red'
    print(colored(stdout, color))
    print(colored(stderr, color))


def main(targets_file='targets.txt'):
    targets = read_urls(targets_file)
    if not targets:
        logging.error("No URLs to scan.")
        return

    rejected = 0
    for target in targets:
        try:
            for tech in techniques:
                stdout, stderr = run_command(target, tech)
                print_output(stdout, stderr)
        except ValueError as exc:
            # One poisoned line must not abort the whole run.
            rejected += 1
            logging.error("Skipping rejected target: %s", exc)

    if rejected:
        logging.error("Skipped %d invalid target line(s) from %s", rejected, targets_file)


if __name__ == "__main__":
    main()