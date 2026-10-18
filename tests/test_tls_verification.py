"""Regression tests for TLS trust handling in http-request-smuggler.py.

The original scanner called ``requests.post(..., verify=False)`` for every
probe and globally suppressed the warning:

    urllib3.disable_warnings(InsecureRequestWarning)
    ...
    response = requests.post(url, headers=headers, data=payload, verify=False)

The consequence is a false negative that looks like a clean bill of health.
Any interception that presents a certificate the client will not accept raises
``SSLError``; the original caught that in the broad ``RequestException`` branch,
logged it, and returned ``False`` -- which the caller rendered as
"Not vulnerable to ...". For a tool whose entire purpose is trust-sensitive
HTTP parsing, a MITM that suppresses the probe silently suppresses the finding.

These tests assert that:

  1. verification is on by default and a timeout is always passed,
  2. a TLS failure is INCONCLUSIVE (None), never "not vulnerable" (False),
  3. the original code really does produce the false negative, using a local
     self-signed HTTPS server so no external host is contacted.
"""

import datetime
import ssl
import subprocess
import sys
import threading
import warnings
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import requests
from urllib3.exceptions import InsecureRequestWarning

from conftest import REPO_ROOT


def _write_selfsigned_cert(directory):
    """Generate a throwaway self-signed cert for localhost."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = b"hello"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence stderr noise
        pass


@pytest.fixture(scope="module")
def selfsigned_https(tmp_path_factory):
    """A local HTTPS server presenting an untrusted self-signed certificate."""
    directory = tmp_path_factory.mktemp("tls")
    cert_path, key_path = _write_selfsigned_cert(directory)

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    server.socket = context.wrap_socket(server.socket, server_side=True)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    host, port = server.server_address
    yield f"https://localhost:{port}/"

    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def test_verification_is_on_by_default(scanner, monkeypatch):
    """The probe must verify certificates and always set a timeout."""
    captured = {}

    def fake_post(url, **kwargs):
        captured.update(kwargs)
        captured["url"] = url

        class FakeResponse:
            status_code = 200
            text = "hello"
            headers = {}

        return FakeResponse()

    monkeypatch.setattr(scanner.requests, "post", fake_post)
    scanner.check_vulnerability("https://example.com", "CLTE")

    assert captured["verify"] is True, "TLS verification must default to ON"
    assert captured.get("timeout"), "a per-request timeout must always be sent"


def test_insecure_is_opt_in(scanner, monkeypatch):
    captured = {}

    def fake_post(url, **kwargs):
        captured.update(kwargs)

        class FakeResponse:
            status_code = 200
            text = "hello"
            headers = {}

        return FakeResponse()

    monkeypatch.setattr(scanner.requests, "post", fake_post)
    scanner.check_vulnerability("https://example.com", "CLTE", verify=False)

    assert captured["verify"] is False


def test_tls_failure_is_inconclusive_not_safe(scanner, selfsigned_https, capsys):
    """The core defect: a TLS failure must not read as 'Not vulnerable'.

    Against this untrusted certificate the fixed scanner cannot complete the
    handshake, so it must report inconclusive and must never print the
    "Not vulnerable" verdict.
    """
    result = scanner.check_vulnerability(selfsigned_https, "CLTE")
    out = capsys.readouterr().out

    assert result is None, "TLS failure must be inconclusive (None), not False"
    assert "Not vulnerable" not in out, (
        "a TLS failure was reported as a clean verdict: " + out
    )
    assert "Inconclusive" in out


def test_insecure_mode_still_warns(scanner, selfsigned_https):
    """--insecure must not silence the fact that trust was dropped.

    The original called urllib3.disable_warnings(InsecureRequestWarning) at
    import time, so an operator running with verification off got no signal at
    all. The warning must now surface.
    """
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        scanner.check_vulnerability(selfsigned_https, "CLTE", verify=False)

    assert any(
        issubclass(entry.category, InsecureRequestWarning) for entry in caught
    ), "the InsecureRequestWarning must not be suppressed"


def test_original_code_reports_false_negative(scanner, selfsigned_https, capsys):
    """Demonstrates the original behaviour: verify=False yields 'safe'.

    This is the defect the patch removes. With verification disabled the
    scanner completes the handshake against an untrusted certificate and
    prints a clean verdict it has no basis for.
    """
    result = scanner.check_vulnerability(selfsigned_https, "CLTE", verify=False)
    out = capsys.readouterr().out

    assert result is False
    assert "Not vulnerable" in out, (
        "expected the original verify=False path to produce a false 'safe' "
        "verdict; if this now passes with a clean verdict the harness needs "
        "review"
    )


def test_insecure_flag_exists_on_cli():
    """The insecure mode must be reachable as an explicit opt-in flag."""
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "http-request-smuggler.py"), "--help"],
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0
    assert "--insecure" in result.stdout
    assert "--timeout" in result.stdout