from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import socket
import ssl
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import pytest
import yaml

from cloud_resource_relay.__main__ import health
from cloud_resource_relay.common import ProviderError, request_json
from cloud_resource_relay.config import load_config
from cloud_resource_relay.server import create_server


@pytest.fixture
def tls(tmp_path, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False).sign(key, hashes.SHA256()))
    certificate, private = tmp_path / "server.crt", tmp_path / "server.key"
    certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
    monkeypatch.setenv("SSL_CERT_FILE", str(certificate))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, private)
    return certificate, private, context


@pytest.mark.parametrize("phase", ["headers", "body"])
def test_upstream_deadline_stops_continuous_slow_data(tls, phase):
    class SlowHandler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            try:
                if phase == "headers":
                    self.wfile.write(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                else:
                    self.send_response(200)
                    self.send_header("Content-Length", "100000")
                    self.end_headers()
                    self.wfile.write(b'{"slow":"')
                for _ in range(1000):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.01)
            except OSError:
                pass

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), SlowHandler)
    upstream.socket = tls[2].wrap_socket(upstream.socket, server_side=True)
    worker = threading.Thread(target=upstream.serve_forever, daemon=True)
    worker.start()
    started = time.monotonic()
    try:
        with pytest.raises(ProviderError, match="transport_error"):
            request_json("GET", f"https://127.0.0.1:{upstream.server_port}/slow", timeout=0.3)
        assert time.monotonic() - started < 3
    finally:
        upstream.shutdown()
        upstream.server_close()
        worker.join(3)


def test_verified_health_and_absolute_inbound_header_deadline(tls, tmp_path):
    path = tmp_path / "config.yaml"
    config = {"version": 1, "api": {"host": "127.0.0.1", "port": 8443, "cert_file": str(tls[0]),
              "key_file": str(tls[1]), "health_server_name": "localhost", "max_workers": 1,
              "request_timeout_seconds": 1}, "clients": [], "accounts": [], "operations": []}
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    relay = create_server(path, port=0)
    config["api"]["port"] = relay.server_port
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    worker = threading.Thread(target=relay.serve_forever, daemon=True)
    worker.start()
    try:
        health(load_config(path))
        client_context = ssl.create_default_context(cafile=str(tls[0]))
        with socket.create_connection(relay.server_address, timeout=3) as connection:
            with client_context.wrap_socket(connection, server_hostname="localhost") as client:
                client.sendall(b"POST /v1/monitor/collect HTTP/1.1\r\nX-Slow: ")
                closed = False
                started = time.monotonic()
                for _ in range(30):
                    try:
                        client.sendall(b"x")
                    except OSError:
                        closed = True
                        break
                    time.sleep(0.1)
                assert closed and time.monotonic() - started < 3
        health(load_config(path))
    finally:
        relay.shutdown()
        relay.server_close()
        worker.join(3)
