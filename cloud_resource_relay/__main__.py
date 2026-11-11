import argparse
from contextlib import ExitStack
import json
import http.client
import logging
import os
from pathlib import Path
import secrets
import signal
import socket
import ssl
import sys
import threading

from .config import ConfigError, load_config
from .server import create_server


def issue_token(path):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as stream:
        stream.write(secrets.token_urlsafe(48) + "\n")


def health(config):
    api = config["api"]
    address = api["host"] if api["host"] not in {"0.0.0.0", "::"} else "127.0.0.1"
    with ExitStack() as stack:
        connection = stack.enter_context(socket.create_connection((address, api["port"]), timeout=5))
        if api["scheme"] == "https":
            context = ssl.create_default_context()
            context.load_verify_locations(api.get("health_ca_file", api["cert_file"]))
            connection = stack.enter_context(context.wrap_socket(connection, server_hostname=api["health_server_name"]))
        connection.sendall(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        response = http.client.HTTPResponse(connection)
        response.begin()
        if response.status != 200 or json.loads(response.read(1025)) != {"status": "ok"}:
            raise ValueError("relay is not ready")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Isolated business resource collection relay")
    parser.add_argument("--config", default="config/config.yaml")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check")
    check.add_argument("--live", action="store_true")
    commands.add_parser("serve")
    commands.add_parser("health")
    token = commands.add_parser("issue-token")
    token.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "issue-token":
            issue_token(args.output)
            print(json.dumps({"created": True, "secret_printed": False}))
            return 0
        if args.command == "check":
            config = load_config(args.config, live=args.live)
            print(json.dumps({"valid": True, "clients": len(config["clients"]),
                              "accounts": len(config["accounts"]), "operations": len(config["operations"])}))
            return 0
        if args.command == "health":
            health(load_config(args.config))
            print(json.dumps({"healthy": True}))
            return 0
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
        server = create_server(args.config)

        def stop(*_):
            threading.Thread(target=server.shutdown, daemon=True).start()

        for name in ("SIGINT", "SIGTERM"):
            if hasattr(signal, name):
                signal.signal(getattr(signal, name), stop)
        try:
            logging.info("relay_started scheme=%s", "https" if server.context is not None else "http")
            server.serve_forever(poll_interval=0.25)
        finally:
            server.server_close()
        return 0
    except ConfigError:
        print("relay configuration is unavailable or invalid", file=sys.stderr)
    except FileExistsError:
        print("output already exists; token was not overwritten", file=sys.stderr)
    except Exception:
        print("relay command failed; check local configuration and file permissions", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
