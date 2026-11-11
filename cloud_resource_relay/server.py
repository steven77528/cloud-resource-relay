"""Authenticated HTTP/HTTPS endpoint with bounded, verified HTTPS upstream access."""

from collections import deque
from copy import deepcopy
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import math
from pathlib import Path
import re
import socket
import ssl
import threading
import time
from urllib.parse import parse_qs, urlsplit

from .config import ConfigError, alias, client_tokens, load_config
from .catalog import validate_upstream
from .common import ProviderError, request_json
from .signers import forward, validate_credentials


LOG = logging.getLogger(__name__)
COLLECT_PATH = "/v1/monitor/collect"
IDENTITY_FIELDS = {"version", "request_id", "provider", "account", "operation", "kind"}
REQUEST_FIELDS = IDENTITY_FIELDS | {"request"}
MAX_BODY = 8192
MAX_RESPONSE = 8 * 1024 * 1024


class RequestError(ValueError):
    def __init__(self, status, reason):
        self.status, self.reason = status, reason
        super().__init__(reason)


def validate_request(payload):
    try:
        if not isinstance(payload, dict) or set(payload) != REQUEST_FIELDS:
            raise ValueError
        if type(payload["version"]) is not int or payload["version"] != 2:
            raise ValueError
        if not isinstance(payload["request_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", payload["request_id"]):
            raise ValueError
        for field in ("provider", "account", "operation", "kind"):
            alias(payload[field])
        request = payload["request"]
        if (not isinstance(request, dict) or set(request) != {"method", "url", "body"}
                or request["method"] not in {"GET", "POST"} or not isinstance(request["url"], str)
                or (request["body"] is not None and not isinstance(request["body"], dict))):
            raise ValueError
        return payload
    except Exception:
        raise RequestError(400, "invalid_request") from None


def _secret_values(account):
    values = set()
    for field in ("access_key_id", "access_key_secret"):
        if isinstance(account.get(field), str) and len(account[field]) >= 8:
            values.add(account[field])
    for field in ("access_key_secret_file", "private_key_file", "token_file"):
        path = account.get(field)
        if not path:
            continue
        try:
            with Path(path).open("rb") as stream:
                raw = stream.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError
            content = raw.decode("utf-8").strip()
            if not content:
                raise ValueError
            values.add(content)
            if field == "private_key_file":
                values.add("".join(line for line in content.splitlines() if not line.startswith("-----")))
            if field == "token_file" and content.startswith("{"):
                cache = json.loads(content)
                if isinstance(cache, dict):
                    for key in ("access_token", "authorizer_access_token"):
                        if isinstance(cache.get(key), str) and len(cache[key]) >= 8:
                            values.add(cache[key])
        except Exception:
            raise ProviderError("credential_file_unavailable") from None
    return {value for value in values if len(value) >= 8}


class UpstreamBudget:
    def __init__(self, transport, operation, secrets):
        self.transport = transport
        self.deadline = time.monotonic() + operation["timeout_seconds"]
        self.remaining_calls = 1
        self.secrets = secrets

    def __call__(self, method, url, *, headers=None, body=None, timeout=20):
        remaining = self.deadline - time.monotonic()
        if self.remaining_calls <= 0 or remaining <= 0:
            raise ProviderError("upstream_budget_exceeded")
        self.remaining_calls -= 1
        # Capture the exact token used by the adapter, including a concurrent token rotation.
        query = parse_qs(urlsplit(url).query)
        for key in ("access_token", "authorizer_access_token"):
            self.secrets.update(value for value in query.get(key, []) if len(value) >= 8)
        result = self.transport(method, url, headers=headers, body=body, timeout=min(timeout, remaining))
        if time.monotonic() > self.deadline:
            raise ProviderError("upstream_budget_exceeded")
        return result


def _contains_secret(value, secrets, depth=0):
    if depth > 64:
        return True
    if isinstance(value, str):
        if any(secret in value for secret in secrets):
            return True
        # Signed vendor payloads can contain JSON strings with escaped credentials.
        if value.lstrip().startswith(("{", "[", '"')):
            try:
                decoded = json.loads(value)
            except (ValueError, RecursionError):
                return False
            return _contains_secret(decoded, secrets, depth + 1)
        return False
    if isinstance(value, list):
        return any(_contains_secret(item, secrets, depth + 1) for item in value)
    if isinstance(value, dict):
        forbidden = {"accesstoken", "authorizeraccesstoken", "accesskey", "accesskeyid", "accesskeysecret",
                     "appsecret", "privatekey", "authorization", "clientsecret"}
        return any(not isinstance(key, str) or re.sub(r"[^a-z]", "", key.lower()) in forbidden
                   or _contains_secret(key, secrets, depth + 1) or _contains_secret(item, secrets, depth + 1)
                   for key, item in value.items())
    return False


class RelayService:
    def __init__(self, config_path, *, upstream_transport=None):
        self.config_path = Path(config_path)
        self.upstream_transport = upstream_transport or request_json
        self.lock = threading.Lock()
        self.client_calls = {}
        self.operation_calls = {}
        self.running = set()

    def authenticate(self, authorization):
        if (not isinstance(authorization, str) or not authorization.startswith("Bearer ")
                or not 24 <= len(authorization[7:]) <= 4096
                or any(not 33 <= ord(c) <= 126 for c in authorization[7:])):
            raise RequestError(401, "unauthorized")
        config = load_config(self.config_path)
        tokens = client_tokens(config)
        digest = hashlib.sha256(authorization[7:].encode("ascii")).digest()
        selected = None
        for client, expected, _ in tokens:
            if hmac.compare_digest(digest, expected):
                selected = client
        if selected is None:
            raise RequestError(401, "unauthorized")
        return config, selected, {token for _, _, token in tokens}

    def _admit(self, config, client, payload):
        now = time.monotonic()
        with self.lock:
            # Bound state to administrator-configured IDs even after configuration reloads.
            clients = {item["id"] for item in config["clients"]}
            operations = {item["id"] for item in config["operations"]}
            self.client_calls = {key: value for key, value in self.client_calls.items() if key in clients}
            self.operation_calls = {key: value for key, value in self.operation_calls.items() if key in operations}
            calls = self.client_calls.setdefault(client["id"], deque())
            while calls and now - calls[0] >= 60:
                calls.popleft()
            if len(calls) >= client["requests_per_minute"]:
                raise ProviderError("rate_limited")
            calls.append(now)
            operation = next((item for item in config["operations"] if item["id"] == payload["operation"]), None)
            if (operation is None or not operation.get("enabled", False)
                    or operation["id"] not in client["operations"]):
                raise ProviderError("permission_denied")
            account = next(item for item in config["accounts"] if item["id"] == operation["account"])
            if (not account.get("enabled", False) or payload["account"] != operation["monitor_account"]
                    or payload["provider"] != account["provider"] or payload["kind"] != operation["kind"]):
                raise ProviderError("permission_denied")
            previous = self.operation_calls.get(operation["id"])
            if operation["id"] in self.running or (previous is not None
                    and now - previous < operation["minimum_interval_seconds"]):
                raise ProviderError("rate_limited")
            self.operation_calls[operation["id"]] = now
            self.running.add(operation["id"])
            return account, operation

    def forward(self, payload, config, client, secrets):
        operation = None
        identity = {key: payload[key] for key in IDENTITY_FIELDS}
        try:
            account, operation = self._admit(config, client, payload)
            validate_upstream(account, operation, payload["request"])
            validate_credentials(account, operation["kind"])
            secrets = secrets | _secret_values(account)
            budget = UpstreamBudget(self.upstream_transport, operation, secrets)
            response, verified = forward(deepcopy(account), operation, deepcopy(payload["request"]),
                                         transport=budget)
            if time.monotonic() > budget.deadline:
                raise ProviderError("upstream_budget_exceeded")
            if not isinstance(response, dict) or _contains_secret(response, secrets):
                raise ProviderError("invalid_response")
            result = {**identity, "status": "ok", "signature_verified": verified, "response": response}
            if len(json.dumps(result, ensure_ascii=False, allow_nan=False).encode("utf-8")) > MAX_RESPONSE:
                raise ProviderError("response_too_large")
            return result
        except Exception as exc:
            reason = "upstream_error"
            if isinstance(exc, ProviderError):
                if exc.reason in {"signature_invalid", "permission_denied", "no_data", "source_data_stale",
                                  "rate_limited"}:
                    reason = exc.reason
                elif "stale" in exc.reason:
                    reason = "source_data_stale"
            return {**identity, "status": "error", "reason": reason}
        finally:
            if operation is not None:
                with self.lock:
                    self.running.discard(operation["id"])


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError
    return result


def _constant(_):
    raise ValueError


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def __init__(self, *args, read_deadline, **kwargs):
        self.read_deadline = read_deadline
        super().__init__(*args, **kwargs)

    def log_message(self, *_):
        pass

    def _send(self, status, payload):
        raw = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.send_response_only(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        self.wfile.write(raw)

    def send_error(self, code, message=None, explain=None):
        self._send(code, {"status": "error", "reason": "invalid_request"})

    def do_GET(self):
        self.read_deadline.cancel()
        if self.path != "/healthz":
            self._send(404, {"status": "error", "reason": "not_found"})
            return
        try:
            client_tokens(load_config(self.server.service.config_path))
        except ConfigError:
            self._send(503, {"status": "error", "reason": "configuration_unavailable"})
            return
        self._send(200, {"status": "ok"})

    def _read(self):
        if self.headers.get_all("Transfer-Encoding"):
            raise RequestError(400, "invalid_request")
        lengths = self.headers.get_all("Content-Length", [])
        types = self.headers.get_all("Content-Type", [])
        if len(types) != 1 or types[0].split(";", 1)[0].strip().lower() != "application/json":
            raise RequestError(415, "invalid_request")
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,5}", lengths[0]):
            raise RequestError(400, "invalid_request")
        size = int(lengths[0])
        if not 0 < size <= MAX_BODY:
            raise RequestError(413, "invalid_request")
        try:
            data = self.rfile.read(size)
            if len(data) != size:
                raise ValueError
            return validate_request(json.loads(data.decode("utf-8"), object_pairs_hook=_pairs,
                                               parse_float=_float, parse_constant=_constant))
        except (ValueError, OSError, UnicodeError, RecursionError):
            raise RequestError(400, "invalid_request") from None

    def do_POST(self):
        payload = None
        try:
            if self.path != COLLECT_PATH:
                raise RequestError(404, "not_found")
            headers = self.headers.get_all("Authorization", [])
            if len(headers) != 1:
                raise RequestError(401, "unauthorized")
            config, client, secrets = self.server.service.authenticate(headers[0])
            payload = self._read()
            self.read_deadline.cancel()
            result = self.server.service.forward(payload, config, client, secrets)
            self._send(200, result)
            LOG.info("collection request=%s client=%s status=%s reason=%s", payload["request_id"],
                     client["id"], result["status"], result.get("reason", "ok"))
        except RequestError as exc:
            self._send(exc.status, {"status": "error", "reason": exc.reason})
        except ConfigError:
            self._send(503, {"status": "error", "reason": "configuration_unavailable"})
        except Exception:
            self._send(500, {"status": "error", "reason": "internal_error"})


class RelayHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, service, context, api):
        self.service, self.context = service, context
        self.slots = threading.BoundedSemaphore(api["max_workers"])
        self.request_timeout = api["request_timeout_seconds"]
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        active_socket = [request]

        def expire():
            try:
                active_socket[0].shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        deadline = threading.Timer(self.request_timeout, expire)
        deadline.daemon = True
        deadline.start()
        try:
            request.settimeout(self.request_timeout)
            if self.context is not None:
                request = self.context.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
                active_socket[0] = request
                request.do_handshake()
            self.RequestHandlerClass(request, client_address, self, read_deadline=deadline)
        except Exception:
            LOG.warning("connection_closed")
        finally:
            deadline.cancel()
            self.shutdown_request(request)
            self.slots.release()

    def handle_error(self, *_):
        LOG.warning("connection_failed")


def create_server(config_path, *, upstream_transport=None, host=None, port=None):
    config = load_config(config_path, live=True)
    api = config["api"]
    context = None
    if api["scheme"] == "https":
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(api["cert_file"], api["key_file"])
        except Exception:
            raise ConfigError() from None
    service = RelayService(config_path, upstream_transport=upstream_transport)
    return RelayHTTPServer((host if host is not None else api["host"], port if port is not None else api["port"]),
                           service, context, api)
