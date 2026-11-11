"""Credential loading, token expiry validation and verified HTTPS transport."""

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import json
import http.client
import math
from pathlib import Path
import re
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit


class ProviderError(ValueError):
    def __init__(self, reason, field=""):
        # Callers pass local reason codes and schema paths, never provider messages or URLs.
        self.reason = reason if isinstance(reason, str) and re.fullmatch(r"[a-z_]{1,64}", reason) else "collection_failed"
        self.field = field if isinstance(field, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.\[\]]{0,95}", field) else ""
        super().__init__(self.reason + (f" field={self.field}" if self.field else ""))


def require_text(value, field):
    if not isinstance(value, str) or not value.strip() or value.startswith("CHANGE_ME"):
        raise ProviderError("missing_configuration", field)
    return value


def decimal_number(value, field):
    if isinstance(value, bool) or value is None or not isinstance(value, (str, int, float, Decimal)):
        raise ProviderError("invalid_number", field)
    try:
        result = Decimal(str(value))
    except (ValueError, InvalidOperation):
        raise ProviderError("invalid_number", field) from None
    if not result.is_finite():
        raise ProviderError("invalid_number", field)
    return result


def number(value, field):
    result = float(decimal_number(value, field))
    if not math.isfinite(result):
        raise ProviderError("invalid_number", field)
    return result


def timestamp(value, field, unit="seconds"):
    try:
        if isinstance(value, datetime):
            result = value
        elif isinstance(value, str) and not re.fullmatch(r"-?[0-9]+(?:\.[0-9]+)?", value):
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            divisor = {"seconds": 1, "milliseconds": 1000}[unit]
            result = datetime.fromtimestamp(number(value, field) / divisor, timezone.utc)
        if result.tzinfo is None:
            raise ValueError
        return result.astimezone(timezone.utc)
    except (ValueError, TypeError, KeyError, OverflowError, OSError):
        raise ProviderError("invalid_timestamp", field) from None


def read_secret_file(path, field):
    require_text(path, field)
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ProviderError("credential_file_unavailable", field)
        value = raw.decode("utf-8").strip()
    except (OSError, UnicodeError):
        raise ProviderError("credential_file_unavailable", field) from None
    return require_text(value, field)


def request_json(method, url, *, headers=None, body=None, timeout=20):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ProviderError("invalid_endpoint")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 120:
        raise ProviderError("invalid_configuration", "timeout_seconds")
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443,
                                             timeout=timeout, context=ssl.create_default_context())
    sockets = []
    deadline = time.monotonic() + timeout
    expired = threading.Event()

    def expire():
        expired.set()
        active = sockets[0] if sockets else connection.sock
        if active is not None:
            try:
                active.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    timer = threading.Timer(timeout, expire)
    timer.daemon = True
    timer.start()
    try:
        connection.connect()
        sockets.append(connection.sock)
        remaining = deadline - time.monotonic()
        if remaining <= 0 or expired.is_set():
            raise ProviderError("transport_error")
        connection.sock.settimeout(remaining)
        path = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        if not 200 <= response.status < 300:
            raise ProviderError("http_error")
        raw = bytearray()
        while True:
            chunk = response.read1(65536)
            if expired.is_set() or time.monotonic() > deadline:
                raise ProviderError("transport_error")
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > 8 * 1024 * 1024:
                raise ProviderError("response_too_large")
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ProviderError("invalid_response")
        return result
    except ProviderError:
        raise
    except (OSError, TimeoutError, http.client.HTTPException):
        raise ProviderError("transport_error") from None
    except (ValueError, UnicodeError):
        raise ProviderError("invalid_response") from None
    finally:
        timer.cancel()
        connection.close()
