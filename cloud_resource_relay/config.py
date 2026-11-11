"""Local administrator configuration. Errors never include configured values."""

from copy import deepcopy
import hashlib
import math
import os
from pathlib import Path
import re

import yaml

from .catalog import OPEN_ENDPOINTS, SUPPORTED_KINDS, validate_scope
from .signers import validate_credentials


ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
MAX_CONFIG_BYTES = 1024 * 1024
ACCOUNT_FIELDS = {
    "qiniu": {"access_key_id", "access_key_secret", "access_key_secret_file", "request_timeout_seconds"},
    "huifu": {"sys_id", "product_id", "huifu_id", "private_key_file", "huifu_public_key_file", "credential_mode"},
    "asign": {"api_mode", "app_id", "endpoint", "timeout_seconds", "private_key_file"},
    "wechat": {"appid", "token_file", "token_type", "third_party_authorized", "permission_sets",
               "request_timeout_seconds"},
}


class ConfigError(ValueError):
    def __init__(self):
        super().__init__("relay configuration is unavailable or invalid")


def alias(value):
    if not isinstance(value, str) or not ALIAS.fullmatch(value):
        raise ConfigError()
    return value


def _fields(value, allowed, required=()):
    if not isinstance(value, dict) or set(value) - allowed or not set(required) <= set(value):
        raise ConfigError()


def _text(value):
    if not isinstance(value, str) or not value.strip() or any(ord(c) < 32 for c in value):
        raise ConfigError()


def _number(value, minimum, maximum, *, integer=False):
    if (type(value) not in ({int} if integer else {int, float})
            or not minimum <= value <= maximum or not math.isfinite(value)):
        raise ConfigError()


def _enabled(item):
    if type(item.get("enabled", False)) is not bool:
        raise ConfigError()


def _items(value, maximum):
    if not isinstance(value, list) or len(value) > maximum:
        raise ConfigError()
    result = {}
    for item in value:
        if not isinstance(item, dict) or alias(item.get("id")) in result:
            raise ConfigError()
        _enabled(item)
        result[item["id"]] = item
    return result


class _Loader(yaml.SafeLoader):
    pass


def _mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str) or key in result:
            raise ConfigError()
        result[key] = loader.construct_object(value_node)
    return result


_Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _expand(value, budget, depth=0):
    budget[0] -= 1
    if depth > 32 or budget[0] < 0:
        raise ConfigError()
    if isinstance(value, str):
        return ENV.sub(lambda match: os.environ.get(match[1], ""), value)
    if isinstance(value, list):
        return [_expand(item, budget, depth + 1) for item in value]
    if isinstance(value, dict):
        return {key: _expand(item, budget, depth + 1) for key, item in value.items()}
    return value


def validate_config(config, *, live=False):
    try:
        cfg = deepcopy(config)
        _fields(cfg, {"version", "api", "clients", "accounts", "operations"}, {"version", "api"})
        if type(cfg["version"]) is not int or cfg["version"] != 1:
            raise ConfigError()
        api = cfg["api"]
        _fields(api, {"scheme", "host", "port", "cert_file", "key_file", "max_workers", "request_timeout_seconds",
                      "health_server_name", "health_ca_file"})
        # Existing certificate-based configurations continue to require TLS.
        scheme = api.setdefault("scheme", "https" if {"cert_file", "key_file"} & api.keys() else "http")
        if scheme not in ("http", "https"):
            raise ConfigError()
        for field, default in (("host", "127.0.0.1"), ("port", 8443), ("max_workers", 8),
                               ("request_timeout_seconds", 15)):
            api.setdefault(field, default)
        _text(api["host"])
        if scheme == "https":
            for field in ("cert_file", "key_file"):
                _text(api[field])
            api.setdefault("health_server_name", "localhost")
        for field in ("cert_file", "key_file", "health_server_name", "health_ca_file"):
            if field in api:
                _text(api[field])
        _number(api["port"], 1, 65535, integer=True)
        _number(api["max_workers"], 1, 64, integer=True)
        _number(api["request_timeout_seconds"], 1, 60)
        accounts = _items(cfg.setdefault("accounts", []), 64)
        for account in accounts.values():
            provider = account.get("provider")
            if not isinstance(provider, str) or provider not in ACCOUNT_FIELDS:
                raise ConfigError()
            _fields(account, ACCOUNT_FIELDS[provider] | {"id", "provider", "enabled", "name"})
            if provider == "asign" and (account.get("api_mode") != "openapi"
                    or account.get("endpoint", "https://oapi.asign.cn") not in OPEN_ENDPOINTS):
                raise ConfigError()
        operations = _items(cfg.setdefault("operations", []), 256)
        for operation in operations.values():
            _fields(operation, {"id", "enabled", "account", "monitor_account", "kind", "scope",
                                "minimum_interval_seconds", "timeout_seconds"},
                    {"account", "monitor_account", "kind"})
            account_id = alias(operation["account"])
            alias(operation["monitor_account"])
            kind = alias(operation["kind"])
            if account_id not in accounts or kind not in SUPPORTED_KINDS[accounts[account_id]["provider"]]:
                raise ConfigError()
            if not isinstance(operation.setdefault("scope", {}), dict):
                raise ConfigError()
            validate_scope(accounts[account_id]["provider"], kind, operation["scope"])
            for field, default, minimum, maximum, integer in (
                ("minimum_interval_seconds", 0, 0, 86400, False),
                ("timeout_seconds", 20, 1, 120, False),
            ):
                _number(operation.setdefault(field, default), minimum, maximum, integer=integer)
            if live and operation.get("enabled", False):
                account = accounts[account_id]
                if not account.get("enabled", False):
                    raise ConfigError()
                validate_credentials(account, kind)
        clients = _items(cfg.setdefault("clients", []), 64)
        for client in clients.values():
            _fields(client, {"id", "enabled", "token_file", "operations", "requests_per_minute"},
                    {"token_file", "operations"})
            _text(client["token_file"])
            grants = client["operations"]
            if (not isinstance(grants, list) or not grants or not all(isinstance(i, str) for i in grants)
                    or len(grants) != len(set(grants)) or not set(grants) <= set(operations)):
                raise ConfigError()
            _number(client.setdefault("requests_per_minute", 60), 1, 600, integer=True)
        if live:
            client_tokens(cfg)
        return cfg
    except Exception:
        raise ConfigError() from None


def load_config(path, *, live=False):
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(MAX_CONFIG_BYTES + 1)
        if len(raw) > MAX_CONFIG_BYTES:
            raise ConfigError()
        config = _expand(yaml.load(raw.decode("utf-8"), Loader=_Loader), [50000])
        return validate_config(config, live=live)
    except Exception:
        raise ConfigError() from None


def client_tokens(config):
    """Read a complete rotation snapshot; duplicate tokens fail closed."""
    result, seen = [], set()
    try:
        for client in config["clients"]:
            if not client.get("enabled", False):
                continue
            with Path(client["token_file"]).open("rb") as stream:
                raw = stream.read(4099)
            token = raw.decode("ascii").strip()
            if len(raw) > 4098 or not 24 <= len(token) <= 4096 or any(not 33 <= ord(c) <= 126 for c in token):
                raise ConfigError()
            digest = hashlib.sha256(token.encode("ascii")).digest()
            if digest in seen:
                raise ConfigError()
            seen.add(digest)
            result.append((client, digest, token))
        return result
    except Exception:
        raise ConfigError() from None
