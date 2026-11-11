"""Authenticate one approved request; return the vendor JSON without metric processing."""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from urllib.parse import urlencode, urlsplit
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from requests_toolbelt.multipart.encoder import MultipartEncoder

from .catalog import OPEN_ENDPOINTS, SUPPORTED_KINDS, validate_upstream
from .common import ProviderError, read_secret_file, require_text, timestamp


def _header(value):
    value = require_text(value, "credential")
    if any(not 33 <= ord(char) <= 126 for char in value):
        raise ProviderError("upstream_error")
    return value


def _key(path, *, private=True):
    content = read_secret_file(path, "private_key_file" if private else "huifu_public_key_file")
    try:
        if content.startswith("-----BEGIN"):
            data = content.encode("ascii")
            value = (serialization.load_pem_private_key(data, password=None) if private
                     else serialization.load_pem_public_key(data))
        else:
            data = base64.b64decode("".join(content.split()), validate=True)
            value = (serialization.load_der_private_key(data, password=None) if private
                     else serialization.load_der_public_key(data))
        if not isinstance(value, rsa.RSAPrivateKey if private else rsa.RSAPublicKey) or value.key_size < 2048:
            raise ValueError
        return value
    except Exception:
        raise ProviderError("upstream_error") from None


def _wechat_token(account, kind):
    token_type = account.get("token_type", "access_token")
    if token_type not in {"access_token", "authorizer_access_token"}:
        raise ProviderError("upstream_error")
    permissions = account.get("permission_sets", [])
    if (type(account.get("third_party_authorized", False)) is not bool or not isinstance(permissions, list)
            or any(type(item) is not int or item <= 0 for item in permissions)):
        raise ProviderError("upstream_error")
    if kind == "annual_review" and token_type != "authorizer_access_token":
        raise ProviderError("permission_denied")
    if token_type == "authorizer_access_token":
        required = 30 if kind == "annual_review" else 18 if kind in {"charge_packages", "js_errors", "performance"} else None
        if account.get("third_party_authorized") is not True or (required is not None and required not in permissions):
            raise ProviderError("permission_denied")
    try:
        cache = json.loads(read_secret_file(account["token_file"], "token_file"))
        if not isinstance(cache, dict) or cache.get("appid") != require_text(account.get("appid"), "appid"):
            raise ValueError
        expiry = cache.get("expires_at")
        if type(expiry) not in {int, float} or timestamp(expiry, "expires_at") <= datetime.now(timezone.utc) + timedelta(seconds=30):
            raise ValueError
        return _header(cache.get(token_type))
    except Exception:
        raise ProviderError("upstream_error") from None


def validate_credentials(account, kind):
    """Read only local credential files; do not request, refresh or mint vendor tokens."""
    try:
        provider = account["provider"]
        if kind not in SUPPORTED_KINDS[provider]:
            raise ValueError
        timeout = account.get("timeout_seconds", account.get("request_timeout_seconds", 20))
        if type(timeout) not in {int, float} or not 0 < timeout <= 120:
            raise ValueError
        if provider == "qiniu":
            _header(account.get("access_key_id"))
            _header(read_secret_file(account["access_key_secret_file"], "access_key_secret_file")
                    if account.get("access_key_secret_file") else account.get("access_key_secret"))
        elif provider == "wechat":
            _wechat_token(account, kind)
        elif provider == "huifu":
            if account.get("credential_mode", "api") != "api":
                raise ValueError
            for field in ("sys_id", "product_id", "huifu_id"):
                _header(account.get(field))
            _key(account["private_key_file"])
            _key(account["huifu_public_key_file"], private=False)
        else:
            if (account.get("api_mode") != "openapi"
                    or account.get("endpoint", "https://oapi.asign.cn") not in OPEN_ENDPOINTS):
                raise ValueError
            _header(account.get("app_id"))
            _key(account["private_key_file"])
    except Exception:
        raise ProviderError("upstream_error") from None


def canonical_data(data):
    if not isinstance(data, dict):
        raise ProviderError("signature_invalid")
    return json.dumps({key: data[key] for key in sorted(data) if data[key] is not None},
                      ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _verify_huifu(response, data, public):
    try:
        raw = response.get("data")
        if isinstance(raw, str):
            signed, result = raw.encode("utf-8"), json.loads(raw)
        else:
            signed, result = canonical_data(raw), raw
        public.verify(base64.b64decode(response.get("sign", ""), validate=True), signed,
                      padding.PKCS1v15(), hashes.SHA256())
        if not isinstance(result, dict):
            raise ValueError
        for field in ("req_date", "req_seq_id", "org_req_date", "org_req_seq_id"):
            if field in data and result.get(field) != data[field]:
                raise ValueError
        if "huifu_id" in result and result["huifu_id"] != data["huifu_id"]:
            raise ValueError
    except (ValueError, TypeError, InvalidSignature, KeyError):
        raise ProviderError("signature_invalid") from None


def forward(account, operation, request, *, transport):
    """Sign and send exactly one approved upstream HTTP request."""
    try:
        validate_upstream(account, operation, request)
        validate_credentials(account, operation["kind"])
        provider = account["provider"]
        method, url, data = request["method"], request["url"], request["body"]
        now = datetime.now(timezone.utc)
        body = json.dumps(data, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8") if data is not None else None
        headers = {"Content-Type": "application/json"}
        public = None
        if provider == "qiniu":
            from qiniu import Auth
            from qiniu.auth import QiniuMacAuth

            key = account["access_key_id"]
            secret = (read_secret_file(account["access_key_secret_file"], "access_key_secret_file")
                      if account.get("access_key_secret_file") else account["access_key_secret"])
            headers["Content-Type"] = "application/json" if body is not None else "application/x-www-form-urlencoded"
            if urlsplit(url).hostname == "fusion.qiniuapi.com":
                headers["Authorization"] = "QBox " + Auth(key, secret).token_of_request(
                    url, body.decode("utf-8") if body else None, headers["Content-Type"])
            else:
                auth = QiniuMacAuth(key, secret)
                headers["X-Qiniu-Date"] = now.strftime("%Y%m%dT%H%M%SZ")
                headers["Authorization"] = "Qiniu " + auth.token_of_request(
                    method, None, url, auth.qiniu_headers(headers), headers["Content-Type"], body)
        elif provider == "wechat":
            url += ("&" if "?" in url else "?") + urlencode({"access_token": _wechat_token(account, operation["kind"])})
        elif provider == "asign":
            payload = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
            stamp = str(round(now.timestamp() * 1000) + 60000)
            digest = hashlib.md5(payload.encode("utf-8"), usedforsecurity=False).hexdigest()
            sign = _key(account["private_key_file"]).sign(
                (payload + digest + account["app_id"] + stamp).encode("utf-8"), padding.PKCS1v15(), hashes.SHA1())
            multipart = MultipartEncoder(fields={"appId": account["app_id"], "bizData": payload, "timestamp": stamp,
                "Content-Type": "application/octet-stream", "type": "application/octet-stream"},
                boundary="-----------------------------" + uuid4().hex)
            headers = {"Content-Type": multipart.content_type, "Accept": "*/*", "sign": base64.b64encode(sign).decode("ascii")}
            body = multipart.to_string()
        else:
            data = {**data, "huifu_id": account["huifu_id"]}
            sign = _key(account["private_key_file"]).sign(canonical_data(data), padding.PKCS1v15(), hashes.SHA256())
            public = _key(account["huifu_public_key_file"], private=False)
            body = json.dumps({"sys_id": account["sys_id"], "product_id": account["product_id"], "data": data,
                               "sign": base64.b64encode(sign).decode("ascii")}, ensure_ascii=False, allow_nan=False).encode("utf-8")
        result = transport(method, url, headers=headers, body=body,
                           timeout=account.get("timeout_seconds", account.get("request_timeout_seconds", 20)))
        if not isinstance(result, dict):
            raise ProviderError("upstream_error")
        if provider == "huifu":
            _verify_huifu(result, data, public)
        return result, True if provider == "huifu" else None
    except ProviderError as exc:
        raise ProviderError(exc.reason if exc.reason in {"permission_denied", "signature_invalid"} else "upstream_error") from None
    except Exception:
        raise ProviderError("upstream_error") from None
