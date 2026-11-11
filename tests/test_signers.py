import base64
from copy import deepcopy
import hashlib
import json
import time
from urllib.parse import parse_qs, urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import pytest
from requests_toolbelt.multipart.decoder import MultipartDecoder

from cloud_resource_relay.catalog import validate_upstream
from cloud_resource_relay.common import ProviderError
from cloud_resource_relay.signers import canonical_data, forward, validate_credentials


def request(url, method="GET", body=None):
    return {"method": method, "url": url, "body": body}


@pytest.fixture
def keys(tmp_path):
    merchant = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    vendor = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path, public_path = tmp_path / "merchant.pem", tmp_path / "vendor.pem"
    private_path.write_bytes(merchant.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))
    public_path.write_bytes(vendor.public_key().public_bytes(serialization.Encoding.PEM,
                                                           serialization.PublicFormat.SubjectPublicKeyInfo))
    return merchant, vendor, str(private_path), str(public_path)


@pytest.mark.parametrize("raw_string", [False, True])
@pytest.mark.parametrize("kind", ["balance", "settlements"])
def test_huifu_signs_one_request_verifies_and_preserves_response(keys, raw_string, kind):
    merchant, vendor, private, public = keys
    account = {"provider": "huifu", "sys_id": "test-system", "product_id": "test-product",
               "huifu_id": "test-merchant", "private_key_file": private, "huifu_public_key_file": public}
    data = ({"req_date": "20260915", "req_seq_id": "test-request-01", "acct_date": "20260915"}
            if kind == "balance" else {"org_req_date": "20260915", "org_req_seq_id": "test-order-01"})
    operation = {"kind": kind, "scope": {} if kind == "balance" else {"orders": [deepcopy(data)]}}
    path = "/v2/trade/acctpayment/balance/query" if kind == "balance" else "/v2/trade/settlement/query"
    captured = []

    def upstream(method, url, **kwargs):
        captured.append((method, url))
        envelope = json.loads(kwargs["body"])
        assert envelope["data"]["huifu_id"] == "test-merchant"
        merchant.public_key().verify(base64.b64decode(envelope["sign"]), canonical_data(envelope["data"]),
                                     padding.PKCS1v15(), hashes.SHA256())
        result = {**envelope["data"], "resp_code": "00000000", "untouched_vendor_field": "preserve-this"}
        payload = json.dumps(result, ensure_ascii=False) if raw_string else result
        signed = payload.encode() if raw_string else canonical_data(payload)
        return {"data": payload, "sign": base64.b64encode(vendor.sign(signed, padding.PKCS1v15(), hashes.SHA256())).decode(),
                "vendor_metadata": [1, 2, 3]}

    result, verified = forward(account, operation, request("https://api.huifu.com" + path, "POST", data), transport=upstream)
    assert verified is True
    assert len(captured) == 1
    assert result["vendor_metadata"] == [1, 2, 3]
    payload = json.loads(result["data"]) if raw_string else result["data"]
    assert payload["untouched_vendor_field"] == "preserve-this"
    assert "huifu_id" not in data


@pytest.mark.parametrize("failure", ["wrong_signature", "wrong_request", "wrong_merchant"])
def test_huifu_rejects_invalid_or_replayed_response(keys, failure):
    _, vendor, private, public = keys
    account = {"provider": "huifu", "sys_id": "test-system", "product_id": "test-product",
               "huifu_id": "test-merchant", "private_key_file": private, "huifu_public_key_file": public}
    data = {"req_date": "20260915", "req_seq_id": "test-request-01", "acct_date": "20260915"}

    def upstream(*_, **kwargs):
        result = {**json.loads(kwargs["body"])["data"], "resp_code": "00000000"}
        if failure == "wrong_request":
            result["req_seq_id"] = "another-request"
        if failure == "wrong_merchant":
            result["huifu_id"] = "another-merchant"
        sign = vendor.sign(canonical_data(result), padding.PKCS1v15(), hashes.SHA256())
        return {"data": result, "sign": base64.b64encode(b"invalid" if failure == "wrong_signature" else sign).decode()}

    with pytest.raises(ProviderError, match="^signature_invalid$"):
        forward(account, {"kind": "balance"}, request("https://api.huifu.com/v2/trade/acctpayment/balance/query", "POST", data),
                transport=upstream)


@pytest.mark.parametrize("endpoint", [None, "https://oapi.asign.cn", "https://prev.asign.cn"])
def test_asign_openapi_sdk_signature_and_raw_response(keys, endpoint):
    merchant, _, private, _ = keys
    account = {"provider": "asign", "api_mode": "openapi", "app_id": "test-app", "private_key_file": private}
    if endpoint is not None:
        account["endpoint"] = endpoint
    selector = {"companyName": "Synthetic Company"}
    raw = {"code": 100000, "data": [{"verified": False}], "untouched": {"nested": [42]}}
    calls = []

    def upstream(method, url, **kwargs):
        calls.append((method, url))
        parts = MultipartDecoder(kwargs["body"], kwargs["headers"]["Content-Type"]).parts
        fields = {}
        for part in parts:
            name = part.headers[b"Content-Disposition"].decode().split('name="')[1].split('"')[0]
            fields[name] = part.content.decode()
        assert json.loads(fields["bizData"]) == selector
        digest = hashlib.md5(fields["bizData"].encode(), usedforsecurity=False).hexdigest()
        signed = (fields["bizData"] + digest + fields["appId"] + fields["timestamp"]).encode()
        merchant.public_key().verify(base64.b64decode(kwargs["headers"]["sign"]), signed,
                                     padding.PKCS1v15(), hashes.SHA1())
        return raw

    result = forward(account, {"kind": "company_verification", "scope": {"company_selectors": [selector]}},
                     request((endpoint or "https://oapi.asign.cn") + "/user/getCompUser", "POST", selector),
                     transport=upstream)
    assert result == (raw, None)
    assert calls == [("POST", (endpoint or "https://oapi.asign.cn") + "/user/getCompUser")]


@pytest.mark.parametrize("endpoint", ["https://sapi.asign.cn", "https://presapi.asign.cn"])
@pytest.mark.parametrize("kind,path,scope", [
    ("saas_authorizations", "/auth/authorizedInfo/user%40example.invalid",
     {"saas_user_ids": ["user@example.invalid"]}),
    ("saas_health", "/health", {}),
])
def test_asign_removed_saas_requests_denied_before_credentials_or_network(monkeypatch, endpoint, kind, path, scope):
    def forbidden(*_, **__):
        pytest.fail("Removed operations must not read credentials or contact upstream")

    monkeypatch.setattr("cloud_resource_relay.signers.read_secret_file", forbidden)
    account = {"provider": "asign", "api_mode": "saas", "endpoint": endpoint,
               "app_id": "test-app", "token_file": "unused.token"}
    with pytest.raises(ProviderError, match="^permission_denied$"):
        forward(account, {"kind": kind, "scope": scope}, request(endpoint + path), transport=forbidden)
    with pytest.raises(ProviderError, match="^upstream_error$"):
        validate_credentials(account, kind)


@pytest.mark.parametrize("extra,url", [
    ({"api_mode": "saas"}, "https://oapi.asign.cn/user/getCompUser"),
    ({"endpoint": "https://sapi.asign.cn"}, "https://sapi.asign.cn/user/getCompUser"),
    ({"endpoint": "https://presapi.asign.cn"}, "https://presapi.asign.cn/user/getCompUser"),
    ({}, "https://prev.asign.cn/user/getCompUser"),
])
def test_asign_openapi_rejects_wrong_mode_or_endpoint(extra, url):
    selector = {"account": "test-company"}
    with pytest.raises(ProviderError, match="^permission_denied$"):
        validate_upstream({"provider": "asign", "api_mode": "openapi", **extra},
                          {"kind": "company_verification", "scope": {"company_selectors": [selector]}},
                          request(url, "POST", selector))


@pytest.mark.parametrize("kind", ["balance", "cdn_usage"])
def test_qiniu_auth_protocol_and_no_response_calculations(kind):
    account = {"provider": "qiniu", "access_key_id": "synthetic-key-1234", "access_key_secret": "synthetic-secret-1234"}
    operation = {"kind": kind, "scope": {"domains": ["example.invalid"]} if kind == "cdn_usage" else {}}
    req = (request("https://fusion.qiniuapi.com/v2/tune/monitoring/flow", "POST",
                   {"domains": "example.invalid", "startDate": "2026-09-14", "endDate": "2026-09-15", "granularity": "5min"})
           if kind == "cdn_usage" else request("https://api.qiniu.com/billing-api/v1/account/balance-overview"))
    raw = {"code": 200 if kind == "cdn_usage" else 0, "data": {"balance": 12000000000}}
    calls = []

    def upstream(*_, **kwargs):
        calls.append(kwargs)
        assert kwargs["headers"]["Authorization"].startswith("QBox " if kind == "cdn_usage" else "Qiniu ")
        assert ("X-Qiniu-Date" in kwargs["headers"]) == (kind != "cdn_usage")
        return raw

    assert forward(account, operation, req, transport=upstream) == (raw, None)
    assert len(calls) == 1


@pytest.mark.parametrize("token_type", ["access_token", "authorizer_access_token"])
def test_wechat_injects_server_token_and_preserves_raw_business_errors(tmp_path, token_type):
    token_path = tmp_path / "wechat.json"
    token_path.write_text(json.dumps({"appid": "test-app", token_type: "synthetic-token-123456",
                                     "expires_at": int(time.time()) + 600}), encoding="utf-8")
    account = {"provider": "wechat", "appid": "test-app", "token_file": str(token_path),
               "token_type": token_type, "third_party_authorized": token_type == "authorizer_access_token"}
    original = request("https://api.weixin.qq.com/cgi-bin/openapi/quota/get", "POST", {"cgi_path": "/cgi-bin/message/send"})
    seen = []

    def upstream(method, url, **kwargs):
        seen.append((method, url))
        assert parse_qs(urlsplit(url).query) == {"access_token": ["synthetic-token-123456"]}
        assert json.loads(kwargs["body"]) == original["body"]
        return {"errcode": 45009, "errmsg": "quota exceeded"}

    response = forward(account, {"kind": "api_quota", "scope": {"cgi_paths": ["/cgi-bin/message/send"]}},
                       original, transport=upstream)
    assert response == ({"errcode": 45009, "errmsg": "quota exceeded"}, None)
    assert len(seen) == 1
    assert "?" not in original["url"]


@pytest.mark.parametrize("invalid", ["expired", "wrong_app", "missing_permission"])
def test_wechat_invalid_cache_or_authorization_rejected_locally(tmp_path, invalid):
    path = tmp_path / "cache.json"
    path.write_text(json.dumps({"appid": "other" if invalid == "wrong_app" else "test-app",
                               "authorizer_access_token": "synthetic-token-123456",
                               "expires_at": int(time.time()) + (-1 if invalid == "expired" else 600)}), encoding="utf-8")
    account = {"provider": "wechat", "appid": "test-app", "token_file": str(path), "token_type": "authorizer_access_token",
               "third_party_authorized": True, "permission_sets": [] if invalid == "missing_permission" else [30]}
    with pytest.raises(ProviderError):
        validate_credentials(account, "annual_review")


@pytest.mark.parametrize("change", [
    {"url": "http://api.qiniu.com/billing-api/v1/account/balance-overview"},
    {"url": "https://api.qiniu.com.evil.invalid/billing-api/v1/account/balance-overview"},
    {"url": "https://user:password@api.qiniu.com/billing-api/v1/account/balance-overview"},
    {"url": "https://api.qiniu.com:443/billing-api/v1/account/balance-overview"},
    {"url": "https://api.qiniu.com/billing-api/v1/account/balance-overview#fragment"},
    {"url": "https://api.qiniu.com/billing-api/v1/account/balance-overview?access_token=forbidden"},
    {"url": "https://api.qiniu.com/billing-api/v1/account/delete"},
    {"method": "DELETE"}, {"body": {}}, {"headers": {"Authorization": "forbidden"}},
])
def test_catalog_rejects_unsafe_route_or_client_auth(change):
    req = {**request("https://api.qiniu.com/billing-api/v1/account/balance-overview"), **change}
    with pytest.raises(ProviderError, match="^permission_denied$"):
        validate_upstream({"provider": "qiniu"}, {"kind": "balance"}, req)


@pytest.mark.parametrize("query", ["bucket=other", "bucket=allowed&bucket=other", "bucket=allowed&token=secret"])
def test_scope_cannot_be_bypassed_with_query_parameters(query):
    url = "https://api.qiniuapi.com/v6/space?begin=20260915000000&end=20260915100000&g=5min&" + query
    with pytest.raises(ProviderError, match="^permission_denied$"):
        validate_upstream({"provider": "qiniu"}, {"kind": "kodo_usage", "scope": {"buckets": ["allowed"]}}, request(url))


def test_forward_denies_before_any_network_call():
    calls = []
    with pytest.raises(ProviderError, match="^permission_denied$"):
        forward({"provider": "wechat"}, {"kind": "api_quota", "scope": {"cgi_paths": ["/allowed"]}},
                request("https://api.weixin.qq.com/cgi-bin/openapi/quota/clear", "POST", {"cgi_path": "/allowed"}),
                transport=lambda *args, **kwargs: calls.append(args))
    assert calls == []


@pytest.mark.parametrize("provider,kind,scope,req,extra", [
    ("qiniu", "billing_snapshot", {}, request("https://api.qiniu.com/billing-api/v2/bill/snapshot?date=2026-09-15T00%3A00%3A00"), {}),
    ("qiniu", "resource_packages_month", {}, request("https://api.qiniu.com/billing-api/v1/respack/month-overview?page=1&page_size=200"), {}),
    ("qiniu", "resource_packages", {}, request("https://api.qiniu.com/billing-api/v1/respack/list?page=2&page_size=200"), {}),
    ("qiniu", "kodo_usage", {"buckets": ["test-bucket"]}, request("https://api.qiniuapi.com/v6/count?begin=20260915000000&end=20260915100000&g=5min&bucket=test-bucket"), {}),
    ("qiniu", "cdn_status", {"domains": ["test.invalid"]}, request("https://fusion.qiniuapi.com/v2/tune/loganalyze/statuscode", "POST", {"domains": ["test.invalid"], "startDate": "2026-09-14", "endDate": "2026-09-15", "freq": "5min", "region": "global", "isp": "all"}), {}),
    ("wechat", "charge_packages", {"spu_ids": ["test-spu"]}, request("https://api.weixin.qq.com/wxa/charge/usage/get?spuId=test-spu&offset=20&limit=20"), {}),
    ("wechat", "annual_review", {}, request("https://api.weixin.qq.com/cgi-bin/account/getaccountbasicinfo", "POST"), {}),
    ("wechat", "annual_review", {}, request("https://api.weixin.qq.com/cgi-bin/account/getaccountbasicinfo"), {}),
    ("wechat", "js_errors", {}, request("https://api.weixin.qq.com/wxaapi/log/jserr_list", "POST", {"appVersion": "0", "errType": "0", "startTime": "2026-09-14", "endTime": "2026-09-14", "keyword": "", "openid": "", "orderby": "pv", "desc": "1", "offset": 0, "limit": 30}), {}),
    ("wechat", "performance", {}, request("https://api.weixin.qq.com/wxaapi/log/get_performance", "POST", {"cost_time_type": 1, "default_start_time": 1790000000, "default_end_time": 1790000600, "device": "@_all", "networktype": "@_all", "scene": "@_all", "is_download_code": "@_all"}), {}),
])
def test_catalog_accepts_readonly_adapter_requests(provider, kind, scope, req, extra):
    validate_upstream({"provider": provider, **extra}, {"kind": kind, "scope": scope}, req)


def test_transport_exception_does_not_expose_credential():
    account = {"provider": "qiniu", "access_key_id": "synthetic-key-1234", "access_key_secret": "synthetic-secret-1234"}

    def upstream(*_, **kwargs):
        raise RuntimeError("unsafe URL synthetic-secret-1234 " + kwargs["headers"]["Authorization"])

    with pytest.raises(ProviderError, match="^upstream_error$") as raised:
        forward(account, {"kind": "balance"}, request("https://api.qiniu.com/billing-api/v1/account/balance-overview"),
                transport=upstream)
    assert "synthetic" not in str(raised.value)
