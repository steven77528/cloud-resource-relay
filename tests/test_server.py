from copy import deepcopy
from http.client import HTTPConnection
import json
from pathlib import Path
import socket
import threading
import time
from uuid import uuid4

import pytest
import yaml

from cloud_resource_relay.__main__ import issue_token, main
from cloud_resource_relay.config import ConfigError, client_tokens, load_config, validate_config
from cloud_resource_relay.common import ProviderError
from cloud_resource_relay.server import RelayService, RequestError, UpstreamBudget, validate_request
from cloud_resource_relay import server


TOKEN = "offline-monitor-client-token-0000000000000"
OTHER_TOKEN = "offline-monitor-other-token-0000000000000"
VENDOR_SECRET = "offline-qiniu-secret-should-not-be-exposed"


@pytest.fixture(autouse=True)
def block_default_network(monkeypatch):
    def forbidden(*_, **__):
        raise AssertionError("Tests must inject upstream transport")
    monkeypatch.setattr(server, "request_json", forbidden)


@pytest.fixture
def configured(tmp_path):
    token = tmp_path / "client.token"
    token.write_text(TOKEN, encoding="ascii")
    config = {
        "version": 1, "api": {"cert_file": "not-used-by-service-tests.crt", "key_file": "not-used.key"},
        "clients": [{"id": "monitor", "enabled": True, "token_file": str(token),
                     "operations": ["balance-read"], "requests_per_minute": 60}],
        "accounts": [{"id": "vendor-internal", "provider": "qiniu", "enabled": True,
                      "access_key_id": "offline-qiniu-access-key", "access_key_secret": VENDOR_SECRET}],
        "operations": [{"id": "balance-read", "enabled": True, "account": "vendor-internal",
                        "monitor_account": "monitor-qiniu", "kind": "balance", "scope": {},
                        "minimum_interval_seconds": 0}],
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return path, config, token


def request(**changes):
    return {"version": 2, "request_id": uuid4().hex, "provider": "qiniu", "account": "monitor-qiniu",
            "operation": "balance-read", "kind": "balance",
            "request": {"method": "GET", "url": "https://api.qiniu.com/billing-api/v1/account/balance-overview",
                        "body": None}, **changes}


def balance():
    return {"code": 0, "data": {"account_id": "finance-example", "currency": "CNY", "cash_balance": 12300000000,
            "present_balance": 0, "credit_line": 0, "unpaid_money": 0}}


def collect(service, payload=None):
    config, client, tokens = service.authenticate("Bearer " + TOKEN)
    return service.forward(payload or request(), config, client, tokens)


def save(path, config):
    path.write_text(yaml.safe_dump(config), encoding="utf-8")


@pytest.fixture
def http_relay(configured):
    path, config, _ = configured
    config["api"] = {"scheme": "http", "host": "127.0.0.1", "max_workers": 1,
                     "request_timeout_seconds": 1}
    save(path, config)
    calls = []

    def upstream(*_, **__):
        calls.append(True)
        return balance()

    relay = server.create_server(path, port=0, upstream_transport=upstream)
    config["api"]["port"] = relay.server_port
    save(path, config)
    worker = threading.Thread(target=relay.serve_forever, daemon=True)
    worker.start()
    try:
        yield relay, path, calls
    finally:
        relay.shutdown()
        relay.server_close()
        worker.join(3)
        assert not worker.is_alive()


def test_http_defaults_require_no_certificate_and_preserve_legacy_https(configured):
    _, config, _ = configured
    assert validate_config(config)["api"]["scheme"] == "https"
    config["api"] = {}
    api = validate_config(config, live=True)["api"]
    assert api["scheme"] == "http" and api["port"] == 8443
    assert "cert_file" not in api and "key_file" not in api


@pytest.mark.parametrize("api", [{"scheme": "ftp"}, {"scheme": "HTTP"}, {"scheme": None},
    {"scheme": "https"}, {"scheme": "https", "cert_file": "unused.crt"}, {"key_file": "unused.key"}])
def test_invalid_listener_configuration_is_rejected(configured, api):
    _, config, _ = configured
    config["api"] = api
    with pytest.raises(ConfigError):
        validate_config(config)


def test_explicit_http_does_not_load_retained_tls_paths(configured):
    path, config, _ = configured
    config["api"]["scheme"] = "http"
    save(path, config)
    relay = server.create_server(path, port=0)
    relay.server_close()


@pytest.mark.parametrize("token,status", [(None, 401), (OTHER_TOKEN, 401), (TOKEN, 200)])
def test_http_ip_listener_enforces_authentication_without_certificates(http_relay, token, status):
    relay, _, calls = http_relay
    connection = HTTPConnection("127.0.0.1", relay.server_port, timeout=3)
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    try:
        connection.request("POST", "/v1/monitor/collect", json.dumps(request()), headers)
        response = connection.getresponse()
        payload = json.loads(response.read())
        assert response.status == status
        if status == 200:
            assert payload["response"] == balance() and len(calls) == 1
        else:
            assert payload == {"status": "error", "reason": "unauthorized"} and not calls
    finally:
        connection.close()


@pytest.mark.parametrize("phase", ["headers", "body"])
def test_http_absolute_read_deadline_releases_worker(http_relay, phase, capsys):
    relay, path, calls = http_relay
    assert main(["--config", str(path), "health"]) == 0
    assert json.loads(capsys.readouterr().out) == {"healthy": True}
    with socket.create_connection(relay.server_address, timeout=3) as connection:
        if phase == "headers":
            prefix = b"POST /v1/monitor/collect HTTP/1.1\r\nX-Slow: "
        else:
            prefix = ("POST /v1/monitor/collect HTTP/1.1\r\nAuthorization: Bearer " + TOKEN +
                      "\r\nContent-Type: application/json\r\nContent-Length: 8000\r\n\r\n").encode("ascii")
        connection.sendall(prefix)
        closed = False
        started = time.monotonic()
        for _ in range(30):
            try:
                connection.sendall(b" ")
            except OSError:
                closed = True
                break
            time.sleep(0.1)
        assert closed and time.monotonic() - started < 3
    assert not calls
    assert main(["--config", str(path), "health"]) == 0
    assert json.loads(capsys.readouterr().out) == {"healthy": True}


def test_raw_forwarding_signs_with_server_owned_credentials_without_metric_calculation(configured):
    path, config, _ = configured
    calls = []

    def upstream(method, url, **kwargs):
        calls.append((method, url, kwargs))
        assert kwargs["headers"]["Authorization"].startswith("Qiniu offline-qiniu-access-key:")
        return balance()

    service = RelayService(path, upstream_transport=upstream)
    payload = request()
    result = collect(service, payload)
    assert result["status"] == "ok"
    assert result["signature_verified"] is None
    assert all(result[key] == value for key, value in payload.items() if key != "request")
    assert result["response"] == balance()
    assert "metrics" not in result and "query_performed" not in result
    assert TOKEN not in json.dumps(result) and VENDOR_SECRET not in json.dumps(result)
    assert len(calls) == 1 and calls[0][0] == "GET"
    assert config["operations"][0]["scope"] == {}


@pytest.mark.parametrize("change", [{"provider": "wechat"}, {"account": "other-account"},
    {"operation": "refund"}, {"kind": "billing_snapshot"}])
def test_acl_binds_every_scope_field_before_vendor_call(configured, change):
    result = collect(RelayService(configured[0]), request(**change))
    assert result["reason"] == "permission_denied"
    assert "metrics" not in result


@pytest.mark.parametrize("changes", [{"options": {"url": "https://attacker.invalid"}}, {"version": True},
    {"version": 1}, {"request_id": "x" * 32}, {"kind": []}, {"account": "bad\naccount"}])
def test_request_rejects_additional_parameters_and_invalid_identity(changes):
    with pytest.raises(RequestError) as error:
        validate_request(request(**changes))
    assert error.value.status == 400


def test_disabled_operation_or_account_removes_access_immediately(configured):
    path, config, _ = configured
    service = RelayService(path)
    for section in ("operations", "accounts"):
        updated = deepcopy(config)
        updated[section][0]["enabled"] = False
        save(path, updated)
        assert collect(service)["reason"] == "permission_denied"


def test_token_rotation_revocation_and_duplicate_token_fail_closed(configured):
    path, config, token = configured
    service = RelayService(path)
    service.authenticate("Bearer " + TOKEN)
    token.write_text(OTHER_TOKEN, encoding="ascii")
    with pytest.raises(RequestError) as error:
        service.authenticate("Bearer " + TOKEN)
    assert error.value.status == 401
    service.authenticate("Bearer " + OTHER_TOKEN)
    duplicate = {**config["clients"][0], "id": "duplicate"}
    config["clients"].append(duplicate)
    save(path, config)
    with pytest.raises(ConfigError):
        service.authenticate("Bearer " + OTHER_TOKEN)
    config["clients"] = [config["clients"][0]]
    config["clients"][0]["enabled"] = False
    save(path, config)
    with pytest.raises(RequestError):
        service.authenticate("Bearer " + OTHER_TOKEN)


@pytest.mark.parametrize("authorization", [None, "", "Basic anything", "Bearer short", "Bearer " + "x" * 4097,
                                          "Bearer " + "x" * 25 + "\n"])
def test_bad_authorization_is_never_accepted(configured, authorization):
    with pytest.raises(RequestError) as error:
        RelayService(configured[0]).authenticate(authorization)
    assert error.value.status == 401


def test_rate_limit_is_principal_and_operation_scoped(configured):
    path, config, _ = configured
    calls = []

    def upstream(*_, **__):
        calls.append(True)
        return balance()

    config["clients"][0]["requests_per_minute"] = 1
    save(path, config)
    service = RelayService(path, upstream_transport=upstream)
    assert collect(service)["status"] == "ok"
    assert collect(service)["reason"] == "rate_limited"
    assert len(calls) == 1
    config["clients"][0]["requests_per_minute"] = 60
    config["operations"][0]["minimum_interval_seconds"] = 30
    save(path, config)
    assert collect(service)["reason"] == "rate_limited"
    assert len(calls) == 1


def test_concurrent_same_operation_cannot_multiply_upstream_requests(configured):
    entered, release = threading.Event(), threading.Event()
    outputs = []

    def upstream(*_, **__):
        entered.set()
        assert release.wait(5)
        return balance()

    service = RelayService(configured[0], upstream_transport=upstream)
    worker = threading.Thread(target=lambda: outputs.append(collect(service)))
    worker.start()
    try:
        assert entered.wait(5)
        assert collect(service)["reason"] == "rate_limited"
    finally:
        release.set()
        worker.join(5)
    assert not worker.is_alive() and outputs[0]["status"] == "ok"
    assert not service.running


@pytest.mark.parametrize("secret", [TOKEN, VENDOR_SECRET, "offline-qiniu-access-key"])
@pytest.mark.parametrize("encoding", ["object", "json_string", "nested_json_string"])
def test_secret_cannot_be_reflected_inside_nested_raw_response(configured, secret, encoding):
    def upstream(*_, **__):
        result = balance()
        nested = [{"value": secret}]
        if encoding != "object":
            nested = json.dumps(nested).replace("o", "\\u006f")
        if encoding == "nested_json_string":
            nested = json.dumps(nested)
        result["data"]["nested"] = nested
        return result

    result = collect(RelayService(configured[0], upstream_transport=upstream))
    assert result["status"] == "error" and "metrics" not in result
    assert secret not in json.dumps(result)


def test_sensitive_field_inside_json_string_is_rejected_without_changing_valid_response(configured):
    state = {"data": '{"value": 123, "currency": "CNY"}'}
    service = RelayService(configured[0], upstream_transport=lambda *_, **__: state.copy())
    assert collect(service)["response"] == state
    state["data"] = '{"app\\u0073ecret": "unknown-to-local-config"}'
    assert collect(service)["status"] == "error"


def test_oversized_credential_file_is_rejected(tmp_path):
    from cloud_resource_relay.common import read_secret_file

    path = tmp_path / "too-large.token"
    path.write_bytes(b"x" * (1024 * 1024 + 1))
    with pytest.raises(ProviderError, match="credential_file_unavailable"):
        read_secret_file(str(path), "token_file")


@pytest.mark.parametrize("field", ["ledger_file", "sdk_result_file"])
def test_monitor_local_sources_are_not_relay_configuration(configured, field):
    _, config, _ = configured
    config["accounts"].append({"id": "asign-local", "provider": "asign", "api_mode": "openapi",
                               field: "not-a-relay-source"})
    with pytest.raises(ConfigError):
        validate_config(config)


@pytest.mark.parametrize("extra", [
    {"api_mode": "saas"}, {"endpoint": "https://sapi.asign.cn"}, {"endpoint": "https://presapi.asign.cn"},
    {"auth_mode": "TOKEN"}, {"token_file": "unused.token"},
])
def test_asign_saas_configuration_is_rejected_even_when_disabled(configured, extra):
    _, config, _ = configured
    config["accounts"].append({"id": "asign-internal", "provider": "asign", "enabled": False,
                               "api_mode": "openapi", **extra})
    with pytest.raises(ConfigError):
        validate_config(config)


@pytest.mark.parametrize("kind,scope", [
    ("saas_authorizations", {"saas_user_ids": ["test-company"]}), ("saas_health", {}),
])
def test_asign_removed_operations_cannot_be_configured(configured, kind, scope):
    _, config, _ = configured
    config["accounts"].append({"id": "asign-internal", "provider": "asign", "api_mode": "openapi"})
    config["operations"].append({"id": "asign-removed", "account": "asign-internal",
                                 "monitor_account": "monitor-asign", "kind": kind, "scope": scope})
    with pytest.raises(ConfigError):
        validate_config(config)


def test_provider_exception_does_not_escape_and_failure_releases_operation(configured):
    state = {"fail": True}

    def upstream(*_, **__):
        if state["fail"]:
            raise RuntimeError("https://private.invalid/ " + VENDOR_SECRET)
        return balance()

    service = RelayService(configured[0], upstream_transport=upstream)
    assert collect(service)["reason"] == "upstream_error"
    state["fail"] = False
    assert collect(service)["status"] == "ok"
    assert not service.running


def test_call_budget_and_remaining_timeout_are_enforced(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(server.time, "monotonic", lambda: now[0])
    timeouts = []

    def upstream(*_, **kwargs):
        timeouts.append(kwargs["timeout"])
        return {}

    budget = UpstreamBudget(upstream, {"timeout_seconds": 10}, set())
    budget("GET", "https://api.example.invalid", timeout=20)
    with pytest.raises(ProviderError, match="upstream_budget_exceeded"):
        budget("GET", "https://api.example.invalid", timeout=20)
    budget = UpstreamBudget(upstream, {"timeout_seconds": 10}, set())
    now[0] = 109.0
    budget("GET", "https://api.example.invalid", timeout=20)
    with pytest.raises(ProviderError, match="upstream_budget_exceeded"):
        budget("GET", "https://api.example.invalid", timeout=20)
    assert timeouts == [10, 1]
    now[0] = 110.0
    with pytest.raises(ProviderError, match="upstream_budget_exceeded"):
        budget("GET", "https://api.example.invalid")


@pytest.mark.parametrize("token_type", ["access_token", "authorizer_access_token"])
def test_changed_token_used_by_adapter_is_included_in_secret_scan(token_type):
    observed = set()
    budget = UpstreamBudget(lambda *_, **__: {}, {"timeout_seconds": 10}, observed)
    budget("POST", "https://api.weixin.qq.com/api?" + token_type + "=changed-wechat-secret")
    assert "changed-wechat-secret" in observed


@pytest.mark.parametrize("section,key,value", [("clients", "operations", ["*"]),
    ("clients", "requests_per_minute", True), ("operations", "max_upstream_calls", 1001),
    ("operations", "timeout_seconds", float("inf")), ("accounts", "endpoint", "https://attacker.invalid")])
def test_invalid_configuration_fails_without_values(configured, section, key, value):
    _, config, _ = configured
    config[section][0][key] = value
    with pytest.raises(ConfigError) as error:
        validate_config(config)
    assert str(error.value) == "relay configuration is unavailable or invalid"


def test_duplicate_yaml_and_recursive_aliases_are_rejected_without_echo(tmp_path):
    path = tmp_path / "config.yaml"
    for content in ("version: 1\nversion: 1\nsecret: hidden-secret-value\n", "x: &x [*x]\n"):
        path.write_text(content, encoding="utf-8")
        with pytest.raises(ConfigError) as error:
            load_config(path)
        assert "hidden-secret-value" not in str(error.value)


def test_cli_token_generation_never_prints_or_overwrites(tmp_path, capsys):
    token = tmp_path / "secrets/client.token"
    assert main(["issue-token", "--output", str(token)]) == 0
    original = token.read_text(encoding="ascii")
    assert len(original.strip()) >= 24 and original not in capsys.readouterr().out
    assert main(["issue-token", "--output", str(token)]) == 1
    assert original == token.read_text(encoding="ascii")
    with pytest.raises(FileExistsError):
        issue_token(token)


def test_example_config_checks_offline_with_all_operations_disabled():
    root = Path(__file__).resolve().parents[1]
    cfg = load_config(root / "config/config.example.yaml", live=True)
    assert len(cfg["operations"]) == 15
    assert all(not item["enabled"] for section in ("clients", "accounts", "operations") for item in cfg[section])
    assert client_tokens(cfg) == []
