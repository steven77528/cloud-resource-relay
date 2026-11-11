"""Verify local HTTP/HTTPS forwarding and monitor calculations without contacting vendors."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
from email import policy
from email.parser import BytesParser
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

CLIENT_PROGRAM = r'''
import json
from pathlib import Path
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from uuid import uuid4

from cloud_monitor.models import utcnow
from cloud_monitor.providers.relay import RelayCollector

settings = json.load(sys.stdin)
results = []
for case in settings["cases"]:
    account = {"id": case["account"], "provider": case["provider"], **case.get("public", {}), "relay": {
        "url": settings["url"], "token_file": case["token_file"], "timeout_seconds": 10}}
    try:
        if case.get("raw"):
            payload = {"version": 2, "request_id": uuid4().hex, "provider": case["provider"],
                "account": case["account"], "operation": case["operation"], "kind": case["kind"],
                "request": {"method": "GET", "body": None,
                    "url": "https://api.qiniu.com/billing-api/v1/account/balance-overview"}}
            if case["raw"] == "injection":
                payload["headers"] = {"Authorization": "unapproved"}
            request = Request(settings["url"], method="POST", data=json.dumps(payload).encode(),
                headers={"Authorization": "Bearer " + Path(case["token_file"]).read_text().strip(),
                         "Content-Type": "application/json"})
            with urlopen(request, timeout=10) as response:
                result = {"label": case["label"], "http_status": response.status}
                if case["raw"] == "probe":
                    result["envelope"] = json.load(response)
                results.append(result)
        else:
            collector = RelayCollector(account)
            metrics = collector.collect(case["kind"], {"operation": case["operation"],
                "source_max_age_seconds": 300, "collector": case.get("collector", {})}, utcnow())
            results.append({"label": case["label"], "status": "ok",
                "query_performed": collector.query_performed, "metrics": [m.to_dict() for m in metrics],
                "adapter_module": type(collector._backend).__module__})
    except HTTPError as exc:
        results.append({"label": case["label"], "http_status": exc.code})
    except Exception as exc:
        results.append({"label": case["label"], "status": "error", "error_type": type(exc).__name__,
                        "reason": getattr(exc, "reason", "unknown")})
print(json.dumps(results, ensure_ascii=False, allow_nan=False))
'''


class CheckFailure(RuntimeError):
    pass


def require(condition, label):
    if not condition:
        raise CheckFailure(label)


def private_key(path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    return key


def certificates(directory):
    now = datetime.now(timezone.utc)
    ca_key = private_key(directory / "ca.key")
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Offline integration CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
          .not_valid_after(now + timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .sign(ca_key, hashes.SHA256()))
    ca_path = directory / "ca.crt"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    key_path = directory / "server.key"
    server_key = private_key(key_path)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])).issuer_name(ca_name)
        .public_key(server_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .sign(ca_key, hashes.SHA256()))
    cert_path = directory / "server.crt"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return ca_path, cert_path, key_path


def compact(data):
    return json.dumps(dict(sorted(data.items())), ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class VendorResponses:
    def __init__(self, merchant, platform, asign, qiniu_secret, wechat_token):
        self.merchant, self.platform, self.asign = merchant, platform, asign
        self.qiniu_secret, self.wechat_token = qiniu_secret, wechat_token
        self.calls = {"qiniu": 0, "huifu": 0, "asign": 0, "wechat": 0}
        self.bad_signature = False
        self.string_data = False

    def __call__(self, method, url, *, headers=None, body=None, timeout=20):
        require(0 < timeout <= 120, "vendor_timeout")
        parsed = urlsplit(url)
        if parsed.hostname == "api.qiniu.com":
            require(method == "GET" and parsed.path == "/billing-api/v1/account/balance-overview", "qiniu_scope")
            signed = ("GET /billing-api/v1/account/balance-overview\nHost: api.qiniu.com\n"
                      "Content-Type: application/x-www-form-urlencoded\nX-Qiniu-Date: "
                      + headers["X-Qiniu-Date"] + "\n\n")
            signature = base64.urlsafe_b64encode(hmac.new(self.qiniu_secret.encode(), signed.encode(),
                                                        hashlib.sha1).digest()).decode()
            require(headers["Authorization"] == "Qiniu offline-qiniu-key:" + signature, "qiniu_signing")
            self.calls["qiniu"] += 1
            return {"code": 0, "data": {"account_id": "finance-one", "currency": "CNY",
                "cash_balance": "12345678901", "present_balance": 0, "credit_line": 20000000000,
                "unpaid_money": "-12345678"}}
        if parsed.hostname == "api.huifu.com":
            require(method == "POST" and parsed.path == "/v2/trade/acctpayment/balance/query", "huifu_scope")
            request = json.loads(body)
            self.merchant.public_key().verify(base64.b64decode(request["sign"]), compact(request["data"]),
                                             padding.PKCS1v15(), hashes.SHA256())
            require(request["data"]["huifu_id"] == "offline-merchant", "huifu_identity")
            self.calls["huifu"] += 1
            data = {"req_date": request["data"]["req_date"], "req_seq_id": request["data"]["req_seq_id"],
                    "resp_code": "00000000", "acctInfo_list": json.dumps([
                        {"huifu_id": "offline-merchant", "acct_id": "main", "acct_type": "01", "acct_stat": "N",
                         "avl_bal": "1234.56", "balance_amt": "1250.00", "frz_bal": "15.44"}])}
            raw_data = compact(data).decode() if self.string_data else data
            signature = self.platform.sign(compact(data), padding.PKCS1v15(), hashes.SHA256())
            return {"data": raw_data, "sign": "invalid" if self.bad_signature else base64.b64encode(signature).decode()}
        if parsed.hostname == "oapi.asign.cn":
            require(method == "POST" and parsed.path == "/user/getCompUser", "asign_scope")
            message = BytesParser(policy=policy.default).parsebytes(
                ("Content-Type: " + headers["Content-Type"] + "\r\nMIME-Version: 1.0\r\n\r\n").encode() + body)
            fields = {part.get_param("name", header="content-disposition"):
                      part.get_payload(decode=True).decode() for part in message.iter_parts()}
            require(json.loads(fields["bizData"]) == {"account": "offline-company"}, "asign_selector")
            digest = hashlib.md5(fields["bizData"].encode(), usedforsecurity=False).hexdigest()
            signed = (fields["bizData"] + digest + fields["appId"] + fields["timestamp"]).encode()
            self.asign.public_key().verify(base64.b64decode(headers["sign"]), signed,
                                          padding.PKCS1v15(), hashes.SHA1())
            self.calls["asign"] += 1
            return {"code": 100000, "data": [{"account": "offline-company", "userType": 1, "status": 1}]}
        if parsed.hostname == "api.weixin.qq.com":
            require(method == "POST" and parsed.path == "/cgi-bin/openapi/quota/get", "wechat_scope")
            require(parse_qs(parsed.query) == {"access_token": [self.wechat_token]}, "wechat_token")
            require(json.loads(body) == {"cgi_path": "/cgi-bin/message/subscribe/send"}, "wechat_options")
            self.calls["wechat"] += 1
            return {"errcode": 0, "quota": {"daily_limit": 1000, "used": 250, "remain": 750}}
        raise CheckFailure("unexpected_upstream_host")


def fixtures(directory, scheme):
    ca_path = None
    api = {"scheme": scheme, "host": "127.0.0.1", "port": 8443, "max_workers": 8}
    if scheme == "https":
        ca_path, cert_path, key_path = certificates(directory)
        api.update(cert_file=str(cert_path), key_file=str(key_path), health_ca_file=str(ca_path),
                   health_server_name="localhost")
    merchant = private_key(directory / "huifu-private.pem")
    platform = private_key(directory / "huifu-platform-private.pem")
    public_path = directory / "huifu-public.pem"
    public_path.write_bytes(platform.public_key().public_bytes(serialization.Encoding.PEM,
                                                               serialization.PublicFormat.SubjectPublicKeyInfo))
    asign = private_key(directory / "asign-private.pem")
    qiniu_secret, wechat_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    qiniu_path, wechat_path = directory / "qiniu-secret.txt", directory / "wechat-token.json"
    qiniu_path.write_text(qiniu_secret, encoding="ascii")
    wechat_path.write_text(json.dumps({"appid": "offline-wechat-app", "access_token": wechat_token,
        "expires_at": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())}), encoding="ascii")
    accounts = [
        {"id": "qiniu-internal", "provider": "qiniu", "enabled": True, "access_key_id": "offline-qiniu-key",
         "access_key_secret_file": str(qiniu_path)},
        {"id": "huifu-internal", "provider": "huifu", "enabled": True, "sys_id": "offline-system",
         "product_id": "offline-product", "huifu_id": "offline-merchant",
         "private_key_file": str(directory / "huifu-private.pem"), "huifu_public_key_file": str(public_path)},
        {"id": "asign-internal", "provider": "asign", "enabled": True, "api_mode": "openapi",
         "app_id": "offline-asign-app", "private_key_file": str(directory / "asign-private.pem")},
        {"id": "wechat-internal", "provider": "wechat", "enabled": True,
         "appid": "offline-wechat-app", "token_file": str(wechat_path)},
    ]
    options = {
        "qiniu": ("balance", {}),
        "huifu": ("balance", {"amount_unit_confirmed": True, "currency": "CNY", "source_amount_unit": "yuan",
            "amount_multiplier": "1", "accounts": [{"acct_id": "main", "acct_type": "01"}]}),
        "asign": ("company_verification", {"resource_id": "company-main", "selector": {"account": "offline-company"}}),
        "wechat": ("api_quota", {"cgi_paths": ["/cgi-bin/message/subscribe/send"]}),
    }
    clients, operations, cases, tokens = [], [], [], []
    for provider, (kind, selected) in options.items():
        operation = provider + "-operation"
        token = secrets.token_urlsafe(32)
        token_path = directory / (provider + ".token")
        token_path.write_text(token, encoding="ascii")
        tokens.append(token)
        clients.append({"id": provider + "-client", "enabled": True, "token_file": str(token_path),
                        "operations": [operation], "requests_per_minute": 60})
        scope = ({"company_selectors": [selected["selector"]]} if provider == "asign" else
                 {"cgi_paths": selected["cgi_paths"]} if provider == "wechat" else {})
        operations.append({"id": operation, "enabled": True, "account": provider + "-internal",
            "monitor_account": provider + "-monitor", "kind": kind, "minimum_interval_seconds": 0,
            "timeout_seconds": 10, "scope": scope})
        public = ({"api_mode": "openapi", "app_id": "offline-asign-app"} if provider == "asign" else
                  {"appid": "offline-wechat-app"} if provider == "wechat" else
                  {"huifu_id": "offline-merchant"} if provider == "huifu" else {})
        cases.append({"label": provider, "provider": provider, "account": provider + "-monitor",
                      "operation": operation, "kind": kind, "token_file": str(token_path),
                      "collector": selected, "public": public})
    wrong_path = directory / "unauthorized.token"
    wrong_path.write_text(secrets.token_urlsafe(32), encoding="ascii")
    config = {"version": 1, "api": api,
        "clients": clients, "accounts": accounts, "operations": operations}
    config_path = directory / "config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    transport = VendorResponses(merchant, platform, asign, qiniu_secret, wechat_token)
    sensitive = [qiniu_secret, wechat_token, *tokens, "-----BEGIN PRIVATE KEY-----"]
    return config_path, ca_path, cases, wrong_path, transport, sensitive


def run_client(monitor, ca, url, cases, sensitive):
    env = dict(os.environ)
    env.update(PYTHONPATH=str(monitor), NO_PROXY="127.0.0.1,localhost")
    if ca is not None:
        env["SSL_CERT_FILE"] = str(ca)
    process = subprocess.run([sys.executable, "-c", CLIENT_PROGRAM], cwd=monitor, env=env,
        input=json.dumps({"url": url, "cases": cases}), capture_output=True, text=True, timeout=45)
    require(not any(value in process.stdout or value in process.stderr for value in sensitive), "credential_output")
    require(process.returncode == 0, "monitor_subprocess")
    try:
        return json.loads(process.stdout)
    except ValueError:
        raise CheckFailure("monitor_report_json") from None


def run_check(monitor, scheme="http"):
    from cloud_resource_relay.server import create_server

    require(scheme in {"http", "https"}, "relay_scheme")
    monitor = Path(monitor).resolve()
    require((monitor / "cloud_monitor/providers/relay.py").is_file(), "monitor_source")
    scratch = ROOT / ".tmp"
    scratch.mkdir(exist_ok=True)
    with TemporaryDirectory(prefix="integration-", dir=scratch) as name:
        directory = Path(name)
        config_path, ca, cases, wrong_path, transport, sensitive = fixtures(directory, scheme)
        if scheme == "http":
            require(ca is None and not list(directory.glob("*.crt")) and not list(directory.glob("*.key")),
                    "http_without_certificates")
        server = create_server(config_path, upstream_transport=transport, host="127.0.0.1", port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"{scheme}://127.0.0.1:{server.server_address[1]}/v1/monitor/collect"
            live_config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
            live_config["api"]["port"] = server.server_address[1]
            config_path.write_text(yaml.safe_dump(live_config), encoding="utf-8")
            health = subprocess.run([sys.executable, "-m", "cloud_resource_relay", "--config", str(config_path),
                "health"], cwd=ROOT, capture_output=True, text=True, timeout=15)
            health_check = "health_private_ca" if scheme == "https" else "health_http_ip"
            require(health.returncode == 0 and json.loads(health.stdout) == {"healthy": True}, health_check)
            results = run_client(monitor, ca, url, cases, sensitive)
            require(len(results) == 4 and all(result.get("status") == "ok" for result in results), "four_providers")
            expected = {"qiniu": ("qiniu_cash_balance", 123.45678901),
                        "huifu": ("huifu_available_balance", 1234.56),
                        "asign": ("company_verified", 1), "wechat": ("api_quota_remaining", 750)}
            for result in results:
                provider = result["label"]
                metric_name, value = expected[provider]
                keyed = {metric["metric"]: metric for metric in result["metrics"]}
                require(keyed[metric_name]["value"] == value, provider + "_normalization")
                require(all(metric["provider"] == provider and metric["account"] == provider + "-monitor"
                            for metric in result["metrics"]), provider + "_binding")
                require(result["query_performed"] is True, provider + "_query_semantics")
                require(result["adapter_module"] == "cloud_monitor.providers." + provider, provider + "_local_adapter")
            counts = dict(transport.calls)
            require(counts == dict.fromkeys(expected, 1), "one_call_per_provider")
            negative = [
                {**cases[0], "label": "unauthorized", "token_file": str(wrong_path)},
                {**cases[0], "label": "cross_account", "account": "another-account"},
                {**cases[1], "label": "cross_client", "token_file": cases[0]["token_file"]},
                {**cases[0], "label": "unknown_operation", "operation": "unknown-operation"},
                {**cases[0], "label": "raw_injection", "raw": "injection"},
            ]
            denials = run_client(monitor, ca, url, negative, sensitive)
            require(all(result.get("status") == "error" for result in denials[:-1]), "acl_denials")
            require(denials[-1].get("http_status") == 400, "raw_parameters_rejected")
            require(transport.calls == counts, "denials_no_upstream")
            probe = run_client(monitor, ca, url, [{**cases[0], "label": "raw_probe", "raw": "probe"}], sensitive)[0]
            envelope = probe.get("envelope", {})
            require(probe.get("http_status") == 200 and envelope.get("version") == 2
                    and "metrics" not in envelope and envelope.get("status") == "ok", "raw_forwarding_envelope")
            raw_cash = envelope.get("response", {}).get("data", {}).get("cash_balance")
            require(raw_cash == "12345678901", "raw_forwarding_no_calculation")
            transport.string_data = True
            string_result = run_client(monitor, ca, url, [cases[1]], sensitive)[0]
            require(string_result.get("status") == "ok" and any(metric["metric"] == "huifu_available_balance"
                and metric["value"] == 1234.56 for metric in string_result["metrics"]), "huifu_signed_string_parsing")
            transport.bad_signature = True
            invalid = run_client(monitor, ca, url, [cases[1]], sensitive)[0]
            require(invalid.get("reason") == "signature_invalid", "signature_failure_preserved")
            if scheme == "https":
                wrong_ca_dir = directory / "untrusted"
                wrong_ca_dir.mkdir()
                wrong_ca, _, _ = certificates(wrong_ca_dir)
                invalid = run_client(monitor, wrong_ca, url, [cases[0]], sensitive)[0]
                require(invalid.get("reason") == "relay_request_failed", "untrusted_tls_rejected")
                require(transport.calls["qiniu"] == 2, "untrusted_tls_no_upstream")
            transport_check = "tls_certificate_verification" if scheme == "https" else "http_without_certificates"
            return {"status": "passed", "transport": "verified_local_tls" if scheme == "https" else "local_http_ip",
                "providers": 4, "business_samples": sum(len(result["metrics"]) for result in results),
                "negative_checks": 7 if scheme == "https" else 6,
                "vendor_requests": transport.calls, "real_vendor_requests": 0,
                "protocol_version": 2, "relay_role": "authenticated_raw_forwarding", "calculation_owner": "monitor",
                "qiniu_cash_proof": {"relay_raw_value": raw_cash, "monitor_value": 123.45678901},
                "checks": [transport_check, health_check, "four_original_monitor_adapters",
                    "vendor_request_signatures", "raw_response_unchanged", "huifu_signed_string_parsing",
                    "metric_normalization", "monitor_account_binding", "token_acl", "unknown_operation",
                    "request_parameter_rejection", "signature_failure_preservation", "credential_output_absent"]}
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=10)
            require(not thread.is_alive(), "server_shutdown")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--monitor-project", "--monitor", dest="monitor", type=Path,
                        default=ROOT.parent / "cloud-resource-monitor")
    parser.add_argument("--report", type=Path, help="Optional sanitized report path inside this relay project")
    parser.add_argument("--scheme", choices=("http", "https"), default="http")
    args = parser.parse_args()
    try:
        report_path = args.report.resolve() if args.report else None
        require(report_path is None or report_path.is_relative_to(ROOT), "report_path")
        report = run_check(args.monitor, scheme=args.scheme)
        serialized = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if report_path:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(serialized, encoding="utf-8")
        print(serialized, end="")
        return 0
    except CheckFailure as exc:
        print(json.dumps({"status": "failed", "check": str(exc)}), file=sys.stderr)
        return 1
    except Exception as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
