from pathlib import Path

import pytest

from scripts.integration_check import run_check


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_monitor_client_with_real_adapters_and_fake_upstream(scheme):
    monitor = Path(__file__).resolve().parents[2] / "cloud-resource-monitor"
    if not (monitor / "cloud_monitor/providers/relay.py").is_file():
        pytest.skip("Optional end-to-end check requires the monitor source checkout")
    result = run_check(monitor, scheme=scheme)
    assert result["status"] == "passed"
    assert result["providers"] == 4
    assert result["business_samples"] == 13
    assert result["negative_checks"] == (7 if scheme == "https" else 6)
    assert result["real_vendor_requests"] == 0
    assert result["protocol_version"] == 2
    assert result["calculation_owner"] == "monitor"
    assert result["qiniu_cash_proof"] == {"relay_raw_value": "12345678901", "monitor_value": 123.45678901}
    assert ("health_private_ca" if scheme == "https" else "health_http_ip") in result["checks"]
    assert ("tls_certificate_verification" if scheme == "https" else "http_without_certificates") in result["checks"]
    assert "huifu_signed_string_parsing" in result["checks"]
