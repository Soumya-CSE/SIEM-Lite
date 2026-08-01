import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from analyzer import analyze_logs


def test_suspicious_ips_are_detected_from_sample_log():
    sample_path = os.path.join(os.path.dirname(__file__), "..", "uploads", "sample.log")
    result = analyze_logs(sample_path)

    assert result["suspiciousIps"] > 0
    assert any(item["ip"] == "45.22.10.5" for item in result["suspiciousIpRows"])
    