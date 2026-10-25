"""Run pipelines/suricata.conf in Logstash and check the ECS output.
The image comes from LOGSTASH_IMAGE (set in .env, pinned by digest).
Covers RISK-REGISTER R-03.
"""
import json
import os
import subprocess
from pathlib import Path
import pytest
ROOT = Path(__file__).resolve().parent.parent
IMAGE = os.environ.get("LOGSTASH_IMAGE")
pytestmark = pytest.mark.skipif(not IMAGE, reason="LOGSTASH_IMAGE not set (see .env)")
def run_pipeline(sample: Path) -> list[dict]:
    cmd = [
        "docker", "run", "--rm", "-i",
        "-v", f"{ROOT / 'pipelines' / 'suricata.conf'}:/pipe/10-suricata.conf:ro",
        "-v", f"{ROOT / 'tests' / 'harness.conf'}:/pipe/00-harness.conf:ro",
        IMAGE, "logstash", "-f", "/pipe", "--log.level=error",
    ]
    out = subprocess.run(
        cmd, input=sample.read_text(), capture_output=True, text=True, timeout=300, check=True
    ).stdout
    return [json.loads(line) for line in out.splitlines() if line.startswith("{")]
def test_alert_maps_to_ecs():
    (ev,) = run_pipeline(ROOT / "tests/samples/suricata_alert.json")
    assert ev["source"] == {"ip": "10.0.0.5", "port": 51514}
    assert ev["destination"] == {"ip": "203.0.113.7", "port": 443}
    assert ev["network"]["transport"] == "tcp"
    assert ev["network"]["protocol"] == "tls"
    assert ev["event"]["kind"] == "alert"
    assert ev["rule"]["id"] == 2024897
    assert ev["rule"]["name"] == "ET MALWARE Demo C2 Beacon"
    assert ev["@timestamp"].startswith("2026-10-19T10:15:30.123")
def test_invalid_json_is_tagged_and_unmapped():
    (ev,) = run_pipeline(ROOT / "tests/samples/suricata_invalid.txt")
    assert "_jsonparsefailure" in ev["tags"]
    assert "source" not in ev and "event" not in ev
