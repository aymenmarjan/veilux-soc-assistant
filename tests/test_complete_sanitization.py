import base64
import csv
import json
from pathlib import Path

import pytest

import server
from secret_detection import apply_custom_rules, detect_secrets, redact_findings, validate_custom_rules


def mask(text, rules=None, allowed=()):
    findings = apply_custom_rules(text, detect_secrets(text), rules)
    return redact_findings(text, findings, allowed=allowed)[0], findings


def test_reviewable_shapes_and_strong_context_precedence():
    guid = "550e8400-e29b-41d4-a716-446655440000"
    bare = detect_secrets("event_id=" + guid)
    assert any(f.value == guid and f.confidence == "ambiguous" and "UUID/GUID" in f.reason for f in bare)
    strong = detect_secrets("Authorization: Bearer " + guid)
    assert any(f.value == guid and f.confidence == "high" for f in strong)


def test_keep_is_exact_and_custom_hide_wins_over_exclusion():
    value = "550e8400-e29b-41d4-a716-446655440000"
    rules = [{"id": "keep-guid", "enabled": True, "pattern": r"[0-9a-f-]{36}", "flags": "i", "action": "exclude", "scope": "heuristics", "mode": "full_value", "capture_group": 0}]
    assert apply_custom_rules(value, detect_secrets(value), rules) == []
    rules.insert(0, {"id": "must-hide", "enabled": True, "pattern": value, "flags": "", "action": "hide_secret", "scope": "all", "mode": "full_value", "capture_group": 0})
    assert any(f.confidence == "high" for f in apply_custom_rules(value, detect_secrets(value), rules))


def test_custom_capture_and_validation():
    rules = [{"id": "customer", "enabled": True, "pattern": r"customer-(\d+)", "flags": "", "action": "hide_secret", "scope": "all", "mode": "substring", "capture_group": 1}]
    out, findings = mask("x customer-8675309 y", rules)
    assert "8675309" not in out and "customer-" in out
    for pattern, flags in (("(", ""), (".*", ""), ("ok", "g")):
        with pytest.raises(ValueError):
            validate_custom_rules([{"enabled": True, "pattern": pattern, "flags": flags, "action": "review", "scope": "all", "mode": "substring"}])


def test_attached_curl_and_encoded_secret():
    for text in ("curl -ualice:demo-pass https://example.test", "curl -u alice:demo-pass https://example.test", "curl --user=alice:demo-pass https://example.test"):
        out, _ = mask(text)
        assert "demo-pass" not in out
    encoded = base64.urlsafe_b64encode(b"password=decoded-secret").decode()
    out, findings = mask("blob " + encoded)
    assert encoded not in out and any(f.kind == "encoded credential" for f in findings)


def test_literal_nested_arrays_keyword_and_placeholder_reservation():
    logs = [json.dumps({"user.name": "alice", "events": [{"user": {"name": "bob"}}]}), "logs_windows_acme-2026 existing ⟦USER#1⟧"]
    out, mapping = server.sanitize_logs(logs, enable_pattern=False, custom_keywords={"acme": "ORG"}, json_keys_to_hide=["user.name"])
    parsed = json.loads(out[0])
    assert "alice" not in str(parsed) and "bob" not in str(parsed)
    assert "acme" not in out[1] and "⟦USER#1⟧" in out[1]
    auto, _ = server.sanitize_logs(["existing ⟦USER#1⟧ User=alice"], enable_pattern=True)
    assert "⟦USER#2⟧" in auto[0]


def test_low_entropy_password_remains_strong():
    assert any(f.value == "aaaa" and f.confidence == "high" for f in detect_secrets("password=aaaa"))


@pytest.mark.parametrize("value", [
    "AKIA" + "A" * 16, "glpat-" + "A" * 20, "A" * 75 + "AZDO" + "A" * 5,
    "pypi-AgEIcHlwaS5vcmc" + "A" * 50, "npm_" + "A" * 36,
    "SG." + "A" * 20 + "." + "B" * 30, "SK" + "a" * 32,
    "key-" + "A" * 32, "dop_v1_" + "a" * 64, "doo_v1_" + "a" * 64,
    "dor_v1_" + "a" * 64, "shpat_" + "a" * 32,
    "EAAA" + "A" * 24, "12345678:" + "A" * 35,
    "A" * 24 + "." + "B" * 6 + "." + "C" * 27, "sk-proj-" + "A" * 30,
    "sk-ant-" + "A" * 30, "hf_" + "A" * 30, "PMAK-" + "A" * 25,
    "hvs." + "A" * 25, "AGE-SECRET-KEY-1" + "A" * 55,
    "CLOJARS_" + "A" * 60, "v1.0-" + "a" * 24 + "-" + "b" * 146,
    "dapi" + "a" * 32, "dp.pt." + "A" * 43,
    "glc_" + "A" * 32, "glsa_" + "A" * 32 + "_" + "a" * 8,
    "pat." + "A" * 22 + "." + "B" * 24 + "." + "C" * 20,
    "lin_api_" + "A" * 40,
    "ghp_" + "A" * 36, "xoxb-" + "A" * 20, "AIza" + "A" * 35,
    "sk_live_" + "A" * 20, "eyJabcde.abcdefgh.ijklmnop",
])
def test_each_adapted_provider_fixture_has_strong_exact_span(value):
    findings = detect_secrets("before " + value + " after", {"heuristics": False, "decoding": False})
    assert any(f.value == value and f.confidence == "high" for f in findings)


@pytest.mark.parametrize("value", [
    "CLOJARS_" + "A" * 59, "v1.0-" + "a" * 24 + "-" + "b" * 145,
    "dapi" + "a" * 31, "dp.pt." + "A" * 42, "glc_" + "A" * 31,
    "glsa_" + "A" * 32 + "_" + "a" * 7, "lin_api_" + "A" * 20,
])
def test_extended_provider_prefixes_reject_truncated_values(value):
    assert not any(f.value == value and f.confidence == "high"
                   for f in detect_secrets(value, {"heuristics": False, "decoding": False}))


def test_pinned_upstream_inventory_is_complete_and_explicit():
    path = Path(__file__).parents[1] / "docs" / "SECRET_RULE_INVENTORY.csv"
    rows = list(csv.DictReader(path.open(newline="", encoding="utf-8")))
    gitleaks = [row for row in rows if row["source"] == "gitleaks"]
    secretlint = [row for row in rows if row["source"] == "secretlint"]
    assert len(gitleaks) == 206 and len(secretlint) == 24
    assert {row["status"] for row in rows} <= {"adapted", "duplicate", "skipped"}
    assert all(row["upstream_rule_id"] and row["version"] and row["commit"] and row["reason"] for row in rows)
    assert all(row["local_id"] for row in rows if row["status"] == "adapted")
