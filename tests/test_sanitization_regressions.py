"""Synthetic privacy/credential regressions; contains no production data."""

import asyncio
import json
from unittest.mock import patch

import server
from secret_detection import detect_secrets, redact_findings


def test_windows_json_account_and_case_variants_share_mask():
    logs = [json.dumps({"event": {"userName": r"ACME\Alice"}}), "user=acme\\alice"]
    sanitized, mapping = server.sanitize_logs(logs)
    joined = "".join(sanitized).lower()
    assert "alice" not in joined
    assert len(set(marker for marker in mapping if marker.startswith("⟦USER#"))) >= 1


def test_request_wide_discovery_masks_earlier_log_with_boundaries():
    sanitized, mapping = server.sanitize_logs(
        ["actor ann launched scanner.exe", 'later User="ann"'], enable_pattern=True
    )
    assert "actor ⟦USER#1⟧" in sanitized[0]
    assert "scanner.exe" in sanitized[0]
    assert list(mapping.values()) == ["ann"]


def test_existing_placeholder_is_atomic_and_does_not_get_remasked():
    sanitized, _ = server.sanitize_logs(
        ["existing ⟦USER#99⟧ user Alice", 'User="alice"']
    )
    assert "⟦USER#99⟧" in sanitized[0]
    assert "Alice" not in sanitized[0]


def test_alias_short_user_nested_path_and_numeric_explicit_key():
    source = {"identity": {"account_name": "xy", "account": {"id": 42}},
              "count": 42, "timestamp": 42}
    sanitized, mapping = server.sanitize_logs(
        [json.dumps(source)], json_keys_to_hide=["identity.account.id"]
    )
    result = json.loads(sanitized[0])
    assert result["identity"]["account_name"].startswith("⟦USER#")
    assert result["identity"]["account"]["id"].startswith("⟦identity.account.id#")
    assert result["count"] == 42 and result["timestamp"] == 42
    assert "42" in mapping.values()


def test_command_credentials_expand_without_login_status_false_positive():
    text = "tool --token synthetic-token --password='space pass' login status:failed"
    redacted, mapping, _ = redact_findings(text, detect_secrets(text))
    assert "synthetic-token" not in redacted
    assert "space pass" not in redacted
    assert "status:failed" in redacted
    assert "failed" not in mapping.values()


def test_secret_case_is_sensitive_while_privacy_case_is_not():
    redacted, _, _ = redact_findings(
        "password=Alice repeated alice", detect_secrets("password=Alice repeated alice")
    )
    assert "password=Alice" not in redacted
    assert "repeated alice" in redacted


def test_sanitize_only_includes_and_honors_statistics_fields():
    stats = [{"fields": [{"field": "account.id", "topValues": [{"value": "A-7", "count": 3}]}]}]
    result = asyncio.run(server._analyze_logs(server.LogAnalysisRequest(
        logs=[], mode="sanitize_only", field_statistics=stats,
        statistics_fields_to_hide=["account-id"], enable_pattern_sanitization=False,
    )))
    assert "A-7" not in result.sanitized_log
    assert result.mapping_table and "A-7" in result.mapping_table.values()


def test_feedback_uses_its_request_options_and_never_persists_raw_secret(tmp_path):
    target = tmp_path / "feedback.json"
    old_data = server.training_data
    server.training_data = {"feedback_entries": []}
    try:
        with patch.object(server, "FEEDBACK_FILE", str(target)):
            asyncio.run(server.submit_feedback(server.FeedbackRequest(
                original_log="password=synthetic-feedback-secret",
                ai_response="ok", user_correction="correct",
            )))
        assert "synthetic-feedback-secret" not in target.read_text()
    finally:
        server.training_data = old_data


def test_force_hidden_value_never_reaches_threat_intelligence():
    captured = []
    async def ti(logs, notes, *args, **kwargs):
        captured.extend(logs)
        return "", []
    async def ai(prompt, key):
        return "ok"
    request = server.LogAnalysisRequest(
        logs=["ioc hidden.example and public 8.8.8.8"], mode="groq", api_key="x",
        sanitize=False, enable_threat_intel=True, enable_whois=True,
        force_hide_values=["hidden.example"],
    )
    with patch.object(server, "enrich_with_threat_intel", ti), patch.object(server, "call_groq_ai", ai):
        asyncio.run(server.analyze_logs(request))
    assert "hidden.example" not in "".join(captured)
