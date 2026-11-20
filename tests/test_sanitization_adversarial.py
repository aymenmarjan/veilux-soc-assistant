import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import pytest

import server
from secret_detection import MECHANISMS


def custom(pattern, action="hide_secret", mode="full_value", capture=0):
    return {"id": "adversarial", "pattern": pattern, "action": action,
            "scope": "all", "mode": mode, "capture_group": capture,
            "enabled": True}


def disabled():
    return {name: False for name in MECHANISMS}


def run_ai(logs, rules=(), config=None, sanitize=False, reply="ok", feedback=()):
    prompts = []
    async def ai(prompt, _key):
        prompts.append(prompt)
        return reply
    request = server.LogAnalysisRequest(
        logs=logs, mode="groq", api_key="synthetic", sanitize=sanitize,
        secret_protection=config or server.SecretProtection(),
        custom_regex_rules=list(rules))
    stored = {"feedback_entries": [{"user_correction": value, "status": "approved"} for value in feedback]}
    with patch.object(server, "training_data", stored), patch.object(server, "call_groq_ai", ai):
        response = asyncio.run(server.analyze_logs(request))
    return prompts[0], response


def prompt_log(prompt):
    return prompt.split("Security Logs:\n```json\n", 1)[1].split("\n```", 1)[0]


def test_late_feedback_strong_secret_revokes_privacy_restoration():
    privacy = custom("tiny", "hide_privacy", "substring")
    prompt, response = run_ai(["tiny"], [privacy], reply="⟦CUSTOM_PRIVACY#1⟧",
                              feedback=["password=tiny"])
    assert "tiny" not in prompt
    assert "⟦SECRET#" in prompt
    assert response.analysis == "⟦CUSTOM_PRIVACY#1⟧"
    assert not any(value == "tiny" for value in (response.mapping_table or {}).values())


def test_strong_value_propagates_to_equivalent_json_escape_before_privacy():
    privacy = custom("acme", "hide_privacy", "full_value")
    prompt, response = run_ai(['{"customer":"a\\u0063me"}'], [privacy],
                              feedback=["password=acme"])
    assert "CUSTOM_PRIVACY" not in prompt
    assert json.loads(prompt_log(prompt))["customer"].startswith("⟦SECRET#")
    assert not any(value == "acme" for value in (response.mapping_table or {}).values())


def test_late_enrichment_strong_evidence_revokes_prior_privacy_marker():
    prompts = []
    async def ti(*_args, **_kwargs): return "enrichment password=tiny", []
    async def ai(prompt, _key): prompts.append(prompt); return "⟦CUSTOM_PRIVACY#1⟧"
    request = server.LogAnalysisRequest(
        logs=["tiny"], mode="groq", api_key="synthetic", sanitize=False,
        enable_threat_intel=True, enable_whois=True,
        custom_regex_rules=[custom("tiny", "hide_privacy", "substring")])
    with patch.object(server, "training_data", {"feedback_entries": []}), \
         patch.object(server, "enrich_with_threat_intel", ti), \
         patch.object(server, "call_groq_ai", ai):
        response = asyncio.run(server.analyze_logs(request))
    assert "tiny" not in prompts[0] and "CUSTOM_PRIVACY" not in prompts[0]
    assert response.analysis == "⟦CUSTOM_PRIVACY#1⟧"
    assert not any(value == "tiny" for value in (response.mapping_table or {}).values())


def test_historical_feedback_marker_never_acquires_current_identity(tmp_path):
    rules = [custom(r"customer-(?:old|new)", "hide_privacy", "substring")]
    storage = {"feedback_entries": []}
    feedback_file = tmp_path / "feedback.json"
    request = server.FeedbackRequest(original_log="public", ai_response="public",
                                     user_correction="customer-old", custom_regex_rules=rules,
                                     secret_protection=disabled())
    with patch.object(server, "training_data", storage), patch.object(server, "FEEDBACK_FILE", str(feedback_file)):
        asyncio.run(server.submit_feedback(request))
        assert storage["feedback_entries"][0]["user_correction"] == "⟦CUSTOM_PRIVACY#1⟧"
        prompt, response = run_ai(["customer-new"], rules, config=disabled(),
                                  reply="feedback said ⟦CUSTOM_PRIVACY#1⟧", feedback=["⟦CUSTOM_PRIVACY#1⟧"])
    assert "⟦CUSTOM_PRIVACY#2⟧" in prompt
    assert response.analysis == "feedback said ⟦CUSTOM_PRIVACY#1⟧"
    assert (response.mapping_table or {}).get("⟦CUSTOM_PRIVACY#2⟧") == "customer-new"


@pytest.mark.parametrize("source,rules", [
    ('{"customer":12345,"other":7}', [custom("12345")]),
    ('{"password":12345,"other":7}', []),
])
def test_secret_numeric_json_is_valid_in_actual_ai_payload(source, rules):
    prompt, response = run_ai([source], rules, config=disabled() if rules else None)
    parsed = json.loads(prompt_log(prompt))
    key = "customer" if "customer" in parsed else "password"
    assert parsed[key].startswith("⟦SECRET#")
    assert parsed["other"] == 7
    assert all(value != "12345" for value in (response.mapping_table or {}).values())


def test_secret_numeric_json_is_valid_in_sanitize_endpoints():
    rules = [custom("12345")]
    request = server.SanitizationRequest(logs=['{"customer":12345,"other":7}'],
                                         enable_pattern_sanitization=False,
                                         secret_protection=disabled(), custom_regex_rules=rules)
    response = asyncio.run(server.sanitize_endpoint(request))
    assert json.loads(response["sanitized_logs"][0])["customer"].startswith("⟦SECRET#")
    analysis = server.LogAnalysisRequest(logs=request.logs, mode="sanitize_only",
                                         enable_pattern_sanitization=False,
                                         secret_protection=disabled(), custom_regex_rules=rules)
    result = asyncio.run(server.analyze_logs(analysis))
    assert json.loads(result.sanitized_log)["customer"].startswith("⟦SECRET#")


def test_secret_rules_use_decoded_values_captures_and_never_keys():
    escaped = custom("acme")
    prompt, _ = run_ai(['{"customer":"a\\u0063me","acme":"public"}'], [escaped], config=disabled())
    parsed = json.loads(prompt_log(prompt))
    assert parsed["customer"].startswith("⟦SECRET#") and parsed["acme"] == "public"

    capture = custom(r"customer-(\d+)", capture=1)
    prompt, _ = run_ai(['{"ref":"customer-12345"}'], [capture], config=disabled())
    parsed = json.loads(prompt_log(prompt))
    assert parsed["ref"].startswith("customer-⟦SECRET#") and "12345" not in parsed["ref"]


def test_raw_full_value_capture_uses_enclosing_match():
    rules = [custom(r"customer-(\d+)", "hide_privacy", "full_value", 1)]
    sanitized, mapping = server.sanitize_logs(["customer-12345 other"], False, custom_regex_rules=rules)
    assert sanitized == ["customer-⟦CUSTOM_PRIVACY#1⟧ other"]
    assert mapping == {"⟦CUSTOM_PRIVACY#1⟧": "12345"}


def test_token_boundaries_treat_identifier_underscores_as_token_characters():
    rules = [custom("acme", "hide_privacy", "token")]
    sanitized, mapping = server.sanitize_logs(["acme soc_acme_id (acme)"], False,
                                              custom_regex_rules=rules)
    assert sanitized == ["⟦CUSTOM_PRIVACY#1⟧ soc_acme_id (⟦CUSTOM_PRIVACY#1⟧)"]
    assert mapping == {"⟦CUSTOM_PRIVACY#1⟧": "acme"}


def test_automatic_privacy_preserves_unrelated_number_lexemes():
    source = '{"ip":"203.0.113.8","ratio":0.12345678901234567890123456789,"big":999999999999999999999999999999,"exp":-1.2300e+45,"customer":12345}'
    rules = [custom("12345", "hide_privacy")]
    sanitized, _ = server.sanitize_logs([source], True, custom_regex_rules=rules)
    assert '0.12345678901234567890123456789' in sanitized[0]
    assert '999999999999999999999999999999' in sanitized[0]
    assert '-1.2300e+45' in sanitized[0]
    assert json.loads(sanitized[0])["customer"] == "⟦CUSTOM_PRIVACY#1⟧"


def test_structured_response_restoration_escapes_and_restores_types():
    source = json.dumps({"text": 'quote"value', "number": 123}, ensure_ascii=False)
    rules = [custom(r'quote"value', "hide_privacy"), custom("123", "hide_privacy")]
    reply = '{"text":"⟦CUSTOM_PRIVACY#1⟧","number":"⟦CUSTOM_PRIVACY#2⟧"}'
    _prompt, response = run_ai([source], rules, config=disabled(), reply=reply)
    assert json.loads(response.analysis) == {"text": 'quote"value', "number": 123}


def test_malformed_json_response_keeps_marker_unresolved():
    rules = [custom("acme", "hide_privacy")]
    _prompt, response = run_ai(["acme"], rules, config=disabled(), reply='{"bad":"⟦CUSTOM_PRIVACY#1⟧"')
    assert response.analysis == '{"bad":"⟦CUSTOM_PRIVACY#1⟧"'
