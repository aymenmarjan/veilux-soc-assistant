import asyncio
import json
from unittest.mock import patch

import server
from secret_detection import MECHANISMS


def rule(pattern, mode="substring", enabled=True):
    return {"id": f"privacy-{mode}", "pattern": pattern, "action": "hide_privacy",
            "scope": "all", "mode": mode, "enabled": enabled}


def disabled_detectors():
    return {name: False for name in MECHANISMS}


def test_partial_numeric_and_boolean_null_preserve_valid_json():
    source = '{"customer":12345,"other":7,"negative":-12.50e2,"yes":true,"no":false,"nil":null}'
    rules = [rule("123", "substring"), rule("true", "full_value"), rule("null", "full_value")]
    sanitized, mapping = server.sanitize_logs([source], False, custom_regex_rules=rules)
    value = json.loads(sanitized[0])
    assert value == {"customer":"⟦CUSTOM_PRIVACY#1⟧", "other":7, "negative":-1250.0,
                     "yes":"⟦CUSTOM_PRIVACY#2⟧", "no":False, "nil":"⟦CUSTOM_PRIVACY#3⟧"}
    assert mapping == {"⟦CUSTOM_PRIVACY#1⟧":"12345", "⟦CUSTOM_PRIVACY#2⟧":"true",
                       "⟦CUSTOM_PRIVACY#3⟧":"null"}
    assert '"negative":-12.50e2' in sanitized[0]  # unchanged lexeme/precision


def test_full_value_does_not_propagate_to_embedded_occurrence():
    source = '{"exact":"acme","other":"prefix acme suffix","items":["acme","x-acme"]}'
    sanitized, mapping = server.sanitize_logs([source], False, custom_regex_rules=[rule("acme", "full_value")])
    assert json.loads(sanitized[0]) == {
        "exact":"⟦CUSTOM_PRIVACY#1⟧", "other":"prefix acme suffix",
        "items":["⟦CUSTOM_PRIVACY#1⟧", "x-acme"]}
    assert mapping == {"⟦CUSTOM_PRIVACY#1⟧":"acme"}


def test_escaped_capture_and_typed_identity_are_source_safe():
    source = '{"escaped":"prefix a\\u0063me suffix","number":123,"string":"123","key123":9}'
    rules = [rule(r"prefix (acme) suffix", "full_value"), rule("123", "full_value")]
    rules[0]["capture_group"] = 1
    sanitized, mapping = server.sanitize_logs([source], False, custom_regex_rules=rules)
    parsed = json.loads(sanitized[0])
    assert parsed["escaped"] == "prefix ⟦CUSTOM_PRIVACY#1⟧ suffix"
    assert parsed["number"] == "⟦CUSTOM_PRIVACY#2⟧"
    assert parsed["string"] == "⟦CUSTOM_PRIVACY#3⟧"
    assert parsed["key123"] == 9
    assert len(mapping) == 3


def test_existing_marker_is_reserved_and_context_is_request_local():
    context = server._new_privacy_context(["⟦CUSTOM_PRIVACY#1⟧"])
    first, mapping = server.sanitize_logs(["alpha"], False, custom_regex_rules=[rule("alpha", "full_value")], privacy_context=context)
    second, mapping = server.sanitize_logs(["beta"], False, custom_regex_rules=[rule("beta", "full_value")], privacy_context=context)
    assert first == ["⟦CUSTOM_PRIVACY#2⟧"] and second == ["⟦CUSTOM_PRIVACY#3⟧"]
    assert mapping["⟦CUSTOM_PRIVACY#2⟧"] == "alpha" and mapping["⟦CUSTOM_PRIVACY#3⟧"] == "beta"
    independent, _ = server.sanitize_logs(["gamma"], False, custom_regex_rules=[rule("gamma", "full_value")])
    assert independent == ["⟦CUSTOM_PRIVACY#1⟧"]


def test_explicit_privacy_hide_reaches_ai_with_automatic_privacy_off():
    prompts = []
    async def ai(prompt, _key):
        prompts.append(prompt)
        return "ok"
    request = server.LogAnalysisRequest(
        logs=["soc_acme_id"], mode="groq", api_key="synthetic", sanitize=False,
        secret_protection=disabled_detectors(), custom_regex_rules=[rule("acme")])
    with patch.object(server, "call_groq_ai", ai):
        asyncio.run(server.analyze_logs(request))
    assert "soc_acme_id" not in prompts[0]
    assert "soc_⟦CUSTOM_PRIVACY#1⟧_id" in prompts[0]


def test_logs_and_saved_feedback_share_allocator_and_restore_separately():
    prompts = []
    async def ai(prompt, _key):
        prompts.append(prompt)
        return "⟦CUSTOM_PRIVACY#1⟧ / ⟦CUSTOM_PRIVACY#2⟧"
    request = server.LogAnalysisRequest(
        logs=["customer-alpha"], mode="groq", api_key="synthetic", sanitize=False,
        secret_protection=disabled_detectors(),
        custom_regex_rules=[rule(r"customer-(?:alpha|beta)")])
    fixture = {"feedback_entries": [{"user_correction": "customer-beta", "status": "approved"}]}
    with patch.object(server, "training_data", fixture), patch.object(server, "call_groq_ai", ai):
        response = asyncio.run(server.analyze_logs(request))
    assert "customer-alpha" not in prompts[0] and "customer-beta" not in prompts[0]
    assert "⟦CUSTOM_PRIVACY#1⟧" in prompts[0] and "⟦CUSTOM_PRIVACY#2⟧" in prompts[0]
    assert response.analysis == "customer-alpha / customer-beta"
    assert response.mapping_table == {"⟦CUSTOM_PRIVACY#1⟧":"customer-alpha",
                                      "⟦CUSTOM_PRIVACY#2⟧":"customer-beta"}


def test_disabled_explicit_rule_has_no_effect():
    sanitized, mapping = server.sanitize_logs(["soc_acme_id"], False,
                                              custom_regex_rules=[rule("acme", enabled=False)])
    assert sanitized == ["soc_acme_id"] and mapping == {}
