import asyncio
import json
import threading
import time
from unittest.mock import patch

import pytest

import server
from secret_detection import MECHANISMS, detect_secrets


def rule(pattern, action="hide_privacy", mode="full_value", capture=0, **extra):
    result = {"id": "deep", "pattern": pattern, "action": action, "scope": "all",
              "mode": mode, "capture_group": capture, "enabled": True}
    result.update(extra)
    return result


def only(*enabled):
    return {name: name in enabled for name in MECHANISMS}


def analyze(logs, *, rules=(), config=None, feedback=(), reply="ok", **kwargs):
    prompts = []
    async def ai(prompt, _key): prompts.append(prompt); return reply
    sanitize = kwargs.pop("sanitize", False)
    request = server.LogAnalysisRequest(logs=logs, mode="groq", api_key="synthetic",
                                        sanitize=sanitize, custom_regex_rules=list(rules),
                                        secret_protection=config or server.SecretProtection(), **kwargs)
    stored = {"feedback_entries": [{"user_correction": item, "status": "approved"} for item in feedback]}
    with patch.object(server, "training_data", stored), patch.object(server, "call_groq_ai", ai):
        response = asyncio.run(server.analyze_logs(request))
    return prompts[0], response


def prompt_log(prompt):
    return prompt.split("Security Logs:\n```json\n", 1)[1].split("\n```", 1)[0]


def test_later_inner_secret_revokes_larger_privacy_original():
    prompts = []
    async def ti(*_args, **_kwargs): return "password=tiny", []
    async def ai(prompt, _key): prompts.append(prompt); return "⟦CUSTOM_PRIVACY#1⟧"
    request = server.LogAnalysisRequest(
        logs=["account tiny"], mode="groq", api_key="x", sanitize=False,
        enable_threat_intel=True, enable_whois=True,
        custom_regex_rules=[rule("account tiny")])
    with patch.object(server, "training_data", {"feedback_entries": []}), \
         patch.object(server, "enrich_with_threat_intel", ti), \
         patch.object(server, "call_groq_ai", ai):
        response = asyncio.run(server.analyze_logs(request))
    assert "tiny" not in prompts[0] and "CUSTOM_PRIVACY" not in prompts[0]
    assert response.analysis == "⟦CUSTOM_PRIVACY#1⟧"
    assert "account tiny" not in (response.mapping_table or {}).values()


def test_escaped_feedback_assignment_revokes_logical_privacy_identity():
    privacy = [rule("acme")]
    prompt, response = analyze(["acme"], rules=privacy,
                               feedback=['{"password":"a\\u0063me"}'],
                               reply="⟦CUSTOM_PRIVACY#1⟧")
    assert "CUSTOM_PRIVACY" not in prompt and "acme" not in prompt
    assert response.analysis == "⟦CUSTOM_PRIVACY#1⟧"
    assert "acme" not in (response.mapping_table or {}).values()


@pytest.mark.parametrize("lexeme", ["1e3", "-0", "1.2300e+45",
                                     "0.12345678901234567890123456789",
                                     "999999999999999999999999999999", "true", "null"])
def test_selected_json_field_uses_exact_scalar_record_in_ai_payload(lexeme):
    source = '{"customer":' + lexeme + ',"other":7}'
    prompt, response = analyze([source], json_keys_to_hide=["customer"], sanitize=True,
                               enable_pattern_sanitization=False)
    protected = prompt_log(prompt)
    parsed = json.loads(protected)
    assert parsed["customer"].startswith("⟦customer#") and parsed["other"] == 7
    assert lexeme not in protected.split('"other"', 1)[0]
    assert any(value == lexeme for value in (response.mapping_table or {}).values())


@pytest.mark.parametrize("action", ["hide_secret", "hide_privacy"])
def test_token_capture_uses_enclosing_match_not_capture_boundaries(action):
    rules = [rule(r"customer_(\d+)", action=action, mode="token", capture=1)]
    prompt, _response = analyze(['{"ref":"customer_12345"}'], rules=rules,
                                config=only(), allowed_ambiguous_secrets=["customer_12345"])
    value = json.loads(prompt_log(prompt))["ref"]
    assert "12345" not in value and "customer_" in value


def test_escaped_known_provider_token_is_strong_despite_keep():
    token = "ghp_" + "A" * 36
    source = '{"ref":"\\u0067' + token[1:] + '"}'
    prompt, _ = analyze([source], config=only("known_tokens"),
                        allowed_ambiguous_secrets=[token])
    assert token not in json.loads(prompt_log(prompt))["ref"]
    assert "⟦SECRET#" in prompt


def test_manual_substring_hide_maps_decoded_json_spans():
    prompt, _ = analyze(['{"ref":"x\\u0061cmey"}', '{"ref":"xacmey"}'],
                        config=only(), force_hide_values=["acme"])
    logs = prompt_log(prompt).split("\n---\n")
    assert all("acme" not in json.loads(item)["ref"] for item in logs)
    assert all("⟦SECRET#" in item for item in logs)


def test_empty_structured_containers_survive_mixed_batch_and_endpoint():
    logs = ['{}', '[]', '{"empty":{}}', '{"host":"example.org"}']
    sanitized, _ = server.sanitize_logs(logs, True)
    assert [json.loads(item) for item in sanitized[:3]] == [{}, [], {"empty": {}}]
    request = server.SanitizationRequest(logs=logs, enable_pattern_sanitization=True)
    response = asyncio.run(server.sanitize_endpoint(request))
    assert [json.loads(item) for item in response["sanitized_logs"][:3]] == [{}, [], {"empty": {}}]


def test_structured_response_restoration_preserves_decimal_and_string_root():
    decimal = "0.12345678901234567890123456789"
    reply = '{"customer":"⟦CUSTOM_PRIVACY#1⟧","ratio":' + decimal + '}'
    _prompt, response = analyze(["acme"], rules=[rule("acme")],
                                config=only(), reply=reply)
    assert decimal in response.analysis and json.loads(response.analysis)["customer"] == "acme"
    _prompt, response = analyze(['quote"value'], rules=[rule(r'quote"value')],
                                config=only(), reply='"⟦CUSTOM_PRIVACY#1⟧"')
    assert json.loads(response.analysis) == 'quote"value'


def test_detector_exclusion_cannot_disable_strong_assignment():
    exclusion = rule("tiny", action="exclude", scope="detectors",
                     detector_ids=["assigned credential"])
    request = server.LogAnalysisRequest(logs=["password=tiny"], mode="sanitize_only",
                                        custom_regex_rules=[exclusion])
    response = asyncio.run(server.analyze_logs(request))
    assert "tiny" not in response.sanitized_log and "⟦SECRET#" in response.sanitized_log


@pytest.mark.parametrize("prefix", ["doo_v1_", "dop_v1_", "dor_v1_"])
def test_digitalocean_formats_have_isolated_exact_known_token_spans(prefix):
    value = prefix + "a" * 64
    findings = detect_secrets("before " + value + " after", only("known_tokens"))
    assert any(f.value == value and f.start == 7 and f.end == 7 + len(value)
               and f.confidence == "high" for f in findings)
    assert not any(f.value == value[:-1] for f in detect_secrets(value[:-1], only("known_tokens")))


def test_distinct_assignment_scaling_and_cooperative_cancellation():
    config = only("assignments")
    durations = []
    for count in (200, 600, 800, 1000):
        source = json.dumps([{"password": f"synth{i:05d}abc"} for i in range(count)])
        started = time.perf_counter()
        protected, mapping, _ = server.protect_secret_inputs([source], config=config)
        durations.append(time.perf_counter() - started)
        assert len(mapping) == count and all(f"synth{i:05d}abc" not in protected[0] for i in range(count))
    assert durations[-1] < 5.0
    cancelled = threading.Event(); cancelled.set()
    source = json.dumps([{"password": f"cancel{i:05d}abc"} for i in range(1000)])
    started = time.perf_counter()
    with pytest.raises(TimeoutError):
        server.protect_secret_inputs([source], config=config, cancel_event=cancelled)
    assert time.perf_counter() - started < 1.0
