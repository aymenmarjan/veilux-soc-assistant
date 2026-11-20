import asyncio
import base64
import json
from unittest.mock import patch

import server
from fastapi import HTTPException
from secret_detection import MECHANISMS, apply_custom_rules, detect_secrets, redact_findings


PASSWORD = "testpassabcabcxyz"
COMMAND = r'net use Z: "\\FILESRV\SharedFolder" /user:EXAMPLE\analyst ' + PASSWORD + ' /persistent:no'


def test_net_use_decoded_and_json_duplicate_spans():
    event = {"_source": {"CommandLine": COMMAND, "message": "Process Create:\n" + COMMAND}}
    raw = json.dumps(event)
    protected, mapping, findings = server.protect_secret_inputs([raw])
    assert sum(f["kind"] == "windows_net_use_password" for f in findings) == 2
    assert PASSWORD not in protected[0]
    assert protected[0].count("⟦SECRET#1⟧") == 2
    parsed = json.loads(protected[0])
    assert "⟦SECRET#1⟧" in parsed["_source"]["CommandLine"]


def test_net_use_variants_and_negative_controls():
    positives = {
        r'net.exe use "\\FILE\A B" "space pass!" /user:a@b.example': "space pass!",
        r'C:\Windows\System32\net.exe USE Z: \\F\S p@ss /USER:EXAMPLE\a': "p@ss",
        r'"C:\Program Files\Tools\net.exe" use Z: \\F\S quotedpath /user:a@example.test': "quotedpath",
        r'cmd.exe /c net use Z: \\F\S tiny /user:example.org\a': "tiny",
        r'net use Z: \\F\S /user:EXAMPLE\a 550e8400-e29b-41d4-a716-446655440000': "550e8400-e29b-41d4-a716-446655440000",
    }
    for command, password in positives.items():
        assert any(f.value == password and f.confidence == "high" for f in detect_secrets(command))
    for command in (r'net use Z: \\F\S /user:EXAMPLE\a', r'net use Z: \\F\S * /user:a',
                    r'net use Z: /delete', r'net use Z: \\F\S /smartcard', 'net user alice password'):
        assert not any(f.kind == "windows_net_use_password" for f in detect_secrets(command))


def test_short_lowercase_heuristic_is_independent_and_uncertain():
    config = {name: False for name in MECHANISMS}
    config["heuristics"] = True
    findings = detect_secrets("neutral " + PASSWORD, config)
    assert any(f.value == PASSWORD and f.confidence == "ambiguous" for f in findings)
    assert not detect_secrets("neutral ordinarymetadata", config)


def test_metadata_context_and_field_exclusion_preserve_keyword_masking():
    event = {"_index": "logs-bluebird-windows-2026.08.02", "_id": "documentidentifierxyz",
             "_source": {"provider": "Microsoft-Windows-Sysmon", "tags": ["ingest_pipeline_default_applied"]}}
    raw = json.dumps(event)
    findings = detect_secrets(raw, field_exclusions=[{"path": "_index", "enabled": True}])
    assert not [f for f in findings if f.confidence == "ambiguous"]
    sanitized, _ = server.sanitize_logs([raw], enable_pattern=False, custom_keywords={"bluebird": "x7q2"})
    assert json.loads(sanitized[0])["_index"] == "logs-⟦x7q2⟧-windows-2026.08.02"
    strong = detect_secrets(json.dumps({"_index": "password=" + PASSWORD}), field_exclusions=[{"path": "_index", "enabled": True}])
    assert any(f.value == PASSWORD and f.confidence == "high" for f in strong)
    repeated = json.dumps({"_id": PASSWORD, "message": PASSWORD})
    scoped = detect_secrets(repeated, field_exclusions=[{"path": "_id", "enabled": True}])
    assert len([f for f in scoped if f.value == PASSWORD and f.confidence == "ambiguous"]) == 1
    dotted = json.dumps({"_source": {"candidate": [PASSWORD]}, "other": {"candidate": [PASSWORD]}})
    dotted_findings = detect_secrets(dotted, field_exclusions=[{"path": "_source.candidate", "enabled": True}])
    assert len([f for f in dotted_findings if f.value == PASSWORD and f.confidence == "ambiguous"]) == 1


def test_decoder_deduplicates_metadata_and_assignment_form():
    batch = json.dumps([{"provider": "Microsoft-Windows-Security-Auditing"} for _ in range(150)])
    detect_secrets(batch)  # must not exhaust the unique decoding-work budget
    encoded = base64.b64encode(b"password=decoded-synthetic-secret").decode()
    findings = detect_secrets("payload=" + encoded)
    assert any(f.kind == "encoded credential" and f.value == encoded for f in findings)
    hexadecimal = b"password=hex-synthetic-secret".hex()
    assert any(f.kind == "encoded credential" and f.value == hexadecimal for f in detect_secrets("payload=" + hexadecimal))
    nested = base64.b64encode(hexadecimal.encode()).decode()
    assert any(f.kind == "encoded credential" and f.value == nested for f in detect_secrets("blob " + nested))


def test_regex_modes_and_restorable_privacy_mapping():
    full = [{"id": "full", "enabled": True, "pattern": "acme", "flags": "", "action": "hide_secret", "scope": "all", "mode": "full_value", "capture_group": 0}]
    findings = apply_custom_rules("acme soc_acme_id", [], full)
    assert [f.start for f in findings] == [0]
    json_findings = apply_custom_rules(json.dumps({"exact": "acme", "embedded": "prefix acme suffix"}), [], full)
    assert len(json_findings) == 1 and json_findings[0].value == "acme"
    substring = [{**full[0], "id": "substring", "mode": "substring"}]
    assert len(apply_custom_rules("acme soc_acme_id", [], substring)) == 2
    privacy = [{**full[0], "id": "privacy", "action": "hide_privacy"}]
    sanitized, mapping = server.sanitize_logs(["acme soc_acme_id"], enable_pattern=False, custom_regex_rules=privacy)
    assert sanitized[0].startswith("⟦CUSTOM_PRIVACY#1⟧") and "acme" in mapping.values()


def test_actual_ai_prompt_masks_duplicate_net_use_password():
    sent = []
    async def fake_ai(prompt, _key):
        sent.append(prompt)
        return "safe"
    raw = json.dumps({"CommandLine": COMMAND, "message": COMMAND})
    request = server.LogAnalysisRequest(logs=[raw], mode="groq", api_key="test", sanitize=False)
    with patch.object(server, "call_groq_ai", new=fake_ai):
        response = asyncio.run(server.analyze_logs(request))
    assert len(sent) == 1 and PASSWORD not in sent[0]
    assert sent[0].count("⟦SECRET#1⟧") >= 2
    assert response.mapping_table["⟦SECRET#1⟧"] == server.PROTECTED_SECRET_LABEL
    assert PASSWORD not in response.mapping_table.values()


def test_sanitize_mapping_lists_secret_without_disclosing_original():
    result = asyncio.run(server.sanitize_endpoint(server.SanitizationRequest(
        logs=["password=synthetic-map-secret"], enable_pattern_sanitization=False
    )))
    assert result["mapping_table"] == {"⟦SECRET#1⟧": server.PROTECTED_SECRET_LABEL}
    assert "synthetic-map-secret" not in json.dumps(result["mapping_table"])


def test_custom_hidden_ioc_is_blocked_before_manual_ti():
    rules = [{"id": "domain-hide", "enabled": True, "pattern": r"hidden\.example", "flags": "", "action": "hide_secret", "scope": "all", "mode": "full_value", "capture_group": 0}]
    request = server.ThreatIntelLookupRequest(ioc="hidden.example", custom_regex_rules=rules)
    try:
        asyncio.run(server.threat_intel_lookup_endpoint(request))
        assert False, "custom-hidden IOC must be rejected"
    except HTTPException as error:
        assert error.status_code == 400


def test_feedback_custom_hide_is_persisted_only_as_placeholder(tmp_path):
    target = tmp_path / "feedback.json"
    old_data = server.training_data
    server.training_data = {"feedback_entries": []}
    rules = [{"id": "feedback-hide", "enabled": True, "pattern": "private-feedback", "flags": "", "action": "hide_secret", "scope": "all", "mode": "full_value", "capture_group": 0}]
    try:
        with patch.object(server, "FEEDBACK_FILE", str(target)):
            asyncio.run(server.submit_feedback(server.FeedbackRequest(original_log="private-feedback", ai_response="safe", user_correction="safe", custom_regex_rules=rules)))
        assert "private-feedback" not in target.read_text()
    finally:
        server.training_data = old_data


def test_privacy_substring_reaches_ai_redacted():
    sent = []
    rules = [{"id":"privacy", "pattern":"acme", "action":"hide_privacy", "scope":"all", "mode":"substring", "enabled":True}]
    async def ai(prompt, _key): sent.append(prompt); return "ok"
    disabled = {name: False for name in MECHANISMS}
    request = server.LogAnalysisRequest(logs=["soc_acme_id"], mode="groq", api_key="x", sanitize=True,
                                        enable_pattern_sanitization=False, secret_protection=disabled, custom_regex_rules=rules)
    with patch.object(server, "call_groq_ai", ai): response = asyncio.run(server.analyze_logs(request))
    assert "soc_acme_id" not in sent[0] and "soc_⟦CUSTOM_PRIVACY#1⟧_id" in sent[0]
    assert response.mapping_table["⟦CUSTOM_PRIVACY#1⟧"] == "acme"


def test_privacy_numeric_json_value():
    rules = [{"id":"number", "pattern":"12345", "action":"hide_privacy", "scope":"all", "mode":"full_value", "enabled":True}]
    sanitized, mapping = server.sanitize_logs(['{"customer":12345,"other":7,"active":true}'], False, custom_regex_rules=rules)
    parsed = json.loads(sanitized[0])
    assert parsed == {"customer":"⟦CUSTOM_PRIVACY#1⟧", "other":7, "active":True}
    assert mapping == {"⟦CUSTOM_PRIVACY#1⟧":"12345"}
    sent = []
    async def ai(prompt, _key): sent.append(prompt); return "ok"
    disabled = {name: False for name in MECHANISMS}
    request = server.LogAnalysisRequest(logs=['{"customer":12345,"other":7}'], mode="groq", api_key="x", sanitize=True,
        enable_pattern_sanitization=False, secret_protection=disabled, custom_regex_rules=rules)
    with patch.object(server, "call_groq_ai", ai): asyncio.run(server.analyze_logs(request))
    fragment = sent[0].split("```json\n", 1)[1].split("\n```", 1)[0]
    assert json.loads(fragment) == {"customer":"⟦CUSTOM_PRIVACY#1⟧", "other":7}


def test_privacy_hide_blocks_manual_and_auto_ti():
    rules = [{"id":"privacy-domain", "pattern":r"client\.example\.com", "action":"hide_privacy", "scope":"all", "mode":"full_value", "enabled":True}]
    request = server.ThreatIntelLookupRequest(ioc="client.example.com", virustotal_api_key="x", custom_regex_rules=rules)
    try:
        asyncio.run(server.threat_intel_lookup_endpoint(request)); assert False
    except HTTPException as error:
        assert error.status_code == 400
    captured = []
    async def ti(logs, notes, *args, **kwargs): captured.extend(logs); return "", []
    async def ai(_prompt, _key): return "ok"
    analysis = server.LogAnalysisRequest(logs=["visit client.example.com"], mode="groq", api_key="x", sanitize=False,
        enable_threat_intel=True, enable_whois=True, custom_regex_rules=rules)
    with patch.object(server, "enrich_with_threat_intel", ti), patch.object(server, "call_groq_ai", ai):
        asyncio.run(server.analyze_logs(analysis))
    assert "client.example.com" not in "".join(captured)


def test_net_use_quoted_account_punctuation_and_evidence_integrity():
    commands = [
        (r'net use Z: \\F\S /user:"EXAMPLE\analyst" tiny /persistent:no', "tiny"),
        (r'net use Z: \\F\S "trailing," /user:a', "trailing,"),
        (r'net use Z: \\F\S "ending}" /user:a && echo done', "ending}"),
    ]
    for command, password in commands:
        finding = [f for f in detect_secrets(command) if f.kind == "windows_net_use_password"]
        assert len(finding) == 1 and finding[0].value == password
        redacted, _, _ = redact_findings(command, finding)
        assert password not in redacted
    raw = json.dumps({"CommandLine":commands[0][0], "message":commands[0][0], "tinyCount":5, "filename":"tinyarchive.exe"})
    protected, _, _ = server.protect_secret_inputs([raw])
    parsed = json.loads(protected[0])
    assert parsed["tinyCount"] == 5 and parsed["filename"] == "tinyarchive.exe"
    assert "tiny" not in parsed["CommandLine"] and "tiny" not in parsed["message"]
    sent = []
    async def ai(prompt, _key): sent.append(prompt); return "ok"
    request = server.LogAnalysisRequest(logs=[raw], mode="groq", api_key="x", sanitize=False)
    with patch.object(server, "call_groq_ai", ai): asyncio.run(server.analyze_logs(request))
    assert " tiny " not in sent[0] and "tinyarchive.exe" in sent[0] and '"tinyCount": 5' in sent[0]


def test_lowercase_and_configured_short_heuristics_without_context():
    config = {name: False for name in MECHANISMS}; config["heuristics"] = True
    low = detect_secrets("neutral abcdecffcefgcefe", config)
    assert any(f.confidence == "ambiguous" and "unusual lowercase" in f.reason for f in low)
    short = detect_secrets("neutral AB12cd34", config, heuristic_config={"min_length":8, "entropy_threshold":2})
    assert any(f.value == "AB12cd34" and f.confidence == "ambiguous" for f in short)


def test_metadata_values_and_json_keys_are_not_candidates():
    raw = json.dumps({"SourceName":"Microsoft-Windows-Sysmon", "event_prog":"Microsoft-Windows-Sysmon",
                      "ParentProcessGuid":"550e8400-e29b-41d4-a716-446655440000"})
    findings = detect_secrets(raw)
    assert not any(f.value in {"Microsoft-Windows-Sysmon", "ParentProcessGuid"} for f in findings)
    assert any(f.value == "550e8400-e29b-41d4-a716-446655440000" and f.confidence == "ambiguous" for f in findings)
    both = json.dumps({"event.hash":"abcdecffcefgcefe", "event":{"hash":"qwertymnbvcxzpl"}})
    literal = detect_secrets(both, field_exclusions=[{"path":"event.hash", "match_mode":"key_anywhere"}])
    assert not any(f.value == "abcdecffcefgcefe" for f in literal)
    assert any(f.value == "qwertymnbvcxzpl" for f in literal)
    nested = detect_secrets(both, field_exclusions=[{"path":"event.hash", "match_mode":"exact_path"}])
    assert any(f.value == "abcdecffcefgcefe" for f in nested)
    assert not any(f.value == "qwertymnbvcxzpl" for f in nested)


def test_feedback_current_policy_before_send():
    old = server.training_data
    server.training_data = {"feedback_entries":[{"user_correction":"legacy private-feedback guidance", "status":"approved"}]}
    rules = [{"id":"current-feedback-hide", "pattern":"private-feedback", "action":"hide_privacy", "scope":"all", "mode":"substring", "enabled":True}]
    sent = []
    async def ai(prompt, _key): sent.append(prompt); return "ok"
    try:
        request = server.LogAnalysisRequest(logs=["safe"], mode="groq", api_key="x", sanitize=False, custom_regex_rules=rules)
        with patch.object(server, "call_groq_ai", ai): asyncio.run(server.analyze_logs(request))
        assert "private-feedback" not in sent[0] and "CUSTOM_PRIVACY" in sent[0]
    finally:
        server.training_data = old
