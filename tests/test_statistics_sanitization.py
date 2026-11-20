import json
import asyncio

import server


def sample_statistics():
    return [{
        "indexPattern": "logs-*",
        "summary": {"query": "user:alice", "filters": ["Category=Logon"], "timeFrame": "last 5m"},
        "sampled": 10,
        "total": 20,
        "fields": [
            {"field": "Event_Ip", "count": 8, "percentage": 80,
             "topValues": [{"value": "203.0.113.9", "count": 4, "percentage": 40}]},
            {"field": "username", "count": 7, "percentage": 70,
             "topValues": [{"value": "alice", "count": 3, "percentage": 30}]},
        ],
    }]


def test_statistics_field_matching_ignores_case_and_punctuation():
    sanitized, mapping = server.sanitize_logs(
        [json.dumps(sample_statistics())],
        enable_pattern=False,
        statistics_fields_to_hide=["event-ip"],
    )
    parsed = json.loads(sanitized[0])
    ip_value = parsed[0]["fields"][0]["topValues"][0]["value"]
    username_value = parsed[0]["fields"][1]["topValues"][0]["value"]
    assert ip_value.startswith("⟦Event_Ip#")
    assert username_value == "alice"
    assert list(mapping.values()) == ["203.0.113.9"]
    assert parsed[0]["fields"][0]["count"] == 8
    assert parsed[0]["summary"]["query"] == "user:alice"


def test_prompt_labels_statistics_as_aggregate_evidence():
    stats_json = json.dumps(sample_statistics())
    prompt = server.build_prompt(["{}"], "case context", stats_json, None, None, False)
    assert "Additional Analyst Context" in prompt
    assert "Search Field Statistics (aggregate evidence, not individual events)" in prompt
    assert stats_json in prompt


def test_statistics_only_analysis_is_accepted():
    request = server.LogAnalysisRequest(
        logs=[], mode="sanitize_only", field_statistics=sample_statistics()
    )
    result = asyncio.run(server._analyze_logs(request))
    assert result.analysis == "[Sanitization completed]"


def test_statistics_only_prompt_explains_that_events_are_absent():
    stats_json = json.dumps(sample_statistics())
    prompt = server.build_prompt([], None, stats_json, None, None, False)
    assert "No individual events were supplied" in prompt
    assert "Search Field Statistics" in prompt


def test_statistics_iocs_use_top_values_not_query_metadata():
    statistics = sample_statistics()
    statistics[0]["summary"]["query"] = "domain:query-only.example.com"
    statistics[0]["fields"][0]["topValues"][0]["value"] = "8.8.8.8"
    text = server.statistics_top_values_text(json.dumps(statistics))
    assert "8.8.8.8" in text
    assert "query-only.example.com" not in text


def test_log_and_statistics_iocs_are_enriched_once(monkeypatch):
    calls = []

    async def fake_lookup(_client, ioc, ioc_type, *_args, **_kwargs):
        calls.append((ioc, ioc_type))
        return {"ioc": ioc, "type": ioc_type, "verdict": "unknown",
                "sources": {"whois": {"status": "ok"}}, "cached": False}

    monkeypatch.setattr(server, "lookup_ioc", fake_lookup)
    monkeypatch.setattr(server, "_save_threat_intel_cache", lambda: None)
    server.threat_intel_cache.clear()
    statistics = [{"fields": [
        {"field": "source.ip", "topValues": [
            {"value": "8.8.8.8"}, {"value": "1.1.1.1"}
        ]},
        {"field": "destination.domain", "topValues": [{"value": "example.com"}]},
    ]}]
    _, findings = asyncio.run(server.enrich_with_threat_intel(
        ["source=8.8.8.8 domain=Example.COM"], None, None, None,
        enable_virustotal=False, enable_abuseipdb=False, enable_whois=True,
        statistics_text=json.dumps(statistics),
    ))
    assert calls.count(("8.8.8.8", "ip")) == 1
    assert calls.count(("1.1.1.1", "ip")) == 1
    assert len([call for call in calls if call[1] == "domain"]) == 1
    assert len(findings) == 3
