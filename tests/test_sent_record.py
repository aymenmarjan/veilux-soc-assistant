"""The record of what left this computer matches what was actually sent."""
import json
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient
import server

REAL_CLIENT = httpx.AsyncClient
LOG = '{"user":"alice","src_ip":"10.1.2.3","dst_ip":"203.0.113.9","event":"failed logon"}'


def run(handler, **body):
    def client(*args, **kwargs):
        return REAL_CLIENT(*args, transport=httpx.MockTransport(handler), **kwargs)
    with patch.object(server.httpx, "AsyncClient", client), patch.object(server, "training_data", {"feedback_entries": []}), \
            patch.object(server, "threat_intel_cache", {}), patch.object(server, "_save_threat_intel_cache", lambda: None):
        return TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN}).post("/analyze", json={"logs": [LOG], "mode": "groq", "api_key": "synthetic-key", **body})


def test_ai_prompt_in_the_record_is_exactly_what_the_provider_received():
    sent = []

    def handler(request):
        sent.append(json.loads(request.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": "OK"}}]})
    response = run(handler)
    assert response.status_code == 200, response.text
    record = response.json()["outbound"]
    ai = record["ai"]
    assert (ai["provider"], ai["model"]) == ("Groq", "llama-3.3-70b-versatile")
    assert ai["endpoint"] == "https://api.groq.com/openai/v1/chat/completions"
    assert ai["outcome"] == "answered"
    assert ai["prompt"] == sent[0]["messages"][0]["content"]
    assert ai["characters"] == len(ai["prompt"])
    assert "alice" not in ai["prompt"] and "10.1.2.3" not in ai["prompt"]
    assert "synthetic-key" not in json.dumps(record)
    assert record["lookups"] == []


def test_lookups_say_whether_each_one_was_sent_or_cached():
    def handler(request):
        if request.url.host == "rdap.org":
            return httpx.Response(200, json={"name": "SYNTHETIC-NET"})
        return httpx.Response(200, json={"choices": [{"message": {"content": "OK"}}]})
    body = {"enable_threat_intel": True, "enable_virustotal": False, "enable_abuseipdb": False, "enable_whois": True}
    record = run(handler, **body).json()["outbound"]
    assert [(l["service"], l["indicator"], l["sent"]) for l in record["lookups"]] == [("whois", "203.0.113.9", True)]
    assert record["lookups"][0]["status"] == "sent, ok"


def test_a_failed_provider_call_is_still_recorded():
    def handler(request):
        return httpx.Response(401, json={"error": "bad key"})
    response = run(handler)
    assert response.status_code == 401
    data = response.json()
    assert data["detail"].startswith("Groq")
    assert data["outbound"]["ai"]["outcome"].startswith("failed: Groq")
    assert "alice" not in data["outbound"]["ai"]["prompt"]


def test_gemini_key_in_the_address_is_not_recorded():
    def handler(request):
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": "OK"}]}, "finishReason": "STOP"}]})
    record = run(handler, mode="gemini").json()["outbound"]
    assert record["ai"]["endpoint"].endswith(":generateContent")
    assert "synthetic-key" not in json.dumps(record)


def test_nothing_is_recorded_when_nothing_leaves():
    def handler(request):
        raise AssertionError("no request expected")
    response = run(handler, mode="sanitize_only")
    assert response.status_code == 200
    assert response.json()["outbound"] == {"ai": None, "lookups": []}


def test_manual_indicator_check_returns_its_record():
    def handler(request):
        return httpx.Response(200, json={"name": "SYNTHETIC-NET"})

    def client(*args, **kwargs):
        return REAL_CLIENT(*args, transport=httpx.MockTransport(handler), **kwargs)
    with patch.object(server.httpx, "AsyncClient", client), patch.object(server, "threat_intel_cache", {}), \
            patch.object(server, "_save_threat_intel_cache", lambda: None):
        data = TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN}).post("/threat-intel/lookup", json={
            "ioc": "203.0.113.9", "enable_virustotal": False, "enable_abuseipdb": False, "enable_whois": True}).json()
    assert [(l["service"], l["indicator"], l["sent"]) for l in data["outbound"]["lookups"]] == [("whois", "203.0.113.9", True)]
    assert data["outbound"]["ai"] is None
