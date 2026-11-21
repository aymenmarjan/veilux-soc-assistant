"""VEILUX 1.0.1 regressions: model choice and discovery, defanging, and the
backend side of log separators. All values are synthetic; outbound HTTP is a
mock transport, so no provider is contacted.
"""
import asyncio
import json
import time
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient

import server

REAL_CLIENT = httpx.AsyncClient
LOG = '{"user":"alice","src_ip":"10.1.2.3","event":"failed logon"}'
ANSWER = {"choices": [{"message": {"content": "OK"}}]}


def patched(handler):
    def client(*args, **kwargs):
        return REAL_CLIENT(*args, transport=httpx.MockTransport(handler), **kwargs)
    return patch.object(server.httpx, "AsyncClient", client)


def api():
    return TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN})


def analyze(handler, **body):
    with patched(handler), patch.object(server, "training_data", {"feedback_entries": []}), \
            patch.object(server, "threat_intel_cache", {}), patch.object(server, "_save_threat_intel_cache", lambda: None):
        return api().post("/analyze", json={"logs": [LOG], "mode": "groq", "api_key": "synthetic-key", **body})


# ---- 1. No built-in model IDs; the analyst's choice is used, never swapped ----

def test_no_model_id_is_built_in_for_any_provider():
    for name, endpoint in server.AI_PROVIDERS.values():
        assert "llama" not in endpoint and "gemini-2" not in endpoint
    source = open(server.__file__, encoding="utf-8").read()
    for retired in ("llama-3.3-70b-versatile", "Qwen2.5-72B", "claude-sonnet-4-6", '"deepseek-chat"', "gemini-2.5-flash"):
        assert retired not in source, retired


@pytest.mark.parametrize("mode", ["groq", "deepseek", "together", "gemini", "claude"])
def test_analysis_without_a_chosen_model_is_refused_before_anything_is_sent(mode):
    sent = []
    response = analyze(lambda r: sent.append(r) or httpx.Response(200, json=ANSWER), mode=mode)
    assert response.status_code == 400 and "Choose a" in response.json()["detail"], response.text
    assert "Load models" in response.json()["detail"]
    assert [r for r in sent if r.url.host != "rdap.org"] == []


@pytest.mark.parametrize("mode, host, path", [
    ("groq", "api.groq.com", "/openai/v1/chat/completions"),
    ("deepseek", "api.deepseek.com", "/v1/chat/completions"),
    ("together", "api.together.xyz", "/v1/chat/completions"),
])
def test_the_chosen_model_is_sent_and_recorded(mode, host, path):
    sent = []
    def provider(request):
        sent.append(request)
        return httpx.Response(200, json=ANSWER)
    response = analyze(provider, mode=mode, model="synthetic/model-2026")
    assert response.status_code == 200, response.text
    assert (sent[0].url.host, sent[0].url.path) == (host, path)
    assert json.loads(sent[0].content)["model"] == "synthetic/model-2026"
    assert response.json()["outbound"]["ai"]["model"] == "synthetic/model-2026"


def test_gemini_and_claude_use_the_chosen_model_and_keep_keys_out_of_the_url():
    sent = []
    def provider(request):
        sent.append(request)
        if request.url.host == "api.anthropic.com":
            return httpx.Response(200, json={"content": [{"text": "OK"}]})
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": "OK"}]}, "finishReason": "STOP"}]})
    with patched(provider):
        assert asyncio.run(server.call_gemini_ai("synthetic prompt", "synthetic-key", "models/gemini-synthetic")) == "OK"
        assert asyncio.run(server.call_claude_ai("synthetic prompt", "synthetic-key", "claude-synthetic")) == "OK"
    assert sent[0].url.path == "/v1beta/models/gemini-synthetic:generateContent"
    assert "synthetic-key" not in str(sent[0].url) and sent[0].headers["x-goog-api-key"] == "synthetic-key"
    assert json.loads(sent[1].content)["model"] == "claude-synthetic"


def test_an_unavailable_model_is_explained_and_no_other_model_is_tried():
    sent = []
    def provider(request):
        sent.append(request)
        return httpx.Response(404, json={"error": {"message": "The model `retired-model` does not exist or you do not have access to it.",
                                                   "type": "invalid_request_error", "code": "model_not_found"}})
    response = analyze(provider, model="retired-model")
    detail = response.json()["detail"]
    assert response.status_code == 400 and "retired-model" in detail and "No other model was tried" in detail
    assert "Load models" in detail
    assert len([r for r in sent if r.url.host == "api.groq.com"]) == 1


@pytest.mark.parametrize("status, body, wording", [
    (401, {"error": {"message": "Invalid API Key"}}, "refused the API key"),
    (403, {"error": {"message": "Forbidden"}}, "refused the API key"),
    (400, {"error": {"message": "model `x` has been decommissioned and is no longer supported"}}, "not available to this API key"),
    (429, {"error": {"message": "Rate limit reached"}}, "rate-limiting"),
])
def test_provider_failures_are_actionable(status, body, wording):
    response = analyze(lambda r: httpx.Response(status, json=body), model="synthetic-model")
    assert wording in response.json()["detail"], response.text


def test_invalid_model_ids_are_refused():
    response = analyze(lambda r: httpx.Response(200, json=ANSWER), model="bad model\nid")
    assert response.status_code == 400 and "not a valid model ID" in response.json()["detail"]


# ---- Model discovery: only the key is sent, never logs ----

def discovery(provider, handler, **body):
    with patched(handler):
        return api().post(f"/providers/{provider}/models", json={"api_key": "synthetic-key", **body})


@pytest.mark.parametrize("provider, url, header, value", [
    ("groq", "https://api.groq.com/openai/v1/models", "authorization", "Bearer synthetic-key"),
    ("deepseek", "https://api.deepseek.com/models", "authorization", "Bearer synthetic-key"),
    ("together", "https://api.together.xyz/v1/models", "authorization", "Bearer synthetic-key"),
    ("gemini", "https://generativelanguage.googleapis.com/v1beta/models", "x-goog-api-key", "synthetic-key"),
    ("claude", "https://api.anthropic.com/v1/models", "x-api-key", "synthetic-key"),
])
def test_model_discovery_sends_only_the_key(provider, url, header, value):
    sent = []
    def handler(request):
        sent.append(request)
        return httpx.Response(200, json={"data": [], "models": []} if provider != "together" else [])
    response = discovery(provider, handler)
    assert response.status_code == 200, response.text
    assert len(sent) == 1 and sent[0].method == "GET" and str(sent[0].url).split("?")[0] == url
    assert sent[0].headers[header] == value and sent[0].content == b""
    assert "alice" not in str(sent[0].url)


def test_groq_list_keeps_chat_models_and_drops_inactive_audio_and_guard_models():
    data = {"object": "list", "data": [
        {"id": "synthetic-chat-70b", "active": True, "context_window": 131072, "owned_by": "Synthetic"},
        {"id": "synthetic-old-8b", "active": False},
        {"id": "whisper-large-v3", "active": True},
        {"id": "synthetic-guard-4", "active": True},
        {"id": "playai-tts", "active": True}]}
    models = discovery("groq", lambda r: httpx.Response(200, json=data)).json()["models"]
    assert [m["id"] for m in models] == ["synthetic-chat-70b"] and models[0]["context_length"] == 131072


def test_together_lists_chat_models_only():
    data = [{"id": "org/chat-model", "type": "chat", "display_name": "Chat model"},
            {"id": "org/embedding", "type": "embedding"}, {"id": "org/image", "type": "image"}]
    models = discovery("together", lambda r: httpx.Response(200, json=data)).json()["models"]
    assert [(m["id"], m["name"]) for m in models] == [("org/chat-model", "Chat model")]


def test_gemini_list_pages_and_keeps_generate_content_models():
    pages = [
        {"models": [{"name": "models/gemini-synthetic-pro", "displayName": "Gemini Synthetic Pro",
                     "supportedGenerationMethods": ["generateContent", "countTokens"], "inputTokenLimit": 1048576},
                    {"name": "models/text-embedding-synthetic", "supportedGenerationMethods": ["embedContent"]}],
         "nextPageToken": "page-2"},
        {"models": [{"name": "models/gemini-synthetic-flash", "supportedGenerationMethods": ["generateContent"]}]}]
    seen = []
    def handler(request):
        seen.append(dict(request.url.params))
        return httpx.Response(200, json=pages[len(seen) - 1])
    models = discovery("gemini", handler).json()["models"]
    assert sorted(m["id"] for m in models) == ["gemini-synthetic-flash", "gemini-synthetic-pro"]
    assert seen[1]["pageToken"] == "page-2"


def test_claude_list_pages_with_after_id():
    pages = [{"data": [{"id": "claude-synthetic-a", "display_name": "Synthetic A"}], "has_more": True, "last_id": "claude-synthetic-a"},
             {"data": [{"id": "claude-synthetic-b", "display_name": "Synthetic B"}], "has_more": False}]
    seen = []
    def handler(request):
        seen.append(request)
        return httpx.Response(200, json=pages[len(seen) - 1])
    models = discovery("claude", handler).json()["models"]
    assert [m["id"] for m in models] == ["claude-synthetic-a", "claude-synthetic-b"]
    assert seen[0].headers["anthropic-version"] and seen[1].url.params["after_id"] == "claude-synthetic-a"


def test_discovery_errors_are_clear():
    assert "refused the API key" in discovery("groq", lambda r: httpx.Response(401, json={"error": {"message": "bad key"}})).json()["detail"]
    with patched(lambda r: httpx.Response(200, json={})):
        assert "API key first" in api().post("/providers/groq/models", json={}).json()["detail"]
        assert api().post("/providers/unknown/models", json={"api_key": "k"}).status_code == 404
    def unreachable(request):
        raise httpx.ConnectError("synthetic-internal-detail")
    response = discovery("deepseek", unreachable)
    assert response.status_code == 502 and "synthetic-internal-detail" not in response.text


def custom(endpoint, fmt="openai", **extra):
    return {"custom_provider": {"name": "Synthetic local", "api_format": fmt, "endpoint": endpoint, "model": "unset", **extra}}


@pytest.mark.parametrize("endpoint, fmt, listed", [
    ("http://localhost:11434/v1/chat/completions", "openai", "http://localhost:11434/v1/models"),
    ("http://10.0.0.5:1234/v1/chat/completions", "openai", "http://10.0.0.5:1234/v1/models"),
    ("https://gateway.corp.local/anthropic/v1/messages", "anthropic", "https://gateway.corp.local/anthropic/v1/models"),
    ("https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent", "gemini",
     "https://generativelanguage.googleapis.com/v1beta/models"),
])
def test_custom_and_local_services_list_their_models(endpoint, fmt, listed):
    sent = []
    def handler(request):
        sent.append(request)
        return httpx.Response(200, json={"data": [{"id": "local-model"}], "models": [
            {"name": "models/local-model", "supportedGenerationMethods": ["generateContent"]}]})
    response = discovery("custom", handler, **custom(endpoint, fmt))
    assert response.status_code == 200, response.text
    assert str(sent[0].url).split("?")[0] == listed and [m["id"] for m in response.json()["models"]] == ["local-model"]


def test_custom_discovery_refuses_metadata_and_unknown_shapes():
    sent = []
    handler = lambda r: sent.append(r) or httpx.Response(200, json={"data": []})
    refused = discovery("custom", handler, **custom("http://169.254.169.254/v1/chat/completions"))
    assert refused.status_code == 400 and "refused" in refused.json()["detail"]
    azure = discovery("custom", handler, **custom(
        "https://synthetic.openai.azure.com/openai/deployments/d/chat/completions?api-version=2024-02-01"))
    assert azure.status_code == 400 and "Enter the model ID" in azure.json()["detail"]
    assert sent == []


# ---- 2. Defanging ----

@pytest.mark.parametrize("original, defanged", [
    ("https://www.google.com/", "hxxps://www[.]google[.]com/"),
    ("https://203.0.113.45/login", "hxxps://203[.]0[.]113[.]45/login"),
    ("http://evil.example/x", "hxxp://evil[.]example/x"),
    ("HTTPS://WWW.GOOGLE.COM/a.php?x=1.2", "HXXPS://WWW[.]GOOGLE[.]COM/a.php?x=1.2"),
    ("visit https://user@evil.example.com:8443/path.html, then", "visit hxxps://user[@]evil[.]example[.]com:8443/path.html, then"),
    ("admin@example.com", "admin[@]example[.]com"),
    ("8.8.8.8 and 10.0.0.1", "8[.]8[.]8[.]8 and 10[.]0[.]0[.]1"),
    ("www.google.com", "www[.]google[.]com"),
    ("ftp://files.example.org/a", "ftp://files[.]example[.]org/a"),
    ("https://[2001:db8::1]:443/x", "hxxps://[2001:db8::1]:443/x"),
    ("https://www.google.com.", "hxxps://www[.]google[.]com."),
])
def test_urls_domains_and_ips_are_defanged_consistently(original, defanged):
    assert server.defang_text(original) == defanged
    assert server.refang_text(defanged) == original
    assert server.defang_text(defanged) == defanged  # defanging twice changes nothing


@pytest.mark.parametrize("text", ["C:\\Windows\\System32\\cmd.exe", "v1.0.1", "e.g. this", "file.txt", "net use \\\\share"])
def test_text_that_is_not_an_indicator_is_left_alone(text):
    assert server.defang_text(text) == text


def test_refang_reads_the_1_0_0_form_and_keeps_letter_case():
    assert server.refang_text("hXXps://evil[.]example/x") == "https://evil.example/x"
    assert server.refang_text("HXXP://EVIL[.]EXAMPLE") == "HTTP://EVIL.EXAMPLE"
    assert server.refang_text("2001[:]db8[:][:]1") == "2001:db8::1"


def test_defanging_long_text_takes_linear_time():
    # Each text was quadratic before the e-mail local part was bounded (64 characters).
    for text in ("a1." * 50000 + "1", "a.b_" * 40000, "x" * 70 + "@example.com"):
        started = time.perf_counter()
        server.defang_text(text)
        assert time.perf_counter() - started < 2, text[:20]
    assert server.defang_text("x" * 70 + "@example.com").endswith("[@]example[.]com")


def test_defang_endpoint_returns_the_original_unchanged():
    original = "https://www.google.com/ and 203.0.113.45"
    body = api().post("/defang", json={"text": original}).json()
    assert body["original"] == original and body["defanged"] == "hxxps://www[.]google[.]com/ and 203[.]0[.]113[.]45"
    assert api().post("/refang", json={"text": body["defanged"]}).json()["refanged"] == original


# ---- 3. Log separators reach the backend as separate logs ----

def test_separated_logs_are_analysed_as_separate_logs():
    sent = []
    def provider(request):
        sent.append(json.loads(request.content))
        return httpx.Response(200, json=ANSWER)
    logs = ['{"event":"first","user":"alice"}', '{"event":"second","user":"bob"}', '{"event":"third"}']
    with patched(provider), patch.object(server, "training_data", {"feedback_entries": []}):
        response = api().post("/analyze", json={"logs": logs, "mode": "sanitize_only", "sanitize": True})
    assert response.status_code == 200, response.text
    assert response.json()["sanitized_log"].count("---LOG SEPARATOR---") == 2
