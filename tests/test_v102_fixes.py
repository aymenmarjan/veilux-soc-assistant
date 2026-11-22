"""VEILUX 1.0.2 regressions: output limits, reasoning settings and answer
reading for the built-in providers, and safe error messages for connection
checks (CodeQL alert 32). All values are synthetic; outbound HTTP is a mock
transport, so no provider or SIEM is contacted.
"""
import json
from unittest.mock import patch

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import server

REAL_CLIENT = httpx.AsyncClient
LOG = '{"user":"alice","src_ip":"10.1.2.3","event":"failed logon"}'
KEY = "synthetic-provider-key-7f3a"
SECRET = "synthetic-secret-91c2"
HOSTS = {"api.groq.com", "api.deepseek.com", "api.together.xyz", "generativelanguage.googleapis.com",
         "api.anthropic.com", "openrouter.ai"}


def patched(handler):
    def client(*args, **kwargs):
        return REAL_CLIENT(*args, transport=httpx.MockTransport(handler), **kwargs)
    return patch.object(server.httpx, "AsyncClient", client)


def api():
    return TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN})


def analyze(reply, mode="deepseek", **body):
    """Runs one analysis against `reply`; returns the response and the provider requests."""
    sent = []
    def handler(request):
        if request.url.host not in HOSTS:
            return httpx.Response(404)
        sent.append(request)
        return reply(request) if callable(reply) else reply
    fields = {"openrouter_model": "synthetic/model"} if mode == "openrouter" else {"model": "synthetic-model"}
    with patched(handler), patch.object(server, "training_data", {"feedback_entries": []}), \
            patch.object(server, "threat_intel_cache", {}), patch.object(server, "_save_threat_intel_cache", lambda: None):
        response = api().post("/analyze", json={"logs": [LOG], "mode": mode, "api_key": KEY,
                                                "enable_threat_intel": False, **fields, **body})
    return response, [json.loads(r.content) for r in sent]


def chat(content, finish="stop", **message):
    return httpx.Response(200, json={"choices": [{"message": {"content": content, **message}, "finish_reason": finish}]})


# ---- Output limits: the old fixed 4,000 left reasoning models without an answer ----

@pytest.mark.parametrize("mode, field", [("groq", "max_completion_tokens"), ("deepseek", "max_tokens"),
                                         ("together", "max_tokens"), ("openrouter", "max_tokens")])
def test_openai_style_providers_send_the_default_or_chosen_output_limit(mode, field):
    response, sent = analyze(chat("Synthetic answer"), mode)
    assert response.status_code == 200, response.text
    assert sent[0][field] == server.DEFAULT_MAX_OUTPUT_TOKENS == 16384
    response, sent = analyze(chat("Synthetic answer"), mode, generation={"max_output_tokens": 2500})
    assert sent[0][field] == 2500
    # Nothing else appears without a setting, so saved 1.0.1 settings send what they sent before, plus the limit.
    assert "thinking" not in sent[0] and "reasoning_effort" not in sent[0] and "reasoning" not in sent[0]


def test_gemini_sends_its_output_limit_and_no_thinking_settings():
    reply = httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": "Synthetic answer"}]}, "finishReason": "STOP"}]})
    response, sent = analyze(reply, "gemini", generation={"max_output_tokens": 30000, "thinking": "on", "effort": "high"})
    assert response.status_code == 200, response.text
    assert sent[0]["generationConfig"]["maxOutputTokens"] == 30000
    assert "thinkingConfig" not in sent[0]["generationConfig"]


def test_claude_sends_no_temperature_and_only_the_reasoning_settings_chosen():
    reply = httpx.Response(200, json={"content": [{"type": "text", "text": "Synthetic answer"}], "stop_reason": "end_turn"})
    response, sent = analyze(reply, "claude")
    assert response.status_code == 200, response.text
    assert sent[0]["max_tokens"] == 16384 and "temperature" not in sent[0]
    assert "thinking" not in sent[0] and "output_config" not in sent[0]
    _, sent = analyze(reply, "claude", generation={"thinking": "on", "effort": "medium"})
    assert sent[0]["thinking"] == {"type": "adaptive"} and sent[0]["output_config"] == {"effort": "medium"}
    _, sent = analyze(reply, "claude", generation={"thinking": "off"})
    assert sent[0]["thinking"] == {"type": "disabled"} and "output_config" not in sent[0]


def test_deepseek_thinking_and_effort_use_its_documented_parameters():
    _, sent = analyze(chat("Synthetic answer"), "deepseek", generation={"thinking": "on", "effort": "max"})
    assert sent[0]["thinking"] == {"type": "enabled"} and sent[0]["reasoning_effort"] == "max"
    _, sent = analyze(chat("Synthetic answer"), "deepseek", generation={"thinking": "off", "effort": "max"})
    assert sent[0]["thinking"] == {"type": "disabled"} and "reasoning_effort" not in sent[0]
    _, sent = analyze(chat("Synthetic answer"), "deepseek", generation={"effort": "low"})
    assert "thinking" not in sent[0] and sent[0]["reasoning_effort"] == "low"


@pytest.mark.parametrize("mode", ["groq", "together"])
def test_providers_without_documented_settings_ignore_thinking_and_effort(mode):
    _, sent = analyze(chat("Synthetic answer"), mode, generation={"thinking": "on", "effort": "high"})
    assert "thinking" not in sent[0] and "reasoning_effort" not in sent[0]


@pytest.mark.parametrize("generation", [{"max_output_tokens": 0}, {"max_output_tokens": -5}, {"effort": "HIGH; drop"},
                                        {"thinking": "maybe"}])
def test_invalid_generation_settings_are_refused_before_sending(generation):
    response, sent = analyze(chat("Synthetic answer"), "deepseek", generation=generation)
    assert response.status_code == 422 and sent == []


# ---- No visible answer is never "Done" ----

def test_reasoning_that_uses_the_whole_limit_fails_clearly_without_a_retry():
    # The reported failure: HTTP 200, all output spent on reasoning, no content.
    reply = chat("", "length", reasoning_content="synthetic private reasoning")
    response, sent = analyze(reply, "deepseek")
    assert response.status_code == 502, response.text
    detail = response.json()["detail"]
    assert "output limit (16,384 tokens)" in detail and "Maximum output tokens" in detail and "DeepSeek → Advanced" in detail
    assert "synthetic private reasoning" not in response.text
    assert len(sent) == 1, "no retry with a larger limit"
    assert response.json()["outbound"]["ai"]["outcome"].startswith("failed: ")


@pytest.mark.parametrize("reply", [chat(""), chat("   \n\t "), chat(None), chat("", reasoning_content="synthetic reasoning"),
                                   chat("<think>synthetic reasoning</think>\n  "),
                                   httpx.Response(200, json={"choices": []}), httpx.Response(200, json={})])
def test_empty_or_reasoning_only_answers_are_errors(reply):
    response, sent = analyze(reply, "deepseek")
    assert response.status_code == 502, response.text
    assert "synthetic reasoning" not in response.text
    assert response.json()["outbound"]["ai"]["outcome"].startswith("failed: ") and len(sent) == 1


def test_a_cut_off_answer_is_shown_with_a_note_and_recorded_as_cut_off():
    response, _ = analyze(chat("Partial synthetic answer", "length"), "groq", generation={"max_output_tokens": 900})
    assert response.status_code == 200, response.text
    analysis = response.json()["analysis"]
    assert analysis.startswith("Partial synthetic answer") and "cut off at the output limit (900 tokens)" in analysis
    assert response.json()["outbound"]["ai"]["outcome"] == "answered (cut off at the output limit)"
    complete, _ = analyze(chat("Synthetic answer"), "groq")
    assert complete.json()["outbound"]["ai"]["outcome"] == "answered" and "cut off" not in complete.json()["analysis"]


def test_thinking_tags_and_reasoning_fields_are_not_part_of_the_answer():
    response, _ = analyze(chat("<think>synthetic reasoning</think>\nVisible answer", reasoning="other reasoning"), "together")
    assert response.json()["analysis"].strip() == "Visible answer"


def test_gemini_reads_every_visible_part_and_skips_thoughts():
    reply = httpx.Response(200, json={"candidates": [{"content": {"parts": [
        {"text": "synthetic thought summary", "thought": True}, {"text": "First half of the answer, "},
        {"text": "second half."}]}, "finishReason": "STOP"}]})
    response, _ = analyze(reply, "gemini")
    assert response.json()["analysis"] == "First half of the answer, second half."


@pytest.mark.parametrize("body, status, wording", [
    ({"candidates": [{"content": {"parts": [{"text": "thinking", "thought": True}]}, "finishReason": "MAX_TOKENS"}]}, 502, "output limit"),
    ({"candidates": [{"content": {"parts": []}, "finishReason": "SAFETY"}]}, 400, "withheld the answer (SAFETY)"),
    ({"candidates": [{"finishReason": "PROHIBITED_CONTENT"}]}, 400, "withheld the answer (PROHIBITED_CONTENT)"),
    ({"promptFeedback": {"blockReason": "BLOCKLIST"}}, 400, "withheld the answer (BLOCKLIST)"),
    ({"candidates": [{"content": {"parts": [{"text": " "}]}, "finishReason": "STOP"}]}, 502, "no answer text"),
])
def test_gemini_answers_that_are_missing_or_withheld(body, status, wording):
    response, _ = analyze(httpx.Response(200, json=body), "gemini")
    assert response.status_code == status and wording in response.json()["detail"], response.text
    assert "thinking" not in response.json()["detail"].replace("on thinking", "")


@pytest.mark.parametrize("body, status, expected", [
    ({"content": [{"type": "thinking", "thinking": "synthetic reasoning"}, {"type": "redacted_thinking", "data": "x"},
                  {"type": "text", "text": "Visible "}, {"type": "text", "text": "answer"}], "stop_reason": "end_turn"}, 200, "Visible answer"),
    ({"content": [{"type": "thinking", "thinking": "synthetic reasoning"}], "stop_reason": "max_tokens"}, 502, "output limit"),
    ({"content": [], "stop_reason": "refusal"}, 400, "withheld the answer (refusal)"),
])
def test_claude_answers(body, status, expected):
    response, _ = analyze(httpx.Response(200, json=body), "claude")
    assert response.status_code == status, response.text
    text = response.json()["analysis"] if status == 200 else response.json()["detail"]
    assert expected in text and "synthetic reasoning" not in response.text


def test_an_output_limit_the_model_refuses_is_explained():
    reply = httpx.Response(400, json={"error": {"message": "max_completion_tokens must be at most 8192"}})
    response, sent = analyze(reply, "groq", generation={"max_output_tokens": 40000})
    assert response.status_code == 400 and len(sent) == 1
    assert "refused the output limit" in response.json()["detail"] and "Groq → Advanced" in response.json()["detail"]


def test_openrouter_errors_do_not_repeat_the_raw_reply():
    reply = httpx.Response(500, text=f"<html>upstream {SECRET} {KEY}</html>")
    response, _ = analyze(reply, "openrouter")
    assert response.status_code == 500 and SECRET not in response.text and KEY not in response.text


def test_provider_errors_never_repeat_the_api_key():
    reply = lambda request: httpx.Response(400, json={"error": {"message": f"Invalid request for key {KEY}"}})
    for mode in ("groq", "deepseek", "gemini", "claude", "openrouter"):
        response, _ = analyze(reply, mode)
        assert KEY not in response.text and "[hidden]" in response.json()["detail"], (mode, response.text)


# ---- Discovery reports each model's limits and reasoning settings ----

def discovery(provider, body):
    with patched(lambda request: httpx.Response(200, json=body)):
        return api().post(f"/providers/{provider}/models", json={"api_key": KEY}).json()["models"]


def test_deepseek_discovery_reports_output_limit_and_effort_levels():
    models = discovery("deepseek", {"object": "list", "data": [
        {"id": "synthetic-flash", "name": "Synthetic Flash", "context_window": 1048576, "max_output_tokens": 393216,
         "effort": {"supported_levels": ["low", "high", "max"], "default_level": "high"}},
        {"id": "synthetic-plain"}]})
    flash, plain = models
    assert (flash["max_output_tokens"], flash["efforts"], flash["default_effort"], flash["thinking_switch"]) == \
        (393216, ["low", "high", "max"], "high", True)
    assert (plain["max_output_tokens"], plain["efforts"], plain["thinking_switch"]) == (None, [], False)


def test_claude_discovery_reports_supported_effort_and_thinking_types():
    models = discovery("claude", {"data": [
        {"id": "claude-synthetic", "max_tokens": 128000, "max_input_tokens": 1000000, "capabilities": {
            "effort": {"supported": True, "max": {"supported": True}, "low": {"supported": True},
                       "medium": {"supported": False}, "high": {"supported": True}},
            "thinking": {"supported": True, "types": {"adaptive": {"supported": True}, "disabled": {"supported": True}}}}},
        {"id": "claude-synthetic-old", "max_tokens": 0, "capabilities": {"thinking": {"types": {"enabled": {"supported": True}}}}}],
        "has_more": False})
    new, old = models
    assert (new["max_output_tokens"], new["context_length"], new["efforts"], new["thinking_switch"]) == \
        (128000, 1000000, ["low", "high", "max"], True)
    assert (old["max_output_tokens"], old["efforts"], old["thinking_switch"]) == (None, [], False)


def test_gemini_and_groq_discovery_report_output_limits():
    gemini = discovery("gemini", {"models": [{"name": "models/gemini-synthetic", "outputTokenLimit": 65536,
                                              "inputTokenLimit": 1048576, "supportedGenerationMethods": ["generateContent"]}]})
    assert gemini[0]["max_output_tokens"] == 65536 and gemini[0]["efforts"] == []
    groq = discovery("groq", {"data": [{"id": "synthetic-chat", "context_window": 131072, "max_completion_tokens": 32768}]})
    assert groq[0]["max_output_tokens"] == 32768


# ---- CodeQL alert 32: connection checks repeat no exception text or secrets ----

def check(handler, endpoint="/test-siem", **options):
    payload = dict(siem_base_url="https://records.test", auth_type="header", auth_header_name="X-Api-Key",
                   auth_header_value=SECRET, verify_ssl=False, result_mode="records", parsed_params=[{"id": "one"}],
                   api_method="GET", api_path_template="/records/${id}", response_path="records", test_path="/api/status")
    payload.update(options)
    with patched(handler):
        return api().post(endpoint, json=payload)


def raising(exc):
    def handler(request):
        raise exc
    return handler


@pytest.mark.parametrize("exc, wording", [
    (ValueError(f"library detail with {SECRET}"), "The request failed (ValueError)"),
    (RuntimeError(f"https://user:{SECRET}@records.test/internal"), "The request failed (RuntimeError)"),
    (httpx.ReadError(f"connection to 10.9.8.7 reset, token {SECRET}"), "could not be reached (ReadError)"),
    (httpx.ReadTimeout(f"timed out {SECRET}"), "timed out"),
])
def test_unexpected_failures_are_named_by_type_only(exc, wording):
    for endpoint in ("/test-siem", "/fetch-siem-logs"):
        response = check(raising(exc), endpoint)
        assert wording in response.text, (endpoint, response.text)
        assert SECRET not in response.text and "10.9.8.7" not in response.text and "records.test/internal" not in response.text


@pytest.mark.parametrize("auth", [
    {"auth_type": "header", "auth_header_name": "X-Api-Key", "auth_header_value": SECRET},
    {"auth_type": "basic", "auth_username": "synthetic-user", "auth_password": SECRET},
    {"auth_type": "cookie", "auth_cookie_name": "session", "auth_cookie": SECRET},
])
def test_credentials_echoed_in_an_error_reply_are_hidden(auth):
    def handler(request):
        return httpx.Response(500, json={"error": {"message": f"Rejected {request.headers.get('x-api-key', '')}"
                                                              f"{request.headers.get('authorization', '')} {request.headers.get('cookie', '')}"
                                                              f" and {SECRET}"}})
    result = check(handler, **auth).json()
    assert result["status"] == "error" and "HTTP 500" in result["message"] and "[hidden]" in result["message"]
    assert SECRET not in json.dumps(result)
    if auth["auth_type"] == "basic":
        assert "synthetic-user" not in json.dumps(result)


def test_raw_and_html_error_bodies_are_not_repeated():
    result = check(lambda request: httpx.Response(500, text=f"<html><pre>Traceback {SECRET}</pre></html>")).json()
    assert result["message"] == "SIEM returned HTTP 500" and SECRET not in json.dumps(result)


def test_connector_errors_keep_their_own_advice():
    assert server.public_error(server.ConnectorError("Enter the path.")) == "Enter the path."
    assert issubclass(server.DestinationError, server.ConnectorError)
    # A connection whose filled-in request body is not JSON says so, without the body.
    response = check(lambda request: httpx.Response(200, json={"records": []}), "/fetch-siem-logs", api_method="POST",
                     api_body_template='{"q": ${id}, "secret": "' + SECRET + '"')
    assert "not valid JSON" in response.text and SECRET not in response.text


def test_error_detail_reads_structured_fields_only():
    request = httpx.Request("GET", "https://records.test/", headers={"Authorization": "Bearer " + SECRET})
    assert server._extract_api_error_detail(httpx.Response(500, text=SECRET, request=request)) == ""
    detail = server._extract_api_error_detail(httpx.Response(400, json={"message": f"bad {SECRET}\x1b[31m"}, request=request))
    assert detail == "bad [hidden] [31m"


def test_usable_answer_has_no_hidden_fallbacks():
    with pytest.raises(HTTPException) as error:
        server.usable_answer("Synthetic", "", "", 100, "the limit")
    assert error.value.status_code == 502
    assert server.usable_answer("Synthetic", "Answer", "", 100, "the limit") == "Answer"


# ---- Text from a service is filtered wherever a message repeats it ----

def test_openrouter_errors_inside_a_200_reply_are_filtered():
    reply = httpx.Response(200, json={"error": {"message": f"Upstream refused key {KEY}\x1b[2J and {SECRET}" + "x" * 500,
                                                "metadata": {"raw": f"raw upstream body {SECRET}"}}})
    response, _ = analyze(reply, "openrouter")
    detail = response.json()["detail"]
    assert response.status_code == 502 and "Upstream refused key [hidden]" in detail
    assert KEY not in response.text and "raw upstream body" not in detail and "\x1b" not in detail
    assert len(detail) < 260


def job(status_reply, **options):
    """A search job whose create and status replies come from `status_reply`."""
    def handler(request):
        if request.method == "POST":
            return httpx.Response(200, json={"id": f"job-1 {request.headers.get('x-api-key')}"})
        return status_reply(request)
    settings = dict(fetch_mode="search_job", job_create_path_template="/jobs", job_status_path_template="/jobs/${job_id}",
                    job_results_path_template="/jobs/${job_id}/results", job_id_path="id", job_status_field="status",
                    job_create_method="POST", job_complete_values=["COMPLETED"], job_error_values=["FAILED"],
                    job_error_message_path="error", job_poll_interval_seconds=0.5, job_timeout_seconds=1, **options)
    return check(handler, "/fetch-siem-logs", **settings)


def test_search_job_error_reasons_and_ids_hide_credentials():
    response = job(lambda request: httpx.Response(200, json={
        "status": "FAILED", "error": f"query failed for {request.headers.get('x-api-key')}\x07 token={SECRET}"}))
    assert "ended in status FAILED" in response.text and "query failed for [hidden]" in response.text
    assert SECRET not in response.text and "\\u0007" not in response.text


def test_upstream_text_is_filtered_and_bounded():
    # Used for search job IDs and statuses as the service reported them.
    request = httpx.Request("GET", "https://records.test/", headers={"X-Api-Key": SECRET})
    shown = server.upstream_text(f"RUNNING {SECRET}\x1b " + "y" * 200, httpx.Response(200, request=request), 60)
    assert shown.startswith("RUNNING [hidden]  y") and len(shown) == 60


@pytest.mark.parametrize("auth", [
    {"auth_type": "basic", "auth_username": "op", "auth_password": "pw1"},
    {"auth_type": "header", "auth_header_name": "X-Api-Key", "auth_header_value": "k9"},
    {"auth_type": "cookie", "auth_cookie_name": "sid", "auth_cookie": "s3"},
])
def test_short_credentials_are_hidden_too(auth):
    secret = auth.get("auth_password") or auth.get("auth_header_value") or auth.get("auth_cookie")
    result = check(lambda request: httpx.Response(500, json={"message": f"Login failed for ({secret}); sorry"}), **auth).json()
    assert "Login failed for ([hidden]); sorry" in result["message"], result
    if auth["auth_type"] == "basic":
        assert "op" not in result["message"].replace("sorry", "")


def test_short_values_are_hidden_only_where_they_stand_alone():
    request = httpx.Request("GET", "https://records.test/", headers={"Cookie": "lang=en; sid=" + SECRET})
    text = server._hide_sent_credentials(f"Session {SECRET} expired; language en; enable again", httpx.Response(401, request=request))
    assert text == "Session [hidden] expired; language [hidden]; enable again"
