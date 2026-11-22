"""Custom model failures reproduced against mocked outbound HTTP."""
import asyncio
import json
from unittest.mock import patch

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError
import server

REAL_CLIENT = httpx.AsyncClient


def config(fmt="anthropic", **kwargs):
    return server.CustomProviderConfig(name="Synthetic model", api_format=fmt,
        endpoint="https://model.test/messages", model="claude-sonnet-5-5", **kwargs)


def invoke(cfg, handler, prompt="synthetic prompt"):
    def client(*args, **kwargs):
        return REAL_CLIENT(*args, transport=httpx.MockTransport(handler), **kwargs)
    with patch.object(server.httpx, "AsyncClient", client):
        return asyncio.run(server.call_custom_ai(prompt, "synthetic-key", cfg))


def answer(fmt="anthropic"):
    return {"content":[{"type":"text","text":"OK"}]} if fmt == "anthropic" else (
        {"candidates":[{"content":{"parts":[{"text":"OK"}]}}]} if fmt == "gemini" else
        {"choices":[{"message":{"content":"OK"}}]})


@pytest.mark.parametrize("fmt", ["anthropic", "openai", "gemini"])
def test_default_uses_model_temperature(fmt):
    sent=[]
    def provider(request):
        sent.append(json.loads(request.content))
        return httpx.Response(200,json=answer(fmt))
    assert invoke(config(fmt),provider) == "OK"
    body=sent[0].get("generationConfig",sent[0])
    assert "temperature" not in body
    assert body.get("maxOutputTokens",body.get("max_tokens")) == 4000


def test_saved_temperature_deprecation_recovers_at_actual_analysis_boundary():
    sent=[]
    def provider(request):
        body=json.loads(request.content); sent.append(body)
        if "temperature" in body:
            return httpx.Response(400,json={"type":"error","error":{"type":"invalid_request_error",
                "message":"`temperature` is deprecated for this model."},"request_id":"req_synthetic"})
        return httpx.Response(200,json=answer())
    def client(*args,**kwargs):
        return REAL_CLIENT(*args,transport=httpx.MockTransport(provider),**kwargs)
    with patch.object(server.httpx,"AsyncClient",client), patch.object(server,"training_data",{"feedback_entries":[]}):
        result=TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN}).post("/analyze",json={"logs":["password=synthetic-credential"],
            "sanitize":False,"mode":"custom","api_key":"synthetic-key",
            "custom_provider":config(temperature=0.2).model_dump()})
    assert result.status_code == 200,result.text
    assert result.json()["analysis"] == "OK"
    assert len(sent) == 2
    assert sent[0]["temperature"] == 0.2 and "temperature" not in sent[1]
    assert sent[0]["messages"] == sent[1]["messages"]
    assert all("synthetic-credential" not in json.dumps(body) for body in sent)
    assert all("SECRET#" in json.dumps(body) for body in sent)


@pytest.mark.parametrize("fmt", ["anthropic","openai","gemini"])
def test_explicit_supported_zero_temperature_is_preserved(fmt):
    sent=[]
    def provider(request):
        sent.append(json.loads(request.content)); return httpx.Response(200,json=answer(fmt))
    cfg=config(fmt,temperature=0)
    assert invoke(cfg,provider) == "OK"
    assert sent[0].get("generationConfig",sent[0])["temperature"] == 0
    assert cfg.temperature == 0


def test_two_specific_compatibility_adjustments_keep_output_limit():
    sent=[]
    def provider(request):
        body=json.loads(request.content);sent.append(body)
        if "temperature" in body:
            return httpx.Response(400,json={"error":{"param":"temperature","code":"unsupported_value",
                "message":"Only the default (1) value is supported."}})
        if "max_tokens" in body:
            return httpx.Response(400,json={"error":{"param":"max_tokens","code":"unsupported_parameter",
                "message":"Use max_completion_tokens instead."}})
        return httpx.Response(200,json=answer("openai"))
    assert invoke(config("openai",temperature=0.2,max_tokens=4321),provider) == "OK"
    assert len(sent) == 3
    assert sent[-1]["max_completion_tokens"] == 4321 and "max_tokens" not in sent[-1]
    assert all(body["messages"] == sent[0]["messages"] for body in sent)


@pytest.mark.parametrize("status,message", [(401,"Invalid API key"),(429,"Rate limit reached"),
    (500,"temperature unsupported"),(400,"temperature must be between 0 and 1"),
    (400,"The model ID is invalid"),(400,"max_tokens is too large")])
def test_unrelated_errors_are_not_retried_and_are_readable(status,message):
    sent=[]
    def provider(request):
        sent.append(request);return httpx.Response(status,json={"error":{"message":message}})
    with pytest.raises(HTTPException) as error:
        invoke(config(temperature=0.2),provider)
    assert error.value.status_code == status
    assert message in error.value.detail
    assert '{"error"' not in error.value.detail
    assert len(sent) == 1


@pytest.mark.parametrize("fmt,body,expected", [
    # Blocks are pieces of one answer and carry their own spacing, so they are
    # joined as they are (as the providers' own SDKs do), not with new lines.
    ("anthropic", {"content":[{"type":"thinking","thinking":"private reasoning"},
        {"type":"text","text":"First part, "},{"type":"text","text":"second part."}]}, "First part, second part."),
    ("openai", {"choices":[{"message":{"content":[{"type":"text","text":"One\n"},
        {"type":"text","text":"Two"}]}}]}, "One\nTwo"),
    ("gemini", {"candidates":[{"content":{"parts":[{"thought":True,"text":"private reasoning"},
        {"text":"Visible ans"},{"text":"wer"}]}}]}, "Visible answer"),
])
def test_all_visible_answer_blocks_are_read(fmt,body,expected):
    assert invoke(config(fmt),lambda request:httpx.Response(200,json=body)) == expected


def test_reasoning_only_reply_explains_output_limit_without_exposing_reasoning():
    with pytest.raises(HTTPException) as error:
        invoke(config(),lambda request:httpx.Response(200,json={"stop_reason":"max_tokens",
            "content":[{"type":"thinking","thinking":"private reasoning"}]}))
    assert "response length" in error.value.detail.lower()
    assert "private reasoning" not in error.value.detail


@pytest.mark.parametrize("field,value", [("temperature",-1),("temperature",float("nan")),
    ("max_tokens",0),("timeout_seconds",0),("api_format","unsupported")])
def test_invalid_configuration_is_rejected(field,value):
    values={field:value}
    if field == "api_format":
        with pytest.raises(ValidationError):config(value)
    else:
        with pytest.raises(ValidationError):config(**values)


def test_compatibility_retry_is_bounded_when_provider_keeps_rejecting():
    sent=[]
    def provider(request):
        sent.append(request);return httpx.Response(400,json={"error":{"message":"temperature is deprecated"}})
    with pytest.raises(HTTPException):invoke(config(temperature=0.2),provider)
    assert len(sent) == 2


def test_started_retry_obeys_one_overall_timeout_and_cancels_work():
    async def run():
        sent=[];stopped=asyncio.Event()
        async def provider(request):
            sent.append(request)
            if len(sent)==1:
                return httpx.Response(400,json={"error":{"message":"temperature is deprecated"}})
            try: await asyncio.Event().wait()
            finally: stopped.set()
        def client(*args,**kwargs):
            return REAL_CLIENT(*args,transport=httpx.MockTransport(provider),**kwargs)
        with patch.object(server.httpx,"AsyncClient",client):
            with pytest.raises(HTTPException) as error:
                await server.call_custom_ai("safe prompt","synthetic-key",config(temperature=0.2,timeout_seconds=.1))
        assert error.value.status_code==504
        assert len(sent)==2 and stopped.is_set()
    asyncio.run(run())


def test_null_temperature_and_legacy_format_spelling():
    sent=[]
    def provider(request):
        sent.append(json.loads(request.content));return httpx.Response(200,json=answer())
    assert invoke(config("ANTHROPIC",temperature=None),provider)=="OK"
    assert "temperature" not in sent[0]


def test_gemini_model_template_and_api_key_are_encoded():
    sent=[]
    def provider(request):
        sent.append(request);return httpx.Response(200,json=answer("gemini"))
    cfg=server.CustomProviderConfig(api_format="gemini",model="models/gemini-fixture",
        endpoint="https://model.test/v1beta/models/{model}:generateContent")
    assert invoke(cfg,provider)=="OK"
    assert str(sent[0].url)=="https://model.test/v1beta/models/gemini-fixture:generateContent"
    # The key travels in a header, never in the address.
    assert sent[0].headers["x-goog-api-key"]=="synthetic-key"
