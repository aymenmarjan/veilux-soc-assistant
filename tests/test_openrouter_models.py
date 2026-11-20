"""OpenRouter free-model lookup and model selection in analysis. All HTTP is mocked."""
import json
from unittest.mock import patch
import httpx
import pytest
from fastapi.testclient import TestClient
import server
from openrouter_sample import OPENROUTER_MODELS

REAL_CLIENT = httpx.AsyncClient


def mocked(handler):
    def client(*args, **kwargs):
        return REAL_CLIENT(*args, transport=httpx.MockTransport(handler), **kwargs)
    return patch.object(server.httpx, 'AsyncClient', client)


def test_only_free_text_chat_models_that_have_not_expired():
    found = server.openrouter_free_models(OPENROUTER_MODELS, today='2026-11-05')
    # A ":free" suffix is not required; music output, variable-price routers,
    # paid and expired models are left out.
    assert [m['id'] for m in found] == ['stealth/unnamed', 'vendor/alpha:free', 'vendor/beta-vision:free']
    alpha = next(m for m in found if m['id'] == 'vendor/alpha:free')
    assert (alpha['context_length'], alpha['reasoning'], alpha['supports_tools']) == (262144, 'always', True)
    assert next(m for m in found if m['id'] == 'vendor/beta-vision:free')['input_modalities'] == ['text', 'image']
    odd = [{'id': 'x/odd', 'pricing': {'prompt': [1], 'completion': '0'}}, {'pricing': {}}, 'not a model',
           {'id': 'x/no-chat', 'pricing': {'prompt': '0', 'completion': '0'}, 'architecture': {'output_modalities': ['text']},
            'endpoints': ['/api/v1/embeddings']}]
    assert server.openrouter_free_models(odd) == []


def test_lookup_endpoint_is_live_and_reports_failures():
    calls = []
    def api(request):
        calls.append(request)
        return httpx.Response(200, json={'data': OPENROUTER_MODELS})
    with mocked(api):
        body = TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN}).get('/providers/openrouter/free-models').json()
        TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN}).get('/providers/openrouter/free-models')
    assert len(calls) == 2, 'every lookup asks OpenRouter again'
    assert str(calls[0].url) == 'https://openrouter.ai/api/v1/models' and 'authorization' not in calls[0].headers
    assert (body['total_models'], body['count']) == (len(OPENROUTER_MODELS), 3)
    for handler, text in [(lambda r: httpx.Response(503), 'HTTP 503'), (lambda r: httpx.Response(200, json={'x': 1}), 'unexpected format')]:
        with mocked(handler):
            response = TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN}).get('/providers/openrouter/free-models')
        assert response.status_code == 502 and text in response.json()['detail']


@pytest.mark.parametrize('reply,status,text', [
    (httpx.Response(429), 429, 'rate-limited'),
    (httpx.Response(200, json={'choices': [{'message': {'content': None}, 'finish_reason': 'length'}]}), 502, 'reasoning'),
    (httpx.Response(200, json={'error': {'message': 'Provider unavailable'}}), 502, 'Provider unavailable'),
])
def test_openrouter_failures_name_the_model_and_the_fix(reply, status, text):
    with mocked(lambda request: reply):
        with pytest.raises(server.HTTPException) as caught:
            server.asyncio.run(server.call_openrouter_ai('prompt', 'key', 'vendor/alpha:free'))
    assert caught.value.status_code == status and text in caught.value.detail


def test_analysis_uses_the_chosen_model_and_requires_one():
    sent = []
    def api(request):
        sent.append(json.loads(request.content))
        return httpx.Response(200, json={'choices': [{'message': {'content': 'Synthetic report'}}]})
    payload = {'logs': ['event=login user=alice'], 'mode': 'openrouter', 'api_key': 'synthetic', 'sanitize': False}
    with mocked(api):
        missing = TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN}).post('/analyze', json=payload)
        chosen = TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN}).post('/analyze', json={**payload, 'openrouter_model': 'vendor/alpha:free'})
    assert missing.status_code == 400 and 'Choose an OpenRouter model' in missing.json()['detail']
    assert chosen.status_code == 200, chosen.text
    assert [body['model'] for body in sent] == ['vendor/alpha:free']
