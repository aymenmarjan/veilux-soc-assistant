"""TI must see eligible originals while AI receives protected inputs."""
import json
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient

import server

REAL_CLIENT = httpx.AsyncClient
IP = '203.0.113.146'
DOMAIN = 'mail.example.net'


def stats(value, field='destination.ip'):
    return [{'fields': [{'field': field, 'topValues': [{'value': value, 'count': 2}]}]}]


def analyze(payload, failure=False):
    calls, prompts = [], []

    def api(request):
        calls.append(request)
        if failure:
            return httpx.Response(401)
        if request.url.host == 'api.abuseipdb.com':
            return httpx.Response(200, json={'data': {'ipAddress': IP, 'abuseConfidenceScore': 80,
                'totalReports': 54, 'isp': 'Synthetic ISP', 'countryCode': 'PT'}})
        return httpx.Response(200, json={'ldhName': 'example.net', 'name': 'SYNTHETIC-NET'})

    def client(*args, **kwargs):
        return REAL_CLIENT(*args, transport=httpx.MockTransport(api), **kwargs)

    async def ai(prompt, key):
        prompts.append(prompt)
        return 'Synthetic analysis'

    request = {'logs': ['event'], 'mode': 'groq', 'api_key': 'synthetic', 'sanitize': True,
        'enable_threat_intel': True, 'enable_virustotal': False, 'enable_abuseipdb': True,
        'abuseipdb_api_key': 'synthetic', 'enable_whois': True, **payload}
    with patch.object(server.httpx, 'AsyncClient', client), patch.object(server, 'call_groq_ai', ai), \
         patch.object(server, 'training_data', {'feedback_entries': []}), \
         patch.object(server, 'threat_intel_cache', {}), patch.object(server, '_save_threat_intel_cache'):
        response = TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN}).post('/analyze', json=request)
    assert response.status_code == 200, response.text
    return response.json(), calls, prompts


@pytest.mark.parametrize('source', ['logs', 'analyst', 'statistics', 'all'])
def test_automatic_ip_masking_does_not_disable_ti(source):
    payload = {}
    if source in ('logs', 'all'):
        payload['logs'] = ['destination=' + IP]
    if source in ('analyst', 'all'):
        payload['analyst_data'] = 'destination=' + IP
    if source in ('statistics', 'all'):
        payload['field_statistics'] = stats(IP)
    result, calls, prompts = analyze(payload)
    assert IP in result['mapping_table'].values()
    abuse = [r for r in calls if r.url.host == 'api.abuseipdb.com']
    assert len(abuse) == 1 and abuse[0].url.params['ipAddress'] == IP
    finding = next(f for f in result['threat_intel_findings'] if f['ioc'] == IP)
    assert finding['sources']['abuseipdb']['total_reports'] == 54
    assert IP not in prompts[0] and '⟦IP_EXT#' in prompts[0]
    assert '54 reports' in prompts[0]


@pytest.mark.parametrize('payload', [
    {'logs': [json.dumps({'host': DOMAIN})]},
    {'field_statistics': stats(DOMAIN, 'Hostname')},
])
def test_automatic_hostname_masking_does_not_disable_rdap(payload):
    result, calls, prompts = analyze(payload)
    assert DOMAIN in result['mapping_table'].values()
    assert any(r.url.host == 'rdap.org' and r.url.path == '/domain/example.net' for r in calls)
    assert any(f['ioc'] == DOMAIN for f in result['threat_intel_findings'])
    assert DOMAIN not in prompts[0]


@pytest.mark.parametrize('payload', [
    {'logs': ['ip=' + IP], 'force_hide_values': [IP]},
    {'logs': [json.dumps({'password': IP})]},
    {'field_statistics': stats(IP, 'password')},
    {'logs': ['ip=' + IP], 'custom_keywords': {IP: 'HIDDEN_IP'}},
    {'logs': [json.dumps({'destination': IP})], 'json_keys_to_hide': ['destination']},
    {'field_statistics': stats(IP), 'statistics_fields_to_hide': ['destination.ip']},
    {'logs': ['ip=' + IP], 'custom_regex_rules': [{'id': 'hide', 'pattern': r'203\.0\.113\.146',
        'action': 'hide_privacy', 'mode': 'substring', 'scope': 'all', 'capture_group': 0, 'enabled': True}]},
    {'logs': ['ip=' + IP], 'internal_cidrs': ['203.0.113.0/24']},
    {'logs': ['host=' + DOMAIN], 'internal_domains': ['example.net']},
    {'logs': ['src=192.168.1.18 dst=10.1.1.3']},
])
def test_explicit_hides_credentials_and_internal_ranges_still_block_dispatch(payload):
    result, calls, prompts = analyze(payload)
    assert calls == []
    assert not result['threat_intel_findings']


@pytest.mark.parametrize('payload,state,fragment', [
    ({'logs': ['src=192.168.1.18']}, 'no_results', 'internal'),
    ({'enable_threat_intel': False}, 'disabled', 'off'),
    ({'enable_whois': False, 'abuseipdb_api_key': None}, 'not_configured', 'source'),
    ({'mode': 'sanitize_only'}, 'local_only', 'local'),
])
def test_empty_enrichment_explains_why(payload, state, fragment):
    result, calls, _ = analyze(payload)
    assert calls == []
    assert result['threat_intel_status']['state'] == state
    assert fragment in result['threat_intel_status']['message'].lower()


def test_provider_errors_remain_visible_with_privacy_on():
    result, calls, prompts = analyze({'logs': ['ip=' + IP]}, failure=True)
    assert len(calls) == 2
    assert result['threat_intel_status']['state'] == 'unavailable'
    assert result['threat_intel_findings'][0]['sources']['abuseipdb']['status'] == 'error'
    assert IP not in prompts[0]


def test_mixed_public_internal_and_encoded_credentials_only_dispatch_eligible_ip():
    secret_ip = '8.8.8.8'
    payload = {'logs': ['ip=' + IP + ' internal=192.168.1.18 ref=' + secret_ip,
                       r'{"\u0070assword":"8.8.8.8"}']}
    result, calls, prompts = analyze(payload)
    assert calls and all(secret_ip not in str(r.url) and '192.168.1.18' not in str(r.url) for r in calls)
    assert {f['ioc'] for f in result['threat_intel_findings']} == {IP}
    assert secret_ip not in json.dumps(result['mapping_table'])
    assert IP not in prompts[0] and secret_ip not in prompts[0]


def test_ipv6_statistics_are_enriched_without_unmasking_ai():
    ipv6 = '2001:4860:4860::8888'
    result, calls, prompts = analyze({'logs': [], 'field_statistics': stats(ipv6)})
    assert any(r.url.host == 'api.abuseipdb.com' and r.url.params['ipAddress'] == ipv6 for r in calls)
    assert any(f['ioc'] == ipv6 for f in result['threat_intel_findings'])
    assert ipv6 not in prompts[0] and ipv6 in result['mapping_table'].values()


def test_enrichment_failure_is_reported_without_failing_analysis():
    async def failed(*args, **kwargs):
        raise RuntimeError('synthetic service failure')
    with patch.object(server, 'enrich_with_threat_intel', failed):
        result, calls, prompts = analyze({'logs': ['ip=' + IP]})
    assert calls == [] and len(prompts) == 1
    assert result['threat_intel_status']['state'] == 'unavailable'
    assert 'continued without enrichment' in result['threat_intel_status']['message']
    assert IP not in prompts[0]
