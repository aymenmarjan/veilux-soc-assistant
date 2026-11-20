"""Provider labels keep their meaning; credential and explicit-hide policy wins."""
import json
import re
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient
import server

IP = '198.51.100.212'
ISP = 'EXAMPLE-FIBRE-QXRVLT02'
REAL_CLIENT = httpx.AsyncClient


def run_metadata(label=ISP, *, score=0, options=None, twice=False):
    calls, prompts = [], []

    def api(request):
        calls.append(request)
        if request.url.host == 'api.abuseipdb.com':
            return httpx.Response(200, json={'data': {'ipAddress': IP, 'isp': label,
                'abuseConfidenceScore': score, 'totalReports': 0, 'numDistinctUsers': 0,
                'usageType': 'Mobile ISP', 'domain': 'example.net', 'countryCode': 'CA',
                'countryName': 'Canada', 'hostnames': ['h198-51-100-212.fibre.example.net']}})
        if request.url.host == 'www.virustotal.com':
            return httpx.Response(200, json={'data': {'attributes': {'as_owner': label, 'asn': 64501,
                'last_analysis_stats': {'malicious': 0, 'suspicious': 0, 'undetected': 92},
                'network': '198.51.100.0/15', 'country': 'CA', 'reputation': 0}}})
        assert request.url.host == 'rdap.org'
        return httpx.Response(200, json={'name': label, 'country': 'CA'})

    def client(*args, **kwargs):
        return REAL_CLIENT(*args, transport=httpx.MockTransport(api), **kwargs)

    async def ai(prompt, key):
        prompts.append(prompt)
        return 'Synthetic analysis'

    request = {'logs': [json.dumps({'dst_ip': IP})], 'mode': 'groq', 'api_key': 'synthetic',
        'sanitize': True, 'enable_threat_intel': True, 'virustotal_api_key': 'synthetic',
        'abuseipdb_api_key': 'synthetic', 'enable_whois': True, **(options or {})}
    with patch.object(server.httpx, 'AsyncClient', client), patch.object(server, 'call_groq_ai', ai), \
         patch.object(server, 'training_data', {'feedback_entries': []}), \
         patch.object(server, 'threat_intel_cache', {}), patch.object(server, '_save_threat_intel_cache'):
        client = TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN})
        result = None
        for _ in range(2 if twice else 1):
            response = client.post('/analyze', json=request)
            assert response.status_code == 200, response.text
            result = response.json()
    return result, calls, prompts


@pytest.mark.parametrize('score', [0, 80])
@pytest.mark.parametrize('sanitize', [False, True])
def test_public_provider_labels_are_not_secrets_in_clean_or_flagged_results(score, sanitize):
    result, calls, prompts = run_metadata(score=score, options={'sanitize': sanitize})
    assert len(calls) == 3
    sources = result['threat_intel_findings'][0]['sources']
    for provider, field in [('abuseipdb', 'isp'), ('virustotal', 'as_owner'), ('whois', 'network_name')]:
        assert sources[provider][field] == ISP
    assert server.PROTECTED_SECRET_LABEL not in (result['mapping_table'] or {}).values()
    if score:
        assert ISP in prompts[0]
    if sanitize:
        assert IP not in prompts[0]


@pytest.mark.parametrize('label', ['CARRIER-FIBRE-REGION07', 'NETWORK-BACKBONE-QXRVLT03'])
def test_other_provider_labels_use_context_rather_than_a_sample_allowlist(label):
    result, _, prompts = run_metadata(label, score=80)
    assert result['threat_intel_findings'][0]['sources']['abuseipdb']['isp'] == label
    assert label in prompts[0]


def test_cached_provider_labels_stay_readable():
    result, calls, prompts = run_metadata(twice=True)
    assert len(calls) == 3 and len(prompts) == 2
    source = result['threat_intel_findings'][0]['sources']['abuseipdb']
    assert source['cached'] and source['isp'] == ISP


@pytest.mark.parametrize('label,secret', [
    ('password=tiny', 'tiny'), ('Authorization: Bearer tiny', 'tiny'),
    (r'password=a\u0063me', 'acme'), ('ghp_' + 'A'*36, 'ghp_' + 'A'*36),
    ('86b5f78249b6ebf6058a426dbe5685cf', '86b5f78249b6ebf6058a426dbe5685cf'),
])
def test_descriptive_fields_still_protect_credentials_and_unreviewed_hashes(label, secret):
    result, calls, prompts = run_metadata(label, score=80)
    assert len(calls) == 3
    assert secret not in json.dumps(result['threat_intel_findings'])
    assert secret not in prompts[0]
    assert '⟦SECRET#' in result['threat_intel_findings'][0]['sources']['abuseipdb']['isp']


@pytest.mark.parametrize('options', [
    {'force_hide_values': [ISP]},
    {'logs': [json.dumps({'dst_ip': IP, 'password': ISP})]},
    {'custom_regex_rules': [{'id': 'hide', 'pattern': re.escape(ISP), 'action': 'hide_secret',
        'mode': 'full_value', 'scope': 'all', 'capture_group': 0, 'enabled': True}]},
    {'custom_regex_rules': [{'id': 'review', 'pattern': re.escape(ISP), 'action': 'review',
        'mode': 'full_value', 'scope': 'all', 'capture_group': 0, 'enabled': True}]},
])
def test_known_credentials_and_explicit_rules_override_provider_metadata(options):
    result, calls, prompts = run_metadata(score=80, options=options)
    assert calls
    assert ISP not in json.dumps(result['threat_intel_findings'])
    assert ISP not in prompts[0]
    assert ISP not in (result['mapping_table'] or {}).values()


def test_log_field_called_isp_does_not_inherit_provider_metadata_policy():
    result, _, prompts = run_metadata(options={'logs': [json.dumps({'dst_ip': IP, 'isp': ISP})]})
    assert ISP not in result['sanitized_log']
    assert ISP not in json.dumps(result['threat_intel_findings'])
    assert ISP not in prompts[0]
