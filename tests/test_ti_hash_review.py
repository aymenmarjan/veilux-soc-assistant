"""Accepted Sysmon hashes retain their identity through TI and response scanning."""
import json
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient
import server

REAL_CLIENT = httpx.AsyncClient
MD5 = 'DE074ECCF61F37B1C3259AC2209A07EF'
SHA256 = 'D24642E2194D6F09B886990EAFA0A40803EE53EA3F9D142435B5214291DBA062'
IMPHASH = '8FB4D12D2A59D2C52D63E323FC6D6B35'


def run_hashes(log, *, options=None, attributes=None):
    calls, prompts = [], []
    attrs = {'last_analysis_stats': {'malicious': 0, 'suspicious': 0, 'undetected': 74},
             'meaningful_name': 'secedit.exe', 'type_description': 'Win32 EXE', 'size': 40960,
             'first_submission_date': 1500000000, 'times_submitted': 12,
             'tags': ['known-distributor', 'peexe'], **(attributes or {})}

    def api(request):
        calls.append(request)
        assert request.url.host == 'www.virustotal.com'
        return httpx.Response(200, json={'data': {'attributes': attrs}})

    def client(*args, **kwargs):
        return REAL_CLIENT(*args, transport=httpx.MockTransport(api), **kwargs)

    async def ai(prompt, key):
        prompts.append(prompt)
        return 'Synthetic report'

    with patch.object(server.httpx, 'AsyncClient', client), patch.object(server, 'call_groq_ai', ai), \
         patch.object(server, 'training_data', {'feedback_entries': []}), \
         patch.object(server, 'threat_intel_cache', {}), patch.object(server, '_save_threat_intel_cache'):
        api_client = TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN})
        scan = api_client.post('/secrets/scan', json={'texts': [log]}).json()
        kept = [f['value'] for f in scan['findings'] if f['confidence'] == 'ambiguous']
        request = {'logs': [log], 'mode': 'groq', 'api_key': 'synthetic', 'sanitize': True,
            'enable_threat_intel': True, 'virustotal_api_key': 'synthetic',
            'enable_abuseipdb': False, 'enable_whois': False,
            'allowed_ambiguous_secrets': kept, **(options or {})}
        response = api_client.post('/analyze', json=request)
    assert response.status_code == 200, response.text
    return response.json(), calls, prompts, scan


@pytest.mark.parametrize('digest', [MD5, MD5.lower(), MD5.title(), SHA256])
def test_reviewed_hash_remains_visible_and_link_targets_actual_hash(digest):
    algorithm = 'MD5' if len(digest) == 32 else 'SHA256'
    result, calls, prompts, scan = run_hashes(json.dumps({'Hashes': algorithm + '=' + digest}))
    assert any(f['confidence'] == 'ambiguous' and digest in f['value'] for f in scan['findings'])
    assert len(calls) == 1 and calls[0].url.path.endswith('/' + digest.lower())
    finding = result['threat_intel_findings'][0]
    assert finding['ioc'].lower() == digest.lower(), finding
    assert finding['sources']['virustotal']['link'].endswith('/' + digest.lower())
    assert not result['mapping_table'] or not any(v == server.PROTECTED_SECRET_LABEL for v in result['mapping_table'].values())


def test_sysmon_md5_sha256_and_imphash_are_distinguished():
    hashes = f'MD5={MD5},SHA256={SHA256},IMPHASH={IMPHASH}'
    result, calls, _, _ = run_hashes(json.dumps({'Hashes': hashes, 'message': 'Hashes: ' + hashes,
                                                'event_ip': '10.48.17.93'}))
    assert {r.url.path.rsplit('/', 1)[1] for r in calls} == {MD5.lower(), SHA256.lower()}
    findings = result['threat_intel_findings']
    assert len(findings) == 3
    import_hash = next(f for f in findings if f['ioc'].lower() == IMPHASH.lower())
    assert import_hash['hash_algorithm'] == 'IMPHASH'
    assert import_hash['sources']['virustotal']['status'] == 'unsupported'
    assert import_hash['verdict'] == 'unknown'


def test_vt_file_report_preserves_relevant_file_fields():
    result, _, _, _ = run_hashes('MD5=' + MD5)
    source = result['threat_intel_findings'][0]['sources']['virustotal']
    assert source['file_name'] == 'secedit.exe'
    assert source['file_type'] == 'Win32 EXE'
    assert source['file_size'] == 40960 and source['times_submitted'] == 12


@pytest.mark.parametrize('options', [
    {'force_hide_values': [MD5]}, {'allowed_ambiguous_secrets': []},
    {'json_keys_to_hide': ['Hashes']},
])
def test_unchecked_or_explicitly_hidden_hash_is_not_dispatched(options):
    result, calls, _, _ = run_hashes(json.dumps({'Hashes': MD5}), options=options)
    assert calls == [] and not result['threat_intel_findings']


def test_canonical_provider_value_must_not_equal_a_known_credential():
    log = json.dumps({'Hashes': MD5, 'password': MD5.lower()})
    result, calls, _, _ = run_hashes(log)
    assert calls == [] and not result['threat_intel_findings']


def test_canonical_provider_value_respects_forced_substring_hides():
    result, calls, _, _ = run_hashes('MD5=' + MD5, options={'force_hide_values': [MD5[:8].lower()]})
    assert calls == [] and not result['threat_intel_findings']


def test_late_strong_evidence_overrides_retained_hash_identity():
    result, calls, prompts, _ = run_hashes('MD5=' + MD5, attributes={'meaningful_name': 'password=' + MD5})
    assert len(calls) == 1
    finding = result['threat_intel_findings'][0]
    assert finding['ioc'].startswith('⟦SECRET#')
    assert MD5.lower() not in json.dumps(result['threat_intel_findings']).lower()
    assert MD5.lower() not in prompts[0].lower()
    assert MD5.lower() not in result['sanitized_log'].lower()


def test_unrelated_provider_hex_value_is_not_automatically_accepted():
    other = '86b5f78249b6ebf6058a426dbe5685cf'
    result, calls, prompts, _ = run_hashes('MD5=' + MD5, attributes={'meaningful_name': other})
    assert result['threat_intel_findings'][0]['ioc'].lower() == MD5.lower()
    assert other not in json.dumps(result['threat_intel_findings'])
    assert other not in prompts[0]


def test_field_excluded_hash_stays_eligible_without_global_keep():
    result, calls, _, _ = run_hashes(json.dumps({'digest': MD5}), options={
        'allowed_ambiguous_secrets': [],
        'heuristic_field_exclusions': [{'path': 'digest', 'match_mode': 'key_anywhere'}]})
    assert len(calls) == 1
    assert result['threat_intel_findings'][0]['ioc'] == MD5.lower()


def test_imphash_statistics_preserve_algorithm_and_do_not_dispatch():
    result, calls, _, _ = run_hashes('event', options={
        'field_statistics': [{'fields': [{'field': 'IMPHASH', 'topValues': [{'value': IMPHASH, 'count': 2}]}]}],
        'allowed_ambiguous_secrets': [IMPHASH]})
    assert calls == []
    assert result['threat_intel_findings'][0]['hash_algorithm'] == 'IMPHASH'
    assert result['threat_intel_status']['state'] == 'not_queried'


def test_late_secret_revokes_enclosing_mapping_and_statistics_preview():
    result, calls, prompts, _ = run_hashes(json.dumps({'Hashes': MD5, 'customer': 'prefix ' + MD5}), options={
        'json_keys_to_hide': ['customer'],
        'field_statistics': [{'fields': [{'field': 'digest', 'topValues': [{'value': MD5, 'count': 2}]}]}],
    }, attributes={'meaningful_name': 'password=' + MD5.lower()})
    assert len(calls) == 1
    for value in (result['sanitized_log'], result['sanitized_field_statistics'],
                  json.dumps(result['mapping_table']), json.dumps(result['threat_intel_findings']), prompts[0]):
        assert MD5.lower() not in value.lower()
