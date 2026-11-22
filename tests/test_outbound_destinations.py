"""Where the backend's outbound requests may go (code-scanning remediation).

The analyst's API address decides the destination, and private or local SIEM
addresses must keep working. Data VEILUX reads while working (values from a
page, IDs and fields from API responses, links, error text) must never change
the destination, the request path, or what the extension is shown. All values
here are synthetic, and outbound HTTP is a mock transport.
"""
import asyncio
import hashlib
import time
from unittest.mock import patch

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import server

REAL_CLIENT = httpx.AsyncClient


def call(endpoint, handler, **options):
    def client(*args, **kwargs):
        return REAL_CLIENT(*args, transport=httpx.MockTransport(handler), **kwargs)
    payload = dict(siem_base_url='https://records.test', auth_type='header', auth_header_name='X-Api-Key',
                   auth_header_value='synthetic-api-key', verify_ssl=False, result_mode='records',
                   parsed_params=[{'id': 'one'}], api_method='GET', api_path_template='/records/${id}',
                   response_path='records', test_path='/api/status')
    payload.update(options)
    with patch.object(server.httpx, 'AsyncClient', client):
        return TestClient(server.app, client=("127.0.0.1", 50000),
                          headers={"X-Veilux-Token": server.ACCESS_TOKEN}).post(endpoint, json=payload)


def records_api(sent):
    def api(request):
        sent.append(request)
        return httpx.Response(200, json={'records': [{'id': 'synthetic'}]})
    return api


# ---- The API address: private infrastructure allowed, metadata refused ----

@pytest.mark.parametrize('base', [
    'https://10.20.30.40', 'http://192.168.1.10:9000', 'https://172.16.0.5:8089', 'https://siem.corp.local',
    'http://localhost:9200', 'http://127.0.0.1:55000', 'https://[::1]:8443', 'https://[fd12:3456::10]',
    'https://siem.example.test/api/v2', 'http://wazuh-indexer:9200'])
def test_private_and_local_siem_addresses_still_work(base):
    sent = []
    response = call('/fetch-siem-logs', records_api(sent), siem_base_url=base)
    assert response.status_code == 200, response.text
    assert len(sent) == 1
    configured = httpx.URL(base)
    assert (sent[0].url.host, sent[0].url.port) == (configured.host, configured.port)
    assert sent[0].url.path == configured.path.rstrip('/') + '/records/one'


@pytest.mark.parametrize('base', [
    'http://169.254.169.254', 'http://169.254.169.254/latest/meta-data', 'http://2852039166', 'http://0xa9fea9fe',
    'http://169.254.43518', 'http://metadata.google.internal', 'http://METADATA.google.internal.',
    'http://[fe80::1]', 'http://[fd00:ec2::254]', 'http://[::ffff:169.254.169.254]', 'http://0.0.0.0:9200',
    'http://224.0.0.1', 'http://240.0.0.1'])
def test_metadata_link_local_and_unusable_addresses_are_refused_before_any_request(base):
    sent = []
    for endpoint in ('/fetch-siem-logs', '/test-siem'):
        response = call(endpoint, records_api(sent), siem_base_url=base)
        body = response.json()
        message = body.get('detail') or body.get('message')
        assert response.status_code in (200, 400) and 'refused' in message, (endpoint, body)
    assert sent == []


@pytest.mark.parametrize('base, wording', [
    ('ftp://records.test', 'http:// or https://'), ('file:///etc/passwd', 'http:// or https://'),
    ('records.test', 'http:// or https://'), ('https://user:synthetic-pass@records.test', 'user name or password'),
    ('https://records.test/?token=synthetic', 'must not contain ? or #'), ('https://records.test/#x', 'must not contain ? or #')])
def test_invalid_api_addresses_are_refused_with_an_actionable_message(base, wording):
    sent = []
    response = call('/fetch-siem-logs', records_api(sent), siem_base_url=base)
    assert response.status_code == 400 and wording in response.json()['detail'], response.text
    assert 'synthetic-pass' not in response.text and sent == []


def test_redirects_are_never_followed_even_to_metadata():
    sent = []
    def api(request):
        sent.append(request)
        return httpx.Response(302, headers={'Location': 'http://169.254.169.254/latest/meta-data/'})
    assert call('/fetch-siem-logs', api).status_code == 502
    assert call('/test-siem', api).json()['status'] == 'redirected'
    assert {r.url.host for r in sent} == {'records.test'}


# ---- Values read from pages cannot move a request ----

@pytest.mark.parametrize('value', ['@evil.test', '@evil.test/steal', 'x?admin=true', 'x#fragment', '//evil.test/x',
                                   'evil.test:443', 'a/b', '%2e%2e', 'https://evil.test/'])
@pytest.mark.parametrize('mode', ['records', 'first'])
def test_page_values_fill_one_path_segment_on_the_configured_host(value, mode):
    sent = []
    response = call('/fetch-siem-logs', records_api(sent), parsed_params=[{'id': value}], result_mode=mode)
    assert response.status_code == 200, response.text
    assert len(sent) == 1 and sent[0].url.host == 'records.test' and sent[0].url.port is None
    raw = sent[0].url.raw_path.decode()
    assert raw.startswith('/records/') and raw.count('/') == 2 and '?' not in raw, raw
    assert sent[0].headers['X-Api-Key'] == 'synthetic-api-key'


@pytest.mark.parametrize('value', ['..', '.', '../admin', '..\\admin', 'x/../../admin', 'x/./y', 'line\r\nX-Injected: 1', 'nul\x00'])
@pytest.mark.parametrize('mode', ['records', 'first'])
def test_page_values_that_would_change_the_path_are_refused(value, mode):
    sent = []
    response = call('/fetch-siem-logs', records_api(sent), parsed_params=[{'id': value}], result_mode=mode)
    assert response.status_code == 502, response.text
    assert sent == []
    assert mode == 'first' or 'not sent' in response.text


def test_a_path_template_cannot_choose_the_host_in_the_legacy_mode():
    sent = []
    response = call('/fetch-siem-logs', records_api(sent), result_mode='first', api_path_template='${id}',
                    parsed_params=[{'id': '.evil.test/x'}])
    assert response.status_code == 502 and sent == []


def test_the_configured_base_path_is_kept():
    sent = []
    response = call('/fetch-siem-logs', records_api(sent), siem_base_url='https://records.test/tenant-a/api',
                    parsed_params=[{'id': '..'}])
    assert response.status_code == 502 and sent == []
    response = call('/fetch-siem-logs', records_api(sent), siem_base_url='https://records.test/tenant-a/api')
    assert response.status_code == 200 and sent[0].url.path == '/tenant-a/api/records/one'


# ---- Values returned by the API cannot move a request either ----

def search_job_options(**overrides):
    options = dict(fetch_mode='search_job', job_create_method='POST', job_create_path_template='/searches',
                   job_id_path='id', job_status_path_template='/searches/${job_id}', job_status_field='status',
                   job_complete_values=['DONE'], job_results_path_template='/searches/${job_id}/results',
                   job_poll_interval_seconds=0.5, parsed_params=[{}])
    options.update(overrides)
    return options


@pytest.mark.parametrize('job_id', ['../../admin/users', '..', '@evil.test', 'x?delete=true'])
def test_a_search_id_from_the_api_stays_one_segment_on_the_api(job_id):
    sent = []
    def api(request):
        sent.append(request)
        if request.method == 'POST':
            return httpx.Response(200, json={'id': job_id})
        if request.url.raw_path.decode().endswith('/results'):
            return httpx.Response(200, json={'records': [{'id': 'synthetic'}]})
        return httpx.Response(200, json={'status': 'DONE'})
    response = call('/fetch-siem-logs', api, **search_job_options())
    assert {r.url.host for r in sent} == {'records.test'}
    for request in sent[1:]:
        raw = request.url.raw_path.decode()
        assert raw.startswith('/searches/') and '?' not in raw and '/../' not in raw, raw
    if '..' in job_id:
        assert response.status_code == 502 and len(sent) == 1, response.text
    else:
        assert response.status_code == 200 and len(sent) == 3, response.text


def test_context_document_fields_cannot_move_the_main_request():
    sent = []
    def api(request):
        sent.append(request)
        if request.url.path == '/alerts/one':
            return httpx.Response(200, json={'index': '../../_security', 'name': 'synthetic'})
        return httpx.Response(200, json={'records': [{'id': 'synthetic'}]})
    response = call('/fetch-siem-logs', api, context_path_template='/alerts/${id}',
                    api_path_template='/records/${context.index}')
    assert [r.url.path for r in sent] == ['/alerts/one'], [r.url for r in sent]
    assert response.status_code == 200 and 'not sent' in ' '.join(response.json()['errors'])


def test_a_page_token_stays_a_query_value_on_the_api():
    sent = []
    def api(request):
        sent.append(request)
        token = 'https://evil.test/next' if len(sent) == 1 else None
        return httpx.Response(200, json={'records': [{'n': len(sent)}], 'next': token})
    response = call('/fetch-siem-logs', api, pagination_mode='cursor', pagination_parameter='cursor',
                    pagination_cursor_path='next', page_size=1)
    assert response.status_code == 200 and len(sent) == 2
    assert {r.url.host for r in sent} == {'records.test'}
    assert sent[1].url.params['cursor'] == 'https://evil.test/next'


# ---- App sign-in and custom AI endpoints ----

@pytest.mark.parametrize('token_url', ['https://169.254.169.254/token', 'https://metadata.google.internal/token',
                                       'https://[fe80::1]/token'])
def test_app_signin_token_address_refuses_metadata(token_url):
    sent = []
    response = call('/fetch-siem-logs', records_api(sent), auth_type='oauth_client_credentials',
                    oauth_token_url=token_url, oauth_client_id='synthetic-client',
                    oauth_client_secret='synthetic-secret')
    assert response.status_code == 400 and 'refused' in response.json()['detail'], response.text
    assert 'synthetic-secret' not in response.text and sent == []


def custom_config(endpoint):
    return server.CustomProviderConfig(name='Synthetic model', api_format='openai', endpoint=endpoint, model='synthetic')


def invoke_custom(endpoint, sent):
    def provider(request):
        sent.append(request)
        return httpx.Response(200, json={'choices': [{'message': {'content': 'OK'}}]})
    def client(*args, **kwargs):
        return REAL_CLIENT(*args, transport=httpx.MockTransport(provider), **kwargs)
    with patch.object(server.httpx, 'AsyncClient', client):
        return asyncio.run(server.call_custom_ai('synthetic prompt', 'synthetic-key', custom_config(endpoint)))


@pytest.mark.parametrize('endpoint', ['http://localhost:11434/v1/chat/completions',
                                      'http://10.0.0.5:8000/v1/chat/completions',
                                      'https://gateway.corp.local/openai/chat/completions'])
def test_local_and_company_model_endpoints_still_work(endpoint):
    sent = []
    assert invoke_custom(endpoint, sent) == 'OK' and str(sent[0].url) == endpoint


@pytest.mark.parametrize('endpoint', ['http://169.254.169.254/v1/chat/completions',
                                      'http://metadata.google.internal/computeMetadata/v1/'])
def test_model_endpoints_refuse_metadata(endpoint):
    sent = []
    with pytest.raises(HTTPException) as refused:
        invoke_custom(endpoint, sent)
    assert refused.value.status_code == 400 and 'refused' in refused.value.detail and sent == []


def test_model_endpoint_redirect_is_not_followed():
    sent = []
    def provider(request):
        sent.append(request)
        return httpx.Response(307, headers={'Location': 'http://169.254.169.254/'})
    def client(*args, **kwargs):
        return REAL_CLIENT(*args, transport=httpx.MockTransport(provider), **kwargs)
    with patch.object(server.httpx, 'AsyncClient', client), pytest.raises(HTTPException):
        asyncio.run(server.call_custom_ai('synthetic prompt', 'synthetic-key', custom_config('https://model.test/v1')))
    assert len(sent) == 1


# ---- Link patterns: bounded time on crafted links ----

def test_link_pattern_named_groups_work_in_both_syntaxes():
    link = 'https://siem.test/#/doc/pattern/logs-2026?_g=()&id=synthetic-42'
    js = r'#/doc/[^/]+/(?<index>[^/?]+)\?(?:[^#]*&)?id=(?<doc_id>[^&]+)'
    assert server.parse_siem_link(link, js) == {'index': 'logs-2026', 'doc_id': 'synthetic-42'}
    assert server.parse_siem_link(link, js.replace('(?<', '(?P<')) == {'index': 'logs-2026', 'doc_id': 'synthetic-42'}
    assert server.parse_siem_link(link, r'(?<=id=)(?<id>\w+)') == {'id': 'synthetic'}
    assert server.parse_siem_link(link, '(unclosed') is None


@pytest.mark.parametrize('pattern', [r'^(a|aa)+$', r'^(?<id>(a|aa)+)$', r'^(\w|\w\w)+$'])
def test_catastrophic_link_pattern_is_stopped_quickly(pattern):
    link = 'a' * 40 + '!'
    started = time.perf_counter()
    with pytest.raises(server.LinkPatternTimeout):
        server.parse_siem_link(link, pattern)
    assert time.perf_counter() - started < 3


def test_catastrophic_link_pattern_ends_the_request_with_a_clear_error():
    sent = []
    started = time.perf_counter()
    response = call('/fetch-siem-logs', records_api(sent), parsed_params=None, link_regex=r'^(?<id>(a|aa)+)$',
                    siem_links=['a' * 40 + '!'] * 20)
    assert response.status_code == 400 and 'took too long' in response.json()['detail']
    assert time.perf_counter() - started < 5 and sent == []


def test_link_limits():
    assert server.parse_siem_link('x' * (server.LINK_MAX_LENGTH + 1), r'(?<id>x)') is None
    assert server.parse_siem_link('x', 'x' * (server.LINK_PATTERN_MAX_LENGTH + 1)) is None
    response = call('/fetch-siem-logs', records_api([]), parsed_params=None, link_regex=r'(?<id>\d+)',
                    siem_links=['1'] * (server.MAX_LINKS + 1))
    assert response.status_code == 400 and 'Too many links' in response.json()['detail']


# ---- Error responses carry no internal details ----

class InternalFailure(Exception):
    pass


def test_connection_check_hides_unexpected_exception_text():
    def api(request):
        raise InternalFailure('synthetic-internal-detail at /home/analyst/secret/path')
    result = call('/test-siem', api).json()
    assert result['status'] == 'error' and 'InternalFailure' in result['message']
    assert 'synthetic-internal-detail' not in str(result) and '/home/analyst' not in str(result)


def test_extraction_hides_unexpected_exception_text_but_keeps_its_own_messages():
    def api(request):
        raise InternalFailure('synthetic-internal-detail')
    response = call('/fetch-siem-logs', api)
    assert response.status_code == 502 and 'synthetic-internal-detail' not in response.text
    assert 'InternalFailure' in response.text
    response = call('/fetch-siem-logs', lambda r: httpx.Response(200, text='not json'))
    assert 'did not return JSON' in response.text


def test_public_error_messages():
    assert server.public_error(httpx.ReadTimeout('synthetic')) == 'The request timed out.'
    assert 'synthetic' not in server.public_error(httpx.ConnectError('synthetic-host-detail'))
    assert server.public_error(server.ConnectorError('Enter the path.')) == 'Enter the path.'
    # Only VEILUX's own messages are repeated; a library's ValueError is not.
    assert 'synthetic' not in server.public_error(ValueError('synthetic-library-detail'))
    assert 'synthetic' not in server.public_error(KeyError('synthetic-key'))


# ---- App sign-in cache key ----

def test_signin_cache_key_is_keyed_and_does_not_reveal_the_secret():
    request = server.SiemFetchRequest(siem_base_url='https://records.test', parsed_params=[{}],
                                      oauth_token_url='https://login.test/token', oauth_client_id='synthetic-client',
                                      oauth_client_secret='password1', oauth_scope='api')
    key = server._oauth_key(request)
    unkeyed = hashlib.sha256('\n'.join(['https://login.test/token', 'synthetic-client', 'password1', 'api']).encode()).hexdigest()
    assert key == server._oauth_key(request) and key != unkeyed and 'password1' not in key
    other = request.model_copy(update={'oauth_client_secret': 'password2'})
    assert server._oauth_key(other) != key
    with patch.object(server, '_OAUTH_CACHE_KEY', b'\x00' * 32):
        assert server._oauth_key(request) != key


# ---- Threat-intelligence lookups ----

def test_virustotal_path_values_are_single_segments():
    sent = []
    async def run():
        async with REAL_CLIENT(transport=httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(404))) as client:
            await server.query_virustotal(client, 'evil.test/../../users', 'domain', 'synthetic-key')
    asyncio.run(run())
    assert sent[0].url.host == 'www.virustotal.com'
    assert sent[0].url.raw_path.decode() == '/api/v3/domains/evil.test%2F..%2F..%2Fusers'
