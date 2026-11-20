"""Sign-in failures and redirects are actionable; no live SIEM or provider calls."""
from unittest.mock import patch
import httpx
import pytest
from fastapi.testclient import TestClient
import server

REAL_CLIENT=httpx.AsyncClient


def request(endpoint,handler,**options):
    def client(*args,**kwargs):
        return REAL_CLIENT(*args,transport=httpx.MockTransport(handler),**kwargs)
    payload=dict(siem_base_url='https://records.test',auth_type='cookie',auth_cookie='synthetic-session',auth_cookie_name='session',
        verify_ssl=False,result_mode='records',parsed_params=[{'id':'one'},{'id':'two'}],
        api_method='GET',api_path_template='/records/${id}',response_path='records',test_path='/api/status')
    payload.update(options)
    with patch.object(server.httpx,'AsyncClient',client):
        return TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN}).post(endpoint,json=payload)


def test_health_redirect_is_explained_without_following_or_platform_probes():
    sent=[]
    def api(req):
        sent.append(req)
        return httpx.Response(302,headers={'Location':'https://login.other.test/?code=synthetic-private-code'},text='synthetic-private-html')
    result=request('/test-siem',api).json()
    assert result['status']=='redirected',result
    assert 'HTTP 302' in result['message'] and 'Use my current browser login' in result['message']
    assert 'synthetic-private' not in str(result)
    assert len(sent)==1 and sent[0].url.path=='/api/status'


@pytest.mark.parametrize('status',[401,403,302])
def test_extraction_access_failure_explains_next_step_and_stops_rejected_signin(status):
    sent=[]
    def api(req):
        sent.append(req)
        return httpx.Response(status,headers={'Location':'https://other.test/login?token=synthetic-private-code'},text='synthetic-private-body')
    response=request('/fetch-siem-logs',api)
    assert response.status_code==502,response.text
    message=response.json()['detail']
    assert f'HTTP {status}' in message and 'Use my current browser login' in message
    assert 'synthetic-private' not in message
    assert len(sent)==(2 if status==403 else 1)


def test_forbidden_record_preserves_existing_partial_results_behavior():
    sent=[]
    def api(req):
        sent.append(req)
        return httpx.Response(403) if req.url.path.endswith('/one') else httpx.Response(200,json={'records':[{'id':'allowed'}]})
    response=request('/fetch-siem-logs',api)
    assert response.status_code==200,response.text
    result=response.json()
    assert result['fetched']==1 and result['failed']==1 and len(sent)==2
    assert 'HTTP 403' in result['errors'][0] and 'allowed' in result['logs'][0]


def test_not_found_record_is_named_and_the_batch_continues():
    sent=[]
    def api(req):
        sent.append(req)
        if req.url.path.endswith('/b'):
            return httpx.Response(404)
        return httpx.Response(200,json={'records':[{'id':req.url.path.rsplit('/',1)[-1]}]})
    response=request('/fetch-siem-logs',api,parsed_params=[{'id':'a'},{'id':'b'},{'id':'c'}])
    assert response.status_code==200,response.text
    result=response.json()
    assert len(sent)==3 and result['fetched']==2 and result['failed']==1
    assert result['errors'][0].startswith('For id=b: ') and 'HTTP 404' in result['errors'][0]
    response=request('/fetch-siem-logs',lambda req:httpx.Response(404),parsed_params=[{'id':'a'},{'id':'b'}])
    assert response.status_code==502
    assert response.json()['detail'].startswith('All 2 requests failed. First failure: For id=a: ')


def test_browser_session_guidance_and_full_session_control():
    def api(req):
        value=req.headers.get('cookie','')
        if all(part in value for part in ('session=main','session_part.0=part0','session_part.1=part1')):
            return httpx.Response(200,json={'records':[{'id':'synthetic'}]})
        return httpx.Response(401,json={'message':'session incomplete'})
    denied=request('/fetch-siem-logs',api,auth_type='browser_session',auth_cookies={'session':'main'})
    assert 'same browser' in denied.json()['detail']
    allowed=request('/fetch-siem-logs',api,auth_type='browser_session',auth_cookies={
        'session':'main','session_part.0':'part0','session_part.1':'part1'})
    assert allowed.status_code==200 and allowed.json()['fetched']==2


def test_search_job_signin_failure_is_actionable_before_polling_or_next_link():
    sent=[]
    def api(req):sent.append(req);return httpx.Response(401,text='synthetic-private-body')
    response=request('/fetch-siem-logs',api,fetch_mode='search_job',job_create_path_template='/jobs',job_create_method='POST',
        job_id_path='job_id',job_status_path_template='/jobs/${job_id}',job_status_field='status',job_complete_values=['COMPLETED'],
        job_results_path_template='/jobs/${job_id}/results')
    assert 'Use my current browser login' in response.json()['detail']
    assert 'synthetic-private' not in response.text and len(sent)==1


@pytest.mark.parametrize('stage',['poll','results'])
def test_search_job_later_signin_failure_stops_without_another_job(stage):
    sent=[]
    def api(req):
        sent.append(req)
        if req.url.path=='/jobs':return httpx.Response(201,json={'job_id':'first'})
        if stage=='results' and req.url.path=='/jobs/first':return httpx.Response(200,json={'status':'COMPLETED'})
        return httpx.Response(401,text='synthetic-private-body')
    response=request('/fetch-siem-logs',api,fetch_mode='search_job',job_create_path_template='/jobs',job_create_method='POST',
        job_id_path='job_id',job_status_path_template='/jobs/${job_id}',job_status_field='status',job_complete_values=['COMPLETED'],
        job_results_path_template='/jobs/${job_id}/results')
    assert response.status_code==502 and 'Use my current browser login' in response.json()['detail']
    assert len(sent)==(2 if stage=='poll' else 3) and 'synthetic-private' not in response.text
