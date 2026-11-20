"""Page-derived values keep their identity at all configured API boundaries."""
import json
import httpx
import pytest
from test_connector_portability import fetch

def job_options(**extra):
    return dict(fetch_mode='search_job',job_create_path_template='/jobs',job_status_path_template='/jobs/${job_id}',
        job_results_path_template='/jobs/${job_id}/results',job_id_path='id',job_status_field='status',
        job_create_method='POST',job_complete_values=['COMPLETED'],**extra)

def test_job_parameters_encode_paths_preserve_versions_and_render_headers():
    sent=[]
    def api(request):
        sent.append(request)
        return httpx.Response(200,json={'id':'job/42?debug=1'} if len(sent)==1 else {'status':'COMPLETED'} if len(sent)==2 else {'data':{'records':[{'event':1}]}})
    options=job_options(job_create_query_template={'q':'${query}'},job_create_body_template='{"tenant":"${tenant}","value":"${value}"}')
    options['job_create_path_template']='/tenants/${tenant}/jobs?api-version=next'
    response=fetch(api,parsed_params=[{'tenant':'a/b','query':'name="x"','value':'one "quoted" \\ value'}],api_headers_template={'X-Tenant':'${tenant}'},**options)
    assert response.status_code==200,response.text
    assert len(sent)==3 and all(r.url.host=='records.test' for r in sent)
    assert b'a%2Fb' in sent[0].url.raw_path
    assert sent[0].url.params['api-version']=='next' and sent[0].url.params['q']=='name="x"'
    assert all(r.headers['X-Tenant']=='a/b' for r in sent)
    assert json.loads(sent[0].content)['value']=='one "quoted" \\ value'
    assert b'job%2F42%3Fdebug%3D1' in sent[1].url.raw_path
    assert b'job%2F42%3Fdebug%3D1' in sent[2].url.raw_path

@pytest.mark.parametrize('changes',[
    {'job_create_body_template':'{"key":"${missing}"}'},
    {'job_create_query_template':{'key':'${missing}'}},
    {'api_headers_template':{'X-Tenant':'${missing}'}},
    {'job_status_path_template':'/jobs/${job_id}/${missing}'},
])
def test_missing_job_values_stop_before_create(changes):
    sent=[];options=job_options();options.update(changes)
    response=fetch(lambda r:sent.append(r),**options)
    assert response.status_code==502 and sent==[]
    assert 'Missing request values' in response.json()['detail']

def test_context_request_uses_encoded_page_values_and_headers():
    sent=[]
    def api(request):
        sent.append(request)
        return httpx.Response(200,json={'start':'today'} if len(sent)==1 else {'data':{'records':[{'event':1}]}})
    response=fetch(api,parsed_params=[{'case_id':'case/42','tenant':'prod'}],context_path_template='/case/${case_id}',
        api_headers_template={'X-Tenant':'${tenant}'},api_query_template={'since':'${context.start}'})
    assert response.status_code==200,response.text
    assert b'case%2F42' in sent[0].url.raw_path and sent[0].headers['X-Tenant']=='prod'
    assert sent[1].url.params['since']=='today'
