"""Connector contracts against synthetic, intercepted HTTP only."""
import asyncio
import json
from unittest.mock import patch
import httpx
import pytest
from fastapi.testclient import TestClient
import server

REAL_CLIENT = httpx.AsyncClient

def fetch(handler, **values):
    def client(*args, **kwargs):
        return REAL_CLIENT(*args, transport=httpx.MockTransport(handler), **kwargs)
    payload = dict(siem_base_url='https://records.test', auth_type='none',
         parsed_params=[{}], api_method='GET',
        api_path_template='/records', api_body_template='', api_headers_template={},
        response_path='data.records', result_mode='records')
    payload.update(values)
    with patch.object(server.httpx, 'AsyncClient', client):
        return TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN}).post('/fetch-siem-logs', json=payload)

def test_generic_get_has_no_opensearch_defaults_and_keeps_all_records():
    requests=[]
    def api(request):
        requests.append(request)
        return httpx.Response(200,json={'data':{'records':[{'id':1},{'id':2}]}})
    response=fetch(api)
    assert response.status_code==200,response.text
    assert [json.loads(v) for v in response.json()['logs']]==[{'id':1},{'id':2}]
    assert requests[0].content==b'' and 'osd-xsrf' not in requests[0].headers

def test_explicit_empty_response_path_reads_root_array():
    response=fetch(lambda r:httpx.Response(200,json=[{'x':1},{'x':2}]),response_path='',
        auth_type='header',auth_header_name='Authorization',auth_header_value='synthetic')
    assert response.status_code==200,response.text
    assert len(response.json()['logs'])==2

def test_api_version_in_path_survives_additional_query_parameters():
    sent=[]
    def api(r):sent.append(r);return httpx.Response(200,json={'data':{'records':[]}})
    response=fetch(api,api_path_template='/records?api-version=next&scope=a&scope=b',api_query_template={'q':'some search'})
    assert response.status_code==200
    assert sent[0].url.params['api-version']=='next'
    assert sent[0].url.params.get_list('scope')==['a','b']
    assert sent[0].url.params['q']=='some search'

def test_columns_and_rows_api_maps_named_fields():
    response=fetch(lambda r:httpx.Response(200,json={'tables':[{'columns':[{'name':'User'},{'name':'Count'}],
        'rows':[['alice',3],['bob',2]]}]}),response_path='tables.0.rows',
        record_format='columns',columns_path='tables.0.columns',auth_type='header',auth_header_name='Authorization',auth_header_value='synthetic')
    assert response.status_code==200,response.text
    assert [json.loads(v) for v in response.json()['logs']]==[{'User':'alice','Count':3},{'User':'bob','Count':2}]

def test_offset_pagination_keeps_filters_and_reports_total():
    sent=[]
    def api(r):
        sent.append(r); offset=int(r.url.params.get('offset',0))
        return httpx.Response(200,json={'data':{'records':[{'id':i} for i in range(offset,min(offset+2,5))],'total':5}})
    response=fetch(api,pagination_mode='offset',pagination_parameter='offset',pagination_size_parameter='limit',
        page_size=2,api_query_template={'filter':'status:open'},total_path='data.total')
    assert response.status_code==200,response.text
    assert len(sent)==3 and len(response.json()['logs'])==5
    assert all(r.url.params['filter']=='status:open' and r.url.params['limit']=='2' for r in sent)
    assert response.json()['available_total']==5 and not response.json()['limited']

def test_record_cap_reports_incomplete_sample():
    response=fetch(lambda r:httpx.Response(200,json={'data':{'records':[{'x':i} for i in range(8)],'total':90}}),
        max_results_per_link=3,total_path='data.total')
    assert response.status_code==200
    assert len(response.json()['logs'])==3 and response.json()['limited']
    assert response.json()['available_total']==90

def test_repeated_cursor_fails_without_returning_partial_records():
    sent=[]
    def api(r):sent.append(r);return httpx.Response(200,json={'data':{'records':[{'x':1}]},'next':'same'})
    response=fetch(api,pagination_mode='cursor',pagination_parameter='cursor',pagination_cursor_path='next')
    assert response.status_code==502 and 'repeated' in response.json()['detail']
    assert len(sent)==2

def test_cursor_is_query_data_not_a_destination():
    sent=[]
    def api(r):
        sent.append(r);return httpx.Response(200,json={'data':{'records':[{'x':len(sent)}]},'next':'https://other.test/?key=x&y=1' if len(sent)==1 else None})
    response=fetch(api,pagination_mode='cursor',pagination_parameter='cursor',pagination_cursor_path='next')
    assert response.status_code==200 and len(sent)==2
    assert all(r.url.host=='records.test' for r in sent)
    assert sent[1].url.params['cursor']=='https://other.test/?key=x&y=1'

@pytest.mark.parametrize('change',[
    {'api_path_template':'https://other.test/records'}, {'api_path_template':'//other.test/records'},
    {'api_path_template':'/records/${missing}'}, {'api_body_template':'{"x":"${missing}"}','api_method':'POST'},
])
def test_invalid_or_unresolved_request_stops_before_http(change):
    sent=[]
    response=fetch(lambda r:sent.append(r),**change)
    assert response.status_code==502 and sent==[]

def test_link_values_are_encoded_for_paths_and_json():
    sent=[]
    def api(r):sent.append(r);return httpx.Response(200,json={'data':{'records':[{'ok':True}]}})
    value='name/with?query="quoted"'
    response=fetch(api,api_method='POST',api_path_template='/events/${id}',api_body_template='{"search":"${query}"}',
        parsed_params=[{'id':value,'query':'x="one" \\ two','tenant':'production'}],api_headers_template={'X-Tenant':'${tenant}'})
    assert response.status_code==200,response.text
    assert b'%2F' in sent[0].url.raw_path and b'%3F' in sent[0].url.raw_path
    assert json.loads(sent[0].content)['search']=='x="one" \\ two'
    assert sent[0].headers['X-Tenant']=='production'

def test_empty_results_are_valid_and_not_auth_failure():
    response=fetch(lambda r:httpx.Response(200,json={'data':{'records':[]}}))
    assert response.status_code==200 and response.json()['logs']==[]

def test_missing_records_location_is_actionable():
    response=fetch(lambda r:httpx.Response(200,json={'different':[]}))
    assert response.status_code==502 and 'Records location' in response.json()['detail']

def test_collection_timeout_stops_started_pagination():
    async def run():
        stopped=asyncio.Event();sent=[]
        async def api(r):
            sent.append(r)
            if len(sent)==1:return httpx.Response(200,json={'data':{'records':[{'id':1}]},'next':'two'})
            try:await asyncio.Event().wait()
            finally:stopped.set()
        request=server.SiemFetchRequest(siem_base_url='https://records.test',auth_type='none',
            parsed_params=[{}],api_method='GET',api_path_template='/records',response_path='data.records',
            result_mode='records',pagination_mode='cursor',pagination_cursor_path='next',connector_timeout_seconds=.05)
        async with REAL_CLIENT(transport=httpx.MockTransport(api)) as client:
            with pytest.raises(TimeoutError):await server.fetch_record_pages(client,request,{}, {})
        assert stopped.is_set() and len(sent)==2
    asyncio.run(run())

def test_record_cap_applies_across_multiple_links():
    sent=[]
    def api(r):sent.append(r);return httpx.Response(200,json={'data':{'records':[{'x':1},{'x':2}]}})
    response=fetch(api,parsed_params=[{'id':'a'},{'id':'b'},{'id':'c'}],max_results_per_link=3)
    assert response.status_code==200 and len(response.json()['logs'])==3
    assert response.json()['limited'] and len(sent)==2

def test_context_document_is_not_counted_as_an_event_for_statistics():
    def api(r):return httpx.Response(200,json={'case':'summary'} if r.url.path=='/case' else {'data':{'records':[{'event':1}]}})
    response=fetch(api,context_path_template='/case')
    assert response.status_code==200
    assert len(response.json()['logs'])==2
    assert [json.loads(v) for v in response.json()['record_logs']]==[{'event':1}]
