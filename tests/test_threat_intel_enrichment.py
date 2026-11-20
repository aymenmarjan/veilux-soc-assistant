"""TI regression coverage at HTTP/provider boundaries; no live provider calls."""
import asyncio
import json
from unittest.mock import patch
import httpx
import pytest
from fastapi.testclient import TestClient
import server

REAL_CLIENT=httpx.AsyncClient
ABUSE={'ipAddress':'203.0.113.146','abuseConfidenceScore':0,'totalReports':54,
       'numDistinctUsers':12,'isp':'Example Transit Networks','usageType':'Fixed Line ISP',
       'domain':'example.net','countryCode':'PT','countryName':'Portugal','hostnames':[],
       'isPublic':True,'ipVersion':4,'isWhitelisted':False,'isTor':False,
       'lastReportedAt':'2026-10-01T12:00:00Z'}

@pytest.fixture(autouse=True)
def isolated_cache():
    with patch.object(server,'threat_intel_cache',{}),patch.object(server,'_save_threat_intel_cache'):
        yield

def endpoint(payload,handler):
    def client(*args,**kwargs):return REAL_CLIENT(*args,transport=httpx.MockTransport(handler),**kwargs)
    with patch.object(server.httpx,'AsyncClient',client):
        return TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN}).post('/threat-intel/lookup',json=payload)

def test_manual_whois_needs_no_paid_provider_key():
    calls=[]
    def api(request):
        calls.append(request)
        return httpx.Response(200,json={'ldhName':'example.net','events':[]})
    response=endpoint({'ioc':'example.net','enable_virustotal':False,'enable_abuseipdb':False,'enable_whois':True},api)
    assert response.status_code==200,response.text
    assert response.json()['sources']['whois']['registered'] is True
    assert len(calls)==1 and calls[0].url.host=='rdap.org'

def test_abuseipdb_preserves_structured_details_and_zero_score():
    def api(request):
        assert request.url.host=='api.abuseipdb.com'
        return httpx.Response(200,json={'data':ABUSE})
    response=endpoint({'ioc':'203.0.113.146','abuseipdb_api_key':'synthetic','enable_whois':False},api)
    assert response.status_code==200,response.text
    data=response.json()['sources']['abuseipdb']
    assert data['isp']==ABUSE['isp'] and data['usage_type']=='Fixed Line ISP'
    assert data['country_name']=='Portugal' and data['domain']=='example.net'
    assert data['total_reports']==54 and data['abuse_confidence_score']==0
    assert data['report_window_days']==90 and data['distinct_reporters']==12
    assert data['asn'] is None and data['city'] is None

def test_cache_respects_source_switches_and_newly_enabled_provider():
    calls=[]
    def api(request):
        calls.append(request.url.host)
        if request.url.host=='api.abuseipdb.com':return httpx.Response(200,json={'data':ABUSE})
        return httpx.Response(200,json={'name':'EXAMPLE-NET','startAddress':'203.0.113.0','endAddress':'203.0.113.255'})
    async def run():
        async with REAL_CLIENT(transport=httpx.MockTransport(api)) as client:
            first=await server.lookup_ioc(client,'203.0.113.146','ip',None,'synthetic',enable_whois=False)
            second=await server.lookup_ioc(client,'203.0.113.146','ip',None,None,enable_abuseipdb=False)
            return first,second
    first,second=asyncio.run(run())
    assert set(first['sources'])=={'abuseipdb'}
    assert set(second['sources'])=={'whois'} and calls==['api.abuseipdb.com','rdap.org']

def test_changed_key_and_explicit_refresh_cannot_reuse_old_success():
    calls=[]
    def api(request):
        calls.append(request.headers['key'])
        return httpx.Response(200,json={'data':ABUSE}) if request.headers['key']=='good' else httpx.Response(401)
    async def run():
        async with REAL_CLIENT(transport=httpx.MockTransport(api)) as client:
            await server.lookup_ioc(client,'203.0.113.146','ip',None,'good',enable_whois=False)
            return await server.lookup_ioc(client,'203.0.113.146','ip',None,'bad',enable_whois=False)
    result=asyncio.run(run())
    assert result['sources']['abuseipdb']['status']=='error' and calls==['good','bad']

def test_missing_score_is_unknown_not_zero_or_clean():
    response=endpoint({'ioc':'203.0.113.146','abuseipdb_api_key':'synthetic','enable_whois':False},
        lambda request:httpx.Response(200,json={'data':{'isp':'EXAMPLE-NET'}}))
    result=response.json()
    assert result['verdict']=='unknown'
    assert result['sources']['abuseipdb'].get('abuse_confidence_score') is None

def test_domain_registration_uses_registry_domain_and_cidr_keeps_prefix_length():
    calls=[]
    def api(request):
        calls.append(str(request.url))
        if '/domain/' in request.url.path:return httpx.Response(200,json={'ldhName':'example.co.uk'})
        return httpx.Response(200,json={'name':'EXAMPLE-NET','startAddress':'203.0.113.0','endAddress':'203.0.113.255',
            'cidr0_cidrs':[{'v4prefix':'203.0.113.0','length':24}]})
    async def run():
        async with REAL_CLIENT(transport=httpx.MockTransport(api)) as client:
            domain=await server.query_rdap(client,'mail.example.co.uk','domain')
            ip=await server.query_rdap(client,'203.0.113.146','ip')
            return domain,ip
    domain,ip=asyncio.run(run())
    assert calls[0].endswith('/domain/example.co.uk')
    assert domain['queried_domain']=='example.co.uk' and domain['requested_domain']=='mail.example.co.uk'
    assert ip['cidr']=='203.0.113.0/24'

def test_rdap_404_does_not_claim_unregistered():
    async def run():
        async with REAL_CLIENT(transport=httpx.MockTransport(lambda request:httpx.Response(404))) as client:
            return await server.query_rdap(client,'example.net','domain')
    result=asyncio.run(run())
    assert result['status']=='not_found' and result.get('registered') is not False

def test_vt_network_metadata_is_retained_without_inventing_detections():
    async def run():
        async with REAL_CLIENT(transport=httpx.MockTransport(lambda request:httpx.Response(200,json={
            'data':{'attributes':{'asn':64500,'as_owner':'EXAMPLE-NET','country':'PT','network':'203.0.113.0/24'}}}))) as client:
            return await server.lookup_ioc(client,'203.0.113.146','ip','synthetic',None,enable_whois=False)
    result=asyncio.run(run())
    assert result['sources']['virustotal']['asn']==64500
    assert result['verdict']=='unknown'


def test_failed_provider_retries_while_success_is_cached_and_whois_is_cached():
    calls=[]
    def api(request):
        calls.append(request.url.host)
        if request.url.host=='api.abuseipdb.com':
            if calls.count('api.abuseipdb.com')==1:return httpx.Response(429)
            return httpx.Response(200,json={'data':ABUSE})
        return httpx.Response(200,json={'name':'EXAMPLE-NET','startAddress':'203.0.113.0'})
    async def run():
        async with REAL_CLIENT(transport=httpx.MockTransport(api)) as client:
            first=await server.lookup_ioc(client,'203.0.113.146','ip',None,'synthetic')
            second=await server.lookup_ioc(client,'203.0.113.146','ip',None,'synthetic')
            third=await server.lookup_ioc(client,'203.0.113.146','ip',None,None)
            return first,second,third
    first,second,third=asyncio.run(run())
    assert first['lookup_status']=='partial' and first['sources']['abuseipdb']['status']=='rate_limited'
    assert second['lookup_status']=='complete' and second['sources']['whois']['cached']
    assert third['cached'] and set(third['sources'])=={'whois'}
    assert calls.count('rdap.org')==1 and calls.count('api.abuseipdb.com')==2
    assert 'synthetic' not in json.dumps(server.threat_intel_cache)


def test_explicit_refresh_and_expired_entry_use_network_again():
    calls=[]
    def api(request):
        calls.append(1)
        return httpx.Response(200,json={'data':ABUSE}) if len(calls)==1 else httpx.Response(401)
    payload={'ioc':'203.0.113.146','abuseipdb_api_key':'synthetic','enable_whois':False}
    assert endpoint(payload,api).json()['sources']['abuseipdb']['status']=='ok'
    assert endpoint(payload,api).json()['cached']
    assert endpoint({**payload,'use_cache':False},api).json()['sources']['abuseipdb']['status']=='error'
    assert endpoint(payload,api).json()['sources']['abuseipdb']['status']=='error'
    assert len(calls)==3
    key=server._ti_cache_key('example.net','domain','whois',None)
    server.threat_intel_cache[key]={'cached_at':0,'result':{'status':'ok'}}
    assert server._get_cached_ti('example.net','domain','whois',None) is None


def test_slow_registry_keeps_reputation_result_and_is_cancelled():
    async def run():
        started,stopped,tick=asyncio.Event(),asyncio.Event(),asyncio.Event()
        async def api(request):
            if request.url.host=='api.abuseipdb.com':return httpx.Response(200,json={'data':ABUSE})
            started.set()
            try:await asyncio.sleep(30)
            finally:stopped.set()
        async def heartbeat():
            await started.wait()
            await asyncio.sleep(0)
            tick.set()
        async with REAL_CLIENT(transport=httpx.MockTransport(api)) as client:
            pulse=asyncio.create_task(heartbeat())
            result=await server.lookup_ioc(client,'203.0.113.146','ip',None,'synthetic',timeout_seconds=.1)
            await pulse
            assert started.is_set() and stopped.is_set() and tick.is_set()
            assert result['sources']['abuseipdb']['total_reports']==54
            assert result['sources']['whois']['status']=='timeout' and result['lookup_status']=='partial'
            again=await server.lookup_ioc(client,'203.0.113.146','ip',None,'synthetic',enable_whois=False)
            assert again['cached']
    asyncio.run(run())


def test_parent_cancellation_stops_all_started_provider_requests():
    async def run():
        started,stopped=set(),set()
        ready=asyncio.Event()
        async def api(request):
            started.add(request.url.host)
            if len(started)==3:ready.set()
            try:await asyncio.sleep(30)
            finally:stopped.add(request.url.host)
        async with REAL_CLIENT(transport=httpx.MockTransport(api)) as client:
            task=asyncio.create_task(server.lookup_ioc(client,'203.0.113.146','ip','vt','abuse'))
            await asyncio.wait_for(ready.wait(),1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):await task
            assert stopped==started and len(stopped)==3 and not server.threat_intel_cache
    asyncio.run(run())


@pytest.mark.parametrize('status,body,expected',[
    (401,{},'error'),(403,{},'error'),(429,{},'rate_limited'),(500,{},'error'),
    (200,{'data':None},'error'),(200,{'data':[]},'error'),
])
def test_abuse_failures_are_unknown_and_not_cached(status,body,expected):
    result=endpoint({'ioc':'203.0.113.146','abuseipdb_api_key':'synthetic','enable_whois':False},
        lambda request:httpx.Response(status,json=body)).json()
    assert result['sources']['abuseipdb']['status']==expected
    assert result['verdict']=='unknown' and result['lookup_status']=='unavailable'
    assert not server.threat_intel_cache


@pytest.mark.parametrize('score',[None,True,-1,101,'0'])
def test_invalid_scores_are_not_verdicts(score):
    result=endpoint({'ioc':'203.0.113.146','abuseipdb_api_key':'synthetic','enable_whois':False},
        lambda request:httpx.Response(200,json={'data':{**ABUSE,'abuseConfidenceScore':score}})).json()
    assert result['sources']['abuseipdb']['abuse_confidence_score'] is None
    assert result['verdict']=='unknown'


def test_registry_ipv6_and_domain_normalization_preserve_url_case():
    calls=[]
    def api(request):
        calls.append(str(request.url))
        if '/ip/' in request.url.path:return httpx.Response(200,json={'name':'SYNTHETIC','cidr0_cidrs':[{'v6prefix':'2001:4860::','length':32}]})
        return httpx.Response(200,json={'ldhName':'example.co.uk'})
    result=endpoint({'ioc':'MAIL.Example.CO.UK.','enable_virustotal':False},api)
    assert result.status_code==200 and result.json()['sources']['whois']['queried_domain']=='example.co.uk'
    result=endpoint({'ioc':'2001:4860:4860::8888'},api).json()
    assert result['sources']['whois']['cidr']=='2001:4860::/32'
    assert server._ti_cache_key('https://example.com/A','url','virustotal','key')!=server._ti_cache_key('https://example.com/a','url','virustotal','key')
    assert len(calls)==2


def test_budget_expiry_reports_skipped_sources_without_dispatch():
    async def run():
        async with REAL_CLIENT(transport=httpx.MockTransport(lambda r:pytest.fail('Provider called after deadline'))) as client:
            return await server.lookup_ioc(client,'203.0.113.146','ip','key','key',timeout_seconds=0)
    result=asyncio.run(run())
    assert len(result['sources'])==3
    assert all(v['status']=='skipped' for v in result['sources'].values())


def test_analysis_enriches_ip_and_domain_at_actual_provider_and_ai_boundaries():
    calls,sent=[],[]
    secret='private-synthetic-pass'
    def api(request):
        calls.append(str(request.url))
        if request.url.host=='api.abuseipdb.com':return httpx.Response(200,json={'data':{**ABUSE,'abuseConfidenceScore':80}})
        if request.url.host=='www.virustotal.com':return httpx.Response(200,json={'data':{'attributes':{
            'last_analysis_stats':{'malicious':1,'suspicious':0,'harmless':90},'asn':64500,'as_owner':'EXAMPLE-NET'}}})
        return httpx.Response(200,json={'ldhName':'example.net','name':'EXAMPLE-NET'})
    def client(*args,**kwargs):return REAL_CLIENT(*args,transport=httpx.MockTransport(api),**kwargs)
    async def ai(prompt,key):sent.append(prompt);return 'Synthetic analysis'
    with patch.object(server.httpx,'AsyncClient',client),patch.object(server,'call_groq_ai',ai),patch.object(server,'training_data',{'feedback_entries':[]}):
        response=TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN}).post('/analyze',json={'logs':[f'ip=203.0.113.146 host=mail.example.net password={secret}'],
            'mode':'groq','api_key':'synthetic','sanitize':False,'enable_threat_intel':True,
            'virustotal_api_key':'synthetic','abuseipdb_api_key':'synthetic'})
    assert response.status_code==200,response.text
    results=response.json()['threat_intel_findings']
    assert {r['type'] for r in results}=={'ip','domain'}
    ip=next(r for r in results if r['type']=='ip')
    assert ip['sources']['abuseipdb']['total_reports']==54 and ip['sources']['abuseipdb']['isp']==ABUSE['isp']
    assert any('/domains/mail.example.net' in c for c in calls)
    assert any('/domain/example.net' in c for c in calls)
    assert not any('abuseipdb' in c and 'mail.example.net' in c for c in calls)
    assert ABUSE['isp'] in sent[0] and '54 reports in 90 days' in sent[0]
    assert secret not in str(calls) and secret not in sent[0]
