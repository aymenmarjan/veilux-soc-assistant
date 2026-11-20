"""Statistics privacy mappings and outbound context, using mocked providers."""
import asyncio
import json
from unittest.mock import patch
import pytest
import server
from secret_detection import MECHANISMS

OFF={name:False for name in MECHANISMS}

def statistics(field,value):
    return [{'indexPattern':'events-*','sampled':17,'total':31,'fields':[
        {'field':field,'count':17,'percentage':100,'topValues':[{'value':value,'count':17,'percentage':100}]}]}]

def run(stats,**options):
    sent=[]
    async def ai(prompt,key):sent.append(prompt);return 'Synthetic analysis'
    with patch.object(server,'call_groq_ai',ai),patch.object(server,'training_data',{'feedback_entries':[]}):
        result=asyncio.run(server.analyze_logs(server.LogAnalysisRequest(logs=[],mode='groq',api_key='synthetic',
            field_statistics=stats,**options)))
    actual=json.loads(sent[0].split('Search Field Statistics (aggregate evidence, not individual events):\n',1)[1].split('```json\n',1)[1].split('\n```',1)[0])
    return actual,result,sent[0]

@pytest.mark.parametrize('field,value',[('User','statistics-alice'),('Computer','workstation-stat')])
def test_automatic_field_context_adds_statistics_to_mapping(field,value):
    actual,result,prompt=run(statistics(field,value),sanitize=True,secret_protection=OFF)
    masked=actual[0]['fields'][0]['topValues'][0]['value']
    assert value not in prompt
    assert result.mapping_table[masked]==value
    assert json.loads(result.sanitized_field_statistics)==actual
    assert actual[0]['fields'][0]['count']==17

@pytest.mark.parametrize('value',[12345,17,True,None,'⟦SensitiveCustomerName⟧','⟦SECRET#1⟧','prefix acme'])
def test_selected_statistics_values_are_typed_and_mapped(value):
    actual,result,prompt=run(statistics('Customer.Id',value),sanitize=True,enable_pattern_sanitization=False,
        statistics_fields_to_hide=['customer-id'],secret_protection=OFF)
    masked=actual[0]['fields'][0]['topValues'][0]['value']
    assert isinstance(masked,str) and masked.startswith('⟦') and masked!=value
    assert masked in result.mapping_table
    assert actual[0]['sampled']==17 and actual[0]['fields'][0]['topValues'][0]['count']==17

def test_json_field_rules_apply_to_statistics_names():
    actual,result,_=run(statistics('host.name','machine-from-stats'),sanitize=True,
        enable_pattern_sanitization=False,json_keys_to_hide=['host.name'],secret_protection=OFF)
    masked=actual[0]['fields'][0]['topValues'][0]['value']
    assert result.mapping_table[masked]=='machine-from-stats'

def test_statistics_credential_context_is_never_restorable_even_with_privacy_disabled():
    actual,result,prompt=run(statistics('password','tiny-stat-secret'),sanitize=False,
        secret_protection={**OFF,'assignments':True})
    masked=actual[0]['fields'][0]['topValues'][0]['value']
    assert 'tiny-stat-secret' not in prompt
    assert masked.startswith('⟦SECRET#') and result.mapping_table[masked]==server.PROTECTED_SECRET_LABEL
    assert 'tiny-stat-secret' not in json.dumps(result.mapping_table)

def test_stats_ip_and_keyword_mapping_already_work_control():
    stats=statistics('message','10.73.5.21 customer-stat')
    actual,result,prompt=run(stats,sanitize=True,custom_keywords={'customer-stat':'ORG'},secret_protection=OFF)
    assert '10.73.5.21' in result.mapping_table.values()
    assert 'customer-stat' in result.mapping_table.values()
    assert '10.73.5.21' not in prompt and 'customer-stat' not in prompt

@pytest.mark.parametrize('value',[True,None,17,'quote " slash \\ Unicode é',['alpha',True,None]])
def test_selected_statistics_restore_types_without_altering_counts(value):
    stats=statistics('customer',value)
    async def echo(prompt,key):return prompt.split('Search Field Statistics',1)[1].split('```json\n',1)[1].split('\n```',1)[0]
    with patch.object(server,'call_groq_ai',echo),patch.object(server,'training_data',{'feedback_entries':[]}):
        result=asyncio.run(server.analyze_logs(server.LogAnalysisRequest(logs=['event-only'],mode='groq',api_key='synthetic',
            field_statistics=stats,sanitize=True,enable_pattern_sanitization=False,
            statistics_fields_to_hide=['customer'],secret_protection=OFF)))
    assert json.loads(result.analysis)==stats
    assert json.loads(result.sanitized_field_statistics)[0]['fields'][0]['topValues'][0]['count']==17

@pytest.mark.parametrize('field,value,mechanism',[
    ('password',12345,'assignments'),('Authorization','Bearer tiny-stat','authorization'),('Cookie','session=tiny-stat','cookies')])
def test_statistics_preflight_and_enforcement_share_credential_context(field,value,mechanism):
    stats=statistics(field,value)
    config={**OFF,mechanism:True}
    scanned=asyncio.run(server.secret_scan_endpoint(server.SecretScanRequest(texts=[json.dumps(stats)],secret_protection=config)))
    assert any(f['confidence']=='high' for f in scanned['findings'])
    actual,result,prompt=run(stats,sanitize=True,statistics_fields_to_hide=[field],secret_protection=config)
    masked=actual[0]['fields'][0]['topValues'][0]['value']
    assert str(value) not in prompt and '⟦SECRET#' in masked
    assert str(value) not in result.mapping_table.values()
    assert server.PROTECTED_SECRET_LABEL in result.mapping_table.values()

def test_privacy_off_is_visible_without_claiming_automatic_masking():
    stats=statistics('User','statistics-alice')
    actual,result,prompt=run(stats,sanitize=False,secret_protection=OFF)
    assert actual==stats and json.loads(result.sanitized_field_statistics)==stats
    assert not result.mapping_table

def test_statistics_heuristic_exclusion_does_not_disable_strong_credentials():
    token='ghp_'+'A'*36
    config={**OFF,'heuristics':True,'known_tokens':True}
    stats=statistics('_index',token)
    req=server.SecretScanRequest(texts=[json.dumps(stats)],secret_protection=config,
        heuristic_field_exclusions=[{'path':'_index','match_mode':'key_anywhere'}])
    findings=asyncio.run(server.secret_scan_endpoint(req))['findings']
    assert any(f['value']==token and f['confidence']=='high' for f in findings)
