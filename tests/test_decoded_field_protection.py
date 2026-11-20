"""Decoded and escaped field names get the same protection as plain ones."""
import asyncio
import json

import pytest

import server
from sanitization_harness import OFF, privacy, run, log_block


@pytest.mark.parametrize('source,key,original', [
    ('{"password":12345}', 'password',12345),
    ('{"Authorization":"Bearer tiny"}', 'Authorization','Bearer tiny'),
    ('{"Cookie":"session=tiny"}', 'Cookie','session=tiny'),
    (r'{"\u0070assword":12345}', 'password',12345),
    (r'{"\u0041uthorization":"Bearer tiny"}', 'Authorization','Bearer tiny'),
    (r'{"\u0043ookie":"session=tiny"}', 'Cookie','session=tiny'),
])
def test_decoded_field_context_is_equivalent(source,key,original):
    prompt,_=run([source])
    actual=json.loads(log_block(prompt))[key]
    assert actual!=original,log_block(prompt)
    assert '⟦SECRET#' in str(actual)

def test_escaped_authorization_value_cannot_be_restored_as_privacy():
    prompt,result=run(['acme'],rules=[privacy('acme')],
        feedback=[r'{"Authorization":"Bearer a\u0063me"}'],
        reply='⟦CUSTOM_PRIVACY#1⟧')
    assert 'acme' not in prompt
    assert 'acme' not in result.analysis, (result.analysis,result.mapping_table)
    assert 'acme' not in (result.mapping_table or {}).values()

def test_combined_privacy_and_field_hide_restore_original_value():
    source='{"customer":"prefix acme"}'
    _,result=run([source],rules=[privacy('acme','substring')],
        sanitize=True,json_keys_to_hide=['customer'],config=OFF,reply=log_block)
    assert json.loads(result.analysis)==json.loads(source),result.analysis

def test_unknown_marker_shaped_value_does_not_bypass_field_hide():
    source='{"customer":"⟦SensitiveCustomerName⟧"}'
    prompt,_=run([source],sanitize=True,json_keys_to_hide=['customer'],config=OFF)
    assert 'SensitiveCustomerName' not in log_block(prompt),log_block(prompt)

def test_preflight_includes_strong_decoded_provider_finding():
    token='ghp_'+'A'*36
    source='{"ref":"\\u0067'+token[1:]+'"}'
    config={**OFF,'known_tokens':True}
    req=server.SecretScanRequest(texts=[source],secret_protection=config)
    scanned=asyncio.run(server.secret_scan_endpoint(req))
    prompt,_=run([source],config=config)
    assert '⟦SECRET#' in log_block(prompt)
    assert any(f['confidence']=='high' and f['value']==token for f in scanned['findings']),scanned
