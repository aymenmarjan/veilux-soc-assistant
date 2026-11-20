"""Provider token formats adapted from Gitleaks, with synthetic offline fixtures."""
import csv
import json
from pathlib import Path

import pytest

from secret_detection import PROVIDER_RULES, scan_secrets
from sanitization_harness import OFF, run, log_block


FORMATS = [
    ('PlanetScale API token', 'pscale_tkn_', 'Ab9_=.-x'*4, 32, 64),
    ('PlanetScale OAuth token', 'pscale_oauth_', 'Ab9_=.-x'*4, 32, 64),
    ('PlanetScale password', 'pscale_pw_', 'Ab9_=.-x'*4, 32, 64),
    ('Pulumi token', 'pul-', '0123456789abcdef'*2+'01234567', 40, 40),
]


@pytest.mark.parametrize('kind,prefix,payload,minimum,maximum', FORMATS)
def test_audited_capture_and_escaped_model_boundary(kind,prefix,payload,minimum,maximum):
    value = prefix+payload
    config = {**OFF,'known_tokens':True}
    for wrapper in ('before %s after','[%s]','"%s"','%s;','(%s),'):
        source = wrapper % value
        findings = scan_secrets(source, config)
        exact = [f for f in findings if f.kind==kind]
        assert len(exact)==1
        assert exact[0].value==value and exact[0].confidence=='high'
        assert source[exact[0].start:exact[0].end]==value
    source = '{"ref":"\\u%04x%s"}' % (ord(value[0]), value[1:])
    prompt,response = run([source],config=config,allowed_ambiguous_secrets=[value])
    assert json.loads(log_block(prompt))['ref'].startswith('⟦SECRET#')
    assert value not in prompt and value not in json.dumps(response.model_dump())
    pattern = next(pattern for name,pattern,_ in PROVIDER_RULES if name==kind)
    assert pattern.fullmatch(prefix+'a'*minimum)
    assert pattern.fullmatch(prefix+'a'*maximum)
    for negative in (prefix+'a'*(minimum-1),prefix+'a'*(maximum+1),'x'+value,prefix+'a'*maximum+'z',
                     prefix+'é'*minimum, prefix+'!'*minimum, 'public_'+payload):
        assert not pattern.search(negative), negative


def test_case_and_public_controls_for_audited_rules():
    rules = {name:pattern for name,pattern,_ in PROVIDER_RULES}
    assert rules['PlanetScale password'].fullmatch('PSCALE_PW_'+'A'*32)
    assert not rules['PlanetScale API token'].search('PSCALE_TKN_'+'A'*32)
    assert not rules['Pulumi token'].search('pul-'+'A'*40)
    assert not scan_secrets('https://app.pulumi.com/user/project pscale_tkn_ documentation',{**OFF,'known_tokens':True})


def test_inventory_audit_dispositions_and_exact_counts():
    rows = list(csv.DictReader((Path(__file__).parents[1]/'docs/SECRET_RULE_INVENTORY.csv').open(encoding='utf-8',newline='')))
    from collections import Counter
    assert len(PROVIDER_RULES)==38
    assert Counter(r['status'] for r in rows if r['source']=='gitleaks') == {'adapted':40,'duplicate':5,'skipped':161}
    assert Counter(r['status'] for r in rows if r['source']=='secretlint') == {'adapted':13,'duplicate':2,'skipped':9}
    assert all(r['audit_disposition'] in {'adapted','duplicate','inapplicable','unreviewed','deferred'} for r in rows)
    assert all(r['audit_disposition'] in {'inapplicable','unreviewed','deferred'} for r in rows if r['status']=='skipped')
