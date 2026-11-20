"""Protection checked where data leaves: the AI prompt, TI lookups and local responses."""
import asyncio
import json
import re
import threading
import time
from unittest.mock import AsyncMock, patch

import pytest

import server
import secret_detection as detection
from sanitization_harness import OFF, privacy, run, log_block


@pytest.mark.parametrize('key,value', [
    ('password', '12345'), ('password', '-0'), ('password', 'true'),
    ('password', 'false'), ('password', 'null'), ('password', '"a\\u0063me"'),
    ('Authorization', '"Bearer a\\u0063me"'), ('Proxy-Authorization', '"Basic a\\u0063me"'),
    ('Cookie', '"session=a\\u0063me"'), ('Set-Cookie', '"session=a\\u0063me; HttpOnly"'),
])
def test_plain_and_escaped_context_duplicate_values_and_exact_numbers(key, value):
    escaped_key = '\\u%04x%s' % (ord(key[0]), key[1:])
    unchanged = '"ratio":0.12345678901234567890123456789,"exp":1.2300e+45,"big":999999999999999999999'
    source = '{"events":[{"%s":%s,"%s":%s},{"%s":%s}],%s}' % (key, value, escaped_key, value, escaped_key, value, unchanged)
    prompt, result = run([source], config={**OFF, 'assignments':True, 'authorization':True, 'cookies':True})
    outbound = log_block(prompt)
    assert unchanged in outbound
    pairs = json.loads(outbound, object_pairs_hook=lambda pairs: pairs)
    events = dict(pairs)['events']
    assert all('⟦SECRET#' in str(v) for event in events for _, v in event)
    assert not any(f['value'] != server.PROTECTED_SECRET_LABEL for f in result.secret_findings)


@pytest.mark.parametrize('key', ['password', r'\u0070assword', 'Authorization', r'\u0041uthorization'])
def test_credential_scalar_arrays(key):
    source = '{"%s":["tiny",12345,true,null],"other":1e3}' % key
    prompt, _ = run([source], config={**OFF, 'assignments':True, 'authorization':True})
    parsed = json.loads(log_block(prompt))
    assert all('⟦SECRET#' in value for value in next(iter(parsed.values())))
    assert '"other":1e3' in log_block(prompt)


@pytest.mark.parametrize('feedback,original', [
    (r'{"password":"a\u0063me"}', 'acme'),
    (r'{"Authorization":"Bearer a\u0063me"}', 'acme'),
    (r'{"\u0041uthorization":"Bearer a\u0063me"}', 'acme'),
    (r'{"Proxy-Authorization":"Basic a\u0063me"}', 'acme'),
    (r'{"Cookie":"session=a\u0063me"}', 'session=acme'),
    (r'{"Set-Cookie":"session=a\u0063me"}', 'session=acme'),
])
@pytest.mark.parametrize('evidence_first', [False, True])
def test_logical_identity_prevents_direct_and_composed_restoration(feedback, original, evidence_first):
    source = json.dumps({'customer': 'prefix '+original})
    logs, saved = ([feedback, source], []) if evidence_first else ([source], [feedback])
    prompt, response = run(logs, feedback=saved, rules=[privacy(re.escape(original), 'substring')],
        sanitize=True, json_keys_to_hide=['customer'], enable_pattern_sanitization=False,
        reply=lambda prompt: log_block(prompt))
    assert original not in prompt
    assert original not in json.dumps(response.model_dump(), ensure_ascii=False)


@pytest.mark.parametrize('marker', ['⟦SensitiveCustomerName⟧', '⟦SECRET#1⟧', '⟦CUSTOM_PRIVACY#1⟧', '⟦customer#1⟧'])
@pytest.mark.parametrize('escaped', [False, True])
def test_selected_source_marker_hidden_and_reserved(marker, escaped):
    source = json.dumps({'customer': marker, 'literal': marker}, ensure_ascii=escaped)
    prompt, response = run([source], config=OFF, sanitize=True, json_keys_to_hide=['customer'],
        enable_pattern_sanitization=False, reply=log_block)
    outbound = json.loads(log_block(prompt))
    assert outbound['customer'] != marker
    assert outbound['literal'] == marker
    assert marker not in (response.mapping_table or {})
    assert json.loads(response.analysis) == json.loads(source)


def test_secret_allocation_reserves_escaped_input_markers():
    source = r'{"password":"tiny","literal":"\u27e6SECRET#1\u27e7"}'
    prompt, response = run([source], reply=log_block)
    values = json.loads(log_block(prompt))
    assert values['password'] != values['literal']
    assert values['literal'] == '⟦SECRET#1⟧'
    assert '⟦SECRET#1⟧' not in response.mapping_table
    assert 'tiny' not in json.dumps(response.model_dump())


def test_keyword_marker_collision_does_not_assign_meaning_to_source():
    source = '{"project":"bluebird","literal":"⟦x7q2⟧"}'
    prompt, response = run([source], config=OFF, sanitize=True,
        enable_pattern_sanitization=False, custom_keywords={'bluebird':'x7q2'}, reply=log_block)
    assert json.loads(log_block(prompt))['project'] != '⟦x7q2⟧'
    assert json.loads(response.analysis) == json.loads(source)


def test_mixed_input_and_generated_markers_do_not_recurse():
    source = json.dumps({'customer':'prefix acme ⟦CUSTOM_PRIVACY#1⟧', 'password':'tiny'})
    prompt, response = run([source], config={**OFF,'assignments':True}, rules=[privacy('acme', 'substring')], sanitize=True,
        json_keys_to_hide=['customer', 'password'], enable_pattern_sanitization=False, reply=log_block)
    assert 'acme' not in log_block(prompt) and 'tiny' not in prompt
    assert json.loads(response.analysis)['customer'] == json.loads(source)['customer']
    assert json.loads(response.analysis)['password'].startswith('⟦SECRET#')
    assert 'tiny' not in json.dumps(response.model_dump())


@pytest.mark.parametrize('value', ['prefix acme beta', 'quote" acme \\beta', 'é🙂 acme beta', '⟦CUSTOM_PRIVACY#2⟧ acme beta'])
def test_multiple_composed_hides_preserve_original_unicode_and_escaping(value):
    source = json.dumps({'customer':[value, value], 'other':7}, ensure_ascii=False)
    prompt, response = run([source], config=OFF, rules=[privacy('acme','substring'), privacy('beta','substring')],
        sanitize=True, json_keys_to_hide=['customer'], enable_pattern_sanitization=False, reply=log_block)
    assert 'acme' not in log_block(prompt) and 'beta' not in log_block(prompt)
    assert json.loads(response.analysis) == json.loads(source)
    assert value in response.mapping_table.values()


@pytest.mark.parametrize('lexeme', ['-0','1.2300e+45','12345','true','false','null'])
def test_composed_typed_hides_restore_exact_lexemes(lexeme):
    source = '{"customer":'+lexeme+',"other":0.12345678901234567890123456789}'
    prompt, response = run([source], config=OFF, rules=[privacy(re.escape(lexeme))], sanitize=True,
        json_keys_to_hide=['customer'], enable_pattern_sanitization=False, reply=log_block)
    assert '⟦' in json.loads(log_block(prompt))['customer']
    assert response.analysis == source


def test_late_header_evidence_revokes_all_composed_privacy_maps():
    seen = []
    async def ti(*args, **kwargs): return r'{"Authorization":"Bearer a\u0063me"}', []
    async def ai(prompt, key): seen.append(prompt); return log_block(prompt)
    request = server.LogAnalysisRequest(logs=['{"customer":"prefix acme"}'], mode='groq', api_key='synthetic',
        sanitize=True, enable_pattern_sanitization=False, json_keys_to_hide=['customer'],
        custom_regex_rules=[privacy('acme','substring')], enable_threat_intel=True, enable_whois=True)
    with patch.object(server,'enrich_with_threat_intel',ti), patch.object(server,'call_groq_ai',ai), \
         patch.object(server,'training_data',{'feedback_entries':[]}):
        response = asyncio.run(server.analyze_logs(request))
    assert 'acme' not in seen[0]
    assert 'acme' not in json.dumps(response.model_dump(), ensure_ascii=False)
    assert all(not key.startswith('⟦CUSTOM_PRIVACY') and not key.startswith('⟦customer') for key in response.mapping_table)


def test_preflight_deduplicates_occurrences_but_counts_repeated_values():
    token = 'ghp_' + 'A'*36
    source = '{"ref":"'+token+'","ref":"\\u0067'+token[1:]+'","array":["'+token+'"]}'
    options = dict(secret_protection={**OFF,'known_tokens':True})
    scanned = asyncio.run(server.secret_scan_endpoint(server.SecretScanRequest(texts=[source,source], **options)))
    findings = scanned['findings']
    assert len(findings) == 6
    assert len({(f['source_index'], f['start'], f['end']) for f in findings}) == 6
    assert all(f['value'] == token and f['confidence']=='high' and f['occurrence_count']==6 for f in findings)
    assert [tuple(f['source_path']) for f in findings[:3]] == [('ref',),('ref',),('array',0)]
    prompt, result = run([source], config=options['secret_protection'], allowed_ambiguous_secrets=[token])
    assert token not in log_block(prompt) and log_block(prompt).count('⟦SECRET#') == 3
    assert token not in json.dumps(result.model_dump())


def test_complete_6000_event_analysis_meets_unchanged_deadline():
    assert server.SCAN_TIMEOUT_SECONDS == 10.0
    source = json.dumps([{'password':f'synth{i:05d}abc'} for i in range(6000)])
    prompt, response = run([source], config={**OFF,'assignments':True})
    parsed = json.loads(log_block(prompt))
    assert len(parsed) == 6000 and all(row['password'].startswith('⟦SECRET#') for row in parsed)
    assert len(response.mapping_table) == 6000 and 'synth' not in prompt


@pytest.mark.parametrize('cancel', [False,True])
def test_started_work_stops_on_deadline_or_request_cancellation(cancel):
    entered, stopped = threading.Event(), threading.Event()
    checks = []
    real_check, real_protect = detection.check_work, server.protect_secret_inputs
    def paced_check():
        checks.append(1)
        if len(checks) >= 25: entered.set()
        # Pace real parser work so cancellation deterministically interrupts
        # an active loop, rather than an already-set event or a fake sleeper.
        time.sleep(.002)
        real_check()
    def observed(*args, **kwargs):
        try: return real_protect(*args, **kwargs)
        finally: stopped.set()
    async def exercise():
        ticks = []
        async def heartbeat():
            while not stopped.is_set():
                ticks.append(time.monotonic()); await asyncio.sleep(.005)
        request = server.LogAnalysisRequest(logs=[json.dumps([{'password':'tiny'}]*6000)], mode='groq',
            api_key='synthetic', request_id='scan-cancel' if cancel else 'scan-timeout',
            enable_threat_intel=True, enable_whois=True, secret_protection={**OFF,'assignments':True})
        ai, ti = AsyncMock(return_value='ok'), AsyncMock(return_value=('',[]))
        with patch.object(detection,'check_work',paced_check), patch.object(server,'protect_secret_inputs',observed), \
             patch.object(server,'SCAN_TIMEOUT_SECONDS',10.0 if cancel else .2), \
             patch.object(server,'call_groq_ai',ai), patch.object(server,'enrich_with_threat_intel',ti):
            ticker = asyncio.create_task(heartbeat())
            task = asyncio.create_task(server.analyze_logs(request))
            async def wait_entered():
                while not entered.is_set(): await asyncio.sleep(.005)
            await asyncio.wait_for(wait_entered(),2)
            assert not stopped.is_set()
            if cancel: await server.cancel_analysis(request.request_id)
            with pytest.raises(server.HTTPException) as error: await task
            assert error.value.status_code == (499 if cancel else 500)
            await asyncio.wait_for(ticker,2)
            count = len(checks); await asyncio.sleep(.05)
            assert len(checks) == count and stopped.is_set() and len(ticks)>2
            ai.assert_not_awaited(); ti.assert_not_awaited()
        # The worker has exited; a fresh request can still reach its mock AI.
        with patch.object(server,'call_groq_ai',ai):
            response = await server.analyze_logs(server.LogAnalysisRequest(logs=['safe'],mode='groq',api_key='synthetic',sanitize=False))
            assert response.analysis == 'ok'
            ai.assert_awaited_once()
    asyncio.run(exercise())


def test_one_pass_restoration_does_not_follow_marker_cycles():
    mapping = {'⟦A⟧':'⟦B⟧', '⟦B⟧':'⟦A⟧'}
    assert server.replace_placeholders('⟦A⟧ ⟦B⟧ ⟦unknown⟧',mapping) == '⟦B⟧ ⟦A⟧ ⟦unknown⟧'


def test_raw_bracket_passwords_remain_protected():
    for source in ('password=[mysecret]', 'password={mysecret}'):
        prompt, _ = run([source],config={**OFF,'assignments':True})
        assert 'mysecret' not in prompt


def test_strong_repeat_is_not_offered_as_uncertain_keep():
    result = asyncio.run(server.secret_scan_endpoint(server.SecretScanRequest(
        texts=['password=tiny','authentication alice:tiny'], secret_protection={**OFF,'assignments':True,'context':True})))
    findings = result['findings']
    assert len(findings)==2 and all(f['confidence']=='high' and f['occurrence_count']==2 for f in findings)


def test_ti_result_fields_participate_in_revocation_and_response_protection():
    async def ti(*args,**kwargs): return '', [{'Authorization':'Bearer acme'}]
    with patch.object(server,'enrich_with_threat_intel',ti):
        prompt,response = run(['acme'],rules=[privacy('acme')],reply='⟦CUSTOM_PRIVACY#1⟧',
            enable_threat_intel=True,enable_whois=True)
    assert 'acme' not in prompt
    assert 'acme' not in json.dumps(response.model_dump())


def test_unicode_surrogate_spans_follow_json_decoder_without_overconsuming():
    source = r'{"customer":"\ud800\u0063 acme \ud83d\ude42"}'
    prompt,response = run([source],config=OFF,rules=[privacy('acme','substring')],sanitize=True,
        enable_pattern_sanitization=False,json_keys_to_hide=['customer'],reply=log_block)
    assert 'acme' not in log_block(prompt)
    assert json.loads(response.analysis)==json.loads(source)
