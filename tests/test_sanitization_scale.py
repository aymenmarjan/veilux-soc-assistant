"""Large batches: protection stays complete and finishes within its bounded limits."""
import asyncio
import base64
import hashlib
import json
import random
import re
import time
import uuid
import pytest
from fastapi.testclient import TestClient
import server
from secret_detection import MECHANISMS, detect_secrets, redact_findings


def realistic_logs(n, seed=7):
    """Windows logon events, firewall CEF lines and JSON events with many distinct values."""
    r = random.Random(seed)
    users = ['alice.martin', 'bob.k', 'svc_backup', 'CORP\\jdoe'] + [f'user{i:03d}' for i in range(60)]
    hosts = [f'WS-{i:04d}.corp.example.org' for i in range(80)]
    out = []
    for i in range(n):
        ip, pub = f'10.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}', f'203.0.113.{r.randint(1, 254)}'
        guid = '{' + str(uuid.UUID(int=r.getrandbits(128))) + '}'
        if i % 3 == 0:
            out.append(json.dumps({'_index': 'logs-windows-2026.11.05', '_source': {'event': {'code': 4625},
                'winlog': {'computer_name': r.choice(hosts), 'event_data': {'TargetUserName': r.choice(users),
                'IpAddress': pub, 'TargetLogonGuid': guid}}, 'host': {'name': r.choice(hosts), 'ip': ip}}}))
        elif i % 3 == 1:
            out.append(f'CEF:0|Vendor|Firewall|1.0|100|Deny|5|src={pub} dst={ip} suser={r.choice(users)} '
                       f'dhost={r.choice(hosts)} fileHash={hashlib.sha256(str(i).encode()).hexdigest()}')
        else:
            out.append(json.dumps({'user': r.choice(users), 'email': f'user{i}@example.com', 'src_ip': ip,
                                   'url': f'https://cdn.example.net/a/{i}.js'}))
    return out


def original_replace(text, reverse_mapping):
    """The masking algorithm as it was before batch compilation (reference)."""
    canonical = {value.lower(): marker for value, marker in reverse_mapping.items()}
    alternatives = sorted(canonical, key=len, reverse=True)
    pattern = re.compile(r"(?<![A-Za-z0-9_])(?:" + "|".join(re.escape(v) for v in alternatives) + r")(?![A-Za-z0-9_])", re.I)
    pieces, cursor = [], 0
    for marker in list(server._PLACEHOLDER_PATTERN.finditer(text)) + [None]:
        end = marker.start() if marker else len(text)
        pieces.append(pattern.sub(lambda m: server._privacy_marker_for(m.group(0), canonical), text[cursor:end]))
        if marker:
            pieces.append(marker.group(0)); cursor = marker.end()
    return ''.join(pieces)


def test_batch_masking_matches_the_original_algorithm():
    r = random.Random(3)
    atoms = ['alice', 'ALICE', 'bo', 'bob', '10', '10.1', '10.1.1.1', '10.1.1.10', 'CORP\\jdoe', 'jdoe', 'user@example.com',
             'example.com', 'srv-01', 'srv-01.corp', '\\\\srv', '{ab-12}', '-x', '_id', 'a b', 'café', 'ſtraße', 'strasse',
             'K', 'k', 'İstanbul', 'istanbul', 's', 'ſ', '.dot']
    seps = [' ', '.', '@', '\\', '-', '_', ':', '"', '/', '⟦IP#1⟧', 'é', 'ſ', 'K', '\n', '', 'İ']
    for _ in range(1500):
        mapping = {v: f'⟦V#{i}⟧' for i, v in enumerate(r.sample(atoms, r.randint(1, 12)))}
        compiled = server._privacy_replacer(mapping)
        for _ in range(6):
            text = ''.join(r.choice(atoms + seps) + r.choice(seps) for _ in range(r.randint(0, 10)))
            assert server._replace_privacy_values(text, mapping, compiled) == original_replace(text, mapping), (text, mapping)


def test_unusual_case_folding_no_longer_stops_the_batch():
    # "s" matches "ſ" case-insensitively; looking the marker up by lower() used to raise KeyError.
    assert server._replace_privacy_values('user ſ logged in', {'s': '⟦USER#1⟧'}) == 'user ⟦USER#1⟧ logged in'


def test_shared_reverse_index_gives_the_same_masking():
    texts = ['token=ghp_' + 'A' * 36 + ' again ghp_' + 'A' * 36, 'password=Sup3rS3cretValue!', 'aws AKIA' + 'B' * 16]
    plain, indexed, index = {}, {}, {}
    for text in texts:
        a = redact_findings(text, detect_secrets(text), mapping=plain)
        b = redact_findings(text, detect_secrets(text), mapping=indexed, reverse_index=index)
        assert a[0] == b[0]
    assert plain == indexed and index == {v: p for p, v in indexed.items()}


def test_local_work_limit_grows_with_request_size_and_stays_bounded():
    seen = []
    async def inner(scope, receive, send):
        seen.append((server._request_bytes.get(), server.local_work_timeout()))
    middleware = server._RequestSizeMiddleware(inner)
    for size in (0, 2_000_000, 10**10):
        asyncio.run(middleware({'type': 'http', 'headers': [(b'content-length', str(size).encode())]}, None, None))
    assert seen == [(0, server.SCAN_TIMEOUT_SECONDS), (2_000_000, server.SCAN_TIMEOUT_SECONDS + 2 * server.SCAN_SECONDS_PER_MB),
                    (10**10, server.SCAN_TIMEOUT_MAX_SECONDS)]


def test_thousands_of_logs_are_protected_within_the_limit():
    logs = realistic_logs(2500)
    started = time.perf_counter()
    response = TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN}).post('/analyze', json={'logs': logs, 'mode': 'sanitize_only', 'sanitize': True,
        'secret_protection': {m: True for m in MECHANISMS}, 'enable_pattern_sanitization': True})
    assert response.status_code == 200, response.text
    body = response.json()
    assert len(body['mapping_table']) > 2000
    # Every internal address and account in the batch was replaced.
    assert not re.search(r'\b10\.\d+\.\d+\.\d+\b', body['sanitized_log'])
    assert 'alice.martin' not in body['sanitized_log'] and 'svc_backup' not in body['sanitized_log']
    assert time.perf_counter() - started < server.SCAN_TIMEOUT_MAX_SECONDS


def certificate_records(n, seed=11):
    """Badge-style JSON records: each has its own IDs, slugs and image paths, like a credential API."""
    r = random.Random(seed)
    records = []
    for i in range(n):
        uid = lambda: str(uuid.UUID(int=r.getrandbits(128)))
        badge = uid()
        records.append(json.dumps({'id': badge, 'issued_to': 'Sample Person', 'issued_at': '2024-02-14T06:30:09.000-06:00',
            'public': True, 'state': 'accepted', 'earner_path': f'/users/sample-person-{i}',
            'issuer': {'summary': 'issued by Example Academy', 'entities': [{'label': 'Issued by', 'primary': True,
                'entity': {'type': 'Organization', 'name': 'Example Academy', 'verified': False}}]},
            'badge_template': {'id': uid(), 'name': f'Networking course {i}', 'vanity_slug': f'networking-course-level-{i}.1',
                'description': 'The earner of this badge completed the course and can configure switches, routers and '
                               'end devices, explain addressing, and troubleshoot connectivity in small networks. ' * 3,
                'image_url': f'https://images.example.org/images/{uid()}/course_badge_{i}.png',
                'skills': [{'name': f'Skill {i}-{k}', 'canonical': False} for k in range(4)]}},
            indent=2))
    return records


def test_a_whole_batch_checked_as_one_text_is_not_capped_at_100_tokens():
    # Each record stays under the per-text minimum on its own, but the final
    # check before the AI reads the whole batch as one text.
    records = certificate_records(40)
    batch = '\n\n'.join(records)
    assert len(batch) > 25_000
    detect_secrets(records[0])
    detect_secrets(batch)
    response = TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN}).post('/sanitize', json={'logs': [batch]})
    assert response.status_code == 200, response.text


def test_decoding_stays_bounded_and_fails_closed_on_dense_unique_tokens():
    from secret_detection import decode_candidate_limit
    assert decode_candidate_limit('x' * 1000) == 100
    assert decode_candidate_limit('x' * 25_000) == 100
    assert decode_candidate_limit('x' * 100_000) == 400
    r = random.Random(5)
    dense = ' '.join(base64.b64encode(r.randbytes(24)).decode() for _ in range(3000))
    with pytest.raises(ValueError, match='Decoded candidate limit exceeded'):
        detect_secrets(dense)
    response = TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN}).post('/sanitize', json={'logs': [dense]})
    assert response.status_code == 500
    assert 'too many distinct encoded-looking values' in response.json()['detail']
    assert dense[:20] not in response.text
