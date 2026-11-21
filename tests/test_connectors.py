"""
VEILUX — connector/backend test suite.

Runs the whole connector engine against a mock SIEM that imitates the API
shapes of the platform templates, so every fetch shape is exercised without a
real console. The mocks follow each vendor's public API documentation:

  * Single request — one call returns the records (OpenSearch Dashboards
                     document lookup)
  * Search job     — create -> poll -> results, with a context document,
                     token-header auth and browser-session auth that repeats
                     CSRF cookies as headers (IBM QRadar), and the same engine
                     with other paths, a nested status field and extra query
                     parameters (Splunk)

Also covered: platform fingerprinting on a wrong health path, error text
surfaced from 401/403 bodies, template arithmetic that limits a search to a
record's own time range, and the threat-intel time budget.

Run it with the backend deps installed:

    pip install -r requirements.txt
    python tests/test_connectors.py
"""

import asyncio
import base64
import json
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from backend_key import use_test_key  # noqa: E402
use_test_key()

from fastapi import FastAPI, Request                      # noqa: E402
from fastapi.responses import JSONResponse                # noqa: E402
from fastapi.testclient import TestClient                 # noqa: E402
import uvicorn                                            # noqa: E402

import server                                             # noqa: E402

# The mock SIEM listens on a loopback port the system chooses. The socket is
# bound here, before the request payloads below use MOCK_URL, and handed to
# uvicorn as it is, so no other program can take the port in between. (A
# fixed port fails where the system reserves it: Windows can exclude ranges
# such as 9367-9466.)
MOCK_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
MOCK_SOCKET.bind(("127.0.0.1", 0))
MOCK_SOCKET.listen(128)
MOCK_PORT = MOCK_SOCKET.getsockname()[1]
MOCK_URL = f"http://127.0.0.1:{MOCK_PORT}"
_MOCK_SERVER = None

mock = FastAPI()
QRADAR = {"polls": 0, "seen_sec": None, "seen_version": None, "query": None}
SPLUNK = {"sid": "1755000000.42", "polls": 0, "search": None, "output_mode": None}

passed = []


def ok(label, detail=""):
    passed.append(label)
    print(f"  PASS  {label}" + (f"  ({detail})" if detail else ""))


# --------------------------------------------------------------------------
# Mock SIEM — QRadar surface
# --------------------------------------------------------------------------

@mock.get("/api/siem/offenses/{offense_id}")
async def qradar_offense(offense_id: int, request: Request):
    QRADAR["seen_sec"] = request.headers.get("sec")
    return {"id": offense_id, "description": "Excessive Firewall Denies", "magnitude": 6,
            "offense_source": "10.0.0.5", "status": "OPEN",
            "start_time": 1785653418148, "last_updated_time": 1785653705140}


@mock.get("/api/siem/offenses")
async def qradar_offense_list(request: Request):
    """Health-check endpoint the QRadar preset uses — 403s with QRadar's own
    body shape unless the token is the good one."""
    if request.headers.get("sec") != "GOODTOKEN":
        return JSONResponse(status_code=403, content={
            "http_response": {"code": 403, "message": "Your account is unable to access the requested resource"},
            "code": 5,
            "description": "The security profile assigned to this token does not grant access to offenses."})
    return []


@mock.post("/api/ariel/searches")
async def qradar_create_search(request: Request):
    if request.headers.get("sec") != "TESTTOKEN":
        return JSONResponse(status_code=401, content={"message": "bad SEC token"})
    QRADAR["seen_version"] = request.headers.get("version")
    QRADAR["query"] = request.query_params.get("query_expression")
    return {"search_id": "abc-123", "status": "WAIT"}


@mock.get("/api/ariel/searches/{sid}")
async def qradar_search_status(sid: str):
    QRADAR["polls"] += 1
    return {"search_id": sid, "status": "COMPLETED" if QRADAR["polls"] >= 2 else "EXECUTE"}


@mock.get("/api/ariel/searches/{sid}/results")
async def qradar_search_results(sid: str):
    return {"events": [
        {"starttime": 1752300000000, "sourceip": "203.0.113.9", "eventname": "Firewall Deny"},
        {"starttime": 1752300001000, "sourceip": "203.0.113.9", "eventname": "Firewall Deny"},
    ]}


@mock.get("/api/help/versions")
async def qradar_versions():
    return [{"version": "12.0"}]


@mock.get("/api/status")
async def qradar_style_404():
    """QRadar answers an unknown path with this distinctive body — the
    fingerprint used to identify the platform when no preset is chosen."""
    return JSONResponse(status_code=404, content={
        "message": "Relative path (/status) is not a known endpoint resource. "
                   "Please refer to documentation for list of endpoint resources."})


@mock.get("/api/session/offenses")
async def qradar_session_api(request: Request):
    """Session-authenticated API: needs the SEC cookie AND the SEC/QRadarCSRF
    values repeated as headers, as the QRadar API documentation describes."""
    if request.cookies.get("SEC") != "SESSSEC" or request.cookies.get("QRadarCSRF") != "CSRF123":
        return JSONResponse(status_code=401, content={"message": "no session"})
    if request.headers.get("sec") != "SESSSEC" or request.headers.get("qradarcsrf") != "CSRF123":
        return JSONResponse(status_code=403, content={
            "description": 'User "j.analyst" has provided insufficient credentials to access this endpoint resource'})
    return []


@mock.get("/api/basic/check")
async def basic_auth_check(request: Request):
    expected = "Basic " + base64.b64encode(b"j.analyst:pw").decode()
    if request.headers.get("authorization") != expected:
        return JSONResponse(status_code=401, content={"message": "bad basic auth"})
    return {"ok": True}


# --------------------------------------------------------------------------
# Mock SIEM — OpenSearch surface
# --------------------------------------------------------------------------

@mock.post("/internal/search/opensearch-with-long-numerals")
async def osd_search(request: Request):
    body = await request.json()
    doc_id = body["params"]["body"]["query"]["ids"]["values"][0]
    return {"rawResponse": {"hits": {"hits": [{"_id": doc_id, "_source": {"event": "test"}}]}}}


# --------------------------------------------------------------------------
# Mock SIEM — Splunk surface
# --------------------------------------------------------------------------

@mock.post("/services/search/jobs")
async def splunk_create(request: Request):
    if request.headers.get("authorization") != "Bearer SPLUNKTOKEN":
        return JSONResponse(status_code=401, content={"messages": [{"text": "unauthorized"}]})
    SPLUNK["search"] = request.query_params.get("search")
    SPLUNK["output_mode"] = request.query_params.get("output_mode")
    return {"sid": SPLUNK["sid"]}


@mock.get("/services/search/jobs/{sid}")
async def splunk_status(sid: str):
    SPLUNK["polls"] += 1
    if sid == "failjob":
        return {"entry": [{"content": {"dispatchState": "FAILED"}}]}
    state = "DONE" if SPLUNK["polls"] >= 2 else "RUNNING"
    return {"entry": [{"content": {"dispatchState": state, "isDone": state == "DONE"}}]}


@mock.get("/services/search/jobs/{sid}/results")
async def splunk_results(sid: str):
    return {"results": [
        {"_time": "2026-08-02T07:55:05", "host": "srv-01", "sourcetype": "WinEventLog:Security",
         "_raw": "EventCode=4625 An account failed to log on"},
        {"_time": "2026-08-02T07:55:07", "host": "srv-01", "sourcetype": "WinEventLog:Security",
         "_raw": "EventCode=4624 An account was successfully logged on"},
    ]}


@mock.get("/services/server/info")
async def splunk_info():
    return {"entry": [{"content": {"version": "9.2.1", "product_type": "splunk"}}]}


# --------------------------------------------------------------------------
# Mock AI services — one per supported API shape, for custom models
# --------------------------------------------------------------------------

AI = {}


@mock.post("/ai/v1/chat/completions")
async def ai_openai_shape(request: Request):
    AI["openai_auth"] = request.headers.get("authorization")
    AI["openai_model"] = (await request.json()).get("model")
    return {"choices": [{"message": {"content": "OPENAI-STYLE ANALYSIS"}}]}


@mock.post("/ai/v1/messages")
async def ai_anthropic_shape(request: Request):
    AI["anthropic_key"] = request.headers.get("x-api-key")
    AI["anthropic_version"] = request.headers.get("anthropic-version")
    return {"content": [{"type": "text", "text": "ANTHROPIC-STYLE ANALYSIS"}]}


@mock.post("/ai/v1beta/generateContent")
async def ai_gemini_shape(request: Request):
    AI["gemini_key"] = request.headers.get("x-goog-api-key")
    AI["gemini_query"] = str(request.query_params)
    return {"candidates": [{"content": {"parts": [{"text": "GEMINI-STYLE ANALYSIS"}]}}]}


@mock.post("/ai/local")
async def ai_local_no_key(request: Request):
    AI["local_auth"] = request.headers.get("authorization")
    return {"choices": [{"message": {"content": "LOCAL MODEL ANALYSIS"}}]}


# --------------------------------------------------------------------------
# Mock RDAP registry responses
# --------------------------------------------------------------------------

@mock.get("/rdap/domain-new")
async def rdap_domain_new():
    from datetime import datetime, timedelta
    created = (datetime.utcnow() - timedelta(days=5)).isoformat() + "Z"
    return {"ldhName": "evil-phish.test",
            "events": [{"eventAction": "registration", "eventDate": created}],
            "entities": [
                {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Cheap Registrar LLC"]]]},
                {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@registrar.test"]]]}],
            "nameservers": [{"ldhName": "ns1.parking.test"}]}


@mock.get("/rdap/domain-old")
async def rdap_domain_old():
    return {"ldhName": "example.test",
            "events": [{"eventAction": "registration", "eventDate": "1998-09-15T04:00:00Z"}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Established Registrar"]]]}]}


@mock.get("/rdap/ip")
async def rdap_ip():
    return {"name": "EXAMPLE-NET", "country": "NL",
            "startAddress": "203.0.113.0", "endAddress": "203.0.113.255",
            "cidr0_cidrs": [{"v4prefix": "203.0.113.0", "length": 24}],
            "events": [{"eventAction": "registration", "eventDate": "2010-01-01T00:00:00Z"}],
            "entities": [
                {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Example ISP BV"]]]},
                {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@isp.test"]]]}]}


def start_mock():
    """Starts the mock SIEM once, on MOCK_SOCKET, and waits until it serves."""
    global _MOCK_SERVER
    if _MOCK_SERVER is not None:
        return
    _MOCK_SERVER = uvicorn.Server(uvicorn.Config(mock, log_level="error"))
    threading.Thread(target=lambda: _MOCK_SERVER.run(sockets=[MOCK_SOCKET]), daemon=True).start()
    deadline = time.monotonic() + 30
    while not _MOCK_SERVER.started:
        if time.monotonic() > deadline:
            raise RuntimeError(f"The mock SIEM did not start on {MOCK_URL}")
        time.sleep(0.05)


def setup_module():
    """Pytest collection needs the same local mock SIEM as the script runner."""
    start_mock()


client = TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN})

QRADAR_PAYLOAD = {
    "siem_links": [
        f"{MOCK_URL}/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=42",
        # duplicated on purpose: must be deduped into one search job
        f"{MOCK_URL}/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=42",
    ],
    "siem_base_url": MOCK_URL,
    "auth_type": "header", "auth_header_name": "SEC", "auth_header_value": "TESTTOKEN",
    "verify_ssl": False,
    # JS-dialect named group on purpose — the backend must normalize it to Python's
    "link_regex": "(?:offensesummary[^#\\s\"']*[?&]summaryId=|/offenses/)(?<offense_id>\\d+)",
    "api_headers_template": {"Version": "12.0", "Accept": "application/json"},
    "response_path": "events",
    "fetch_mode": "search_job",
    "job_create_method": "POST",
    "job_create_path_template": "/api/ariel/searches",
    "job_create_query_template": {
        "query_expression": "SELECT * FROM events WHERE INOFFENSE(${offense_id}) "
                            "ORDER BY starttime DESC LIMIT 50 LAST 7 DAYS"},
    "job_id_path": "search_id",
    "job_status_path_template": "/api/ariel/searches/${job_id}",
    "job_status_field": "status",
    "job_complete_values": ["COMPLETED"], "job_error_values": ["ERROR", "CANCELED"],
    "job_results_path_template": "/api/ariel/searches/${job_id}/results",
    "job_poll_interval_seconds": 0.5, "job_timeout_seconds": 20,
    "context_method": "GET",
    "context_path_template": "/api/siem/offenses/${offense_id}",
}

SPLUNK_PAYLOAD = {
    "siem_links": [], "parsed_params": [{}],
    "siem_base_url": MOCK_URL,
    "auth_type": "header", "auth_header_name": "Authorization",
    "auth_header_value": "Bearer SPLUNKTOKEN",
    "verify_ssl": False,
    "api_headers_template": {"Accept": "application/json"},
    "response_path": "results",
    "fetch_mode": "search_job",
    "job_create_method": "POST",
    "job_create_path_template": "/services/search/jobs",
    "job_create_query_template": {"search": "search index=wineventlog EventCode=4625 | head 50",
                                  "output_mode": "json"},
    "job_id_path": "sid",
    "job_status_path_template": "/services/search/jobs/${job_id}?output_mode=json",
    "job_status_field": "entry.0.content.dispatchState",
    "job_complete_values": ["DONE"], "job_error_values": ["FAILED"],
    "job_results_path_template": "/services/search/jobs/${job_id}/results?output_mode=json&count=50",
    "job_poll_interval_seconds": 0.5, "job_timeout_seconds": 20,
}


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------

def test_qradar_search_job():
    QRADAR["polls"] = 0
    r = client.post("/fetch-siem-logs", json=QRADAR_PAYLOAD)
    body = r.json()
    assert r.status_code == 200, body
    assert body["fetched"] == 3, body            # offense context + 2 events
    assert body["parsed_links"] == 1, body       # duplicate link deduped
    assert json.loads(body["logs"][0])["description"] == "Excessive Firewall Denies"
    assert json.loads(body["logs"][1])["eventname"] == "Firewall Deny"
    assert QRADAR["seen_sec"] == "TESTTOKEN"
    assert QRADAR["seen_version"] == "12.0"
    assert "INOFFENSE(42)" in QRADAR["query"]
    assert QRADAR["polls"] >= 2                  # actually polled to completion
    ok("QRadar search job", f"offense + 2 events, {QRADAR['polls']} polls, dedup")


def test_context_chained_template_arithmetic():
    """The context record's own timestamps bound the event search, with padding —
    ${context.start_time-600000} must render as real epoch millis."""
    QRADAR["polls"] = 0
    payload = {**QRADAR_PAYLOAD, "job_create_query_template": {"query_expression":
        "SELECT QIDNAME(qid) AS event_name, UTF8(payload) AS payload FROM events "
        "WHERE INOFFENSE(${offense_id}) ORDER BY starttime DESC LIMIT 50 "
        "START ${context.start_time-600000} STOP ${context.last_updated_time+600000}"}}
    r = client.post("/fetch-siem-logs", json=payload)
    assert r.status_code == 200, r.text
    assert "START 1785652818148" in QRADAR["query"], QRADAR["query"]   # start - 10 min
    assert "STOP 1785654305140" in QRADAR["query"], QRADAR["query"]    # updated + 10 min
    ok("context-chained template arithmetic", "search bounded to the offense window")


def test_parsed_params_without_links():
    """Content-regex detection yields params directly — no URL involved."""
    QRADAR["polls"] = 0
    r = client.post("/fetch-siem-logs", json={**QRADAR_PAYLOAD, "siem_links": [],
                                              "parsed_params": [{"offense_id": "42"}]})
    body = r.json()
    assert r.status_code == 200 and body["fetched"] == 3, body
    assert "INOFFENSE(42)" in QRADAR["query"]
    ok("parsed_params (content-regex path)", "offense + 2 events, no links")


def test_adhoc_query():
    QRADAR["polls"] = 0
    payload = {**QRADAR_PAYLOAD, "siem_links": [], "parsed_params": [{}],
               "job_create_query_template": {"query_expression": "SELECT * FROM events LAST 15 MINUTES"}}
    payload.pop("context_path_template"), payload.pop("context_method")
    r = client.post("/fetch-siem-logs", json=payload)
    assert r.status_code == 200 and r.json()["fetched"] == 2, r.text
    assert QRADAR["query"] == "SELECT * FROM events LAST 15 MINUTES"
    ok("ad-hoc query", "analyst SPL/AQL passed through verbatim")


OPENSEARCH_REQUEST = {
    "link_regex": r"#/doc/[^/]+/(?<index>[^/?]+)\?(?:[^#]*&)?id=(?<doc_id>[^&]+)",
    "api_method": "POST", "api_path_template": "/internal/search/opensearch-with-long-numerals",
    "api_headers_template": {"osd-xsrf": "osd-fetch"}, "response_path": "rawResponse.hits.hits",
    "api_body_template": json.dumps({"params": {"index": "${index}", "body": {"query": {"ids": {"values": ["${doc_id}"]}}}}}),
}


def test_opensearch_single_request_regression():
    link = f"{MOCK_URL}/app/discover#/doc/idx-pattern/my-index-2026?id=DOC1"
    base = {"siem_links": [link], "siem_base_url": MOCK_URL, "auth_type": "cookie", "auth_cookie": "sess",
            "auth_cookie_name": "session", "verify_ssl": False}
    r = client.post("/fetch-siem-logs", json={**base, **OPENSEARCH_REQUEST})
    assert r.status_code == 200, r.text
    assert json.loads(r.json()["logs"][0])["_id"] == "DOC1"
    # Blank settings are never filled in with OpenSearch values.
    r = client.post("/fetch-siem-logs", json=base)
    assert r.status_code == 400 and "API request path" in r.json()["detail"], r.text
    r = client.post("/fetch-siem-logs", json={**base, **OPENSEARCH_REQUEST, "auth_cookie_name": None})
    assert r.status_code == 400 and "cookie name" in r.json()["detail"], r.text
    ok("OpenSearch single-request regression", "explicit request works; blanks are refused, not guessed")


def test_auth_guard():
    r = client.post("/fetch-siem-logs", json={**QRADAR_PAYLOAD, "auth_header_value": None})
    assert r.status_code == 400, r.text
    ok("auth guard", "no credentials -> 400, not a confusing fetch failure")


def test_health_check_and_error_detail():
    r = client.post("/test-siem", json={**QRADAR_PAYLOAD, "auth_header_value": "GOODTOKEN",
                                        "test_path": "/api/siem/offenses?fields=id&filter=id%3D0"})
    assert r.json()["status"] == "connected", r.text
    ok("/test-siem success")

    r = client.post("/test-siem", json={**QRADAR_PAYLOAD, "auth_header_value": "BADTOKEN",
                                        "test_path": "/api/siem/offenses?fields=id&filter=id%3D0"})
    body = r.json()
    assert body["status"] == "auth_failed", body
    assert "security profile" in body["message"], body   # SIEM's own words surfaced
    ok("/test-siem surfaces the SIEM's 403 reason")


def test_browser_session_csrf_echo():
    """Session cookies alone give 403; repeating SEC/QRadarCSRF as headers
    is what makes session auth work."""
    payload = {
        "siem_links": [], "siem_base_url": MOCK_URL, "auth_type": "browser_session",
        "auth_cookies": {"SEC": "SESSSEC", "QRadarCSRF": "CSRF123", "JSESSIONID": "abc"},
        "auth_headers_from_cookies": {"SEC": "SEC", "QRadarCSRF": "QRadarCSRF"},
        "api_headers_template": {"Version": "12.0", "Accept": "application/json"},
        "verify_ssl": False, "test_path": "/api/session/offenses"}
    assert client.post("/test-siem", json=payload).json()["status"] == "connected"
    ok("browser session + CSRF echo", "authenticates with the analyst's own login")

    body = client.post("/test-siem", json={**payload, "auth_headers_from_cookies": None}).json()
    assert body["status"] == "auth_failed" and "insufficient credentials" in body["message"], body
    ok("browser session without the CSRF headers is refused", "403, as the API documents")


def test_platform_detection():
    """No preset chosen -> default OSD health path 404s on QRadar; the
    backend must recognise the platform and name it."""
    body = client.post("/test-siem", json={
        "siem_links": [], "siem_base_url": MOCK_URL, "auth_type": "basic",
        "auth_username": "j.analyst", "auth_password": "pw",
        "verify_ssl": False, "test_path": None}).json()
    assert body["status"] == "reachable", body
    assert body["detected_platform"] == "qradar", body
    assert "preset" in body["message"], body
    ok("platform fingerprinting", "wrong health path -> 'this looks like IBM QRadar'")


def test_basic_auth():
    r = client.post("/test-siem", json={
        "siem_links": [], "siem_base_url": MOCK_URL, "auth_type": "basic",
        "auth_username": "j.analyst", "auth_password": "pw",
        "verify_ssl": False, "test_path": "/api/basic/check"})
    assert r.json()["status"] == "connected", r.text
    ok("basic auth", "username/password reaches the SIEM as an Authorization header")


def test_splunk_search_job():
    SPLUNK["polls"] = 0
    r = client.post("/fetch-siem-logs", json=SPLUNK_PAYLOAD)
    body = r.json()
    assert r.status_code == 200 and body["fetched"] == 2, body
    assert "EventCode=4625" in json.loads(body["logs"][0])["_raw"]
    assert SPLUNK["output_mode"] == "json", SPLUNK      # extra create params preserved
    assert SPLUNK["polls"] >= 2
    ok("Splunk search job", "nested status path, extra query params preserved")

    assert client.post("/test-siem", json={**SPLUNK_PAYLOAD,
                                           "test_path": "/services/server/info?output_mode=json"}
                       ).json()["status"] == "connected"
    ok("Splunk /test-siem")


def test_splunk_failed_job_surfaces():
    SPLUNK["polls"] = 0
    r = client.post("/fetch-siem-logs", json={
        **SPLUNK_PAYLOAD,
        "job_status_path_template": "/services/search/jobs/failjob?output_mode=json"})
    assert r.status_code == 502, r.text   # reported, not hung until timeout
    ok("failed search job surfaces", "error state ends the poll loop")


def test_threat_intel_budget():
    """Enrichment must yield to the clock instead of stalling an analysis."""
    original_lookup = server.lookup_ioc
    original_client = server.httpx.AsyncClient
    original_save = server._save_threat_intel_cache
    original_budget = server.THREAT_INTEL_TIME_BUDGET_SECONDS
    try:
        server.THREAT_INTEL_TIME_BUDGET_SECONDS = 2.0
        server.threat_intel_cache.clear()
        calls = {"n": 0}

        async def slow_lookup(client_, ioc, ioc_type, vt, abuse, use_cache=True, **switches):
            calls["n"] += 1
            await asyncio.sleep(0.5)
            return {"ioc": ioc, "type": ioc_type, "verdict": "clean",
                    "sources": {"virustotal": {"status": "ok"}}}

        server.lookup_ioc = slow_lookup
        server._save_threat_intel_cache = lambda: None
        # Lookup is completely mocked. Building an unused real TLS client can
        # consume the two-second fixture budget before the first mocked result,
        # especially on Windows. Keep the same deadline and assertions while
        # isolating this test from system certificate initialization.
        class UnusedClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

        server.httpx.AsyncClient = UnusedClient

        logs = [" ".join("203.0.113.%d" % i for i in range(1, 41))]
        started = time.time()
        _, findings = asyncio.new_event_loop().run_until_complete(
            server.enrich_with_threat_intel(logs, None, "vtkey", None))
        elapsed = time.time() - started

        assert elapsed < 6.0, f"budget not enforced: {elapsed:.1f}s"
        assert calls["n"] < 40, f"should have skipped uncached IOCs, made {calls['n']} calls"
        assert findings, "findings collected before the budget must be kept"
        ok("threat-intel time budget", f"{elapsed:.1f}s, {calls['n']}/40 enriched then yielded")
    finally:
        server.lookup_ioc = original_lookup
        server.httpx.AsyncClient = original_client
        server._save_threat_intel_cache = original_save
        server.THREAT_INTEL_TIME_BUDGET_SECONDS = original_budget


def test_custom_ai_providers():
    """Analyst-defined models: one code path, three API shapes, and local
    models with no API key at all."""
    def analyze(cfg, key):
        return client.post("/analyze", json={"logs": ["test log line"], "mode": "custom",
                                             "sanitize": False, "api_key": key,
                                             "custom_provider": cfg})

    r = analyze({"name": "MyGroq", "api_format": "openai",
                 "endpoint": MOCK_URL + "/ai/v1/chat/completions", "model": "llama-3.3-70b"}, "KEY123")
    assert r.status_code == 200 and r.json()["analysis"] == "OPENAI-STYLE ANALYSIS", r.text
    assert AI["openai_auth"] == "Bearer KEY123" and AI["openai_model"] == "llama-3.3-70b"
    ok("custom model: OpenAI-compatible shape")

    r = analyze({"name": "MyClaude", "api_format": "anthropic",
                 "endpoint": MOCK_URL + "/ai/v1/messages", "model": "claude-x"}, "ANTHKEY")
    assert r.json()["analysis"] == "ANTHROPIC-STYLE ANALYSIS", r.text
    assert AI["anthropic_key"] == "ANTHKEY" and AI["anthropic_version"] == "2023-06-01"
    ok("custom model: Anthropic shape")

    r = analyze({"name": "MyGemini", "api_format": "gemini",
                 "endpoint": MOCK_URL + "/ai/v1beta/generateContent", "model": "gemini-x"}, "GKEY")
    assert r.json()["analysis"] == "GEMINI-STYLE ANALYSIS", r.text
    assert AI["gemini_key"] == "GKEY"          # Gemini gets the key in a header,
    assert AI["gemini_query"] == ""            # never in the address
    ok("custom model: Gemini shape")

    r = analyze({"name": "Ollama", "api_format": "openai",
                 "endpoint": MOCK_URL + "/ai/local", "model": "llama3"}, None)
    assert r.json()["analysis"] == "LOCAL MODEL ANALYSIS", r.text
    assert AI["local_auth"] is None
    ok("custom model: local runner with no API key")

    r = analyze({"name": "Dead", "api_format": "openai",
                 "endpoint": "http://127.0.0.1:9/v1/chat/completions", "model": "x"}, "k")
    assert r.status_code == 502 and "cannot reach" in r.json()["detail"], r.text
    ok("custom model: unreachable endpoint gives an actionable error")

    r = client.post("/analyze", json={"logs": ["x"], "mode": "custom", "sanitize": False, "api_key": "k"})
    assert r.status_code == 400, r.text
    ok("custom model: missing configuration rejected")


def test_rdap_whois():
    """RDAP is the keyless WHOIS successor: registration facts for domains,
    ownership for IPs — and domain age is a triage signal by itself."""
    import httpx

    async def probe(path, ioc, ioc_type):
        async with httpx.AsyncClient() as c:
            real_get = c.get

            async def redirected(_url, **kw):
                return await real_get(MOCK_URL + path, **kw)

            c.get = redirected
            return await server.query_rdap(c, ioc, ioc_type)

    loop = asyncio.new_event_loop()

    res = loop.run_until_complete(probe("/rdap/domain-new", "evil-phish.test", "domain"))
    assert res["status"] == "ok" and res["registered"] is True, res
    assert res["newly_registered"] is True and res["age_days"] <= 6, res
    assert res["registrar"] == "Cheap Registrar LLC", res
    assert res["abuse_contact"] == "abuse@registrar.test", res
    ok("RDAP domain", f"age {res['age_days']}d flagged newly registered, registrar + abuse contact parsed")

    res = loop.run_until_complete(probe("/rdap/domain-old", "example.test", "domain"))
    assert res.get("newly_registered") is not True, res
    ok("RDAP domain: an established domain is not flagged")

    res = loop.run_until_complete(probe("/rdap/ip", "203.0.113.9", "ip"))
    assert res["status"] == "ok" and res["network_name"] == "EXAMPLE-NET", res
    assert res["country"] == "NL" and res["abuse_contact"] == "abuse@isp.test", res
    ok("RDAP ip", "network, country and abuse contact parsed")


def test_threat_intel_source_switches():
    """Each source can be turned off independently from the popup."""
    calls = {"vt": 0, "abuse": 0, "rdap": 0}
    originals = (server.query_virustotal, server.query_abuseipdb, server.query_rdap)

    async def fake_vt(c, ioc, t, key):
        calls["vt"] += 1
        return {"status": "ok", "malicious": 0, "suspicious": 0, "total_engines": 90}

    async def fake_abuse(c, ip, key):
        calls["abuse"] += 1
        return {"status": "ok", "abuse_confidence_score": 0, "total_reports": 0}

    async def fake_rdap(c, ioc, t):
        calls["rdap"] += 1
        return {"status": "ok", "registered": True, "network_name": "X"}

    server.query_virustotal, server.query_abuseipdb, server.query_rdap = fake_vt, fake_abuse, fake_rdap
    try:
        import httpx
        loop = asyncio.new_event_loop()

        async def run(**switches):
            async with httpx.AsyncClient() as c:
                server.threat_intel_cache.clear()
                return await server.lookup_ioc(c, "203.0.113.9", "ip", "vtkey", "abusekey",
                                               use_cache=False, **switches)

        res = loop.run_until_complete(run())
        assert set(res["sources"]) == {"virustotal", "abuseipdb", "whois"}, res
        ok("TI sources: all three queried when enabled")

        calls.update({"vt": 0, "abuse": 0, "rdap": 0})
        res = loop.run_until_complete(run(enable_virustotal=False, enable_abuseipdb=False))
        assert set(res["sources"]) == {"whois"}, res
        assert calls["vt"] == 0 and calls["abuse"] == 0, calls
        ok("TI sources: WHOIS alone works with no API keys involved")

        calls.update({"vt": 0, "abuse": 0, "rdap": 0})
        res = loop.run_until_complete(run(enable_whois=False))
        assert "whois" not in res["sources"] and calls["rdap"] == 0, res
        ok("TI sources: WHOIS can be switched off")
    finally:
        server.query_virustotal, server.query_abuseipdb, server.query_rdap = originals


def test_whois_does_not_fabricate_a_verdict():
    """Registration data is context. RDAP answering must not make an IOC look
    'clean', but a days-old domain must still raise suspicion."""
    import httpx
    originals = (server.query_virustotal, server.query_abuseipdb, server.query_rdap)
    loop = asyncio.new_event_loop()
    try:
        async def none_vt(*a, **k):
            return None

        async def none_abuse(*a, **k):
            return None

        server.query_virustotal, server.query_abuseipdb = none_vt, none_abuse

        async def plain_rdap(c, ioc, t):
            return {"status": "ok", "registered": True, "network_name": "X"}

        server.query_rdap = plain_rdap

        async def run(ioc, ioc_type):
            async with httpx.AsyncClient() as c:
                server.threat_intel_cache.clear()
                return await server.lookup_ioc(c, ioc, ioc_type, None, None, use_cache=False)

        res = loop.run_until_complete(run("203.0.113.9", "ip"))
        assert res["verdict"] == "unknown", res      # not "clean"
        ok("WHOIS alone never yields a 'clean' verdict")

        async def new_domain_rdap(c, ioc, t):
            return {"status": "ok", "registered": True, "newly_registered": True, "age_days": 3}

        server.query_rdap = new_domain_rdap
        res = loop.run_until_complete(run("evil-phish.test", "domain"))
        assert res["verdict"] == "suspicious", res
        ok("a days-old domain is flagged suspicious on registration age alone")
    finally:
        server.query_virustotal, server.query_abuseipdb, server.query_rdap = originals


TESTS = [
    test_qradar_search_job,
    test_context_chained_template_arithmetic,
    test_parsed_params_without_links,
    test_adhoc_query,
    test_opensearch_single_request_regression,
    test_auth_guard,
    test_health_check_and_error_detail,
    test_browser_session_csrf_echo,
    test_platform_detection,
    test_basic_auth,
    test_splunk_search_job,
    test_splunk_failed_job_surfaces,
    test_threat_intel_budget,
    test_custom_ai_providers,
    test_rdap_whois,
    test_threat_intel_source_switches,
    test_whois_does_not_fabricate_a_verdict,
]


def main():
    start_mock()
    failures = []
    for test in TESTS:
        try:
            test()
        except Exception as e:
            failures.append((test.__name__, e))
            print(f"  FAIL  {test.__name__}: {e}")

    print()
    if failures:
        print(f"{len(passed)} checks passed, {len(failures)} FAILED")
        return 1
    print(f"All {len(passed)} checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
