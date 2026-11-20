"""Platform templates, end to end against mock vendor APIs.

Each test takes a real template from extension/connector_presets.js, turns it
into the request the extension sends (VeiluxConnectorClient.requestPayload,
run in Node), and posts it to the backend. The backend's outbound requests go
to mock APIs that answer the way each vendor's public API reference
describes, and refuse requests that do not match it: wrong paths, missing API
versions, a search outside the form body, a token for another API, and so on.

All data is synthetic: documentation IP ranges, example domains and invented
names. Passing here shows the templates follow the documented API shapes; it
does not replace a check against a real deployment, whose version, permissions
and data can differ.
"""
import json
import os
import subprocess
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest
from fastapi.testclient import TestClient

from backend_key import use_test_key

use_test_key()
import server  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
client = TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN})
TENANT = "11111111-2222-3333-4444-555555555555"
SUBSCRIPTION = "00000000-1111-2222-3333-444444444444"
SENTINEL_INCIDENT_ID = "8a1c2e3f-4b5d-4e6f-8a9b-0c1d2e3f4a5b"
PORTAL_INCIDENT = (f"https://portal.azure.com/#asset/Microsoft_Azure_Security_Insights/Incident/subscriptions/{SUBSCRIPTION}"
                   "/resourceGroups/rg-security/providers/Microsoft.OperationalInsights/workspaces/law-security"
                   f"/providers/Microsoft.SecurityInsights/Incidents/{SENTINEL_INCIDENT_ID}")
APP = {"tokenUrl": f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
       "clientId": "6e5f4d3c-2b1a-4c9d-8e7f-0a1b2c3d4e5f", "clientSecret": "synthetic-client-secret"}

PAYLOAD_SCRIPT = r"""
const fs = require('fs'), vm = require('vm');
const ctx = { console, URL, structuredClone };
vm.createContext(ctx);
for (const file of ['connector_config.js', 'connector_presets.js', 'connector_client.js'])
  vm.runInContext(fs.readFileSync('extension/' + file, 'utf8'), ctx, { filename: file });
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const template = structuredClone(vm.runInContext('CONNECTOR_PRESETS', ctx)[input.preset]);
const website = new URL(input.website);
const profile = { ...template, schemaVersion: 2, platform: input.preset, name: 'Synthetic ' + input.preset,
  websiteUrl: website.href, siemHost: website.hostname, siemBaseUrl: input.base || template.siemBaseUrl,
  maxRecords: input.maxRecords || 5000,
  auth: { ...template.auth, ...input.auth },
  api: { ...template.api, ...(input.api || {}), parameters: { ...(template.api.parameters || {}), ...(input.parameters || {}) },
    job: { ...(template.api.job || {}), ...(input.job || {}) } } };
const run = async () => {
  const client = vm.runInContext('VeiluxConnectorClient', ctx), config = vm.runInContext('VeiluxConnectors', ctx);
  let options = {};
  if (input.page) {
    const params = config.linkParams(profile, input.page);
    if (!params) throw new Error('The template does not read this page address: ' + input.page);
    options = { params: [params] };
  } else if (input.query !== undefined) options = { query: input.query };
  process.stdout.write(JSON.stringify(await client.requestPayload(profile, options)));
};
run().catch(error => { process.stderr.write(error.message); process.exit(1); });
"""


def payload(preset, website, **options):
    """The backend request the extension builds for this template."""
    spec = {"preset": preset, "website": website, **options}
    result = subprocess.run(["node", "-e", PAYLOAD_SCRIPT], input=json.dumps(spec), capture_output=True,
                            text=True, cwd=ROOT, timeout=30)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


# --------------------------------------------------------------------------
# Mock vendor APIs
# --------------------------------------------------------------------------

def error(status, body):
    return httpx.Response(status, json=body)


class Vendors:
    def __init__(self):
        self.calls = []
        self.token_requests = []
        self.polls = {}

    # ---- Microsoft identity platform: client credentials grant ----
    def token(self, request):
        form = parse_qs(request.content.decode())
        self.token_requests.append(form)
        if request.headers.get("content-type", "").split(";")[0] != "application/x-www-form-urlencoded":
            return error(400, {"error": "invalid_request", "error_description": "AADSTS900144: The request body must contain the parameter grant_type."})
        if form.get("grant_type") != ["client_credentials"] or form.get("client_id") != [APP["clientId"]]:
            return error(400, {"error": "unauthorized_client", "error_description": "AADSTS700016: Application not found in the directory."})
        if form.get("client_secret") != [APP["clientSecret"]]:
            return error(401, {"error": "invalid_client", "error_description":
                "AADSTS7000215: Invalid client secret provided. Ensure the secret being sent in the request is the client secret value."
                "\r\nTrace ID: 0d1e2f3a-0000-4000-8000-000000000000\r\nCorrelation ID: 1a2b3c4d-0000-4000-8000-000000000000"
                "\r\nTimestamp: 2026-11-17 08:00:00Z"})
        scope = (form.get("scope") or [""])[0]
        if not scope.endswith("/.default"):
            return error(400, {"error": "invalid_scope", "error_description": "AADSTS1002012: The provided value for scope is not valid."})
        return httpx.Response(200, json={"token_type": "Bearer", "expires_in": 3599, "ext_expires_in": 3599,
                                         "access_token": "token-for " + scope.removesuffix("/.default")})

    def bearer(self, request, resource):
        return request.headers.get("authorization") == "Bearer token-for " + resource

    # ---- Azure Monitor Logs query API ----
    def log_analytics(self, request):
        if not self.bearer(request, "https://api.loganalytics.io"):
            return error(401, {"error": {"code": "InvalidTokenError", "message": "The provided authentication is not valid for this resource."}})
        body = json.loads(request.content)
        query = body.get("query", "")
        if "parse_error" in query:
            return error(400, {"error": {"message": "The request had some invalid properties", "code": "BadArgumentError",
                "correlationId": "c0ffee00-0000-4000-8000-000000000000",
                "innererror": {"code": "SyntaxError", "message": "A recognition error occurred in the query.",
                               "innererror": {"code": "SYN0002", "message": "Query could not be parsed at 'parse_error' on line [1,16]",
                                              "line": 1, "pos": 16, "token": "parse_error"}}}})
        table = {"name": "PrimaryResult",
                 "columns": [{"name": "TimeGenerated", "type": "datetime"}, {"name": "AlertName", "type": "string"},
                             {"name": "AlertSeverity", "type": "string"}, {"name": "CompromisedEntity", "type": "string"}],
                 "rows": [["2026-11-17T07:55:05Z", "Password spray", "Medium", "ws-0042.contoso.example"],
                          ["2026-11-17T07:58:41Z", "Suspicious inbox rule", "High", "j.doe@contoso.example"]]}
        answer = {"tables": [table], "timespan": body.get("timespan")}
        if "take 100000" in query:
            answer["error"] = {"code": "PartialError", "message": "There were some errors when processing your query.",
                               "details": [{"code": "EngineError", "message": "Something went wrong processing your query on the server.",
                                            "innererror": {"code": "-2133196797", "message": "Query result set has exceeded the internal record count limit 500000.",
                                                           "severity": 2, "severityName": "Error"}}]}
        return httpx.Response(200, json=answer)

    # ---- Azure Resource Manager: Microsoft.SecurityInsights ----
    def arm(self, request):
        if not self.bearer(request, "https://management.azure.com"):
            return error(401, {"error": {"code": "InvalidAuthenticationToken", "message": "The access token is invalid."}})
        if request.url.params.get("api-version") != "2025-09-01":
            return error(400, {"error": {"code": "MissingApiVersionParameter", "message": "The api-version query parameter (?api-version=) is required for all requests."}})
        prefix = (f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-security/providers/Microsoft.OperationalInsights/workspaces/law-security"
                  f"/providers/Microsoft.SecurityInsights/incidents/{SENTINEL_INCIDENT_ID}")
        if request.url.path == prefix and request.method == "GET":
            return httpx.Response(200, json={"id": prefix, "name": SENTINEL_INCIDENT_ID, "type": "Microsoft.SecurityInsights/Incidents",
                "properties": {"title": "Multistage attack involving j.doe", "severity": "High", "status": "New", "incidentNumber": 4211,
                               "createdTimeUtc": "2026-11-17T07:59:00Z", "additionalData": {"alertsCount": 2}}})
        if request.url.path == prefix + "/alerts" and request.method == "POST":
            return httpx.Response(200, json={"value": [
                {"id": prefix + "/alerts/a1", "kind": "SecurityAlert", "properties": {"alertDisplayName": "Password spray", "severity": "Medium",
                 "status": "New", "compromisedEntity": "j.doe@contoso.example", "tactics": ["CredentialAccess"]}},
                {"id": prefix + "/alerts/a2", "kind": "SecurityAlert", "properties": {"alertDisplayName": "Sign-in from an unfamiliar location",
                 "severity": "High", "status": "New", "compromisedEntity": "j.doe@contoso.example", "tactics": ["InitialAccess"]}}]})
        return error(404, {"error": {"code": "NotFound", "message": "Resource not found."}})

    # ---- Microsoft Graph security API ----
    def graph(self, request):
        if not self.bearer(request, "https://graph.microsoft.com"):
            return error(401, {"error": {"code": "InvalidAuthenticationToken", "message": "Access token validation failure."}})
        if request.url.path == "/v1.0/security/incidents":
            return httpx.Response(200, json={"value": [{"id": "2972"}]})
        if request.url.path != "/v1.0/security/incidents/2972":
            return error(404, {"error": {"code": "NotFound", "message": "Incident not found."}})
        incident = {"id": "2972", "displayName": "Ransomware activity on multiple endpoints", "severity": "high", "status": "active",
                    "incidentWebUrl": "https://security.microsoft.com/incidents/2972?tid=" + TENANT}
        if request.url.params.get("$expand") == "alerts":
            incident["alerts"] = [
                {"id": "da0000000000000001", "title": "Suspicious process injection", "severity": "high", "serviceSource": "microsoftDefenderForEndpoint",
                 "evidence": [{"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "ws-0042.contoso.example"}]},
                {"id": "da0000000000000002", "title": "File backups were deleted", "severity": "high", "serviceSource": "microsoftDefenderForEndpoint",
                 "evidence": [{"@odata.type": "#microsoft.graph.security.processEvidence", "processCommandLine": "vssadmin delete shadows /all"}]}]
        return httpx.Response(200, json=incident)

    # ---- Splunk REST API (management port) ----
    SPLUNK_RESULTS = [{"_time": f"2026-11-17T07:{i // 60:02d}:{i % 60:02d}.000+00:00", "host": f"ws-{i % 7:04d}", "sourcetype": "WinEventLog:Security",
                       "EventCode": "4625", "src_ip": f"198.51.100.{i % 250}", "_raw": f"EventCode=4625 An account failed to log on. record={i}"}
                      for i in range(250)]

    def splunk(self, request):
        if request.headers.get("authorization") != "Bearer splunk-token":
            return error(401, {"messages": [{"type": "WARN", "text": "call not properly authenticated"}]})
        path = request.url.path
        if path == "/services/server/info":
            return httpx.Response(200, json={"entry": [{"content": {"version": "9.3.2", "product_type": "enterprise"}}]})
        if path == "/services/search/jobs" and request.method == "POST":
            if request.headers.get("content-type", "").split(";")[0] != "application/x-www-form-urlencoded" or request.url.params:
                return error(400, {"messages": [{"type": "FATAL", "text": "Empty search."}]})
            form = parse_qs(request.content.decode())
            search = (form.get("search") or [""])[0]
            self.calls.append(("splunk create", form))
            if not (search.startswith("search ") or search.startswith("|")):
                return error(400, {"messages": [{"type": "FATAL", "text": f"Unknown search command '{search.split()[0]}'."}]})
            sid = "1731830000.77" if "| eval broken" in search else "1731830000.42"
            return httpx.Response(201, json={"sid": sid})
        # Results come from the v2 endpoint (Splunk 9.0.1 and later); status stays on v1.
        if path.startswith("/services/search/jobs/") and path.endswith("/results"):
            return error(410, {"messages": [{"type": "FATAL", "text": "The template should read results from search/v2."}]})
        sid = path.split("/")[-2 if path.endswith("/results") else -1] if "/search/" in path and "/jobs/" in path else ""
        if sid not in ("1731830000.42", "1731830000.77"):
            return error(404, {"messages": [{"type": "FATAL", "text": "Unknown sid."}]})
        if path.endswith("/results"):
            if request.url.params.get("output_mode") != "json":
                return httpx.Response(200, text="<results/>", headers={"content-type": "text/xml"})
            offset, count = int(request.url.params.get("offset", 0)), int(request.url.params.get("count", 100))
            self.calls.append(("splunk results", offset, count))
            return httpx.Response(200, json={"preview": False, "init_offset": offset, "messages": [],
                                             "fields": [{"name": "_time"}, {"name": "host"}, {"name": "_raw"}],
                                             "results": self.SPLUNK_RESULTS[offset:offset + count]})
        self.polls[sid] = self.polls.get(sid, 0) + 1
        if sid == "1731830000.77":
            return httpx.Response(200, json={"entry": [{"content": {"dispatchState": "FAILED", "isFailed": True, "messages": [
                {"type": "INFO", "text": "Your timerange was substituted based on your search string"},
                {"type": "FATAL", "text": "Error in 'eval' command: The expression is malformed. Expected )."}]}}]})
        state = "DONE" if self.polls[sid] >= 2 else "RUNNING"
        return httpx.Response(200, json={"entry": [{"content": {"dispatchState": state, "isDone": state == "DONE", "resultCount": 250}}]})

    # ---- Elasticsearch / OpenSearch / Wazuh indexer ----
    HITS = [{"_index": "wazuh-alerts-4.x-2026.11.17", "_id": f"doc-{i}", "_score": None,
             "_source": {"@timestamp": f"2026-11-17T07:{i // 60:02d}:{i % 60:02d}.000Z",
                         "timestamp": f"2026-11-17T07:{i // 60:02d}:{i % 60:02d}.000+0000", "rule": {"id": "5710", "level": 5,
                         "description": "sshd: Attempt to login using a non-existent user"},
                         "agent": {"name": f"srv-{i % 5:02d}"}, "data": {"srcip": f"203.0.113.{i % 250}"}}} for i in range(230)]

    def elastic(self, request):
        if request.headers.get("authorization") != "Basic " + __import__("base64").b64encode(b"analyst:synthetic-pass").decode():
            return error(401, {"error": {"root_cause": [{"type": "security_exception", "reason": "missing authentication credentials"}],
                                         "type": "security_exception", "reason": "missing authentication credentials"}, "status": 401})
        parts = request.url.path.strip("/").split("/")
        if parts[0] == "nope":
            return error(404, {"error": {"root_cause": [{"type": "index_not_found_exception", "reason": "no such index [nope]"}],
                                         "type": "index_not_found_exception", "reason": "no such index [nope]", "index": "nope"}, "status": 404})
        if len(parts) == 2 and parts[1] == "_search" and request.method == "POST":
            body = json.loads(request.content)
            self.calls.append(("es search", parts[0], dict(request.url.params), body))
            time_filter = body["query"]["bool"]["filter"][0]["range"]
            assert list(time_filter) == ["@timestamp"] and time_filter["@timestamp"] == {"gte": "now-24h"}, body
            start, size = int(request.url.params.get("from", 0)), int(request.url.params.get("size", 10))
            return httpx.Response(200, json={"took": 3, "timed_out": False, "hits": {"total": {"value": len(self.HITS), "relation": "eq"},
                                             "max_score": None, "hits": self.HITS[start:start + size]}})
        if len(parts) == 3 and parts[1] == "_doc" and request.method == "GET":
            match = next((h for h in self.HITS if h["_index"] == parts[0] and h["_id"] == parts[2]), None)
            if not match:
                return error(404, {"_index": parts[0], "_id": parts[2], "found": False})
            return httpx.Response(200, json={**match, "_version": 1, "_seq_no": 7, "_primary_term": 1, "found": True})
        return error(400, {"error": {"type": "illegal_argument_exception", "reason": "unsupported request"}, "status": 400})

    def __call__(self, request):
        host = request.url.host
        if host == "login.microsoftonline.com" and request.url.path == f"/{TENANT}/oauth2/v2.0/token":
            return self.token(request)
        if host == "api.loganalytics.azure.com":
            return self.log_analytics(request)
        if host == "management.azure.com":
            return self.arm(request)
        if host == "graph.microsoft.com":
            return self.graph(request)
        if host == "splunk.example.test" and request.url.port == 8089:
            return self.splunk(request)
        if host == "es.example.test" and request.url.port == 9200:
            return self.elastic(request)
        return error(599, {"message": "unexpected host " + str(request.url)})


@pytest.fixture
def vendors(monkeypatch):
    mock = Vendors()
    original = httpx.AsyncClient
    monkeypatch.setattr(server.httpx, "AsyncClient",
                        lambda *args, **kwargs: original(*args, **{**kwargs, "transport": httpx.MockTransport(mock)}))
    server._OAUTH_TOKENS.clear()
    yield mock
    server._OAUTH_TOKENS.clear()


def extract(body):
    response = client.post("/fetch-siem-logs", json=body)
    return response.status_code, response.json()


def records(answer):
    return [json.loads(log) for log in answer["logs"]]


# --------------------------------------------------------------------------
# Splunk
# --------------------------------------------------------------------------

SPLUNK_WEB = "https://splunk.example.test:8000"
SPLUNK_API = "https://splunk.example.test:8089"
SPLUNK_TOKEN = {"type": "header", "headerName": "Authorization", "headerValue": "Bearer splunk-token"}


def test_splunk_reads_every_page_of_the_search_on_screen(vendors):
    page = SPLUNK_WEB + "/en-US/app/search/search?q=search%20index%3Dwineventlog%20EventCode%3D4625&sid=1731830000.42&display.page.search.mode=smart"
    status, answer = extract(payload("splunk_results", SPLUNK_WEB, base=SPLUNK_API, auth=SPLUNK_TOKEN, page=page))
    assert status == 200, answer
    rows = records(answer)
    assert len(rows) == 250 and rows[0]["_raw"].endswith("record=0") and rows[-1]["_raw"].endswith("record=249")
    assert [c[1:] for c in vendors.calls if c[0] == "splunk results"] == [(0, 100), (100, 100), (200, 100)]
    assert answer["limited"] is False


def test_splunk_expired_search_says_why(vendors):
    page = SPLUNK_WEB + "/en-US/app/search/search?sid=1731000000.1"
    status, answer = extract(payload("splunk_results", SPLUNK_WEB, base=SPLUNK_API, auth=SPLUNK_TOKEN, page=page))
    assert status == 502 and "Unknown sid" in answer["detail"], answer


def test_splunk_runs_a_search_job_with_a_form_body(vendors):
    body = payload("splunk", SPLUNK_WEB, base=SPLUNK_API, auth=SPLUNK_TOKEN, query="search index=wineventlog EventCode=4625",
                   job={"pollIntervalSeconds": 0.5}, maxRecords=150)
    status, answer = extract(body)
    assert status == 200, answer
    created = next(c[1] for c in vendors.calls if c[0] == "splunk create")
    assert created["search"] == ["search index=wineventlog EventCode=4625"]
    assert created["output_mode"] == ["json"] and created["earliest_time"] == ["-24h"] and created["latest_time"] == ["now"]
    assert vendors.polls["1731830000.42"] >= 2
    assert len(answer["logs"]) == 150 and answer["limited"] is True


def test_splunk_default_search_needs_the_search_command(vendors):
    body = payload("splunk", SPLUNK_WEB, base=SPLUNK_API, auth=SPLUNK_TOKEN, job={"pollIntervalSeconds": 0.5})
    assert body["job_create_query_template"]["search"] == "search index=* | head 100"
    assert extract(body)[0] == 200
    status, answer = extract(payload("splunk", SPLUNK_WEB, base=SPLUNK_API, auth=SPLUNK_TOKEN, query="index=main"))
    assert status == 502 and "Unknown search command 'index=main'" in answer["detail"], answer


def test_splunk_failed_search_reports_splunks_reason(vendors):
    body = payload("splunk", SPLUNK_WEB, base=SPLUNK_API, auth=SPLUNK_TOKEN, query="search index=main | eval broken=(",
                   job={"pollIntervalSeconds": 0.5})
    status, answer = extract(body)
    assert status == 502, answer
    assert "FAILED" in answer["detail"] and "The expression is malformed" in answer["detail"], answer
    assert "timerange was substituted" not in answer["detail"]


def test_splunk_connection_check_and_rejected_token(vendors):
    body = payload("splunk", SPLUNK_WEB, base=SPLUNK_API, auth=SPLUNK_TOKEN)
    assert client.post("/test-siem", json=body).json()["status"] == "connected"
    rejected = client.post("/test-siem", json={**body, "auth_header_value": "Bearer expired"}).json()
    assert rejected["status"] == "auth_failed" and "not properly authenticated" in rejected["message"], rejected


# --------------------------------------------------------------------------
# Microsoft Sentinel and the Defender portal
# --------------------------------------------------------------------------

def test_sentinel_kql_signs_in_as_an_app_and_maps_columns(vendors):
    body = payload("sentinel", "https://portal.azure.com", auth=APP, parameters={"workspace": "f00dcafe-0000-4000-8000-000000000001"})
    assert body["auth_type"] == "oauth_client_credentials" and body["oauth_scope"] == "https://api.loganalytics.io/.default"
    status, answer = extract(body)
    assert status == 200, answer
    rows = records(answer)
    assert rows[0] == {"TimeGenerated": "2026-11-17T07:55:05Z", "AlertName": "Password spray", "AlertSeverity": "Medium",
                       "CompromisedEntity": "ws-0042.contoso.example"}
    # The token is reused until shortly before it expires.
    assert extract(body)[0] == 200
    assert len(vendors.token_requests) == 1
    assert answer["warnings"] == []


def test_sentinel_reports_partial_results_and_query_errors(vendors):
    base = dict(auth=APP, parameters={"workspace": "f00dcafe-0000-4000-8000-000000000001"})
    status, answer = extract(payload("sentinel", "https://portal.azure.com", query="SecurityAlert | take 100000", **base))
    assert status == 200 and len(answer["logs"]) == 2, answer
    assert "may be incomplete" in answer["warnings"][0] and "internal record count limit" in answer["warnings"][0], answer
    status, answer = extract(payload("sentinel", "https://portal.azure.com", query="SecurityAlert | parse_error", **base))
    assert status == 502, answer
    assert "Query could not be parsed at 'parse_error'" in answer["detail"], answer


def test_app_sign_in_errors_name_the_cause_without_the_secret(vendors):
    body = payload("sentinel", "https://portal.azure.com", auth={**APP, "clientSecret": "wrong-secret"},
                   parameters={"workspace": "f00dcafe-0000-4000-8000-000000000001"})
    status, answer = extract(body)
    assert status == 502, answer
    assert "AADSTS7000215: Invalid client secret provided" in answer["detail"], answer
    assert "Trace ID" not in answer["detail"] and "wrong-secret" not in answer["detail"]
    for unsafe in ("http://login.example.test/token", "https://user:pw@login.example.test/token"):
        status, answer = extract({**body, "oauth_token_url": unsafe})
        assert status == 400 and "https://" in answer["detail"], answer
    status, answer = extract({**body, "oauth_client_secret": ""})
    assert status == 400 and "client secret" in answer["detail"], answer


def test_sentinel_incident_from_the_portal_address(vendors):
    body = payload("sentinel_incident", "https://portal.azure.com", auth=APP, page=PORTAL_INCIDENT)
    assert body["oauth_scope"] == "https://management.azure.com/.default"
    status, answer = extract(body)
    assert status == 200, answer
    incident, *alerts = records(answer)
    assert incident["properties"]["title"] == "Multistage attack involving j.doe"
    assert [a["properties"]["alertDisplayName"] for a in alerts] == ["Password spray", "Sign-in from an unfamiliar location"]


def test_a_token_for_one_microsoft_api_is_not_sent_to_another(vendors):
    graph = payload("defender_incident", "https://security.microsoft.com", auth=APP,
                    page="https://security.microsoft.com/incidents/2972?tid=" + TENANT)
    arm = payload("sentinel_incident", "https://portal.azure.com", auth=APP, page=PORTAL_INCIDENT)
    assert extract(graph)[0] == 200 and extract(arm)[0] == 200
    assert sorted(r["scope"][0] for r in vendors.token_requests) == ["https://graph.microsoft.com/.default",
                                                                      "https://management.azure.com/.default"]
    status, answer = extract({**arm, "oauth_scope": "https://graph.microsoft.com/.default"})
    assert status == 502 and "HTTP 401" in answer["detail"] and "scope" in answer["detail"], answer


def test_defender_portal_incident_and_its_alerts(vendors):
    for page in ("https://security.microsoft.com/incidents/2972?tid=" + TENANT,
                 "https://security.microsoft.com/incident2/2972/overview?tid=" + TENANT):
        status, answer = extract(payload("defender_incident", "https://security.microsoft.com", auth=APP, page=page))
        assert status == 200, answer
        incident, *alerts = records(answer)
        assert incident["displayName"] == "Ransomware activity on multiple endpoints" and "alerts" not in incident
        assert [a["title"] for a in alerts] == ["Suspicious process injection", "File backups were deleted"]
        assert alerts[1]["evidence"][0]["processCommandLine"] == "vssadmin delete shadows /all"
    check = client.post("/test-siem", json=payload("defender_incident", "https://security.microsoft.com", auth=APP)).json()
    assert check["status"] == "connected", check


# --------------------------------------------------------------------------
# Elasticsearch, OpenSearch and the Wazuh indexer
# --------------------------------------------------------------------------

ES_API = "https://es.example.test:9200"
ES_LOGIN = {"type": "basic", "username": "analyst", "password": "synthetic-pass"}


def test_index_search_reads_pages_with_the_total(vendors):
    body = payload("elastic_search", "https://wazuh.example.test", base=ES_API, auth=ES_LOGIN,
                   parameters={"index": "wazuh-alerts-*"},
                   query='rule.id:5710 AND agent.name:"srv-01"')
    status, answer = extract(body)
    assert status == 200, answer
    searches = [c for c in vendors.calls if c[0] == "es search"]
    assert [c[1] for c in searches] == ["wazuh-alerts-*"] * 3
    assert [(c[2]["from"], c[2]["size"]) for c in searches] == [("0", "100"), ("100", "100"), ("200", "100")]
    assert searches[0][3]["query"]["bool"]["must"][0]["query_string"]["query"] == 'rule.id:5710 AND agent.name:"srv-01"'
    assert searches[0][3]["sort"] == [{"@timestamp": {"order": "desc"}}] and searches[0][3]["track_total_hits"] is True
    assert len(answer["logs"]) == 230 and answer["available_total"] == 230 and answer["limited"] is False


def test_index_errors_are_reported_in_the_clusters_words(vendors):
    body = payload("elastic_search", "https://wazuh.example.test", base=ES_API, auth=ES_LOGIN,
                   parameters={"index": "nope"})
    status, answer = extract(body)
    assert status == 502 and "no such index [nope]" in answer["detail"], answer
    status, answer = extract({**body, "auth_password": "wrong"})
    assert status == 502 and "HTTP 401" in answer["detail"], answer


def test_discover_document_link_reads_the_document_api(vendors):
    for dashboard in ("https://kibana.example.test/app/discover#/doc/7d1f0a2c-data-view/wazuh-alerts-4.x-2026.11.17?id=doc-7",
                      "https://wazuh.example.test/app/data-explorer/discover#/doc/wazuh-alerts-*/wazuh-alerts-4.x-2026.11.17?id=doc-7"):
        site = dashboard.split("/app/")[0]
        status, answer = extract(payload("elastic_document", site, base=ES_API, auth=ES_LOGIN, page=dashboard))
        assert status == 200, answer
        (document,) = records(answer)
        assert document["_id"] == "doc-7" and document["found"] is True
        assert document["_source"]["rule"]["description"].startswith("sshd: Attempt to login")
    missing = dashboard.replace("doc-7", "doc-9999")
    status, answer = extract(payload("elastic_document", site, base=ES_API, auth=ES_LOGIN, page=missing))
    assert status == 502 and "HTTP 404" in answer["detail"], answer


def test_every_template_names_its_documented_requirements():
    script = ("const fs=require('fs'),vm=require('vm');const ctx={};vm.createContext(ctx);"
              "for(const f of ['connector_config.js','connector_presets.js'])vm.runInContext(fs.readFileSync('extension/'+f,'utf8'),ctx);"
              "process.stdout.write(JSON.stringify(vm.runInContext('({p:CONNECTOR_PRESETS,n:CONNECTOR_PRESET_NOTES})',ctx)))")
    data = json.loads(subprocess.run(["node", "-e", script], capture_output=True, text=True, cwd=ROOT, check=True).stdout)
    presets, notes = data["p"], data["n"]
    assert set(presets) == set(notes)
    assert list(presets)[:2] == ["splunk_results", "splunk"] and list(presets)[-1] == "qradar"
    for key, template in presets.items():
        api = template["api"]
        for path in (api.get("pathTemplate"), api.get("testPath"), api.get("context", {}).get("pathTemplate"),
                     *(api.get("job", {}).get(k) for k in ("createPathTemplate", "statusPathTemplate", "resultsPathTemplate"))):
            assert not path or path.startswith("/"), (key, path)
        if template["auth"]["type"] == "oauth_client_credentials":
            assert template["auth"]["scope"].endswith("/.default") and template["auth"]["tokenUrl"].startswith("https://login.microsoftonline.com/")
            assert "YOUR-TENANT-ID" in notes[key]


# --------------------------------------------------------------------------
# Engine behaviour behind the templates
# --------------------------------------------------------------------------

def test_app_tokens_are_renewed_before_expiry_and_after_a_401(vendors, monkeypatch):
    body = payload("sentinel", "https://portal.azure.com", auth=APP, parameters={"workspace": "f00dcafe-0000-4000-8000-000000000001"})
    clock = [1000.0]
    monkeypatch.setattr(server, "_oauth_clock", lambda: clock[0])
    assert extract(body)[0] == 200 and len(vendors.token_requests) == 1
    clock[0] += 3599 - 121          # still valid: renewed two minutes before expiry
    assert extract(body)[0] == 200 and len(vendors.token_requests) == 1
    clock[0] += 2
    assert extract(body)[0] == 200 and len(vendors.token_requests) == 2
    # A token the API rejects is forgotten, so the next extraction asks again.
    server._OAUTH_TOKENS[server._oauth_key(server.SiemFetchRequest(**body))] = ("revoked", clock[0] + 1000)
    assert extract(body)[0] == 502
    assert extract(body)[0] == 200 and len(vendors.token_requests) == 3


def test_a_search_start_cannot_mix_form_and_json_bodies(vendors):
    body = payload("splunk", SPLUNK_WEB, base=SPLUNK_API, auth=SPLUNK_TOKEN, job={"createBodyTemplate": '{"search":"${query}"}'})
    status, answer = extract(body)
    assert status == 502 and "form body or with a JSON body" in answer["detail"], answer
