"""Local browser-test server. All external HTTP is mocked."""
import os
import tempfile

import asyncio
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from backend_key import use_test_key
use_test_key()
import httpx
import server
from openrouter_sample import OPENROUTER_MODELS
from fastapi.staticfiles import StaticFiles

sent = []
original_client = httpx.AsyncClient


async def transport(request):
    sent.append({"url": str(request.url), "body": request.content.decode()})
    if request.url.host == '127.0.0.1':
        if request.url.path == '/test/session-health':
            return httpx.Response(200, json={'status':'green'})
        if request.url.path == '/internal/search/opensearch-with-long-numerals':
            return httpx.Response(401, json={'message':'session must be used in browser'})
    if request.url.host == "login.test" and request.url.path.endswith('/oauth2/v2.0/token'):
        return httpx.Response(200, json={'token_type':'Bearer','expires_in':3599,'access_token':'synthetic-access-token'})
    if request.url.host == "records.test":
        rows=[{'user':'alice','event':1},{'user':'bob','event':2}]
        if request.url.path == '/slow-records':
            # Slow enough for a test to close the popup while it is running.
            await asyncio.sleep(4)
            return httpx.Response(200, json={'data': {'records': rows, 'total': 2}})
        if request.url.path.startswith('/api/siem/offenses/'):
            return httpx.Response(200,json={'id':42,'start_time':1000,'last_updated_time':3000})
        if request.url.path == '/api/ariel/searches':
            return httpx.Response(201,json={'search_id':'synthetic-job'})
        if request.url.path.startswith('/api/ariel/searches/'):
            return httpx.Response(200,json={'events':rows} if request.url.path.endswith('/results') else {'status':'COMPLETED'})
        if request.url.path == '/services/search/jobs':
            return httpx.Response(201,json={'sid':'synthetic-job'})
        if request.url.path.startswith(('/services/search/jobs/','/services/search/v2/jobs/')):
            return httpx.Response(200,json={'results':rows} if request.url.path.endswith('/results') else {'entry':[{'content':{'dispatchState':'DONE'}}]})
        if request.url.path == '/internal/search/opensearch-with-long-numerals':
            return httpx.Response(200,json={'rawResponse':{'hits':{'hits':[{'_source':r} for r in rows]}}})
        if request.url.path.endswith('/missing'):
            return httpx.Response(404,json={'message':'not found'})
        if request.url.path == '/health':
            return httpx.Response(200,json={'status':'ok'})
        if '/workspaces/' in request.url.path:
            return httpx.Response(200,json={'tables':[{'columns':[{'name':'User'},{'name':'Count'}],'rows':[['alice',3],['bob',2]]}]})
        return httpx.Response(200,json={'data':{'records':rows, 'total':2}})
    if request.url.host == "custom-model.test":
        body = json.loads(request.content)
        if "temperature" in body:
            return httpx.Response(400, json={"error":{"type":"invalid_request_error",
                "message":"`temperature` is deprecated for this model."}})
        return httpx.Response(200, json={"content":[
            {"type":"thinking","thinking":"Synthetic internal reasoning"},
            {"type":"text","text":"Custom model connected."}]})
    if request.url.host == "openrouter.ai":
        if request.url.path == "/api/v1/models":
            return httpx.Response(200, json={"data": OPENROUTER_MODELS})
        if request.url.path == "/api/v1/chat/completions":
            model = json.loads(request.content)["model"]
            return httpx.Response(200, json={"choices": [{"message": {"content": "Synthetic report from " + model}, "finish_reason": "stop"}]})
    if "groq.com" in str(request.url):
        prompt = "\n".join(m.get("content", "") for m in json.loads(request.content).get("messages", []))
        if "Answer with JSON only" in prompt:
            # Email report request: answer in the report format, quoting one
            # protected marker so tests can check it is restored locally.
            markers = re.findall(r"⟦[^⟧]+⟧", prompt.split("Security Logs", 1)[-1])
            marker = markers[0] if markers else "no marker"
            report = {"title": "Synthetic failed logon burst", "severity": "high", "detection_time": "2026-01-15 09:42",
                      "summary": "Repeated failed logons from " + marker + ".",
                      "details": [{"label": "Source", "value": marker, "highlight": True}, {"label": "Event", "value": "failed logon", "highlight": False}],
                      "context": "Synthetic context.", "risks": ["Synthetic risk"], "recommendations": ["Synthetic action"],
                      "annexes": [{"label": "Synthetic evidence"}]}
            return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(report)}}]})
        if "Latest question from the analyst:" in prompt:
            # Follow-up question: answer with a protected marker from the logs
            # and repeat the question, so tests can follow both.
            markers = re.findall(r"⟦[^⟧]+⟧", prompt.split("Security Logs", 1)[-1])
            question = prompt.split("Latest question from the analyst:", 1)[1].split("```", 1)[0].strip()
            answer = "**Finding:** the activity involves " + (markers[0] if markers else "no marker") + ".\n- Asked: " + question
            return httpx.Response(200, json={"choices": [{"message": {"content": answer}}]})
        return httpx.Response(
            200, json={"choices": [{"message": {"content": "Synthetic report"}}]}
        )
    if request.url.host == 'api.abuseipdb.com':
        if request.url.params.get('ipAddress') in ('198.51.100.212', '192.0.2.138'):
            isp = 'EXAMPLE-FIBRE-QXRVLT02' if request.url.params['ipAddress'] == '198.51.100.212' else 'Example Media Services S.L.'
            return httpx.Response(200, json={'data': {'ipAddress': request.url.params['ipAddress'],
                'abuseConfidenceScore': 0, 'totalReports': 0, 'isp': isp, 'usageType': 'Mobile ISP'}})
        return httpx.Response(200, json={'data': {'ipAddress': request.url.params.get('ipAddress'),
            'abuseConfidenceScore': 80, 'totalReports': 54, 'isp': 'Synthetic ISP', 'countryCode': 'PT'}})
    if request.url.host == 'www.virustotal.com' and request.url.path.startswith('/api/v3/files/'):
        return httpx.Response(200, json={'data': {'attributes': {
            'last_analysis_stats': {'malicious': 0, 'suspicious': 0, 'undetected': 74},
            'meaningful_name': 'secedit.exe', 'type_description': 'Win32 EXE', 'size': 40960,
            'first_submission_date': 1500000000, 'times_submitted': 12,
            'tags': ['known-distributor', 'peexe']}}})
    if (request.url.host == 'www.virustotal.com'
            and request.url.path in ('/api/v3/ip_addresses/198.51.100.212', '/api/v3/ip_addresses/192.0.2.138')):
        return httpx.Response(200, json={'data': {'attributes': {
            'last_analysis_stats': {'malicious': 0, 'suspicious': 0, 'undetected': 92},
            'as_owner': 'Example Fibre Ltd.', 'asn': 64501, 'reputation': 0}}})
    if request.url.host == 'rdap.org':
        return httpx.Response(200, json={'name': 'SYNTHETIC-NET', 'ldhName': 'example.net'})
    await asyncio.sleep(1.5)
    return httpx.Response(404, json={})


def client(*args, **kwargs):
    return original_client(*args, transport=httpx.MockTransport(transport), **kwargs)


server.httpx.AsyncClient = client
server.threat_intel_cache = {}
server._save_threat_intel_cache = lambda: None
# Lessons written by UI tests go to a temporary file, never the project folder.
server.FEEDBACK_FILE = os.path.join(tempfile.mkdtemp(prefix="veilux-ui-lessons-"), "training_feedback.json")
server.training_data = {"feedback_entries": []}


@server.app.get("/test/sent")
async def get_sent():
    return sent


@server.app.get("/test/pairing-code")
async def pairing_code():
    # Test-only: what the backend prints in its console at start-up.
    return {"code": server.PAIRING["code"]}


@server.app.post("/test/reset")
async def reset():
    sent.clear()
    server.threat_intel_cache.clear()
    server.training_data["feedback_entries"].clear()
    return {}


# The test pages and fixture endpoints are served without the backend key.
server.PUBLIC_PREFIXES = ("/extension/", "/test/")
server.app.mount(
    "/extension",
    StaticFiles(directory=Path(__file__).resolve().parents[1] / "extension"),
    name="extension",
)
if __name__ == "__main__":
    import uvicorn

    # The test pages are served from this address, not from an extension origin.
    server.ALLOWED_ORIGINS.add(f"http://127.0.0.1:{sys.argv[1]}")
    uvicorn.run(server.app, host="127.0.0.1", port=int(sys.argv[1]), log_level="error")
