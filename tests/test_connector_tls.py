"""Local TLS handshakes only: synthetic CA, verified API, invalid issuer/name/expiry."""
import asyncio
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import ssl
import threading
from unittest.mock import patch
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from fastapi.testclient import TestClient
import server

@pytest.fixture(scope='module')
def certificates():
    now=datetime.now(timezone.utc);key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Synthetic VEILUX test CA')])
    ca=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(days=3)).not_valid_after(now+timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
        .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),critical=False).sign(key,hashes.SHA256()))
    def leaf(wrong_name=False,expired=False):
        private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Local fixture')]))
            .issuer_name(name).public_key(private.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-timedelta(days=2)).not_valid_after(now-timedelta(days=1) if expired else now+timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('wrong.test')] if wrong_name else [x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),critical=False)
            .sign(key,hashes.SHA256()))
        return (cert.public_bytes(serialization.Encoding.PEM),private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    return ca.public_bytes(serialization.Encoding.PEM).decode(),leaf

@pytest.fixture
def tls_server(tmp_path,certificates):
    running=[]
    def start(**options):
        cert,key=certificates[1](**options)
        certpath=tmp_path/f'cert-{len(running)}.pem';keypath=tmp_path/f'key-{len(running)}.pem'
        certpath.write_bytes(cert);keypath.write_bytes(key)
        calls=[]
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                calls.append(self.path);body=json.dumps({'records':[{'event':'synthetic TLS'}]}).encode()
                self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        http=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(certpath,keypath)
        http.socket=context.wrap_socket(http.socket,server_side=True)
        thread=threading.Thread(target=http.serve_forever,daemon=True);thread.start();running.append((http,thread))
        return f'https://127.0.0.1:{http.server_port}',calls
    yield start
    for http,thread in running:http.shutdown();http.server_close();thread.join(timeout=3)

def payload(url,ca=''):
    return dict(siem_base_url=url,auth_type='none',verify_ssl=True,tls_trust='bundled',ca_bundle_pem=ca,
        result_mode='records',parsed_params=[{}],api_method='GET',api_path_template='/records',response_path='records',test_path='/records')

def test_untrusted_issuer_has_actionable_error_then_ca_allows_verified_extraction(tls_server,certificates):
    url,calls=tls_server();client=TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN})
    denied=client.post('/fetch-siem-logs',json=payload(url))
    assert denied.status_code==502 and 'Organization CA certificate' in denied.json()['detail'] and calls==[]
    health=client.post('/test-siem',json=payload(url))
    assert health.json()['status']=='certificate_error' and calls==[]
    ca=certificates[0];allowed=client.post('/fetch-siem-logs',json=payload(url,ca))
    assert allowed.status_code==200,allowed.text
    assert len(allowed.json()['logs'])==1 and calls==['/records']
    assert client.post('/test-siem',json=payload(url,ca)).json()['status']=='connected'
    context=server._connector_ssl_context('bundled',ca)
    assert context.check_hostname and context.verify_mode==ssl.CERT_REQUIRED

@pytest.mark.parametrize('options',[{'wrong_name':True},{'expired':True}])
def test_trusted_ca_does_not_bypass_hostname_or_expiry(tls_server,certificates,options):
    url,calls=tls_server(**options)
    result=TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN}).post('/fetch-siem-logs',json=payload(url,certificates[0]))
    assert result.status_code==502 and 'certificate could not be verified' in result.json()['detail'] and calls==[]

def test_system_trust_loads_os_store_without_disabling_checks():
    server._connector_ssl_context.cache_clear()
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    with patch.object(server.ssl,'create_default_context',return_value=context) as create,patch.object(context,'load_default_certs') as load:
        actual=server._connector_ssl_context('system','')
        assert actual is context and actual.check_hostname and actual.verify_mode==ssl.CERT_REQUIRED
        create.assert_called_once();load.assert_called_once_with(ssl.Purpose.SERVER_AUTH)
    server._connector_ssl_context.cache_clear()

@pytest.mark.parametrize('pem',['not a certificate','-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----','-----BEGIN CERTIFICATE-----\nbad\n-----END CERTIFICATE-----'])
def test_invalid_ca_fails_before_api_dispatch(pem):
    with patch.object(server.httpx,'AsyncClient') as client:
        result=TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN}).post('/fetch-siem-logs',json=payload('https://unused.test',pem))
    assert result.status_code==400 and client.call_count==0
    assert 'certificate' in result.json()['detail'] or 'CA' in result.json()['detail']

def test_ssl_failure_never_retries_without_verification():
    original=httpx.AsyncClient;calls=[];verify=[]
    def transport(request):
        calls.append(request);raise httpx.ConnectError('[SSL: CERTIFICATE_VERIFY_FAILED] unable to get local issuer certificate')
    def client(*args,**kwargs):
        verify.append(kwargs['verify']);return original(*args,transport=httpx.MockTransport(transport),**kwargs)
    with patch.object(server.httpx,'AsyncClient',client):
        result=TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN}).post('/fetch-siem-logs',json={**payload('https://synthetic.test'),'parsed_params':[{'id':'one'},{'id':'two'}]})
    assert result.status_code==502 and len(calls)==1
    assert all(isinstance(ctx,ssl.SSLContext) and ctx.check_hostname for ctx in verify)
