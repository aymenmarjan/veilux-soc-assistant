"""Native extension/session regressions. All remote HTTP is intercepted locally."""
import json
import re
import unittest
from playwright.sync_api import expect
import test_extension_ui as harness

DOC_LINK = r'#/doc/[^/]+/(?<index>[^/?]+)\?(?:[^#]*&)?id=(?<doc_id>[^&]+)'
DOC_BODY = json.dumps({'params': {'index': '${index}', 'body': {'query': {'ids': {'values': ['${doc_id}']}},
                                                              'stored_fields': ['*'], '_source': True}}}, separators=(',', ':'))
INSPECTOR = {key: f'[data-test-subj="{value}"]' for key, value in {
    'openButtonSelector': 'openInspectorButton', 'closeButtonSelector': 'euiFlyoutCloseButton',
    'responseTabSelector': 'inspectorRequestDetailResponse', 'responseBodySelector': 'inspectorResponseBody',
    'requestTabSelector': 'inspectorRequestDetailRequest', 'requestBodySelector': 'inspectorRequestBody',
    'requestUrlSelector': 'inspectorRequestUrl', 'statisticsTabSelector': 'inspectorRequestDetailStatistics'}.items()}
INSPECTOR.update(hitsPath='hits.hits', totalPath='hits.total')



class BrowserSessionTests(unittest.TestCase):
    setUpClass = classmethod(harness.ExtensionUITests.setUpClass.__func__)
    tearDownClass = classmethod(harness.ExtensionUITests.tearDownClass.__func__)
    setUp = harness.ExtensionUITests.setUp
    tearDown = harness.ExtensionUITests.tearDown
    install_background = harness.ExtensionUITests.install_background
    native_extension = harness.ExtensionUITests.native_extension

    def profile(self):
        # The OpenSearch Dashboards template's request, written out as the editor saves it.
        return dict(id='browser-login', schemaVersion=2, name='Session SIEM', platform='opensearch',
            websiteUrl=self.url, siemHost='127.0.0.1', siemBaseUrl=self.url,
            verifySsl=True, auth={'type':'browser_session'}, maxRecords=50, statistics={'mode':'records'},
            api={'enabled':True, 'testPath':'/test/session-health', 'executeVia':'auto', 'fetchMode':'single_request',
                 'linkRegex':DOC_LINK, 'method':'POST', 'pathTemplate':'/internal/search/opensearch-with-long-numerals',
                 'headersTemplate':{'osd-xsrf':'osd-fetch'}, 'responsePath':'rawResponse.hits.hits', 'bodyTemplate':DOC_BODY},
            dom={'discover':{'strategy':'inspector_panel', **INSPECTOR}},
            pageSources=[dict(name='Cases', website=self.url, urlIncludes='/test/session-case',
                mode='links', linkSelector='a[href]', rules=[], pattern=DOC_LINK)])

    def setup_native(self, native, profile=None, status=200):
        worker=native.service_workers[0] if native.service_workers else native.wait_for_event('serviceworker')
        extension_id=worker.url.split('/')[2]
        native.route('http://localhost:8000/**', lambda route:route.continue_(
            url=route.request.url.replace('http://localhost:8000', self.url)))
        native.route('**/test/session-health', lambda route:route.fulfill(json={'status':'green'}))
        native.route('**/test/session-case', lambda route:route.fulfill(content_type='text/html',
            body=f'<a href="{self.url}/app/discover#/doc/view/log-index?id=first">Log</a>'))
        native.route('**/app/discover*', lambda route:route.fulfill(content_type='text/html',body='<p>Signed in</p>'))
        sent=[]
        def records(route):
            req=route.request
            sent.append(dict(headers=req.all_headers(), body=req.post_data_json))
            if status!=200:
                route.fulfill(status=status, headers={'Location':self.url+'/test/session-login'},body='private-response')
            elif 'session=path-session' not in req.all_headers().get('cookie',''):
                route.fulfill(status=401)
            else:
                route.fulfill(json={'rawResponse':{'hits':{'hits':[{'_source':{'event':'native-session-record'}}]}}})
        native.route('**/internal/search/opensearch-with-long-numerals', records)
        native.add_cookies([
            dict(name='session', value='stale-root-session', domain='127.0.0.1', path='/', httpOnly=True),
            dict(name='session', value='path-session', domain='127.0.0.1', path='/internal', httpOnly=True)])
        worker.evaluate('p=>chrome.storage.local.set({connectorProfiles:[p]})', profile or self.profile())
        case=native.new_page();case.goto(self.url+'/test/session-case')
        tab=worker.evaluate('url=>chrome.tabs.query({}).then(t=>t.find(p=>p.url===url))',case.url)
        siem=native.new_page();siem.goto(self.url+'/app/discover#/doc/view/log-index?id=first')
        return worker, extension_id, tab, sent, siem

    def test_native_session_health_preview_save_and_popup_use_same_live_session(self):
        with self.native_extension() as native:
            worker, extension_id, tab, sent, siem=self.setup_native(native)
            settings=native.new_page();settings.goto(f'chrome-extension://{extension_id}/settings.html')
            settings.get_by_role('button', name='Edit Session SIEM').click()
            settings.locator('#test-connector').click()
            expect(settings.locator('#connector-test-result')).to_contain_text('Connection check succeeded', timeout=10000)
            settings.locator('#preview-connector').click()
            expect(settings.locator('#connector-preview-result')).to_contain_text('native-session-record', timeout=10000)
            expect(settings.locator('#connector-test-result')).to_contain_text('record access has not been checked')
            settings.locator('#save-connector').click()
            popup=native.new_page();popup.goto(f'chrome-extension://{extension_id}/popup.html?tabId={tab["id"]}')
            popup.locator('#extract-btn').click()
            expect(popup.locator('#logs-textarea')).to_have_value(re.compile('native-session-record'),timeout=10000)
            self.assertEqual(2,len(sent))
            for request in sent:
                self.assertEqual('log-index',request['body']['params']['index'])
                self.assertEqual(['first'],request['body']['params']['body']['query']['ids']['values'])
                self.assertIn('session=path-session',request['headers']['cookie'])
                self.assertEqual('osd-fetch',request['headers']['osd-xsrf'])
            self.assertEqual([],self.page.request.get(self.url+'/test/sent').json())

    def test_native_rejected_session_does_not_retry_through_backend(self):
        with self.native_extension() as native:
            worker, extension_id, tab, sent, siem=self.setup_native(native,status=401)
            popup=native.new_page();popup.goto(f'chrome-extension://{extension_id}/popup.html?tabId={tab["id"]}')
            popup.locator('#extract-btn').click()
            expect(popup.locator('#status-text')).to_contain_text('HTTP 401',timeout=10000)
            expect(popup.locator('#status-text')).to_contain_text('signed-in SIEM tab')
            self.assertEqual(1,len(sent))
            self.assertNotIn('private-response',popup.locator('#status-text').inner_text())
            self.assertEqual([],self.page.request.get(self.url+'/test/sent').json())

    def test_native_redirect_is_not_followed(self):
        with self.native_extension() as native:
            worker, extension_id, tab, sent, siem=self.setup_native(native,status=302)
            redirected=[]
            native.route('**/test/session-login',lambda route:(redirected.append(route.request.url),route.fulfill(body='Login')))
            popup=native.new_page();popup.goto(f'chrome-extension://{extension_id}/popup.html?tabId={tab["id"]}')
            popup.locator('#extract-btn').click()
            expect(popup.locator('#status-text')).to_contain_text('redirected',timeout=10000)
            self.assertEqual(1,len(sent));self.assertEqual([],redirected)
            self.assertEqual([],self.page.request.get(self.url+'/test/sent').json())
