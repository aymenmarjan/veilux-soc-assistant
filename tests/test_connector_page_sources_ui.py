"""Page rules and multi-SIEM routing through the actual worker, editor and backend."""
import json
import re
import unittest
from pathlib import Path
import certifi
from playwright.sync_api import expect
import test_connector_setup_ui as harness
import test_extension_ui as native_harness

class PageSourceTests(unittest.TestCase):
    setUpClass=classmethod(harness.ConnectorSetupTests.setUpClass.__func__)
    tearDownClass=classmethod(harness.ConnectorSetupTests.tearDownClass.__func__)
    setUp=harness.ConnectorSetupTests.setUp
    tearDown=harness.ConnectorSetupTests.tearDown
    install_background=harness.ConnectorSetupTests.install_background
    settings=harness.ConnectorSetupTests.settings
    api_form=harness.ConnectorSetupTests.api_form
    tab=harness.ConnectorSetupTests.tab
    value=harness.ConnectorSetupTests.value
    more=harness.ConnectorSetupTests.more
    edit=harness.ConnectorSetupTests.edit
    stored=harness.ConnectorSetupTests.stored
    native_extension=native_harness.ExtensionUITests.native_extension

    def source(self,mode='parameters',rules=None):
        return dict(name='Ticket page',website='https://cases.test',urlIncludes='/case/',mode=mode,selector='a[href]',rules=rules or [])

    def profile(self,name='Events',host='console.test',sources=None):
        link='/event/(?<id>[^/?#]+)'
        # As the editor saves them: every "Links on a page" source has its own pattern.
        sources=[dict(s,pattern=link) if s.get('mode')=='links' and not s.get('pattern') and not s.get('linkTemplate') else s for s in sources or []]
        return dict(id=name,name=name,schemaVersion=2,siemHost=host,siemBaseUrl='https://records.test',auth={'type':'none'},
            dom={'discover':{'strategy':'api_request'}},statistics={'mode':'records'},pageSources=sources,
            api={'enabled':True,'method':'GET','pathTemplate':'/records/${id}','responsePath':'data.records','linkRegex':link})

    def popup(self,profiles,html):
        self.page.evaluate('profiles=>browser.storage.local.set({connectorProfiles:profiles})',profiles)
        self.page.goto(self.url+'/extension/popup.html');self.tab('https://cases.test/case/42',html)

    def test_case_page_values_from_text_address_attribute_html_and_fixed_value(self):
        self.api_form()
        self.page.locator('#conn-api-path').fill('/records/${id}')
        self.page.locator('#conn-api-query').fill('{"tenant":"${tenant}","case":"${case_id}","context":"${context}","stamp":"${stamp}","kind":"${kind}"}')
        first=self.value('text',site='other',website='https://cases.test',selector='#Details',pattern=r'tenant=(?<tenant>\w+); id=(?<id>\S+)',decode=True)
        # Later sources start on the same website as the previous one.
        url=self.value('url',patternType='regex',regex=r'/case/(?<case_id>\d+)')
        expect(url.locator('[data-key=website]')).to_have_value('https://cases.test')
        self.value('attribute',selector='#context',attribute='data-value',name='context')
        self.value('text',selector='#meta',read='html',pattern=r'data-kind="(?<kind>[^"]+)"')
        self.value('fixed',name='stamp',value='synthetic')
        expect(self.page.locator('#conn-placeholders .placeholder-missing')).to_have_count(0)
        html='<div id="Details">tenant=prod; id=evt%2042</div><div id="context" data-value="a &quot;quote&quot; \\ value"></div><div id="meta"><span data-kind="alert"></span></div>'
        self.tab('https://cases.test/case/42',html)
        first.get_by_role('button',name='Test on the open page').click()
        expect(first.locator('.value-result')).to_contain_text('1 request would be made. Nothing was sent.')
        expect(first.locator('.value-result')).to_contain_text('evt 42')
        self.assertEqual([],self.page.request.get(self.url+'/test/sent').json())
        self.page.locator('#save-connector').click()
        saved=self.stored()
        self.assertEqual(1,len(saved['pageSources']));self.assertEqual(4,len(saved['pageSources'][0]['rules']))
        self.assertEqual({'stamp':'synthetic'},saved['api']['parameters'])
        self.edit()
        expect(self.page.locator('.value-card')).to_have_count(5)
        expect(self.page.locator('#conn-siem-base-url')).to_have_value('https://records.test')
        self.page.locator('#cancel-connector').click()
        self.page.goto(self.url+'/extension/popup.html');self.tab('https://cases.test/case/42',html)
        self.page.locator('#extract-btn').click()
        expect(self.page.locator('#logs-textarea')).to_have_value(re.compile('alice'),timeout=10000)
        sent=self.page.request.get(self.url+'/test/sent').json()
        self.assertEqual(1,len(sent));self.assertIn('/records/evt%2042',sent[0]['url'])
        self.assertIn('case=42',sent[0]['url']);self.assertIn('kind=alert',sent[0]['url']);self.assertIn('tenant=prod',sent[0]['url'])

    def test_own_website_values_fall_back_to_the_page_reader(self):
        # An attribute on the connection's own website is optional: without it the table is read.
        self.api_form()
        self.page.locator('#conn-api-path').fill('/records/${id}')
        self.value('attribute',selector='[data-event-id]',attribute='data-event-id',name='id')
        self.page.locator('#conn-api-fallback').select_option('table')
        self.page.locator('#save-connector').click()
        self.page.goto(self.url+'/extension/popup.html')
        self.tab('https://console.test/events','<table><tr><th>user</th></tr><tr><td>table-row</td></tr></table>')
        self.page.locator('#extract-btn').click()
        expect(self.page.locator('#logs-textarea')).to_have_value(re.compile('table-row'),timeout=10000)
        self.assertEqual([],self.page.request.get(self.url+'/test/sent').json())
        self.page.goto(self.url+'/extension/popup.html')
        self.tab('https://console.test/events','<div data-event-id="evt7">Event</div>')
        self.page.locator('#extract-btn').click()
        expect(self.page.locator('#logs-textarea')).to_have_value(re.compile('alice'),timeout=10000)
        self.assertIn('/records/evt7',self.page.request.get(self.url+'/test/sent').json()[0]['url'])

    def two_tabs(self,html):
        """The connection's own website is the active tab; the value-source page is open in the background."""
        self.tab('https://console.test/events/own-site-id',html)
        self.page.evaluate("""()=>{browser.tabs.query=async()=>[{id:17,url:'https://console.test/events/own-site-id',active:true,windowId:1},
          {id:18,url:'https://cases.test/profile',active:false,windowId:1}];}""")

    def test_preview_reads_the_value_source_page_not_the_sign_in_tab(self):
        self.api_form()
        self.page.locator('#conn-api-path').fill('/records/${id}')
        self.value('url',template='https://console.test/events/{id}')
        self.value('text',site='other',website='https://cases.test',selector='.credential',pattern=r'Credential ID (?<id>\w+)',repeat=True)
        self.two_tabs('<p class="credential">Credential ID first</p><p class="credential">Credential ID second</p>')
        self.page.locator('#preview-connector').click()
        result=self.page.locator('#connector-preview-result')
        expect(result).to_contain_text('Read from: https://cases.test/profile',timeout=10000)
        urls=[r['url'] for r in self.page.request.get(self.url+'/test/sent').json()]
        self.assertEqual(2,len(urls));self.assertIn('/records/first',urls[0]);self.assertIn('/records/second',urls[1])
        self.assertFalse(any('own-site-id' in u for u in urls))

    def test_missing_record_is_reported_and_other_records_are_kept(self):
        self.api_form()
        self.page.locator('#conn-api-path').fill('/records/${id}')
        self.value('text',site='other',website='https://cases.test',selector='.credential',pattern=r'Credential ID (?<id>\w+)',repeat=True)
        html='<p class="credential">Credential ID first</p><p class="credential">Credential ID missing</p><p class="credential">Credential ID third</p>'
        self.tab('https://cases.test/profile',html)
        self.page.locator('#preview-connector').click()
        result=self.page.locator('#connector-preview-result')
        expect(result).to_contain_text('4 records read, 1 failed',timeout=10000)
        expect(result).to_contain_text('For id=missing:')
        self.page.locator('#save-connector').click()
        self.page.request.post(self.url+'/test/reset')
        self.page.goto(self.url+'/extension/popup.html');self.tab('https://cases.test/profile',html)
        self.page.locator('#extract-btn').click()
        expect(self.page.locator('#status-text')).to_contain_text('1 failed: For id=missing: API returned HTTP 404',timeout=10000)
        self.assertEqual(3,len(self.page.request.get(self.url+'/test/sent').json()))
        expect(self.page.locator('#logs-textarea')).to_have_value(re.compile('alice'))

    def test_repeated_captures_keep_values_paired_across_requests(self):
        source=self.source(rules=[dict(source='text',selector='#rows',pattern=r'tenant=(?<tenant>\w+) id=(?<id>\w+)',repeat=True)])
        p=self.profile(sources=[source]);p['api']['queryTemplate']={'tenant':'${tenant}'}
        self.popup([p],'<div id="rows">tenant=a id=one; tenant=b id=two</div>')
        self.page.locator('#extract-btn').click();expect(self.page.locator('#logs-textarea')).to_have_value(re.compile('alice'))
        sent=self.page.request.get(self.url+'/test/sent').json()
        self.assertEqual(2,len(sent));self.assertIn('/records/one?tenant=a',sent[0]['url']);self.assertIn('/records/two?tenant=b',sent[1]['url'])

    def test_shared_case_host_routes_by_matching_link_and_statistics(self):
        other=self.profile('Other','other.test',[self.source('links')]);wanted=self.profile('Wanted','console.test',[self.source('links')])
        self.popup([other,wanted],'<a href="https://console.test/event/42">Open record</a>')
        self.page.locator('#extract-stats-btn').click()
        expect(self.page.locator('#statistics-list')).to_contain_text('Wanted',timeout=10000)
        self.assertEqual(1,len(self.page.request.get(self.url+'/test/sent').json()))

    def test_links_on_a_ticket_page_feed_statistics_requests(self):
        source=self.source('links');source.update(urlIncludes='/tickets/',pattern=r'/records/(?<index>[^/?#]+)/(?<doc_id>[^/?#]+)')
        p=self.profile(sources=[source])
        p['api'].update(method='POST',pathTemplate='/records/${doc_id}',linkRegex=source['pattern'],bodyTemplate='{"index":"${index}","id":"${doc_id}"}')
        html='<div><h3>Linked records</h3><a href="https://console.test/records/events-index/record42">View log</a></div>'
        self.popup([p],html);self.tab('https://cases.test/tickets/4821',html)
        self.page.locator('#extract-stats-btn').click()
        expect(self.page.locator('#statistics-list')).to_contain_text('configured API request',timeout=10000)
        sent=self.page.request.get(self.url+'/test/sent').json()
        self.assertEqual(1,len(sent));self.assertEqual({'index':'events-index','id':'record42'},json.loads(sent[0]['body']))

    def test_multiple_matching_connections_require_choice_and_cancel_is_local(self):
        first=self.profile('First','first.test',[self.source('links')]);second=self.profile('Second','second.test',[self.source('links')])
        self.popup([first,second],'<a href="https://first.test/event/one">First</a><a href="https://second.test/event/two">Second</a>')
        self.page.locator('#extract-btn').click();expect(self.page.locator('#connector-choice')).to_be_visible()
        self.assertEqual([],self.page.request.get(self.url+'/test/sent').json())
        self.page.locator('#connector-choice').get_by_role('button',name='Cancel').click()
        self.assertEqual([],self.page.request.get(self.url+'/test/sent').json())
        self.page.locator('#extract-btn').click();self.page.locator('#connector-choice-select').select_option('1')
        self.page.locator('#connector-choice').get_by_role('button',name='Use connection').click()
        expect(self.page.locator('#logs-textarea')).to_have_value(re.compile('alice'))
        sent=self.page.request.get(self.url+'/test/sent').json();self.assertEqual(1,len(sent));self.assertIn('/records/two',sent[0]['url'])

    def test_missing_or_ambiguous_required_values_stop_before_http(self):
        rule=dict(source='text',selector='.value',name='id')
        for html,message in [('<div>No value</div>','found no value'),('<div class="value">one</div><div class="value">two</div>','different values')]:
            with self.subTest(message=message):
                self.popup([self.profile(sources=[self.source(rules=[rule])])],html)
                self.page.locator('#extract-btn').click();expect(self.page.locator('#status-text')).to_contain_text(message)
                self.assertEqual([],self.page.request.get(self.url+'/test/sent').json())

    def test_started_slow_regex_is_terminated_and_next_preview_works(self):
        result=self.page.evaluate('''async()=>{
          let started=false,ticks=0;const Native=Worker;
          window.Worker=class extends Native {constructor(...args){super(...args);this.addEventListener('message',e=>{if(e.data.started)started=true;});}};
          const timer=setInterval(()=>ticks++,10);let error='';
          try{await ConnectorSources.run([{source:'constant',pattern:'(?<id>(a+)+)$'}],[[{text:'a'.repeat(40000)+'!'}]]);}catch(e){error=e.message;}
          clearInterval(timer);window.Worker=Native;
          const next=await ConnectorSources.run([{source:'constant',name:'id'}],[[{text:'next'}]]);
          return {started,ticks,error,next:next.records[0].params.id};
        }''')
        self.assertTrue(result['started']);self.assertGreater(result['ticks'],0);self.assertIn('stopped',result['error']);self.assertEqual('next',result['next'])
        self.assertEqual([],self.page.request.get(self.url+'/test/sent').json())

    def test_copy_case_platform_sources_from_another_connection(self):
        self.api_form()
        self.value('links',site='other',website='https://cases.test',template='https://console.test/event/{id}')
        self.page.locator('#save-connector').click()
        self.page.locator('#add-connector-trigger').click()
        self.page.locator('#conn-name').fill('Second SIEM');self.page.locator('#conn-siem-address').fill('https://other.test')
        self.page.locator('#conn-source-api').check()
        self.page.locator('#conn-copy-values').select_option(label='Portable SOC (1)')
        card=self.page.locator('.value-card')
        expect(card.locator('[data-key=website]')).to_have_value('https://cases.test')
        expect(card.locator('[data-key=template]')).to_have_value('https://console.test/event/{id}')
        card.get_by_role('button',name='Remove').click()
        expect(self.page.locator('.value-card')).to_have_count(0)
        self.page.locator('#cancel-connector').click()
        p=self.stored();self.assertEqual('/records',p['api']['pathTemplate']);self.assertEqual(1,len(p['pageSources']))

    def test_native_extension_csp_worker_and_element_capture(self):
        with self.native_extension() as native:
            worker=native.service_workers[0] if native.service_workers else native.wait_for_event('serviceworker',timeout=10000)
            extension_id=worker.url.split('/')[2]
            native.route('http://localhost:8000/**',lambda route:route.continue_(url=route.request.url.replace('http://localhost:8000',self.url)))
            source_url=self.url+'/test/parameter-source'
            native.route('**/test/parameter-source',lambda route:route.fulfill(content_type='text/html',
                headers={'Content-Security-Policy':"default-src 'none'"},body='<div id="event">Record native42</div>'))
            source=native.new_page();source.goto(source_url)
            binding=dict(name='Native case',website=self.url,urlIncludes='/test/parameter-source',mode='parameters',
                rules=[dict(source='text',selector='#event',pattern=r'Record (?<id>\w+)')])
            worker.evaluate('p=>chrome.storage.local.set({connectorProfiles:[p]})',self.profile(sources=[binding]))
            tab=worker.evaluate('url=>chrome.tabs.query({}).then(t=>t.find(p=>p.url===url))',source_url)
            popup=native.new_page();popup.goto(f'chrome-extension://{extension_id}/popup.html?tabId={tab["id"]}')
            popup.locator('#extract-btn').click()
            expect(popup.locator('#logs-textarea')).to_have_value(re.compile('alice'),timeout=15000)
            sent=self.page.request.get(self.url+'/test/sent').json();self.assertEqual(1,len(sent));self.assertIn('/records/native42',sent[0]['url'])

    def test_ca_import_test_and_save_keep_verification_enabled(self):
        self.api_form()
        pem=re.search(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',Path(certifi.where()).read_text(),re.S).group()
        self.more();self.page.get_by_text('Organization CA certificate (optional)',exact=True).click()
        self.page.locator('#conn-ca-file').set_input_files(dict(name='organization-ca.pem',mimeType='application/x-pem-file',buffer=pem.encode()))
        expect(self.page.locator('#conn-ca-status')).to_contain_text('Certificate loaded')
        expect(self.page.locator('#conn-verify-ssl')).to_be_checked()
        requests=[]
        self.page.on('request',lambda request:requests.append(request.post_data_json) if request.url.endswith('/test-siem') else None)
        self.page.locator('#test-connector').click()
        expect(self.page.locator('#connector-test-result')).to_contain_text('Connection check succeeded',timeout=10000)
        self.assertTrue(requests[0]['verify_ssl']);self.assertEqual('system',requests[0]['tls_trust']);self.assertEqual(pem,requests[0]['ca_bundle_pem'])
        self.page.locator('#save-connector').click()
        self.edit();self.more()
        expect(self.page.locator('#conn-ca-pem')).to_have_value(pem)
        expect(self.page.locator('#conn-verify-ssl')).to_be_checked()

    def test_private_key_is_rejected_by_ca_import_and_form(self):
        self.api_form();self.more();self.page.get_by_text('Organization CA certificate (optional)',exact=True).click()
        private='-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----'
        self.page.locator('#conn-ca-file').set_input_files(dict(name='key.pem',mimeType='text/plain',buffer=private.encode()))
        expect(self.page.locator('#conn-ca-status')).to_contain_text('not a private key')
        expect(self.page.locator('#conn-ca-pem')).to_have_value('')
        self.page.locator('#conn-ca-pem').fill(private);self.page.locator('#save-connector').click()
        expect(self.page.locator('#conn-ca-pem')).to_have_attribute('aria-invalid','true')
        self.assertEqual([],self.page.request.get(self.url+'/test/sent').json())
