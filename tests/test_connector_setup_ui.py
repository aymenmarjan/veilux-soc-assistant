"""Portable connector setup, real DOM and backend, intercepted external HTTP."""
import json
from urllib.parse import parse_qs
import re
import unittest
from playwright.sync_api import expect
import test_extension_ui as harness
from backend_key import TEST_BACKEND_KEY

class ConnectorSetupTests(unittest.TestCase):
    setUpClass=classmethod(harness.ExtensionUITests.setUpClass.__func__)
    tearDownClass=classmethod(harness.ExtensionUITests.tearDownClass.__func__)
    setUp=harness.ExtensionUITests.setUp
    tearDown=harness.ExtensionUITests.tearDown
    install_background=harness.ExtensionUITests.install_background

    def settings(self):
        self.page.goto(self.url+'/extension/settings.html')
        expect(self.page.locator('#settings-save-state')).to_have_text('Settings saved')
        self.page.locator('#add-connector-trigger').click()

    def api_form(self):
        self.settings()
        for id,value in [('name','Portable SOC'),('siem-address','https://console.test/events')]:self.page.locator('#conn-'+id).fill(value)
        self.page.locator('#conn-source-api').check()
        self.page.locator('#conn-siem-base-url').fill('https://records.test')
        self.page.locator('#conn-api-path').fill('/records')
        self.page.locator('#conn-response-path').fill('data.records')
        self.page.locator('#conn-auth-type').select_option('none')

    def value(self,kind,**fields):
        """Adds a value source and fills its fields; returns the card."""
        self.page.locator('[data-add-value="'+kind+'"]').click()
        cards=self.page.locator('.value-card');card=cards.nth(cards.count()-1)
        for key,value in fields.items():
            field=card.locator('[data-key="'+key+'"]')
            if not field.is_visible() and field.evaluate("el=>!!el.closest('.value-options:not([open])')"):
                card.locator('summary').filter(has_text='Options').click()
            if isinstance(value,bool):field.set_checked(value)
            elif field.evaluate('el=>el.tagName')=='SELECT':field.select_option(value)
            else:field.fill(value)
        return card

    def more(self):
        if not self.page.locator('#conn-more').evaluate('el=>el.open'):self.page.locator('#conn-more > summary').click()

    def edit(self,name='Portable SOC'):
        self.page.locator('#connector-list .prompt-item').filter(has_text=name).get_by_role('button',name='Edit '+name).click()

    def stored(self,name='Portable SOC'):
        return next(p for p in self.page.evaluate("()=>browser.storage.local.get('connectorProfiles')")['connectorProfiles'] if p['name']==name)

    def tab(self,url='https://console.test/events',html=None):
        self.page.evaluate('url=>{browser.tabs.query=async()=>[{id:17,url,active:true,windowId:1}];}',url)
        if html is not None:
            self.page.evaluate('''html=>{const f=document.createElement('iframe');f.id='source-fixture';document.body.append(f);f.contentDocument.body.innerHTML=html;
              browser.scripting={executeScript:async options=>[{result:await f.contentWindow.eval('('+options.func.toString()+')')(...options.args)}]};}''',html)

    def test_api_preview_save_edit_extract_statistics_share_mapping(self):
        self.api_form();self.tab()
        self.page.locator('#conn-total-records-path').fill('data.total')
        self.page.locator('#preview-connector').click()
        expect(self.page.locator('#connector-preview-result')).to_contain_text('2 records read',timeout=10000)
        self.page.locator('#save-connector').click()
        self.page.reload()
        row=self.page.locator('#connector-list .prompt-item').filter(has_text='Portable SOC')
        row.get_by_role('button',name='Edit Portable SOC').click()
        expect(self.page.locator('#conn-siem-base-url')).to_have_value('https://records.test')
        expect(self.page.locator('#conn-siem-address')).to_have_value('https://console.test/events')
        self.page.locator('#cancel-connector').click()
        self.page.goto(self.url+'/extension/popup.html');self.tab()
        self.page.locator('#extract-btn').click()
        expect(self.page.locator('#logs-textarea')).to_have_value(re.compile('alice'),timeout=10000)
        expect(self.page.locator('#logs-textarea')).to_have_value(re.compile('bob'))
        self.page.locator('#extract-stats-btn').click()
        expect(self.page.locator('#statistics-list')).to_contain_text('total matches: 2',timeout=10000)
        expect(self.page.locator('#statistics-list')).to_contain_text('configured API request')
        self.assertEqual(3,len(self.page.request.get(self.url+'/test/sent').json()))

    def test_case_description_links_values_and_source_metadata(self):
        self.api_form()
        self.page.locator('#conn-api-path').fill('/records/${case_id}')
        self.page.locator('#conn-api-query').fill('{"tenant":"${tenant}"}')
        card=self.value('links',site='other',website='https://cases.test',selector='div.record-links',
            template='https://files.test/logs/{case_id}?tenant={tenant}',example='https://files.test/logs/evt%2042?tenant=production')
        card.get_by_role('button',name='Check example').click()
        expect(card.locator('.value-result')).to_contain_text('evt 42')
        expect(self.page.locator('#conn-placeholders .placeholder-missing')).to_have_count(0)
        self.page.locator('#save-connector').click()
        self.page.goto(self.url+'/extension/popup.html')
        self.tab('https://cases.test/cases/42','<div class="record-links"><a href="https://files.test/logs/evt%2042?tenant=production">Log</a> https://files.test/logs/evt%2042?tenant=production</div><a href="https://files.test/logs/outside?tenant=x">Ignore outside description</a>')
        self.page.locator('#extract-btn').click()
        expect(self.page.locator('#logs-textarea')).to_have_value(re.compile('alice'),timeout=10000)
        sent=self.page.request.get(self.url+'/test/sent').json()
        self.assertEqual(1,len(sent));self.assertIn('/records/evt%2042',sent[0]['url'])
        self.assertIn('tenant=production',sent[0]['url'])
        pages=self.page.evaluate("()=>browser.storage.local.get('capturedLogPages')")['capturedLogPages']
        self.assertIn('https://files.test/logs/evt%2042?tenant=production',pages[-1]['linkedUrls'])

    def test_sentinel_columns_preview_and_kql_body(self):
        self.api_form();self.page.locator('#conn-preset').select_option('sentinel')
        expect(self.page.locator('#conn-siem-base-url')).to_have_value('https://api.loganalytics.azure.com')
        self.page.locator('#conn-siem-base-url').fill('https://records.test')
        # The template signs in as an app; a pasted token remains an option.
        expect(self.page.locator('#conn-auth-type')).to_have_value('oauth_client_credentials')
        self.page.locator('#conn-auth-type').select_option('header')
        self.page.locator('#conn-header-value').fill('Bearer synthetic')
        workspace=self.page.locator('.value-card[data-type=fixed] [data-key=value]').first
        expect(workspace).to_have_value('YOUR-WORKSPACE-ID');workspace.fill('workspace-id')
        self.page.locator('#conn-default-query').fill('SecurityEvent | take 2')
        self.tab();self.page.locator('#preview-connector').click()
        expect(self.page.locator('#connector-preview-result')).to_contain_text('"User": "alice"',timeout=10000)
        sent=self.page.request.get(self.url+'/test/sent').json()
        self.assertEqual('SecurityEvent | take 2',json.loads(sent[0]['body'])['query'])
        self.assertIn('/workspaces/workspace-id/query',sent[0]['url'])

    def test_sentinel_app_sign_in_gets_a_token_then_queries(self):
        self.api_form();self.page.locator('#conn-preset').select_option('sentinel')
        self.page.locator('#conn-siem-base-url').fill('https://records.test')
        expect(self.page.locator('#conn-oauth-group')).to_be_visible()
        expect(self.page.locator('#conn-oauth-scope')).to_have_value('https://api.loganalytics.io/.default')
        self.page.locator('#conn-oauth-token-url').fill('https://login.test/tenant-a/oauth2/v2.0/token')
        self.page.locator('#conn-oauth-client-id').fill('synthetic-client')
        self.page.locator('#conn-oauth-client-secret').fill('synthetic-secret')
        self.tab();self.page.locator('#preview-connector').click()
        expect(self.page.locator('#connector-preview-result')).to_contain_text('"User": "alice"',timeout=10000)
        sent=self.page.request.get(self.url+'/test/sent').json()
        token=parse_qs(sent[0]['body'])
        self.assertEqual('https://login.test/tenant-a/oauth2/v2.0/token',sent[0]['url'])
        self.assertEqual(['client_credentials'],token['grant_type']);self.assertEqual(['synthetic-client'],token['client_id'])
        self.assertEqual(['https://api.loganalytics.io/.default'],token['scope'])
        self.assertIn('/workspaces/YOUR-WORKSPACE-ID/query',sent[1]['url'])
        self.assertEqual('P1D',json.loads(sent[1]['body'])['timespan'])
        # The secret is a credential: a settings export leaves it out.
        self.page.locator('#save-connector').click()
        stored=self.page.evaluate("()=>browser.storage.local.get('connectorProfiles')")['connectorProfiles'][-1]
        self.assertEqual('synthetic-secret',stored['auth']['clientSecret'])

    # One page per template, with the credentials its sign-in method needs.
    TEMPLATE_CASES = [
        ('splunk_results', 'https://splunk.example.test:8000', 'https://splunk.example.test:8089',
         'https://splunk.example.test:8000/en-US/app/search/search?q=search%20index%3Dmain&sid=1731830000.42'),
        ('splunk', 'https://splunk.example.test:8000', 'https://splunk.example.test:8089', None),
        ('sentinel_incident', 'https://portal.azure.com', None,
         'https://portal.azure.com/#asset/Microsoft_Azure_Security_Insights/Incident/subscriptions/00000000-1111-2222-3333-444444444444'
         '/resourceGroups/rg-security/providers/Microsoft.OperationalInsights/workspaces/law-security'
         '/providers/Microsoft.SecurityInsights/Incidents/8a1c2e3f-4b5d-4e6f-8a9b-0c1d2e3f4a5b'),
        ('sentinel', 'https://portal.azure.com', None, None),
        ('defender_incident', 'https://security.microsoft.com', None, 'https://security.microsoft.com/incidents/2972?tid=t'),
        ('elastic_search', 'https://wazuh.example.test', 'https://es.example.test:9200', None),
        ('elastic_document', 'https://kibana.example.test', 'https://es.example.test:9200',
         'https://kibana.example.test/app/discover#/doc/view-1/logs-2026.11.17?id=doc-7'),
        ('opensearch', 'https://dashboards.example.test', None, 'https://dashboards.example.test/app/discover#/doc/view-1/logs-2026.11.17?id=doc-7'),
        ('qradar', 'https://qradar.example.test', None,
         'https://qradar.example.test/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=42'),
    ]

    def test_every_template_is_saved_exactly_as_written(self):
        """The editor turns a template into form fields and back. The saved
        connection must send the same request as the template itself."""
        credentials = {'header': {'headerValue': 'Bearer synthetic'}, 'basic': {'username': 'analyst', 'password': 'synthetic'},
                       'browser_session': {}, 'oauth_client_credentials': {
                           'tokenUrl': 'https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/oauth2/v2.0/token',
                           'clientId': 'synthetic-client', 'clientSecret': 'synthetic-secret'}}
        fields = {'headerValue': 'header-value', 'username': 'basic-username', 'password': 'basic-password',
                  'tokenUrl': 'oauth-token-url', 'clientId': 'oauth-client-id', 'clientSecret': 'oauth-client-secret'}
        for preset, website, base, page in self.TEMPLATE_CASES:
            with self.subTest(preset=preset):
                self.settings()
                self.page.locator('#conn-name').fill('Template ' + preset)
                self.page.locator('#conn-siem-address').fill(website)
                self.page.locator('#conn-preset').select_option(preset)
                if base: self.page.locator('#conn-siem-base-url').fill(base)
                auth = self.page.locator('#conn-auth-type').input_value()
                for key, value in credentials[auth].items(): self.page.locator('#conn-' + fields[key]).fill(value)
                self.page.locator('#save-connector').click()
                expect(self.page.locator('#connector-list')).to_contain_text('Template ' + preset)
                saved = self.stored('Template ' + preset)
                self.assertEqual(preset, saved['platform'])
                compare = self.page.evaluate("""async ([saved, preset, website, base, page, extra]) => {
                  const t = structuredClone(CONNECTOR_PRESETS[preset]), url = new URL(website);
                  const direct = {...t, schemaVersion: 2, platform: preset, name: saved.name, websiteUrl: url.href, siemHost: url.hostname,
                    siemBaseUrl: base || t.siemBaseUrl || url.origin, maxRecords: 5000, auth: {...t.auth, ...extra}};
                  const options = p => page ? {params: [VeiluxConnectors.linkParams(p, page)]} : {};
                  const keys = ['siem_base_url','parsed_params','auth_type','api_method','api_path_template','api_headers_template','api_body_template',
                    'response_path','api_query_template','fetch_mode','record_format','columns_path','total_path','pagination_mode','pagination_parameter',
                    'pagination_size_parameter','page_size','max_pages','test_path','context_path_template','context_response_path','oauth_token_url',
                    'oauth_client_id','oauth_scope','auth_headers_from_cookies','job_create_method','job_create_path_template','job_create_query_template',
                    'job_create_parameters_as','job_id_path','job_status_path_template','job_status_field','job_complete_values','job_error_values',
                    'job_error_message_path','job_results_path_template'];
                  const pick = async p => { const r = await VeiluxConnectorClient.requestPayload(p, {...options(p), includeAuth: p.auth.type !== 'browser_session'});
                    return Object.fromEntries(keys.map(k => [k, r[k] ?? null])); };
                  return [await pick(saved), await pick(direct), options(saved)];
                }""", [saved, preset, website, base, page, credentials[auth]])
                stored, expected, used = compare
                if expected['fetch_mode'] != 'search_job':
                    # Search-job fields are not used by a single request; the editor keeps its own defaults there.
                    stored = {k: v for k, v in stored.items() if not k.startswith('job_')}
                    expected = {k: v for k, v in expected.items() if not k.startswith('job_')}
                self.maxDiff = None
                self.assertEqual(expected, stored)
                if page: self.assertTrue(used['params'][0], used)

    def test_known_platform_presets_reach_their_actual_request_shapes(self):
        self.api_form()
        for platform in ('opensearch','qradar','splunk'):
            with self.subTest(platform=platform):
                self.page.request.post(self.url+'/test/reset')
                self.page.locator('#conn-preset').select_option(platform)
                expect(self.page.locator('#conn-source-api')).to_be_checked()
                self.page.locator('#conn-siem-base-url').fill('https://records.test')
                self.page.locator('#conn-auth-type').select_option('header')
                self.page.locator('#conn-header-value').fill('synthetic-token')
                if platform=='opensearch':
                    expect(self.page.locator('#conn-api-fallback')).to_have_value('inspector')
                    self.tab('https://console.test/#/doc/view/logs-index?id=record-one')
                else:
                    expect(self.page.locator('#conn-api-fallback')).to_have_value('table')
                    self.page.locator('#conn-api-fallback').select_option('request')
                    self.page.locator('#conn-default-query').fill('synthetic search')
                    self.tab(html='<p>Search results</p>')
                self.page.locator('#preview-connector').click()
                expect(self.page.locator('#connector-preview-result')).to_contain_text('2 records read',timeout=10000)
                expect(self.page.locator('#connector-preview-result')).to_contain_text('alice')
                sent=self.page.request.get(self.url+'/test/sent').json()
                if platform=='opensearch':
                    self.assertEqual(1,len(sent));self.assertEqual('logs-index',json.loads(sent[0]['body'])['params']['index'])
                else:
                    self.assertEqual(3,len(sent))
                    if platform=='splunk':
                        # Splunk documents the search parameters as a form body.
                        form=parse_qs(sent[0]['body'])
                        self.assertEqual(['synthetic search'],form['search']);self.assertEqual(['json'],form['output_mode'])
                        self.assertEqual(['-24h'],form['earliest_time'])
                        self.assertIn('offset=0',sent[2]['url']);self.assertIn('count=100',sent[2]['url'])
                    else:self.assertIn('synthetic',sent[0]['url'])

    def test_json_page_reader_and_disabled_statistics(self):
        self.settings()
        self.page.locator('#conn-name').fill('JSON page')
        self.page.locator('#conn-siem-address').fill('https://json.test')
        self.page.locator('#conn-source-json').check()
        expect(self.page.locator('#conn-api-step')).to_be_hidden()
        expect(self.page.locator('#conn-json-panel #conn-response-path')).to_be_visible()
        self.page.locator('#conn-response-path').fill('events')
        self.more();self.page.locator('#conn-statistics-mode').select_option('disabled')
        self.page.locator('#save-connector').click()
        self.page.goto(self.url+'/extension/popup.html')
        self.tab('https://json.test','<pre>{"events":[{"user":"alice"},{"user":"bob"}]}</pre>')
        self.page.locator('#extract-btn').click()
        expect(self.page.locator('#logs-textarea')).to_have_value(re.compile('bob'))
        self.page.locator('#extract-stats-btn').click()
        expect(self.page.locator('#status-text')).to_contain_text('Statistics are disabled')
        self.assertEqual([],self.page.request.get(self.url+'/test/sent').json())

    def test_qradar_static_page_keeps_content_id_and_context_query(self):
        self.api_form();self.page.locator('#conn-preset').select_option('qradar')
        expect(self.page.locator('.value-card[data-type=text] [data-key=pattern]')).to_have_value(r'Offense\s+(?<offense_id>\d+)\s*\(Summary\)')
        self.page.locator('#conn-siem-base-url').fill('https://records.test')
        self.page.locator('#conn-auth-type').select_option('header')
        self.page.locator('#conn-header-value').fill('synthetic-token')
        self.tab('https://console.test/console/base','<p>All Offenses &gt; Offense 42 (Summary)</p>')
        self.page.locator('#preview-connector').click()
        expect(self.page.locator('#connector-preview-result')).to_contain_text('3 records read',timeout=10000)
        sent=self.page.request.get(self.url+'/test/sent').json()
        self.assertIn('/api/siem/offenses/42',sent[0]['url'])
        from urllib.parse import unquote
        query=unquote(sent[1]['url']).replace('+',' ')
        self.assertIn('INOFFENSE(42)',query)
        self.assertNotIn('${context',query)

    def test_page_table_statistics_without_any_api_calls(self):
        self.settings()
        self.page.locator('#conn-name').fill('Local table')
        self.page.locator('#conn-siem-address').fill('https://table.test/events')
        self.page.locator('#conn-source-table').check()
        expect(self.page.locator('#conn-table-auto')).to_be_checked()
        self.page.locator('#save-connector').click()
        self.assertFalse(self.stored('Local table')['api']['enabled'])
        self.page.goto(self.url+'/extension/popup.html')
        self.tab('https://table.test/events','<table><tr><th>user</th><th>status</th></tr><tr><td>alice</td><td>open</td></tr><tr><td>bob</td><td>open</td></tr></table>')
        self.page.locator('#extract-stats-btn').click()
        expect(self.page.locator('#statistics-list')).to_contain_text('visible rows only',timeout=10000)
        expect(self.page.locator('#statistics-list')).to_contain_text('open')
        self.assertEqual([],self.page.request.get(self.url+'/test/sent').json())

    def test_table_finder_picks_one_of_several_tables(self):
        self.settings()
        self.page.locator('#conn-name').fill('Chosen table')
        self.page.locator('#conn-siem-address').fill('https://table.test/events')
        self.page.locator('#conn-source-table').check()
        self.page.locator('#conn-table-specific').check()
        html=('<table class="menu"><tr><th>Menu</th></tr><tr><td>Home</td></tr><tr><td>Cases</td></tr><tr><td>Rules</td></tr></table>'
              '<div><table><thead><tr><th>user</th><th>action</th></tr></thead><tbody><tr><td>alice</td><td>login</td></tr></tbody></table></div>')
        self.tab('https://table.test/events',html)
        self.page.locator('#conn-find-tables').click()
        choices=self.page.locator('#conn-table-list .table-choice')
        expect(choices).to_have_count(2)
        expect(choices.nth(1)).to_contain_text('Columns: user, action')
        choices.nth(1).get_by_role('button').click()
        selector=self.page.locator('#conn-table-selector').input_value()
        self.assertTrue(selector)
        self.page.locator('#save-connector').click()
        self.assertEqual(selector,self.stored('Chosen table')['dom']['discover']['tableSelector'])
        self.page.goto(self.url+'/extension/popup.html');self.tab('https://table.test/events',html)
        self.page.locator('#extract-btn').click()
        expect(self.page.locator('#logs-textarea')).to_have_value(re.compile('login'),timeout=10000)
        self.assertNotIn('Cases',self.page.locator('#logs-textarea').input_value())

    def test_page_address_value_and_placeholder_check(self):
        self.api_form()
        self.page.locator('#conn-api-path').fill('/records/${event_id}')
        self.page.locator('#conn-api-query').fill('{"tenant":"${tenant}"}')
        missing=self.page.locator('#conn-placeholders .placeholder-missing')
        expect(missing).to_have_count(2)
        card=self.value('url',template='https://console.test/events/{event_id}',example='https://console.test/events/abc%201')
        card.get_by_role('button',name='Check example').click()
        expect(card.locator('.value-result')).to_contain_text('abc 1')
        expect(missing).to_have_count(1);expect(missing).to_contain_text('${tenant}')
        self.value('fixed',name='tenant',value='prod')
        expect(missing).to_have_count(0)
        self.value('fixed',name='unused',value='x')
        expect(self.page.locator('#conn-placeholders')).to_contain_text('Captured but not used in the request: ${unused}')
        self.page.locator('.value-card').last.get_by_role('button',name='Remove').click()
        self.tab('https://console.test/events/abc%201')
        self.page.locator('#preview-connector').click()
        expect(self.page.locator('#connector-preview-result')).to_contain_text('2 records read',timeout=10000)
        sent=self.page.request.get(self.url+'/test/sent').json()
        self.assertEqual(1,len(sent));self.assertIn('/records/abc%201?tenant=prod',sent[0]['url'])
        self.page.locator('#save-connector').click()
        p=self.stored()
        self.assertEqual('https://console.test/events/{event_id}',p['api']['linkTemplate'])
        self.assertEqual({'tenant':'prod'},p['api']['parameters']);self.assertEqual([],p['pageSources'])

    def test_text_in_one_element_of_own_page_feeds_the_request(self):
        self.api_form()
        self.page.locator('#conn-api-path').fill('/records/${id}')
        self.value('text',selector='.title',pattern=r'Event (?<id>\d+)',ignoreCase=True)
        self.page.locator('#save-connector').click()
        p=self.stored()
        self.assertEqual(('.title','i'),(p['api']['contentSelector'],p['api']['contentFlags']));self.assertEqual([],p['pageSources'])
        self.page.goto(self.url+'/extension/popup.html')
        self.tab('https://console.test/events','<p>Event 99 elsewhere</p><h1 class="title">event 7</h1>')
        self.page.locator('#extract-btn').click()
        expect(self.page.locator('#logs-textarea')).to_have_value(re.compile('alice'),timeout=10000)
        sent=self.page.request.get(self.url+'/test/sent').json()
        self.assertEqual(1,len(sent));self.assertIn('/records/7',sent[0]['url'])

    def test_connection_from_a_pre_release_build_is_set_aside_and_kept(self):
        old=dict(id='pre-release',name='Old format',siemHost='console.test',siemBaseUrl='https://records.test',api={},dom={'discover':{}})
        self.page.goto(self.url+'/extension/settings.html')
        self.page.evaluate('p=>browser.storage.local.set({connectorProfiles:[p]})',old)
        self.page.reload();expect(self.page.locator('#settings-save-state')).to_have_text('Settings saved')
        # It is not listed or converted, and Settings says why.
        expect(self.page.locator('#connector-set-aside')).to_be_visible()
        expect(self.page.locator('#connector-set-aside')).to_contain_text('1 connection was saved by a development build')
        expect(self.page.locator('#connector-set-aside')).to_contain_text('It is kept unchanged')
        expect(self.page.locator('#connector-list')).to_contain_text('No connections yet')
        self.assertEqual(old,self.page.evaluate("()=>browser.storage.local.get('connectorProfiles')")['connectorProfiles'][0])
        # Saving another connection keeps it stored, unchanged.
        self.api_form();self.page.locator('#conn-api-path').fill('/records/${id}')
        self.page.locator('#save-connector').click()
        stored=self.page.evaluate("()=>browser.storage.local.get('connectorProfiles')")['connectorProfiles']
        self.assertEqual(['Portable SOC','Old format'],[p['name'] for p in stored]);self.assertEqual(old,stored[1])
        # Extract never uses it: with only the pre-release connection left, there is none.
        self.page.goto(self.url+'/extension/popup.html')
        self.tab('https://console.test/search','<table><tr><th>user</th></tr><tr><td>row</td></tr></table>')
        self.page.evaluate("()=>browser.storage.local.get('connectorProfiles').then(s=>browser.storage.local.set({connectorProfiles:s.connectorProfiles.slice(1)}))")
        self.page.locator('#extract-btn').click()
        expect(self.page.locator('#status-text')).to_contain_text('No connections yet')
        expect(self.page.locator('#status-text')).to_contain_text('1 saved connection is from a development build before VEILUX 1.0.0')
        self.assertEqual([],self.page.request.get(self.url+'/test/sent').json())
        # Settings removes it on request.
        self.page.goto(self.url+'/extension/settings.html')
        self.page.once('dialog',lambda dialog:dialog.accept())
        self.page.locator('#connector-set-aside-remove').click()
        expect(self.page.locator('#connector-set-aside')).to_be_hidden()
        self.assertEqual([],self.page.evaluate("()=>browser.storage.local.get('connectorProfiles')")['connectorProfiles'])

    def test_backend_address_setting_is_checked_saved_and_used(self):
        self.page.goto(self.url+'/extension/settings.html')
        expect(self.page.locator('#settings-save-state')).to_have_text('Settings saved')
        address=self.page.locator('#backend-url')
        address.fill('ftp://elsewhere')
        self.page.locator('#save-settings').click()
        expect(address).to_have_attribute('aria-invalid','true')
        address.fill(self.url+'/')
        self.page.locator('#check-backend').click()
        expect(self.page.locator('#backend-status')).to_contain_text('The backend is running at '+self.url)
        self.page.locator('#save-settings').click()
        expect(self.page.locator('#settings-save-state')).to_have_text('Settings saved')
        self.assertEqual(self.url,self.page.evaluate("()=>browser.storage.local.get('backendUrl')")['backendUrl'])
        # The popup now calls that address directly, not localhost:8000.
        self.page.goto(self.url+'/extension/popup.html')
        requests=[]
        self.page.on('request',lambda r:requests.append(r.url) if '/defang' in r.url else None)
        self.page.locator('#stage-tab-tools').click()
        self.page.locator('#defang-toggle').click()
        self.page.locator('#defang-input').fill('http://evil.example/x')
        self.page.locator('#defang-btn').click()
        expect(self.page.locator('#defang-output')).to_have_value(re.compile('hXXp'))
        self.assertEqual([self.url+'/defang'],requests)

    def test_pairing_with_the_backend_code_stores_the_key_and_signs_requests(self):
        self.page.evaluate("()=>browser.storage.local.set({backendToken:''})")
        # Not paired: the popup says where to pair, and backend requests are refused.
        self.page.goto(self.url+'/extension/popup.html')
        expect(self.page.locator('#status-text')).to_contain_text('not paired')
        self.page.goto(self.url+'/extension/settings.html')
        expect(self.page.locator('#settings-save-state')).to_have_text('Settings saved')
        self.page.locator('#backend-url').fill(self.url)
        self.page.locator('#check-backend').click()
        expect(self.page.locator('#backend-status')).to_contain_text('not paired with it yet')
        self.page.locator('#pair-backend').click()
        expect(self.page.locator('#backend-pairing-code')).to_have_attribute('aria-invalid','true')
        self.page.locator('#backend-pairing-code').fill('AAAA-AAAA')
        self.page.locator('#pair-backend').click()
        expect(self.page.locator('#backend-status')).to_contain_text('Pairing failed: Wrong pairing code')
        self.assertEqual('',self.page.evaluate("()=>browser.storage.local.get('backendToken')")['backendToken'])
        # The code the backend printed at start-up pairs this browser.
        code=self.page.request.get(self.url+'/test/pairing-code').json()['code']
        self.page.locator('#backend-pairing-code').fill(code.lower())
        self.page.locator('#pair-backend').click()
        expect(self.page.locator('#backend-status')).to_contain_text('Paired with the backend')
        expect(self.page.locator('#backend-pairing-code')).to_have_value('')
        self.assertEqual(TEST_BACKEND_KEY,self.page.evaluate("()=>browser.storage.local.get('backendToken')")['backendToken'])
        # Saved at once; the address typed above is still an unsaved change.
        expect(self.page.locator('#settings-save-state')).to_contain_text('Unsaved')
        self.page.locator('#check-backend').click()
        expect(self.page.locator('#backend-status')).to_contain_text('this browser is paired with it')
        self.page.locator('#save-settings').click()
        expect(self.page.locator('#settings-save-state')).to_have_text('Settings saved')
        # A backend refusing the browser explains itself.
        self.page.route('**/health',lambda route:route.fulfill(status=403,content_type='application/json',
                        body='{"detail":"This backend only answers the VEILUX extension."}'))
        self.page.locator('#check-backend').click()
        expect(self.page.locator('#backend-status')).to_contain_text('refused this browser: This backend only answers')
        self.page.unroute('**/health')
        # Backups leave the key out unless keys are included.
        self.assertIn('backendToken',self.page.evaluate('API_KEY_SETTINGS'))
        # Every backend request now carries the key, and is answered.
        self.page.goto(self.url+'/extension/popup.html')
        expect(self.page.locator('#status-text')).to_contain_text('connected')
        sent=[]
        self.page.on('request',lambda r:sent.append(r.headers.get('x-veilux-token')) if '/defang' in r.url else None)
        self.page.locator('#stage-tab-tools').click()
        self.page.locator('#defang-toggle').click()
        self.page.locator('#defang-input').fill('http://evil.example/x')
        self.page.locator('#defang-btn').click()
        expect(self.page.locator('#defang-output')).to_have_value(re.compile('hXXp'))
        self.assertEqual([TEST_BACKEND_KEY],sent)

    def test_blank_typed_query_parameter_survives_job_edit(self):
        self.api_form()
        self.page.locator('#conn-preset').select_option('splunk')
        self.page.locator('#conn-header-value').fill('Bearer synthetic')
        expect(self.page.locator('#conn-job-query-parameter')).to_have_value('search')
        self.page.locator('#conn-job-query-parameter').fill('')
        self.page.locator('#save-connector').click()
        self.edit()
        expect(self.page.locator('#conn-job-query-parameter')).to_have_value('')

    def test_sample_mapping_validation_and_presets_remain_editable(self):
        self.api_form()
        for preset in ('opensearch','qradar','splunk','sentinel'):
            with self.subTest(preset=preset):
                self.page.locator('#conn-preset').select_option(preset)
                expect(self.page.locator('#conn-name')).to_have_value('Portable SOC')
                expect(self.page.locator('#conn-siem-address')).to_have_value('https://console.test/events')
        self.page.locator('#conn-preset').select_option('')
        expect(self.page.locator('input[name=conn-source]:checked')).to_have_count(0)
        expect(self.page.locator('.value-card')).to_have_count(0)
        self.page.locator('#conn-source-api').check()
        self.page.locator('#conn-auth-type').select_option('none')
        self.page.locator('#conn-api-path').fill('/v2/records')
        self.page.locator('#conn-sample-details summary').click()
        self.page.locator('#conn-sample-response').fill('{"payload":{"items":[{"message":"sample"}]}}')
        self.page.locator('#conn-inspect-sample').click()
        self.page.locator('#conn-sample-path').select_option('payload.items')
        self.page.locator('#conn-preview-sample').click()
        expect(self.page.locator('#conn-sample-result')).to_contain_text('1 records')
        self.page.locator('#conn-api-headers').fill('[]')
        self.page.locator('#save-connector').click()
        expect(self.page.locator('#conn-api-headers')).to_have_attribute('aria-invalid','true')
        self.page.locator('#conn-api-headers').fill('{"Version":"next"}')
        self.page.locator('#save-connector').click()
        expect(self.page.locator('#connector-form')).not_to_be_visible()
        p=self.stored()
        self.assertEqual('next',p['api']['headersTemplate']['Version'])
        self.assertEqual('payload.items',p['api']['responsePath'])
        self.assertEqual('/v2/records',p['api']['pathTemplate'])
        self.assertNotIn('sample-response',str(p))
