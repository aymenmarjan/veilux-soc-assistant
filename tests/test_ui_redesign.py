"""UI workflow regressions, with synthetic data and mocked provider/SIEM HTTP."""
import json
import re
import unittest
from playwright.sync_api import expect
import test_extension_ui as harness
from secret_detection import MECHANISMS


class InterfaceUITests(unittest.TestCase):
    # Reuse the real popup/background/server fixture without inheriting its tests.
    setUpClass = classmethod(harness.ExtensionUITests.setUpClass.__func__)
    tearDownClass = classmethod(harness.ExtensionUITests.tearDownClass.__func__)
    setUp = harness.ExtensionUITests.setUp
    tearDown = harness.ExtensionUITests.tearDown
    install_background = harness.ExtensionUITests.install_background
    sanitize = harness.ExtensionUITests.sanitize

    def settings(self):
        self.page.goto(self.url + '/extension/settings.html')
        expect(self.page.locator('#settings-save-state')).to_have_text('Settings saved')

    def store(self, data):
        self.page.evaluate('(data) => browser.storage.local.set(data)', data)

    def stored(self, key):
        return self.page.evaluate('(key) => browser.storage.local.get(key)', key).get(key)

    def mock_json(self, path, response):
        calls = []
        def handle(route):
            calls.append(route.request.post_data_json)
            route.fulfill(json=response)
        self.context.route('**/' + path, handle)
        return calls

    def clipboard(self):
        self.page.evaluate("Object.defineProperty(navigator, 'clipboard', {value:{writeText:async text=>{window.copied=text}},configurable:true})")

    def test_provider_modes_keep_request_contract_and_preferences(self):
        names = ['groq', 'deepseek', 'together', 'openrouter', 'gemini', 'claude']
        builtin = ['groq', 'deepseek', 'together', 'gemini', 'claude']
        self.store({**{name + 'ApiKey': 'synthetic-' + name for name in names}, 'openrouterModel': 'vendor/alpha:free',
                    'providerModels': {name: {'id': 'synthetic-' + name + '-model'} for name in builtin},
                    'customAiProviders': [{'id':'local', 'name':'Synthetic local model',
                        'endpoint':'http://model.test/v1/chat/completions',
                        'model':'synthetic-model', 'apiFormat':'openai', 'apiKey':'synthetic-custom'}]})
        self.page.reload()
        self.install_background()
        self.mock_json('secrets/scan', {'findings':[]})
        calls = self.mock_json('analyze', {'analysis':'Synthetic answer', 'sanitized_log':'safe input', 'mapping_table':{}})
        for name in names + ['custom:local']:
            with self.subTest(provider=name):
                self.page.locator('input[value="ai"]').check()
                self.page.locator('#ai-provider').select_option(name)
                self.page.locator('#analyze-btn').click()
                expect(self.page.locator('#loading-overlay')).to_be_hidden(timeout=15000)
                expect(self.page.locator('#analysis-output')).to_contain_text('Synthetic answer')
                request = calls[-1]
                self.assertEqual('custom' if name.startswith('custom:') else name, request['mode'])
                self.assertEqual('synthetic-custom' if name.startswith('custom:') else 'synthetic-' + name, request['api_key'])
                self.assertEqual({mechanism: True for mechanism in MECHANISMS}, request['secret_protection'])
                if name.startswith('custom:'):
                    self.assertEqual('synthetic-model', request['custom_provider']['model'])
                self.assertEqual('vendor/alpha:free' if name == 'openrouter' else None, request.get('openrouter_model'))
                # Built-in providers send the model chosen in Settings, and only theirs.
                self.assertEqual('synthetic-' + name + '-model' if name in builtin else None, request.get('model'))
        self.page.locator('input[value="sanitize_only"]').check()
        expect(self.page.locator('#provider-controls')).to_be_hidden()
        expect(self.page.locator('#ti-toggle-container')).to_be_hidden()
        self.page.reload()
        expect(self.page.locator('input[value="sanitize_only"]')).to_be_checked()
        self.page.locator('input[value="ai"]').check()
        expect(self.page.locator('#ai-provider')).to_have_value('custom:local')
        self.page.evaluate('() => {browser.tabs.create=async args=>{window.opened=args.url}}')
        self.page.locator('#provider-settings').click()
        self.assertTrue(self.page.evaluate('window.opened').endswith('settings.html#ai'))
        self.page.locator('#settings-btn').click()
        self.assertTrue(self.page.evaluate('window.opened').endswith('settings.html'))

    def test_keyboard_layout_and_accessible_control_names(self):
        self.page.set_viewport_size({'width':720, 'height':600})
        # Logs, Statistics and Case notes are tabs: the keyboard selects them.
        header = self.page.locator('#analyst-data-toggle')
        expect(header).to_have_attribute('aria-selected', 'false')
        header.focus()
        self.page.keyboard.press('Space')
        expect(header).to_have_attribute('aria-selected', 'true')
        expect(self.page.locator('#analyst-data-textarea')).to_be_visible()
        self.page.locator('#logs-toggle').focus()
        self.page.keyboard.press('Enter')
        expect(header).to_have_attribute('aria-selected', 'false')
        expect(self.page.locator('#logs-textarea')).to_be_visible()
        for width in (720, 360):
            with self.subTest(width=width):
                if width == 360:
                    self.page.evaluate("document.documentElement.classList.add('standalone-popup')")
                self.page.set_viewport_size({'width':width, 'height':600})
                bounds = self.page.evaluate("""() => ({width:innerWidth, scroll:document.documentElement.scrollWidth,
                    dock:document.querySelector('.workflow-dock').getBoundingClientRect().toJSON(),
                    main:document.querySelector('#main-workflow').getBoundingClientRect().toJSON()})""")
                self.assertLessEqual(bounds['scroll'], bounds['width'])
                self.assertLessEqual(bounds['dock']['bottom'], 601)
                self.assertLessEqual(bounds['main']['bottom'], bounds['dock']['top'])
        for path in ('popup.html', 'settings.html'):
            self.page.goto(self.url + '/extension/' + path)
            unnamed = self.page.locator('input:not([type=hidden]),select,textarea').evaluate_all("""els=>els.filter(e=>!e.labels?.length&&!e.getAttribute('aria-label')&&!e.getAttribute('aria-labelledby')).map(e=>e.id)""")
            self.assertEqual([], unnamed, path)

    def test_result_tabs_copy_compare_edit_and_clear(self):
        self.clipboard()
        self.mock_json('secrets/scan', {'findings':[]})
        self.mock_json('analyze', {'analysis':'Synthetic analysis', 'sanitized_log':'protected log',
            'sanitized_analyst_data':'protected context', 'mapping_table':{'⟦CUSTOM#1⟧':'private-name'},
            'threat_intel_findings':[{'ioc':'8.8.8.8', 'type':'ip', 'verdict':'clean', 'sources':{}}]})
        self.page.locator('#analyze-btn').click()
        expect(self.page.locator('#loading-overlay')).to_be_hidden(timeout=15000)
        expect(self.page.locator('#tab-analysis')).to_have_attribute('aria-selected', 'true')
        expect(self.page.locator('#tab-analysis')).to_be_focused()
        feedback = self.mock_json('feedback', {'status':'saved'})
        self.page.locator('#feedback-details summary').click()
        self.page.locator('#correction-textarea').fill('Synthetic correction')
        self.page.locator('#submit-feedback-btn').click()
        expect(self.page.locator('#correction-textarea')).to_have_value('')
        self.assertEqual('Synthetic correction', feedback[0]['user_correction'])
        for tab, value in [('analysis','Synthetic analysis'), ('sanitized','protected log'), ('changes','private-name'), ('ti','8.8.8.8')]:
            self.page.locator('#tab-' + tab).click()
            self.page.locator('#copy-result-action').click()
            self.assertIn(value, self.page.evaluate('window.copied'))
        expect(self.page.locator('#tab-changes')).to_contain_text('(1)')
        expect(self.page.locator('#tab-ti')).to_contain_text('(1)')
        self.page.locator('#tab-analysis').focus()
        # Arrow keys walk the tabs in reading order: Analysis, Ask, Report, then
        # the details. Ask is focused without being opened.
        self.page.keyboard.press('ArrowRight')
        expect(self.page.locator('#tab-chat')).to_be_focused()
        expect(self.page.locator('#tab-chat')).to_have_attribute('aria-selected', 'false')
        self.page.keyboard.press('ArrowRight')
        self.page.keyboard.press('ArrowRight')
        expect(self.page.locator('#tab-sanitized')).to_be_focused()
        expect(self.page.locator('#tab-sanitized')).to_have_attribute('aria-selected', 'true')
        self.page.locator('#sanitized-textarea').fill('edited protected log')
        self.page.locator('#tab-analysis').click()
        self.page.locator('#tab-sanitized').click()
        expect(self.page.locator('#sanitized-textarea')).to_have_value('edited protected log')
        self.page.locator('#compare-source').click()
        expect(self.page.locator('#logs-textarea')).to_be_focused()
        self.page.reload()
        expect(self.page.locator('#tab-sanitized')).to_have_attribute('aria-selected', 'true')
        self.page.locator('#clear-btn').click()
        expect(self.page.locator('#results-workspace')).to_be_hidden()
        expect(self.page.locator('#logs-textarea')).to_have_value('')
        expect(self.page.locator('#analyze-btn')).to_be_disabled()

    def test_review_decision_labels_filter_and_cancel(self):
        token = '5770385F-C22A-43E0-BF4C-06F5698FFBD9'
        self.page.locator('#logs-textarea').fill('reference ' + token)
        self.page.locator('#analyze-btn').click()
        expect(self.page.locator('#secret-review')).to_be_visible(timeout=15000)
        expect(self.page.locator('#secret-review-filter')).to_be_focused()
        checkbox = self.page.locator('#secret-review-list input[data-secret-index]').first
        expect(checkbox).to_be_checked()
        expect(self.page.locator('#secret-review-decisions')).to_contain_text('1 kept')
        checkbox.uncheck()
        expect(self.page.locator('.secret-decision')).to_have_text('Hide')
        expect(self.page.locator('#secret-review-decisions')).to_have_text('0 kept · 1 to hide')
        self.page.locator('#secret-review-filter').fill('no matching candidate')
        expect(self.page.locator('#secret-review-decisions')).to_have_text('0 kept · 1 to hide')
        self.page.locator('#secret-review-filter').fill('')
        expect(checkbox).not_to_be_checked()
        self.page.locator('#secret-review-list summary').click()
        expect(self.page.locator('#secret-review-list details')).to_have_attribute('open', '')
        self.page.locator('#secret-review-cancel').click()
        expect(self.page.locator('#secret-review')).to_be_hidden()
        expect(self.page.locator('#main-actions')).to_be_visible()
        self.assertEqual([], self.page.request.get(self.url + '/test/sent').json())

    def test_settings_general_save_errors_and_independent_editor_drafts(self):
        self.settings()
        for section in ('ai', 'protection', 'prompts', 'backup', 'connections'):
            self.page.locator('.settings-nav a[href="#' + section + '"]').click()
            expect(self.page.locator('.settings-nav a[href="#' + section + '"]')).to_have_attribute('aria-current','location')
        self.page.locator('#groq-card > summary').click()
        self.page.locator('#groq-api-key').fill('synthetic-edited')
        expect(self.page.locator('#settings-save-state')).to_contain_text('Unsaved settings')
        self.page.locator('#add-custom-model-trigger').click()
        self.page.locator('#cm-name').fill('Unfinished model')
        self.page.locator('#save-settings').click()
        expect(self.page.locator('#settings-save-state')).to_contain_text('Unsaved editor changes')
        self.assertEqual('synthetic-edited', self.stored('groqApiKey'))
        self.page.locator('#cancel-custom-model').click()
        expect(self.page.locator('#settings-save-state')).to_have_text('Settings saved')
        self.page.locator('#groq-api-key').fill('synthetic-retry')
        self.page.evaluate('() => {window.realSet=browser.storage.local.set;browser.storage.local.set=async()=>{throw Error("synthetic storage failure")}}')
        self.page.locator('#save-settings').click()
        expect(self.page.locator('#save-settings-error')).to_contain_text('Could not save')
        expect(self.page.locator('#groq-api-key')).to_have_value('synthetic-retry')
        self.page.evaluate('() => {browser.storage.local.set=window.realSet}')
        self.page.locator('#save-settings').click()
        expect(self.page.locator('#settings-save-state')).to_have_text('Settings saved')
        expect(self.page.locator('#save-settings-error')).to_have_count(0)
        self.page.reload()
        expect(self.page.locator('#groq-api-key')).to_have_value('synthetic-retry')

    def test_custom_models_and_prompts_edit_save_cancel_delete(self):
        self.settings()
        self.page.locator('#add-custom-model-trigger').click()
        self.page.locator('#save-custom-model').click()
        expect(self.page.locator('#cm-name')).to_be_focused()
        expect(self.page.locator('#cm-name')).to_have_attribute('aria-invalid','true')
        self.page.locator('#cm-name').fill('Synthetic model')
        self.page.locator('#cm-endpoint').fill('https://model.test/v1/chat/completions')
        self.page.locator('#cm-model').fill('fixture-model')
        calls = self.mock_json('analyze', {'analysis':'OK'})
        self.page.locator('#test-custom-model').click()
        expect(self.page.locator('#custom-model-test-result')).to_contain_text('OK')
        self.assertEqual('fixture-model', calls[0]['custom_provider']['model'])
        self.page.locator('#save-custom-model').click()
        models = self.stored('customAiProviders')
        self.assertEqual('Synthetic model', models[0]['name'])
        row = self.page.locator('#custom-model-list .prompt-item').first
        row.get_by_role('button', name='Edit Synthetic model').click()
        self.page.locator('#cm-name').fill('Cancelled title')
        self.page.locator('#cancel-custom-model').click()
        expect(row).to_contain_text('Synthetic model')
        self.page.locator('#groq-card > summary').click()
        self.page.locator('#groq-api-key').fill('unsaved-key')
        row.get_by_role('button', name='Edit Synthetic model').click()
        self.page.locator('#cm-name').fill('Renamed model')
        self.page.locator('#save-custom-model').click()
        self.assertEqual(models[0]['id'], self.stored('customAiProviders')[0]['id'])
        expect(self.page.locator('#settings-save-state')).to_contain_text('Unsaved settings')
        self.page.locator('#save-settings').click()
        self.page.locator('#add-prompt-trigger').click()
        self.page.locator('#new-prompt-title').fill('Synthetic prompt')
        self.page.locator('#new-prompt-content').fill('Analyze synthetic events.')
        self.page.locator('#save-new-prompt').click()
        prompt_id = self.stored('customPrompts')[0]['id']
        self.page.locator('#default-prompt-select').select_option(prompt_id)
        self.assertEqual(prompt_id, self.stored('defaultPromptId'))
        self.page.locator('#prompt-list').get_by_role('button', name='Edit Synthetic prompt').click()
        self.page.locator('#edit-title-0').fill('Edited prompt')
        self.page.locator('#save-edit-0').click()
        self.assertEqual(prompt_id, self.stored('customPrompts')[0]['id'])
        self.page.on('dialog', lambda dialog: dialog.accept())
        self.page.locator('#prompt-list').get_by_role('button', name='Remove Edited prompt').click()
        self.page.locator('#custom-model-list').get_by_role('button', name='Remove Renamed model').click()
        self.assertEqual([], self.stored('customPrompts'))
        self.assertEqual([], self.stored('customAiProviders'))

    def test_connector_presets_validation_test_and_persistence(self):
        self.settings()
        self.page.locator('#add-connector-trigger').click()
        self.page.locator('#save-connector').click()
        expect(self.page.locator('#conn-name')).to_be_focused()
        self.page.locator('#conn-name').fill('Synthetic SIEM')
        self.page.locator('#conn-siem-address').fill('https://siem.test')
        for preset in ('opensearch','splunk','qradar'):
            self.page.locator('#conn-preset').select_option(preset)
            expect(self.page.locator('#conn-name')).to_have_value('Synthetic SIEM')
            expect(self.page.locator('#conn-siem-address')).to_have_value('https://siem.test')
        self.page.locator('#conn-auth-type').select_option('header')
        self.page.locator('#conn-header-value').fill('synthetic-token')
        more = self.page.locator('#conn-more > summary')
        more.focus()
        self.page.keyboard.press('Enter')
        expect(self.page.locator('#conn-execute-via')).to_be_visible()
        self.page.locator('#conn-api-headers').fill('{broken')
        self.page.locator('#save-connector').click()
        expect(self.page.locator('#conn-api-headers')).to_have_attribute('aria-invalid','true')
        self.page.locator('#conn-api-headers').fill('{"Version":"12.0"}')
        calls = self.mock_json('test-siem', {'status':'connected','message':'Synthetic connected'})
        self.page.locator('#test-connector').click()
        expect(self.page.locator('#connector-test-result')).to_contain_text('Synthetic connected')
        self.assertEqual('synthetic-token', calls[0]['auth_header_value'])
        self.page.locator('#save-connector').click()
        saved = next(p for p in self.stored('connectorProfiles') if p['name'] == 'Synthetic SIEM')
        self.assertEqual('search_job', saved['api']['fetchMode'])
        row = self.page.locator('#connector-list .prompt-item').filter(has_text='Synthetic SIEM')
        row.get_by_role('button', name='Edit Synthetic SIEM').click()
        self.page.locator('#conn-name').fill('Discard this name')
        self.page.locator('#cancel-connector').click()
        expect(row).to_be_visible()
        self.page.on('dialog', lambda dialog: dialog.accept())
        row.get_by_role('button', name='Remove Synthetic SIEM').click()
        self.assertFalse(any(p['id'] == saved['id'] for p in self.stored('connectorProfiles')))

    def test_protection_lists_regex_and_general_toggles_save_reload(self):
        self.settings()
        self.page.locator('#enable-pattern-sanitization').check()
        entries = [('new-cidr','10.20.0.0/16','add-cidr-btn','custom-cidrs-list'),
            ('new-domain','synthetic.internal','add-domain-btn','custom-domains-list'),
            ('new-json-key','customer','add-json-key-btn','json-keys-list'),
            ('new-statistics-field','host.name','add-statistics-field-btn','statistics-fields-list')]
        for field, value, button, container in entries:
            self.page.locator('#' + field).fill(value)
            self.page.locator('#' + button).click()
            row = self.page.locator('#' + container + ' .list-item').filter(has_text=value)
            row.locator('input[type=checkbox]').uncheck()
            row.locator('input[type=checkbox]').check()
        self.page.locator('#new-keyword').fill('company')
        self.page.locator('#new-replacement').fill('ORG')
        self.page.locator('#add-keyword-btn').click()
        # Regex and field rules share one list and one form.
        self.page.locator('#regex-name').fill('Fixture rule')
        self.page.locator('#rule-target').fill('synthetic-value')
        self.page.locator('#regex-action').select_option('hide_secret')
        self.page.locator('#add-rule').click()
        self.page.locator('#rule-kind').select_option('field')
        expect(self.page.locator('#rule-name-control')).to_be_hidden()
        expect(self.page.locator('#regex-action')).to_have_value('exclude')
        self.page.locator('#rule-target').fill('fixture.ref')
        self.page.locator('.rule-advanced summary').click()
        self.page.locator('#heuristic-field-mode').select_option('exact_path')
        self.page.locator('#add-rule').click()
        rules = self.page.locator('#custom-rules-list .rule-item')
        expect(rules).to_have_count(2)
        expect(rules.nth(0)).to_contain_text('Hide · credential')
        expect(rules.nth(1)).to_contain_text('Keep')
        expect(rules.nth(1)).to_contain_text('exact path')
        # Editing a field rule keeps it a field rule.
        rules.nth(1).locator('.edit-rule').click()
        expect(self.page.locator('#rule-kind')).to_be_disabled()
        expect(self.page.locator('#rule-target')).to_have_value('fixture.ref')
        self.page.locator('#cancel-rule-edit').click()
        expect(self.page.locator('#rule-kind')).to_be_enabled()
        self.page.locator('#heuristic-min-length').fill('12')
        self.page.locator('#heuristic-entropy').fill('3.8')
        for field in ('enable-json-key-sanitization', 'enable-statistics-field-sanitization', 'enable-custom-keywords'):
            self.page.locator('#' + field).uncheck()
        self.page.locator('#enable-threat-intel').check()
        self.page.locator('#extraction-mode-raw').check()
        self.page.locator('#save-settings').click()
        self.assertEqual(12, self.stored('heuristicSettings')['min_length'])
        self.assertEqual(3.8, self.stored('heuristicSettings')['entropy_threshold'])
        self.assertEqual('hide_secret', self.stored('customRegexRules')[0]['action'])
        self.assertEqual('raw_request', self.stored('extractionOutputMode'))
        self.page.reload()
        expect(self.page.locator('#enable-threat-intel')).to_be_checked()
        for field in ('enable-json-key-sanitization', 'enable-statistics-field-sanitization', 'enable-custom-keywords'):
            expect(self.page.locator('#' + field)).not_to_be_checked()
        self.assertEqual([{'path': 'fixture.ref', 'enabled': True, 'scope': 'heuristics', 'match_mode': 'exact_path'}],
                         self.stored('heuristicFieldExclusions'))
        self.page.locator('.rule-test summary').click()
        self.page.locator('#regex-test-text').fill('synthetic-value')
        self.page.locator('#test-regex-rule').click()
        expect(self.page.locator('#regex-test-result')).to_contain_text('SECRET', timeout=15000)
        self.page.locator('#test-sanitization').click()
        expect(self.page.locator('#sanitization-test-result')).to_contain_text('Test Successful', timeout=15000)

    def test_settings_backup_import_reset_and_mocked_key_tests(self):
        self.settings()
        calls = []
        def provider_reply(route):
            calls.append(route.request.url)
            route.fulfill(json={}, headers={'Access-Control-Allow-Origin':'*'})
        self.context.route(re.compile(r'^https://'), provider_reply)
        for provider in ('groq','deepseek','together','openrouter','gemini','claude'):
            self.page.locator('#' + provider + '-card > summary').click()
            self.page.locator('#' + provider + '-api-key').fill('synthetic-key')
        # Keys are checked through each provider's model list (via the backend);
        # only OpenRouter's key endpoint is called from the browser. No prompt is sent.
        listed = self.mock_json('providers/*/models', {'models': [{'id': 'synthetic-model', 'name': 'Synthetic model'}]})
        self.page.locator('#test-apis-btn').click()
        expect(self.page.locator('#api-test-results')).to_contain_text('Claude',timeout=15000)
        self.assertEqual(['https://openrouter.ai/api/v1/key'], calls)
        self.assertEqual(5, len(listed))
        self.assertTrue(all(body == {'api_key': 'synthetic-key'} for body in listed), listed)
        expect(self.page.locator('#api-test-results')).to_contain_text('choose a model')
        self.mock_json('threat-intel/lookup', {'verdict':'clean', 'sources':{'virustotal':{'status':'ok'}}})
        self.page.locator('#test-threat-intel-btn').click()
        expect(self.page.locator('#threat-intel-test-result')).to_contain_text('Lookup completed')
        self.page.locator('#save-settings').click()
        for include in (False, True):
            self.page.locator('#export-include-keys').set_checked(include)
            with self.page.expect_download() as download:
                self.page.locator('#export-settings-btn').click()
            payload = json.loads(download.value.path().read_text())
            self.assertEqual(include, 'groqApiKey' in payload)
        self.page.locator('#import-settings-file').set_input_files({'name':'broken.json','mimeType':'application/json','buffer':b'{broken'})
        expect(self.page.locator('#import-settings-btn-error')).to_contain_text('not a valid JSON')
        self.page.locator('#import-settings-file').set_input_files({'name':'fixture.json','mimeType':'application/json','buffer':b'{"groqApiKey":"imported-synthetic"}'})
        expect(self.page.locator('#groq-api-key')).to_have_value('imported-synthetic')
        expect(self.page.locator('#import-settings-btn-error')).to_have_count(0)
        self.page.on('dialog', lambda dialog: dialog.accept())
        self.page.locator('#reset-all').click()
        expect(self.page.locator('#groq-api-key')).to_have_value('')
        expect(self.page.locator('#settings-save-state')).to_have_text('Settings saved')
        self.assertIsNone(self.stored('groqApiKey'))

    def test_importing_a_connection_with_a_page_script_asks_first(self):
        scripted = json.dumps({'groqApiKey': 'imported-synthetic', 'connectorProfiles': [
            {'id': 'shared', 'name': 'Shared preset', 'schemaVersion': 2, 'dom': {'discover': {'strategy': 'custom_script',
                                                                           'customScript': 'return {logs: []}'}}}]}).encode()
        self.settings()
        before = self.stored('groqApiKey')
        messages = []
        self.page.once('dialog', lambda dialog: messages.append(dialog.message) or dialog.dismiss())
        self.page.locator('#import-settings-file').set_input_files({'name': 'shared.json', 'mimeType': 'application/json', 'buffer': scripted})
        expect(self.page.locator('#success-msg')).to_contain_text('Import cancelled')
        self.assertIn('"Shared preset"', messages[0])
        self.assertIn('page script', messages[0])
        self.assertEqual(before, self.stored('groqApiKey'))
        self.page.once('dialog', lambda dialog: dialog.accept())
        self.page.locator('#import-settings-file').set_input_files({'name': 'shared-again.json', 'mimeType': 'application/json', 'buffer': scripted})
        expect(self.page.locator('#groq-api-key')).to_have_value('imported-synthetic')
        self.assertEqual('Shared preset', self.stored('connectorProfiles')[0]['name'])

    def test_tools_defang_refang_ioc_and_loading_keyboard_cancel(self):
        self.clipboard()
        self.page.locator('#stage-tab-tools').click()
        self.page.locator('#defang-toggle').click()
        self.page.locator('#defang-input').fill('https://example.test/1')
        self.page.locator('#defang-btn').click()
        expect(self.page.locator('#defang-output')).to_have_value('hxxps://example[.]test/1')
        self.page.locator('#copy-defang-btn').click()
        self.assertEqual('hxxps://example[.]test/1',self.page.evaluate('window.copied'))
        self.page.locator('#defang-input').fill('hxxps://example[.]test/1')
        self.page.locator('#refang-btn').click()
        expect(self.page.locator('#defang-output')).to_have_value('https://example.test/1')
        self.page.locator('#ioc-lookup-toggle').click()
        self.mock_json('threat-intel/lookup', {'ioc':'8.8.8.8','type':'ip','verdict':'clean','sources':{}})
        self.page.locator('#ioc-lookup-input').fill('8.8.8.8')
        self.page.locator('#ioc-lookup-btn').click()
        expect(self.page.locator('#ioc-lookup-result')).to_contain_text('8.8.8.8')
        self.mock_json('secrets/scan', {'findings':[]})
        # Hold an actual in-flight request, then cancel using the modal keyboard.
        pending = []
        self.context.route('**/analyze', lambda route: pending.append(route))
        with self.page.expect_request('**/analyze'):
            self.page.locator('#analyze-btn').click()
        expect(self.page.locator('#loading-dismiss-btn')).to_be_focused()
        # While work runs, Tab cycles between Cancel and the case switcher.
        for target in ('#case-prev', '#case-next', '#loading-dismiss-btn'):
            self.page.keyboard.press('Tab')
            expect(self.page.locator(target)).to_be_focused()
        self.page.keyboard.press('Escape')
        expect(self.page.locator('#loading-overlay')).to_be_hidden()
        expect(self.page.locator('#status-text')).to_contain_text('cancelled')
        for route in pending:
            route.abort()
        self.assertEqual([], self.page.request.get(self.url + '/test/sent').json())

    def test_tools_statistics_manual_fetch_query_and_clear_scopes(self):
        self.clipboard()
        inspector = self.page.evaluate('VeiluxConnectors.opensearch.inspector')
        self.store({'connectorProfiles':[{'id':'fixture','name':'Synthetic SIEM','schemaVersion':2,
            'siemHost':'siem.test','siemBaseUrl':'https://siem.test','websiteUrl':'https://siem.test',
            'statistics':{'mode':'opensearch'},'dom':{'discover':{'strategy':'table_scrape',**inspector}},
            'auth':{'type':'header','headerName':'Authorization','headerValue':'synthetic-token'},
            'api':{'enabled':True,'fetchMode':'search_job','linkRegex':'/doc/(?<index>[^/]+)/(?<doc_id>[^/?#]+)',
                'job':{'createMethod':'POST','jobIdPath':'id','statusField':'status','completeValues':'DONE','errorValues':'FAILED'}}}]})
        stats = {'success':True,'indexPattern':'fixture-*','sampled':2,'total':2,
            'fields':[{'field':'host.name','count':2,'percentage':100,
                'topValues':[{'value':'host-a','count':2,'percentage':100}]}],
            'summary':{'query':'*'},'request':{'query':{'match_all':{}}}}
        self.page.evaluate("""stats => {
            window.bridgeCalls=[];
            browser.tabs.query=async()=>[{id:9,url:'https://siem.test/search',title:'Synthetic search',active:true}];
            browser.tabs.sendMessage=async(id,message)=>{bridgeCalls.push(message);return structuredClone(stats)};
        }""", stats)
        self.page.locator('#extract-stats-btn').click()
        expect(self.page.locator('#statistics-list')).to_contain_text('host-a')
        expect(self.page.locator('#source-summary')).to_contain_text('1 statistics queries')
        self.page.locator('#copy-statistics-btn').click()
        self.assertIn('host-a',self.page.evaluate('window.copied'))
        self.page.locator('#stage-tab-tools').click()
        expect(self.page.locator('#stage-tools')).not_to_contain_text('statistics lab')
        expect(self.page.locator('#stage-tools')).not_to_contain_text('Fetch by Link')
        self.page.evaluate('(stat)=>appendFieldStatistics(stat)',stats)
        expect(self.page.locator('#statistics-list article')).to_have_count(2)
        # Each query opens and closes. A new query opens and the older one
        # closes, so both headers are within reach.
        entries = self.page.locator('#statistics-list details')
        self.assertEqual([False, True], entries.evaluate_all('nodes => nodes.map(node => node.open)'))
        expect(entries.nth(0).locator('.field-stat-name')).to_be_hidden()
        expect(entries.nth(1).locator('.field-stat-name')).to_be_visible()
        expect(entries.nth(0).locator('summary')).to_contain_text('2 records · 1 field')
        toggle = self.page.locator('#statistics-toggle-all')
        expect(toggle).to_have_text('Collapse all')
        toggle.click()
        self.assertEqual([False, False], entries.evaluate_all('nodes => nodes.map(node => node.open)'))
        expect(toggle).to_have_text('Expand all')
        toggle.click()
        self.assertEqual([True, True], entries.evaluate_all('nodes => nodes.map(node => node.open)'))
        entries.nth(1).locator('summary').click()
        self.assertEqual([True, False], entries.evaluate_all('nodes => nodes.map(node => node.open)'))
        self.page.locator('[data-remove-stat-field="0:0"]').click()
        # Removing a field keeps what was open.
        self.assertEqual([True, False], entries.evaluate_all('nodes => nodes.map(node => node.open)'))
        expect(self.page.locator('#statistics-list article').first.locator('.field-stat')).to_have_count(0)
        self.page.locator('[data-remove-stat="0"]').click()
        expect(self.page.locator('#statistics-list article')).to_have_count(1)
        expect(toggle).to_be_hidden()
        expect(self.page.locator('#source-summary')).to_contain_text('1 statistics queries')
        self.page.locator('#clear-statistics-btn').click()
        expect(self.page.locator('#statistics-section')).to_be_hidden()
        self.assertTrue(self.stored('capturedLogs'))
        self.page.evaluate('(stat)=>appendFieldStatistics(stat)',stats)
        expect(self.page.locator('#statistics-list article')).to_have_count(1)
        self.page.locator('#clear-btn').click()
        expect(self.page.locator('#statistics-list article')).to_have_count(0)
        expect(self.page.locator('#source-summary')).to_have_text('Paste logs or extract from a source page.')
        self.assertEqual(['veiluxExtractDiscoverFieldStats'],
                         self.page.evaluate('window.bridgeCalls.map(call=>call.action)'))

    def test_custom_model_defaults_use_same_configuration_in_test_and_analysis(self):
        self.settings()
        self.page.locator('#add-custom-model-trigger').click()
        self.page.locator('#cm-preset').select_option('anthropic')
        expect(self.page.locator('#cm-connection-details')).not_to_have_attribute('open','')
        expect(self.page.locator('#cm-advanced')).not_to_have_attribute('open','')
        expect(self.page.locator('#cm-model')).to_have_value('')
        self.page.locator('#cm-name').fill('My Claude')
        self.page.locator('#cm-model').fill('claude-sonnet-5-5')
        self.page.locator('#cm-key').fill('synthetic-key')
        self.page.locator('#cm-connection-details summary').click()
        self.page.locator('#cm-endpoint').fill('https://custom-model.test/messages')
        self.page.get_by_role('button',name='Test connection',exact=True).click()
        expect(self.page.locator('#custom-model-test-result')).to_contain_text('Custom model connected.',timeout=15000)
        self.page.locator('#save-custom-model').click()
        profile = self.stored('customAiProviders')[0]
        self.assertIsNone(profile['temperature'])
        self.page.reload()
        self.page.locator('#custom-model-list').get_by_role('button',name='Edit My Claude').click()
        expect(self.page.locator('#cm-preset')).to_have_value('anthropic')
        expect(self.page.locator('#cm-temperature')).to_have_value('')
        self.page.locator('#cancel-custom-model').click()
        self.page.goto(self.url + '/extension/popup.html')
        expect(self.page.locator('#logs-textarea')).to_have_value('password=synthetic-initial')
        self.install_background()
        self.page.locator('#ai-provider').select_option('custom:' + profile['id'])
        self.page.locator('#analyze-btn').click()
        expect(self.page.locator('#analysis-output')).to_contain_text('Custom model connected.',timeout=15000)
        bodies=[json.loads(call['body']) for call in self.page.request.get(self.url + '/test/sent').json()]
        self.assertEqual(2,len(bodies))
        for body in bodies:
            self.assertNotIn('temperature',body)
            self.assertEqual(4000,body['max_tokens'])
            self.assertEqual('claude-sonnet-5-5',body['model'])
        self.assertNotIn('synthetic-initial',json.dumps(bodies[-1]))
        self.assertIn('SECRET#',json.dumps(bodies[-1]))

    def test_legacy_custom_model_recovers_in_test_and_analysis(self):
        self.store({'customAiProviders':[{'id':'legacy','name':'Legacy Claude','apiFormat':'anthropic',
            'endpoint':'https://custom-model.test/messages','model':'claude-sonnet-5-5',
            'temperature':0.2,'maxTokens':2468,'apiKey':'synthetic-key'}]})
        self.settings()
        self.page.locator('#custom-model-list').get_by_role('button',name='Edit Legacy Claude').click()
        self.page.locator('#test-custom-model').click()
        expect(self.page.locator('#custom-model-test-result')).to_contain_text('Custom model connected.',timeout=15000)
        self.page.locator('#cancel-custom-model').click()
        self.page.goto(self.url + '/extension/popup.html')
        expect(self.page.locator('#logs-textarea')).to_have_value('password=synthetic-initial')
        self.install_background()
        self.page.locator('#ai-provider').select_option('custom:legacy')
        self.page.locator('#analyze-btn').click()
        expect(self.page.locator('#analysis-output')).to_contain_text('Custom model connected.',timeout=15000)
        bodies=[json.loads(call['body']) for call in self.page.request.get(self.url + '/test/sent').json()]
        self.assertEqual(4,len(bodies))
        self.assertEqual([0.2,None,0.2,None],[body.get('temperature') for body in bodies])
        self.assertTrue(all(body['max_tokens']==2468 for body in bodies))
        self.assertEqual(bodies[2]['messages'],bodies[3]['messages'])
        self.assertNotIn('synthetic-initial',json.dumps(bodies))
        self.assertEqual(0.2,self.stored('customAiProviders')[0]['temperature'])

    def test_custom_model_advanced_validation_and_explicit_zero(self):
        self.settings()
        self.page.locator('#add-custom-model-trigger').click()
        self.page.locator('#cm-name').fill('Fixture')
        self.page.locator('#cm-model').fill('fixture-model')
        self.page.locator('#cm-endpoint').fill('relative/path')
        self.page.locator('#save-custom-model').click()
        expect(self.page.locator('#cm-endpoint')).to_have_attribute('aria-invalid','true')
        self.page.locator('#cm-endpoint').fill('https://custom-model.test/messages')
        self.page.locator('#cm-advanced summary').click()
        for field,value,message in [('cm-temperature','-1','0 to 2'),('cm-max-tokens','0','positive whole'),
                                    ('cm-extra-headers','[]','JSON object')]:
            self.page.locator('#'+field).fill(value)
            self.page.locator('#cm-advanced summary').click()
            self.page.locator('#save-custom-model').click()
            expect(self.page.locator('#cm-advanced')).to_have_attribute('open','')
            expect(self.page.locator('#'+field+'-error')).to_contain_text(message)
            self.page.locator('#'+field).fill('')
        self.page.locator('#cm-temperature').fill('0')
        self.page.locator('#cm-max-tokens').fill('6144')
        self.page.locator('#cm-extra-headers').fill('{"X-Team":"SOC"}')
        calls=self.mock_json('analyze',{'analysis':'OK'})
        self.page.locator('#test-custom-model').click()
        expect(self.page.locator('#custom-model-test-result')).to_contain_text('OK')
        self.assertEqual(0,calls[0]['custom_provider']['temperature'])
        self.assertEqual(6144,calls[0]['custom_provider']['max_tokens'])
        self.assertEqual({'X-Team':'SOC'},calls[0]['custom_provider']['extra_headers'])
        self.page.locator('#save-custom-model').click()
        self.assertEqual(0,self.stored('customAiProviders')[0]['temperature'])
