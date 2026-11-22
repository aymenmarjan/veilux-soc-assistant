"""VEILUX 1.0.1 popup and Settings regressions: log separators and the
"Insert log separator" button, and the built-in providers' model picker.
Synthetic data; the real popup and Settings pages with the local test backend."""
import unittest
from playwright.sync_api import expect
import test_extension_ui as harness

SEPARATOR = '---LOG SEPARATOR---'


class V101UITests(unittest.TestCase):
    setUpClass = classmethod(harness.ExtensionUITests.setUpClass.__func__)
    tearDownClass = classmethod(harness.ExtensionUITests.tearDownClass.__func__)
    setUp = harness.ExtensionUITests.setUp
    tearDown = harness.ExtensionUITests.tearDown
    install_background = harness.ExtensionUITests.install_background
    sanitize = harness.ExtensionUITests.sanitize

    def captured(self):
        return self.page.evaluate("() => caseStorage.get('capturedLogs')").get('capturedLogs')

    def analyze_requests(self):
        bodies = []
        def record(route):
            bodies.append(route.request.post_data_json)
            route.continue_(url=route.request.url.replace('http://localhost:8000', self.url))
        self.context.route('**/analyze', record)
        return bodies

    # ---- Log separators ----

    def test_pasted_logs_with_separators_are_counted_and_sent_as_separate_logs(self):
        page = self.page
        page.locator('#logs-textarea').fill('first log\n\n' + SEPARATOR + '\n\nsecond log\n' + SEPARATOR + '\nthird log')
        expect(page.locator('#log-count')).to_have_text('3 logs')
        expect(page.locator('#case-count-logs')).to_have_text('3')
        page.wait_for_function("() => caseStorage.get('capturedLogs').then(v => (v.capturedLogs || []).length === 3)")
        self.assertEqual(['first log', 'second log', 'third log'], self.captured())
        bodies = self.analyze_requests()
        page.locator('#stage-tab-options').click()
        self.sanitize()
        self.assertEqual(['first log', 'second log', 'third log'], bodies[-1]['logs'])

    def test_a_single_log_without_separator_is_kept_exactly(self):
        page = self.page
        text = '  {"event": "one"}\n  second line of the same log  '
        page.locator('#logs-textarea').fill(text)
        expect(page.locator('#log-count')).to_have_text('1 log')
        page.wait_for_function("(t) => caseStorage.get('capturedLogs').then(v => (v.capturedLogs || [])[0] === t)", arg=text)
        page.locator('#logs-textarea').fill('')
        expect(page.locator('#log-count')).to_have_text('0 logs')

    def test_insert_log_separator_button(self):
        page = self.page
        logs = page.locator('#logs-textarea')
        logs.fill('first log')
        expect(page.locator('#log-count')).to_have_text('1 log')
        page.locator('#insert-separator-btn').click()
        expect(logs).to_have_value('first log\n\n' + SEPARATOR + '\n\n')
        self.assertTrue(page.evaluate("() => document.activeElement.id === 'logs-textarea'"))
        page.keyboard.type('second log')
        expect(page.locator('#log-count')).to_have_text('2 logs')
        expect(logs).to_have_value('first log\n\n' + SEPARATOR + '\n\nsecond log')
        # At the cursor, between two lines that are already there.
        logs.evaluate("(el) => { el.focus(); el.setSelectionRange(9, 9); }")
        page.locator('#insert-separator-btn').click()
        self.assertEqual(2, logs.input_value().count(SEPARATOR))
        expect(page.locator('#log-count')).to_have_text('2 logs')  # an empty part between two separators is not a log

    def test_extracted_logs_still_display_and_reload_with_separators(self):
        page = self.page
        page.evaluate("() => caseStorage.set({capturedLogs: ['{\"a\":1}', '{\"b\":2}']})")
        page.reload()
        expect(page.locator('#logs-textarea')).to_have_value('{"a":1}\n\n' + SEPARATOR + '\n\n{"b":2}')
        expect(page.locator('#log-count')).to_have_text('2 logs')
        self.assertEqual(['{"a":1}', '{"b":2}'], self.captured())

    # ---- Model choice ----

    def test_analysis_without_a_chosen_model_stops_before_sending(self):
        page = self.page
        page.evaluate("() => browser.storage.local.set({providerModels: {}})")
        page.reload()
        self.install_background()
        bodies = self.analyze_requests()
        page.locator('#logs-textarea').fill('{"event":"synthetic"}')
        page.locator('#stage-tab-options').click()
        page.locator('input[value="ai"]').check()
        expect(page.locator('#provider-status')).to_contain_text('No model chosen yet')
        page.locator('#analyze-btn').click()
        expect(page.locator('#status-text')).to_contain_text('Choose a Groq model first', timeout=10000)
        self.assertEqual([], bodies)

    def test_the_chosen_model_is_sent_with_the_analysis(self):
        page = self.page
        page.evaluate("() => browser.storage.local.set({providerModels: {groq: {id: 'synthetic-chat-model', name: 'Synthetic'}}})")
        page.reload()
        self.install_background()
        bodies = self.analyze_requests()
        page.locator('#logs-textarea').fill('{"event":"synthetic"}')
        page.locator('#stage-tab-options').click()
        page.locator('summary', has_text='Privacy methods').click()
        page.locator('#enable-ti').uncheck()
        page.locator('input[value="ai"]').check()
        expect(page.locator('#provider-status')).to_contain_text('Model: synthetic-chat-model')
        page.locator('#analyze-btn').click()
        expect(page.locator('#status-text')).to_contain_text('Done!', timeout=20000)
        self.assertEqual('synthetic-chat-model', bodies[-1]['model'])
        self.assertEqual('groq', bodies[-1]['mode'])

    def test_settings_model_picker_lists_saves_and_never_sends_logs(self):
        page = self.page
        page.goto(self.url + '/extension/settings.html')
        expect(page.locator('#settings-save-state')).to_have_text('Settings saved')
        listed = []
        def models(route):
            listed.append((route.request.url, route.request.post_data_json))
            route.fulfill(json={'models': [{'id': 'synthetic-a', 'name': 'Synthetic A', 'context_length': 131072},
                                           {'id': 'synthetic-b', 'name': 'synthetic-b'}]})
        self.context.route('**/providers/*/models', models)
        page.locator('#groq-card > summary').click()
        page.locator('#groq-api-key').fill('')
        page.locator('#groq-model-load').click()
        expect(page.locator('#groq-model-status')).to_contain_text('Enter the Groq API key first')
        self.assertEqual([], listed)
        page.locator('#groq-api-key').fill('synthetic-key')
        page.locator('#groq-model-load').click()
        expect(page.locator('#groq-model-status')).to_contain_text('2 models available')
        self.assertEqual([{'api_key': 'synthetic-key'}], [body for _, body in listed])
        self.assertTrue(listed[0][0].endswith('/providers/groq/models'))
        page.locator('#groq-model-list').select_option('synthetic-b')
        page.locator('#groq-model-use').click()
        expect(page.locator('#groq-model-current')).to_contain_text('synthetic-b')
        self.assertEqual({'id': 'synthetic-b', 'name': 'synthetic-b'},
                         page.evaluate("() => browser.storage.local.get('providerModels')")['providerModels']['groq'])
        # A typed model ID is checked, then saved as typed.
        page.locator('#gemini-card > summary').click()
        page.locator('#gemini-model-picker summary', has_text='Enter a model ID').click()
        page.locator('#gemini-model-manual').fill('bad id with spaces')
        page.locator('#gemini-model-manual-use').click()
        expect(page.locator('#gemini-model-status')).to_contain_text('exactly as Gemini lists it')
        page.locator('#gemini-model-manual').fill('gemini-synthetic-pro')
        page.locator('#gemini-model-manual-use').click()
        expect(page.locator('#gemini-model-current')).to_contain_text('gemini-synthetic-pro')
        saved = page.evaluate("() => browser.storage.local.get('providerModels')")['providerModels']
        self.assertEqual({'groq', 'gemini'}, set(saved))
        # The current model missing from a later list is pointed out, not replaced.
        self.context.unroute('**/providers/*/models')
        self.context.route('**/providers/*/models', lambda route: route.fulfill(json={'models': [{'id': 'synthetic-c'}]}))
        page.locator('#groq-model-load').click()
        expect(page.locator('#groq-model-status')).to_contain_text('synthetic-b is not in the list any more')
        self.assertEqual('synthetic-b', page.evaluate("() => browser.storage.local.get('providerModels')")['providerModels']['groq']['id'])
        self.assertEqual([], self.errors)
