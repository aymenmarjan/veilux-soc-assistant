"""VEILUX 1.0.2 Settings and popup: provider cards, Advanced generation
settings and what the popup sends. Synthetic data; the real pages with the
local test backend, and model lists from a mocked route."""
import unittest
from playwright.sync_api import expect
import test_extension_ui as harness

DEEPSEEK_MODELS = [
    {'id': 'synthetic-reasoner', 'name': 'Synthetic Reasoner', 'max_output_tokens': 393216,
     'efforts': ['low', 'high', 'max'], 'default_effort': 'high', 'thinking_switch': True},
    {'id': 'synthetic-small', 'name': 'Synthetic Small', 'max_output_tokens': 8192,
     'efforts': [], 'default_effort': None, 'thinking_switch': False},
]


class V102UITests(unittest.TestCase):
    setUpClass = classmethod(harness.ExtensionUITests.setUpClass.__func__)
    tearDownClass = classmethod(harness.ExtensionUITests.tearDownClass.__func__)
    setUp = harness.ExtensionUITests.setUp
    tearDown = harness.ExtensionUITests.tearDown
    install_background = harness.ExtensionUITests.install_background

    def stored(self, key):
        return self.page.evaluate('(key) => browser.storage.local.get(key)', key).get(key)

    def settings(self):
        self.page.goto(self.url + '/extension/settings.html')
        expect(self.page.locator('#settings-save-state')).to_have_text('Settings saved')

    def list_models(self, models):
        listed = []
        def reply(route):
            listed.append(route.request.post_data_json)
            route.fulfill(json={'models': models})
        self.context.route('**/providers/*/models', reply)
        return listed

    def choose(self, provider, model_id):
        page = self.page
        page.locator('#' + provider + '-card > summary').click()
        page.locator('#' + provider + '-api-key').fill('synthetic-key')
        page.locator('#' + provider + '-model-load').click()
        expect(page.locator('#' + provider + '-model-status')).to_contain_text('available')
        page.locator('#' + provider + '-model-list').select_option(model_id)
        page.locator('#' + provider + '-model-use').click()
        expect(page.locator('#' + provider + '-model-current')).to_contain_text(model_id)

    def test_cards_are_collapsed_and_show_each_providers_state(self):
        self.settings()
        page = self.page
        cards = page.locator('.provider-card')
        expect(cards).to_have_count(6)
        for i in range(6):
            expect(cards.nth(i)).not_to_have_attribute('open', '')
        # The fixture has a Groq key and model saved.
        expect(page.locator('#groq-state')).to_have_text('llama-3.3-70b-versatile')
        expect(page.locator('#deepseek-state')).to_have_text('No key')
        expect(page.locator('#deepseek-api-key')).to_be_hidden()
        page.locator('#deepseek-card > summary').click()
        expect(page.locator('#deepseek-api-key')).to_be_visible()
        expect(page.locator('#deepseek-model-load')).to_be_visible()
        expect(page.locator('#deepseek-model-test')).to_be_visible()
        expect(page.locator('#deepseek-gen-details')).not_to_have_attribute('open', '')
        page.locator('#deepseek-api-key').fill('synthetic-key')
        expect(page.locator('#deepseek-state')).to_have_text('Choose a model')
        expect(page.locator('#deepseek-state')).to_have_attribute('data-state', 'partial')
        listed = self.list_models([{'id': 'synthetic-chat', 'name': 'Synthetic chat'}])
        page.locator('#deepseek-model-load').click()
        page.locator('#deepseek-model-use').click()
        expect(page.locator('#deepseek-state')).to_have_text('synthetic-chat')
        expect(page.locator('#deepseek-state')).to_have_attribute('data-state', 'ready')
        # Test connection checks this one provider, with the key only.
        page.locator('#deepseek-model-test').click()
        expect(page.locator('#deepseek-model-status')).to_contain_text('✓ OK · synthetic-chat')
        self.assertEqual([{'api_key': 'synthetic-key'}] * 2, listed)
        # Labels still name the provider for screen readers.
        expect(page.get_by_label('DeepSeek API key')).to_have_count(1)
        self.assertEqual([], self.errors)

    def test_advanced_shows_only_what_the_model_reports_and_saves(self):
        self.settings()
        page = self.page
        self.list_models(DEEPSEEK_MODELS)
        self.choose('deepseek', 'synthetic-reasoner')
        page.locator('#deepseek-gen-details > summary').click()
        expect(page.locator('#deepseek-gen-max')).to_have_attribute('placeholder', '16,384 (default)')
        expect(page.locator('#deepseek-gen-max-hint')).to_contain_text('synthetic-reasoner allows up to 393,216')
        expect(page.locator('#deepseek-gen-thinking')).to_be_visible()
        expect(page.locator('#deepseek-gen-effort option')).to_have_text(['Model default (high)', 'Low', 'High', 'Max'])
        page.locator('#deepseek-gen-max').fill('40000')
        page.locator('#deepseek-gen-max').blur()
        page.locator('#deepseek-gen-effort').select_option('max')
        expect(page.locator('#deepseek-gen-status')).to_contain_text('Saved')
        self.assertEqual({'deepseek': {'max_output_tokens': 40000, 'effort': 'max'}}, self.stored('providerGeneration'))
        page.locator('#deepseek-gen-thinking').select_option('off')
        expect(page.locator('#deepseek-gen-effort')).to_be_disabled()
        page.locator('#deepseek-gen-max').fill('500000')
        page.locator('#deepseek-gen-max').blur()
        expect(page.locator('#deepseek-gen-status')).to_contain_text('from 1 to 393,216')
        self.assertEqual(40000, self.stored('providerGeneration')['deepseek']['max_output_tokens'])
        # A model without reasoning settings shows the output limit only, capped at its maximum.
        page.locator('#deepseek-model-list').select_option('synthetic-small')
        page.locator('#deepseek-model-use').click()
        expect(page.locator('#deepseek-gen-thinking')).to_be_hidden()
        expect(page.locator('#deepseek-gen-effort')).to_be_hidden()
        expect(page.locator('#deepseek-gen-max')).to_have_attribute('placeholder', '8,192 (default)')
        expect(page.locator('#deepseek-gen-max-hint')).to_contain_text("Analyses use 8,192, this model's maximum")
        # Gemini: output limit only; a typed model ID has no reported limits.
        page.locator('#gemini-card > summary').click()
        page.locator('#gemini-model-picker summary', has_text='Enter a model ID').click()
        page.locator('#gemini-model-manual').fill('gemini-synthetic')
        page.locator('#gemini-model-manual-use').click()
        page.locator('#gemini-gen-details > summary').click()
        expect(page.locator('#gemini-gen-thinking')).to_be_hidden()
        expect(page.locator('#gemini-advanced')).to_contain_text('Load models and choose the model from the list')
        # Saved with the export, and kept after a reload.
        self.assertIn('providerGeneration', page.evaluate('() => SETTINGS_KEYS'))
        page.reload()
        page.locator('#deepseek-card > summary').click()
        page.locator('#deepseek-gen-details > summary').click()
        expect(page.locator('#deepseek-gen-max')).to_have_value('40000')
        self.assertEqual([], self.errors)

    def analyze_body(self, storage, provider='deepseek'):
        page = self.page
        page.evaluate('(values) => browser.storage.local.set(values)', storage)
        page.reload()
        self.install_background()
        bodies = []
        def record(route):
            bodies.append(route.request.post_data_json)
            route.fulfill(json={'analysis': 'Synthetic answer', 'outbound': {'ai': None, 'lookups': []}})
        self.context.route('**/analyze', record)
        page.locator('#logs-textarea').fill('{"event":"synthetic"}')
        page.locator('#stage-tab-options').click()
        page.locator('summary', has_text='Privacy methods').click()
        page.locator('#enable-ti').uncheck()
        page.locator('input[value="ai"]').check()
        page.locator('#ai-provider').select_option(provider)
        page.locator('#analyze-btn').click()
        expect(page.locator('#status-text')).to_contain_text('Done!', timeout=20000)
        return bodies[-1]

    def test_the_popup_sends_the_settings_the_model_supports(self):
        model = dict(DEEPSEEK_MODELS[0])
        body = self.analyze_body({'deepseekApiKey': 'synthetic-key', 'providerModels': {'deepseek': model},
                                  'providerGeneration': {'deepseek': {'max_output_tokens': 40000, 'thinking': 'on', 'effort': 'max'}}})
        self.assertEqual(('deepseek', 'synthetic-reasoner'), (body['mode'], body['model']))
        self.assertEqual({'max_output_tokens': 40000, 'thinking': 'on', 'effort': 'max'}, body['generation'])

    def test_saved_1_0_1_settings_send_the_default_limit_only(self):
        # A model saved by 1.0.1 has only an ID and name; an effort it never reported is not sent.
        body = self.analyze_body({'deepseekApiKey': 'synthetic-key',
                                  'providerModels': {'deepseek': {'id': 'synthetic-old', 'name': 'synthetic-old'}},
                                  'providerGeneration': {'deepseek': {'effort': 'max', 'thinking': 'on'}}})
        self.assertEqual({'max_output_tokens': 16384}, body['generation'])

    def test_a_limit_above_the_models_maximum_is_lowered_to_it(self):
        body = self.analyze_body({'deepseekApiKey': 'synthetic-key', 'providerModels': {'deepseek': DEEPSEEK_MODELS[1]},
                                  'providerGeneration': {'deepseek': {'max_output_tokens': 40000}}})
        self.assertEqual({'max_output_tokens': 8192}, body['generation'])

    def test_settings_page_in_dark_theme_has_no_errors(self):
        self.page.evaluate("() => browser.storage.local.set({theme: 'dark'})")
        self.settings()
        self.page.locator('#claude-card > summary').click()
        expect(self.page.locator('html')).to_have_attribute('data-theme', 'dark')
        self.assertEqual([], self.errors)

    # ---- Cut-off answers in Analyze, Ask and Report ----

    def test_cut_off_answers_say_so_in_analyze_ask_and_report(self):
        page = self.page
        self.install_background()
        note = '\n\n---\n*The answer was cut off at the output limit (16,384 tokens). Raise Maximum output tokens to get it complete.*'
        bodies, replies = [], []
        def reply(route):
            bodies.append(route.request.post_data_json)
            route.fulfill(json={'analysis': replies.pop(0) + note, 'outbound': {'ai': {
                'provider': 'Groq', 'model': 'llama-3.3-70b-versatile', 'outcome': 'answered (cut off at the output limit)'}, 'lookups': []}})
        self.context.route('**/analyze', reply)
        page.locator('#logs-textarea').fill('{"event":"synthetic"}')
        page.locator('#stage-tab-options').click()
        page.locator('summary', has_text='Privacy methods').click()
        page.locator('#enable-ti').uncheck()
        page.locator('input[value="ai"]').check()
        # Analyze: the partial analysis is shown with the note.
        replies.append('Partial synthetic analysis')
        page.locator('#analyze-btn').click()
        expect(page.locator('#status-text')).to_contain_text('Done!', timeout=20000)
        expect(page.locator('#analysis-output')).to_contain_text('cut off at the output limit')
        # Ask: the partial answer is kept with the note.
        replies.append('Partial synthetic answer')
        page.locator('#ask-btn').click()
        page.locator('#chat-question').fill('What happened?')
        page.locator('#chat-send').click()
        expect(page.locator('.chat-exchange:not(.pending) .chat-answer')).to_contain_text('cut off at the output limit', timeout=20000)
        # Report: a report cut off mid-JSON names the output limit, not the model.
        replies.append('{"title": "Synthetic", "summary": "Cut off here')
        page.locator('#report-btn').click()
        page.locator('#report-generate').click()
        expect(page.locator('#report-hint')).to_contain_text('cut off at the output limit', timeout=20000)
        expect(page.locator('#report-hint')).to_contain_text('Maximum output tokens')
        expect(page.locator('#report-output')).to_be_hidden()
        # All three sent the provider's output limit.
        self.assertEqual(3, len(bodies))
        self.assertTrue(all(body['generation'] == {'max_output_tokens': 16384} for body in bodies), bodies)
        self.assertEqual([], self.errors)

    # ---- Settings saved by 1.0.1 ----

    def test_settings_saved_by_1_0_1_keep_working(self):
        page = self.page
        # Exactly what 1.0.1 stored: keys, models as {id, name}, OpenRouter's model and its facts; no providerGeneration.
        page.evaluate("""() => browser.storage.local.clear().then(() => browser.storage.local.set({
            groqApiKey: 'synthetic-groq', claudeApiKey: 'synthetic-claude', openrouterApiKey: 'synthetic-or',
            providerModels: {groq: {id: 'synthetic-groq-model', name: 'synthetic-groq-model'}},
            openrouterModel: 'vendor/synthetic:free', openrouterModelInfo: {id: 'vendor/synthetic:free', max_completion_tokens: 4096},
            capturedLogs: [], backendToken: 'veilux-test-backend-key-0123456789'}))""")
        self.settings()
        expect(page.locator('#groq-state')).to_have_text('synthetic-groq-model')
        expect(page.locator('#claude-state')).to_have_text('Choose a model')
        expect(page.locator('#openrouter-state')).to_have_text('vendor/synthetic:free')
        page.locator('#openrouter-card > summary').click()
        page.locator('#openrouter-gen-details > summary').click()
        expect(page.locator('#openrouter-gen-max')).to_have_attribute('placeholder', '4,096 (default)')
        self.assertIsNone(self.stored('providerGeneration'))  # nothing is written until the analyst changes something
        # The popup sends the default limit for the 1.0.1 model, and OpenRouter's reported maximum.
        page.goto(self.url + '/extension/popup.html')
        body = self.analyze_body({}, provider='groq')
        self.assertEqual(('groq', 'synthetic-groq-model'), (body['mode'], body['model']))
        self.assertEqual({'max_output_tokens': 16384}, body['generation'])
        body = self.analyze_body({}, provider='openrouter')
        self.assertEqual('vendor/synthetic:free', body['openrouter_model'])
        self.assertEqual({'max_output_tokens': 4096}, body['generation'])

    # ---- The Save settings bar ----

    def test_keyboard_focus_is_never_hidden_behind_the_save_bar(self):
        page = self.page
        for width, height in ((360, 640), (640, 360), (900, 1000)):
            page.set_viewport_size({'width': width, 'height': height})
            self.settings()
            for card in page.locator('.provider-card > summary').all():
                card.click()
            page.locator('#groq-api-key').fill('synthetic-unsaved')  # the bar now says there are unsaved changes
            covered = page.evaluate("""() => {
              const covered = [];
              for (const el of document.querySelectorAll('.settings-page :is(input,select,textarea,button,summary)')) {
                if (!el.checkVisibility() || el.disabled || el.closest('.settings-dock')) continue;
                window.scrollTo(0, 0); el.focus();
                if (document.activeElement !== el) continue;
                const r = el.getBoundingClientRect();
                const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
                if (hit && hit.closest('.settings-dock')) covered.push(el.id || el.textContent.trim().slice(0, 40));
              }
              return covered;
            }""")
            self.assertEqual([], covered, (width, height))
