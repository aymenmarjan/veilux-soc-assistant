"""OpenRouter free-model picker in Settings and the popup, through the real backend
(OpenRouter itself is mocked by tests/ui_fixture.py)."""
import unittest
from playwright.sync_api import expect
import test_extension_ui as harness


class OpenRouterPickerTests(unittest.TestCase):
    setUpClass = classmethod(harness.ExtensionUITests.setUpClass.__func__)
    tearDownClass = classmethod(harness.ExtensionUITests.tearDownClass.__func__)
    setUp = harness.ExtensionUITests.setUp
    tearDown = harness.ExtensionUITests.tearDown
    install_background = harness.ExtensionUITests.install_background

    def stored(self, key):
        return self.page.evaluate('(key) => browser.storage.local.get(key)', key).get(key)

    def test_settings_lookup_shows_metadata_and_saves_the_choice(self):
        self.page.goto(self.url + '/extension/settings.html')
        expect(self.page.locator('#settings-save-state')).to_have_text('Settings saved')
        picker = self.page.locator('#openrouter-model-picker')
        self.page.locator('#openrouter-card > summary').click()
        expect(picker).to_contain_text('No OpenRouter model chosen yet')
        self.page.locator('#openrouter-find').click()
        expect(self.page.locator('#openrouter-status')).to_contain_text('3 free models available')
        options = self.page.locator('#openrouter-list option')
        expect(options).to_have_count(3)
        expect(options.nth(1)).to_have_text('Vendor: Alpha (free) — 262K context · always reasons')
        expect(options.nth(2)).to_have_text('Vendor: Beta Vision (free) — 131K context · reads image')
        self.page.locator('#openrouter-list').select_option('vendor/beta-vision:free')
        details = self.page.locator('#openrouter-details')
        expect(details).to_contain_text('vendor/beta-vision:free')
        expect(details).to_contain_text('text, image')
        expect(picker).to_contain_text('Vendor: Beta Vision (free) synthetic description.')
        self.page.locator('#openrouter-sort').select_option('newest')
        expect(options.first).to_have_attribute('value', 'vendor/beta-vision:free')
        self.page.locator('#openrouter-use').click()
        expect(picker).to_contain_text('Current model: Vendor: Beta Vision (free)')
        self.assertEqual('vendor/beta-vision:free', self.stored('openrouterModel'))
        self.assertEqual(131072, self.stored('openrouterModelInfo')['context_length'])
        # Any other model ID can be entered too.
        self.page.get_by_text('Use another model ID').click()
        self.page.locator('#openrouter-manual').fill('not a model')
        self.page.get_by_role('button', name='Use this ID').click()
        expect(self.page.locator('#openrouter-status')).to_contain_text('Enter a model ID such as')
        self.page.locator('#openrouter-manual').fill('vendor/paid')
        self.page.get_by_role('button', name='Use this ID').click()
        expect(picker).to_contain_text('Current model: vendor/paid')

    def test_popup_requires_a_model_then_analyses_with_it(self):
        self.page.evaluate("() => browser.storage.local.set({openrouterApiKey: 'synthetic-openrouter', enablePatternSanitization: false})")
        self.page.reload()
        self.install_background()
        self.page.locator('#ai-provider').select_option('openrouter')
        panel = self.page.locator('#openrouter-model-panel')
        expect(panel).to_be_visible()
        expect(panel.locator('> summary')).to_have_text('OpenRouter model: not chosen')
        self.page.locator('#logs-textarea').fill('event=login result=failure')
        self.page.locator('#analyze-btn').click()
        expect(self.page.locator('#status-text')).to_contain_text('Choose an OpenRouter model first')
        expect(panel).to_have_attribute('open', '')
        self.page.locator('#popup-openrouter-find').click()
        self.page.locator('#popup-openrouter-list').select_option('vendor/alpha:free')
        self.page.locator('#popup-openrouter-use').click()
        expect(panel.locator('> summary')).to_have_text('OpenRouter model: Vendor: Alpha (free)')
        self.page.locator('#analyze-btn').click()
        expect(self.page.locator('#analysis-output')).to_contain_text('Synthetic report from vendor/alpha:free', timeout=15000)
        self.page.locator('#ai-provider').select_option('groq')
        expect(panel).to_be_hidden()


if __name__ == '__main__':
    unittest.main()
