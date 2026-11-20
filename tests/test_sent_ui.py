"""Sent: the per-case record of what left this computer."""
import json
import unittest
from playwright.sync_api import expect
import test_extension_ui as harness

LOG = '{"user":"alice","src_ip":"10.1.2.3","event":"failed logon"}'


class SentTests(unittest.TestCase):
    setUpClass = classmethod(harness.ExtensionUITests.setUpClass.__func__)
    tearDownClass = classmethod(harness.ExtensionUITests.tearDownClass.__func__)
    setUp = harness.ExtensionUITests.setUp
    tearDown = harness.ExtensionUITests.tearDown
    install_background = harness.ExtensionUITests.install_background

    def groq_bodies(self):
        sent = self.page.request.get(self.url + '/test/sent').json()
        return [json.loads(r['body']) for r in sent if 'groq.com' in r['url']]

    def analyze(self, mode='ai'):
        page = self.page
        page.locator('#logs-textarea').fill(LOG)
        page.locator('summary', has_text='Privacy methods').click()
        page.locator('#enable-pattern').check()
        page.locator('#enable-ti').uncheck()
        page.locator('input[value="%s"]' % mode).check()
        page.locator('#analyze-btn').click()
        expect(page.locator('#status-text')).to_contain_text('Sanitized!' if mode == 'sanitize_only' else 'Done!', timeout=20000)

    def test_ai_request_is_recorded_with_the_exact_prompt(self):
        page = self.page
        expect(page.locator('#tab-sent')).to_be_disabled()
        self.analyze()
        page.locator('#tab-sent').click()
        expect(page.locator('#tab-sent')).to_have_text('Sent (1)')
        entry = page.locator('.sent-entry')
        expect(entry).to_have_count(1)
        expect(entry.locator('summary')).to_contain_text('Analysis')
        expect(entry.locator('summary')).to_contain_text('Groq · llama-3.3-70b-versatile')
        entry.locator('summary').click()
        expect(entry.locator('.sent-facts')).to_contain_text('https://api.groq.com/openai/v1/chat/completions')
        expect(entry.locator('.sent-facts')).to_contain_text('answered')
        expect(page.locator('#sent-backend')).to_contain_text('on this computer')
        prompt = entry.locator('.sent-prompt').text_content()
        self.assertEqual(self.groq_bodies()[0]['messages'][0]['content'], prompt)
        self.assertNotIn('alice', prompt)
        self.assertNotIn('synthetic-api', json.dumps(self.page.evaluate("() => caseStorage.get('sendRecord')")))

        # Local-only runs are listed as such.
        self.analyze('sanitize_only')
        expect(page.locator('.sent-entry')).to_have_count(2)
        expect(page.locator('.sent-entry').first.locator('summary')).to_contain_text('Nothing left this computer (sanitize only)')

        with page.expect_download() as download:
            page.locator('#sent-export').click()
        exported = json.loads(open(download.value.path(), encoding='utf-8').read())
        self.assertEqual(2, len(exported['entries']))
        self.assertEqual(prompt, exported['entries'][0]['ai']['prompt'])

        # The record belongs to the case and is cleared with it.
        page.locator('#clear-btn').click()
        expect(page.locator('#tab-sent')).to_be_disabled()

    def test_indicator_check_is_recorded(self):
        page = self.page
        page.locator('#stage-tab-tools').click()
        page.locator('#ioc-lookup-toggle').click()
        page.locator('#manual-ti-vt').uncheck()
        page.locator('#manual-ti-abuse').uncheck()
        page.locator('#ioc-lookup-input').fill('198.51.100.212')
        page.locator('#ioc-lookup-btn').click()
        expect(page.locator('#status-text')).to_contain_text('Lookup complete')
        page.locator('#tab-sent').click()
        entry = page.locator('.sent-entry')
        expect(entry.locator('summary')).to_contain_text('Indicator check')
        expect(entry.locator('summary')).to_contain_text('1 lookup sent')
        entry.locator('summary').click()
        expect(entry.locator('.sent-lookups')).to_contain_text('WHOIS / RDAP')
        expect(entry.locator('.sent-lookups')).to_contain_text('198.51.100.212')


if __name__ == '__main__':
    unittest.main()
