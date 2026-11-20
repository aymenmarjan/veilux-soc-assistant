"""Email reports: templates in Settings, generation per case through the protected request."""
import json
import re
import unittest
from playwright.sync_api import expect
import test_extension_ui as harness

LOG = '{"user":"alice","src_ip":"10.1.2.3","event":"failed logon"}'


class ReportTests(unittest.TestCase):
    setUpClass = classmethod(harness.ExtensionUITests.setUpClass.__func__)
    tearDownClass = classmethod(harness.ExtensionUITests.tearDownClass.__func__)
    setUp = harness.ExtensionUITests.setUp
    tearDown = harness.ExtensionUITests.tearDown
    install_background = harness.ExtensionUITests.install_background

    def ai_prompts(self):
        sent = self.page.request.get(self.url + '/test/sent').json()
        return ['\n'.join(m['content'] for m in json.loads(r['body'])['messages']) for r in sent if 'groq.com' in r['url']]

    def case_value(self, key):
        return self.page.evaluate('(key) => caseStorage.get(key).then(s => s[key])', key)

    def prepare(self, log=LOG):
        page = self.page
        page.locator('#logs-textarea').fill(log)
        page.locator('summary', has_text='Privacy methods').click()
        page.locator('#enable-pattern').check()

    def generate(self):
        page = self.page
        page.locator('#report-generate').click()
        # The usual credential review runs first when a value is uncertain.
        expect(page.locator('#report-output:not([hidden]), #secret-review:visible').first).to_be_visible(timeout=20000)
        if page.locator('#secret-review').is_visible():
            page.locator('#secret-review-continue').click()
        expect(page.locator('#report-output')).to_be_visible(timeout=20000)

    def srcdoc(self):
        return self.page.locator('#report-frame').get_attribute('srcdoc')

    def test_report_without_an_analysis_restores_values_locally(self):
        page = self.page
        self.prepare()
        page.locator('#report-btn').click()
        expect(page.locator('#tab-report')).to_have_attribute('aria-selected', 'true')
        expect(page.locator('#report-severity option')).to_have_text(['Auto (the AI decides)', 'Low', 'Medium', 'High', 'Critical'])
        page.locator('#report-case-id').fill('INC-42')
        self.generate()
        expect(page.locator('#report-subject-line')).to_have_text('Case #INC-42 - Synthetic failed logon burst')
        html = self.srcdoc()
        # The AI saw only markers; the finished email shows the real value, on this computer.
        self.assertIn('alice', html)
        self.assertNotIn('⟦', html)
        self.assertIn('#DC2626', html)  # High, matched to the template's scale
        prompts = self.ai_prompts()
        self.assertEqual(1, len(prompts))
        self.assertIn('Answer with JSON only', prompts[0])
        for value in ('alice', '10.1.2.3'):
            self.assertNotIn(value, prompts[0])
        # A report never replaces the case's analysis results.
        self.assertIsNone(self.case_value('lastAnalysis'))
        expect(page.locator('#tab-analysis')).to_be_disabled()

        # Copy for email puts only the body on the clipboard: no subject line
        # from <title>, no page wrapper.
        page.evaluate("""() => { window.__copied = null; navigator.clipboard.write = async items => {
            window.__copied = await (await items[0].getType('text/html')).text(); }; }""")
        page.locator('#report-copy-email').click()
        expect(page.locator('#status-text')).to_contain_text('Email copied')
        copied = page.evaluate('() => window.__copied')
        self.assertIn('Synthetic failed logon burst', copied)
        self.assertIn('alice', copied)
        for absent in ('<title', '<head', '<body', '<html'):
            self.assertNotIn(absent, copied)
        self.assertTrue(copied.startswith('<div style="font-family:Arial'))

        # The report and its fields stay with the case.
        page.reload()
        expect(page.locator('#report-output')).to_be_visible()
        expect(page.locator('#report-case-id')).to_have_value('INC-42')
        expect(page.locator('#report-subject-line')).to_have_text('Case #INC-42 - Synthetic failed logon burst')

        # Editing the content re-renders without another AI request.
        page.locator('.report-edit summary').click()
        content = json.loads(page.locator('#report-content').input_value())
        content['summary'] = 'Edited summary by the analyst.'
        page.locator('#report-content').fill(json.dumps(content))
        page.locator('#report-apply').click()
        expect(page.locator('#status-text')).to_contain_text('Report updated')
        self.assertIn('Edited summary by the analyst.', self.srcdoc())
        self.assertEqual(1, len(self.ai_prompts()))

        # Changing the severity re-renders at once.
        page.locator('#report-severity').select_option('Low')
        expect(page.locator('#report-frame')).to_have_attribute('srcdoc', re.compile('#2E7D32'))

        page.locator('#clear-btn').click()
        self.assertIsNone(self.case_value('reportState'))
        expect(page.locator('#report-output')).to_be_hidden()

    def test_the_whole_case_is_sent_and_chosen_fields_win(self):
        page = self.page
        self.prepare()
        if 'collapsed' in (page.locator('#analyst-data-preview').get_attribute('class') or ''):
            page.locator('#analyst-data-toggle').click()
        page.locator('#analyst-data-textarea').fill('The user is travelling this week.')
        page.evaluate("""() => appendFieldStatistics({indexPattern: 'auth-*', sampled: 10, total: 10, fields: [{field: 'event.outcome',
            count: 10, percentage: 100, topValues: [{value: 'failure-burst-value', count: 10, percentage: 100}]}],
            summary: {query: '', filters: [], timeFrame: []}})""")
        page.evaluate("""() => caseStorage.set({lastAnalysis: 'Earlier verdict: likely a misconfigured scanner.',
            lastThreatIntelFindings: [{ioc: '198.51.100.7', type: 'ip', verdict: 'suspicious',
              sources: {abuseipdb: {status: 'ok', abuse_confidence_score: 42, total_reports: 7}, whois: {status: 'timeout'}}}]})""")
        page.locator('#report-btn').click()
        page.locator('#report-extra-context').fill('The user already reset the password.')
        expect(page.locator('#report-included')).to_contain_text(
            'Uses: 1 log · 1 statistics query · case notes · threat intel for 1 indicator · the AI analysis · email instructions.')
        page.locator('#report-title').fill('Chosen title')
        page.locator('#report-severity').select_option('Critical')
        self.generate()
        expect(page.locator('#report-subject-line')).to_have_text('Case #[Case ID] - Chosen title')
        html = self.srcdoc()
        self.assertIn('Chosen title', html)
        self.assertIn('>Critical<', html)
        prompt = self.ai_prompts()[0]
        for expected in ('Earlier AI analysis of this case', 'misconfigured scanner',
                         'Threat intelligence already gathered for this case', 'do not list these results', '(ip): suspicious',
                         'abuse confidence score 42', 'whois: timeout',
                         'Instructions from the analyst for this email', 'already reset the password',
                         'travelling this week', 'failure-burst-value',
                         'fixed by the analyst: "Chosen title"', 'fixed by the analyst: "Critical"'):
            self.assertIn(expected, prompt)
        # Added context is protected like everything else: the IP from threat intel is masked.
        self.assertNotIn('198.51.100.7', prompt)
        # The instructions stay with the case.
        page.reload()
        page.locator('#tab-report').click()
        expect(page.locator('#report-extra-context')).to_have_value('The user already reset the password.')

    def test_custom_template_from_settings_drives_the_report_page(self):
        page = self.page
        page.goto(self.url + '/extension/settings.html#reports')
        expect(page.locator('#report-template-list .report-template-card')).to_have_count(1)
        page.locator('#report-new').click()
        page.locator('#report-name').fill('Team escalation')
        page.locator('#report-language').fill('French')
        rows = page.locator('#report-severities .severity-row-edit')
        expect(rows).to_have_count(4)
        rows.nth(3).get_by_role('button', name='Remove').click()
        page.locator('#report-add-severity').click()
        page.locator('#report-severities .severity-row-edit input[type=text]').last.fill('Very high')
        page.locator('#report-subject').fill('Case #{{case_id}} - {{title}} ({{team}})')
        expect(page.locator('#report-fields-preview')).to_contain_text('Team')
        page.locator('#report-html').fill('<p>{{team}} | {{title}} | <span style="color:{{severity_color}}">{{severity}}</span></p>'
                                          '<ul>{{#risks}}<li>{{.}}</li>{{/risks}}</ul>')
        page.locator('#report-preview').click()
        expect(page.locator('#report-preview-frame')).to_be_visible()
        expect(page.locator('#report-status')).to_contain_text('Subject: Case #12345')
        expect(page.locator('#report-status')).to_contain_text('(Team value)')
        page.locator('#report-save').click()
        expect(page.locator('#report-status')).to_contain_text('saved')
        expect(page.locator('#report-template-list .report-template-card')).to_have_count(2)
        custom = page.locator('#report-default option', has_text='Team escalation').get_attribute('value')
        page.locator('#report-default').select_option(custom)
        expect(page.locator('#report-template-list')).to_contain_text('Team escalation · default')

        page.goto(self.url + '/extension/popup.html')
        self.install_background()
        self.prepare()
        page.locator('#report-btn').click()
        expect(page.locator('#report-template')).to_have_value(custom)
        expect(page.locator('#report-severity option')).to_have_text(['Auto (the AI decides)', 'Low', 'Medium', 'High', 'Very high'])
        page.locator('#report-field-team').fill('Network')
        page.locator('#report-case-id').fill('7')
        expect(page.locator('#report-subject-line')).to_have_text('Case #7 - … (Network)')
        self.generate()
        expect(page.locator('#report-subject-line')).to_have_text('Case #7 - Synthetic failed logon burst (Network)')
        self.assertIn('Network | Synthetic failed logon burst', self.srcdoc())
        self.assertIn('Write every text value in French.', self.ai_prompts()[0])

        # Switching back to the built-in template keeps the generated content.
        page.locator('#report-template').select_option('builtin')
        expect(page.locator('#report-subject-line')).to_have_text('Case #7 - Synthetic failed logon burst')
        expect(page.locator('#report-field-team')).to_have_count(0)

    def test_masked_template_keeps_markers(self):
        page = self.page
        page.evaluate("""() => VeiluxReports.saveOwn([VeiluxReports.normalize({...VeiluxReports.BUILTIN, id: 'masked',
            name: 'Masked', keepMasked: true})]).then(() => VeiluxReports.setDefault('masked'))""")
        page.reload()
        self.install_background()
        self.prepare()
        page.locator('#report-btn').click()
        self.generate()
        html = self.srcdoc()
        self.assertIn('⟦USER#1⟧', html)
        self.assertNotIn('alice', html)

    def test_templates_export_and_import_in_settings(self):
        page = self.page
        page.goto(self.url + '/extension/settings.html#reports')
        exported = page.evaluate("""() => VeiluxReports.exportFile(VeiluxReports.normalize({...VeiluxReports.BUILTIN,
            id: 'x', name: 'Shared template', subjectPattern: '{{team}} - {{title}}'}))""")
        page.locator('#report-import-file').set_input_files(files=[{'name': 'shared.json', 'mimeType': 'application/json', 'buffer': exported.encode()}])
        expect(page.locator('#report-status')).to_contain_text('Imported "Shared template"')
        card = page.locator('.report-template-card', has_text='Shared template')
        expect(card).to_be_visible()
        card.get_by_role('button', name='Preview').click()
        expect(card.locator('iframe')).to_be_visible()
        card.get_by_role('button', name='Delete').click()
        card.get_by_role('button', name='Click again to delete').click()
        expect(page.locator('.report-template-card', has_text='Shared template')).to_have_count(0)
        page.locator('#report-import-file').set_input_files(files=[{'name': 'bad.json', 'mimeType': 'application/json', 'buffer': b'{"nope":1}'}])
        expect(page.locator('#report-status')).to_contain_text('not a VEILUX report template')


if __name__ == '__main__':
    unittest.main()
