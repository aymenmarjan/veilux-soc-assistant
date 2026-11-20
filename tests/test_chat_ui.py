"""Ask: follow-up questions per case, through the protected request."""
import json
import re
import unittest
from playwright.sync_api import expect
import test_extension_ui as harness

LOG = '{"user":"alice","src_ip":"10.1.2.3","event":"failed logon"}'
HASH = '0123456789abcdef' * 4
OTHER_HASH = 'fedcba9876543210' * 4


class ChatTests(unittest.TestCase):
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
        self.page.locator('#logs-textarea').fill(log)
        self.page.locator('summary', has_text='Privacy methods').click()
        self.page.locator('#enable-pattern').check()

    def ask(self, question, answers=1):
        page = self.page
        page.locator('#chat-question').fill(question)
        page.locator('#chat-send').click()
        expect(page.locator('.chat-exchange:not(.pending)')).to_have_count(answers, timeout=20000)

    def test_questions_are_protected_kept_per_case_and_feed_the_report(self):
        page = self.page
        self.prepare()
        page.locator('#ask-btn').click()
        expect(page.locator('#tab-chat')).to_have_attribute('aria-selected', 'true')
        expect(page.locator('#chat-quick .chat-chip')).to_have_count(4)
        page.locator('#chat-quick .chat-chip', has_text='timeline').click()
        expect(page.locator('#chat-question')).to_have_value('Build a timeline of the key events.')
        self.ask('Was alice seen on other hosts?')

        answer = page.locator('.chat-exchange .chat-answer').first
        # The AI saw markers only; the answer shows the real value here.
        expect(answer).to_contain_text('the activity involves')
        expect(answer.locator('strong')).to_have_text('Finding:')
        expect(answer).not_to_contain_text('⟦')
        prompt = self.ai_prompts()[0]
        self.assertIn('Latest question from the analyst', prompt)
        self.assertIn('Was ⟦', prompt)
        for value in ('alice', '10.1.2.3'):
            self.assertNotIn(value, prompt)
        # Answers never replace the case's analysis.
        self.assertIsNone(self.case_value('lastAnalysis'))

        # A second question carries the conversation, re-protected with the case.
        page.locator('#chat-model').select_option('groq')
        self.ask('And what should we block?', answers=2)
        second = self.ai_prompts()[1]
        self.assertIn('Conversation so far', second)
        self.assertIn('Analyst: Was ⟦', second)
        self.assertNotIn('alice', second)
        expect(page.locator('.chat-meta').last).to_contain_text('Groq')

        # The conversation stays with the case.
        page.reload()
        expect(page.locator('.chat-exchange')).to_have_count(2)
        expect(page.locator('#tab-chat')).to_contain_text('Ask (2)')

        # An answer kept as a case note reaches the report as a finding of the
        # case, not as a conversation.
        page.locator('.chat-use').first.click()
        expect(page.locator('.chat-use').first).to_have_attribute('aria-pressed', 'true')
        expect(page.locator('.chat-use').first).to_have_text('In case notes ✓')
        page.locator('#report-btn').click()
        expect(page.locator('#report-included')).to_contain_text('Uses: 1 log · case notes (1 from Ask).')
        page.locator('#report-generate').click()
        # Words from VEILUX's own answer format never trigger the credential review.
        expect(page.locator('#report-output')).to_be_visible(timeout=20000)
        report_prompt = self.ai_prompts()[2]
        self.assertIn('Case notes kept by the analyst from follow-up questions', report_prompt)
        self.assertIn('never mention questions, a chat', report_prompt)
        self.assertNotIn('alice', report_prompt)

        # Start over clears the conversation after a second click.
        page.locator('#tab-chat').click()
        page.locator('#chat-reset').click()
        expect(page.locator('#chat-reset')).to_have_text('Click again to start over')
        page.locator('#chat-reset').click()
        expect(page.locator('.chat-exchange')).to_have_count(0)
        self.assertIsNone(self.case_value('chatState'))

    def test_only_the_last_eight_exchanges_are_kept(self):
        page = self.page
        self.prepare()
        page.evaluate("""() => caseStorage.set({chatState: {exchanges: Array.from({length: 8}, (_, i) =>
            ({question: 'Question ' + i, answer: 'Answer ' + i, askedAt: Date.now()}))}})""")
        page.reload()
        self.install_background()
        page.locator('#tab-chat').click()
        expect(page.locator('.chat-exchange')).to_have_count(8)
        page.locator('#chat-question').fill('Ninth question')
        page.locator('#chat-send').click()
        expect(page.locator('.chat-exchange').last).to_contain_text('Ninth question', timeout=20000)
        expect(page.locator('.chat-exchange:not(.pending)')).to_have_count(8, timeout=20000)
        expect(page.locator('.chat-exchange').first).to_contain_text('Question 1')

    def test_review_decisions_are_remembered_for_the_case(self):
        page = self.page
        self.prepare('{"user":"alice","hash":"' + HASH + '"}')
        page.locator('#ask-btn').click()
        page.locator('#chat-question').fill('What is this hash?')
        page.locator('#chat-send').click()
        expect(page.locator('#secret-review')).to_be_visible(timeout=15000)
        expect(page.locator('#secret-review-list')).to_contain_text(HASH)
        page.locator('#secret-review-continue').click()
        expect(page.locator('.chat-exchange:not(.pending)')).to_have_count(1, timeout=20000)

        # Same values: no second review.
        scans = []
        page.on('request', lambda request: scans.append(1) if request.url.endswith('/secrets/scan') else None)
        page.locator('#chat-question').fill('Anything else?')
        page.locator('#chat-send').click()
        expect(page.locator('.chat-exchange:not(.pending)')).to_have_count(2, timeout=20000)
        self.assertEqual(1, len(scans))

        # A new uncertain value in the message is the only one asked about.
        page.locator('#chat-question').fill('Is ' + OTHER_HASH + ' related?')
        page.locator('#chat-send').click()
        expect(page.locator('#secret-review')).to_be_visible(timeout=15000)
        expect(page.locator('#secret-review-list .secret-review-item')).to_have_count(1)
        expect(page.locator('#secret-review-list')).to_contain_text(OTHER_HASH)
        page.locator('#secret-review-cancel').click()
        # A cancelled question returns to the box.
        expect(page.locator('#chat-question')).to_have_value('Is ' + OTHER_HASH + ' related?')
        expect(page.locator('.chat-exchange')).to_have_count(2)

    def test_answers_finished_while_the_popup_was_closed_are_shown(self):
        page = self.page
        self.prepare()
        report = {'title': 'Finished in the background', 'severity': 'High', 'summary': 'Done while closed.'}
        page.evaluate("""(raw) => caseStorage.set({
            chatState: {exchanges: [], pending: {question: 'Pending question', askedAt: Date.now()}},
            pendingAnswer: {purpose: 'chat', raw: 'Answer written while closed.', mapping: null}})""", json.dumps(report))
        page.reload()
        expect(page.locator('.chat-exchange')).to_have_count(1)
        expect(page.locator('.chat-exchange')).to_contain_text('Pending question')
        expect(page.locator('.chat-answer')).to_have_text('Answer written while closed.')
        self.assertIsNone(self.case_value('pendingAnswer'))

        page.evaluate("""(raw) => caseStorage.set({pendingAnswer: {purpose: 'report', raw, mapping: null}})""", json.dumps(report))
        page.reload()
        expect(page.locator('#report-output')).to_be_visible()
        expect(page.locator('#report-subject-line')).to_have_text('Case #[Case ID] - Finished in the background')
        self.assertIsNone(self.case_value('pendingAnswer'))

    def test_case_notes_are_shared_by_analysis_ask_and_report(self):
        page = self.page
        self.prepare()

        def analyze():
            before = len(self.ai_prompts())
            page.locator('#status-text').evaluate("node => node.textContent = ''")
            page.locator('#analyze-btn').click()
            expect(page.locator('#status-text')).to_contain_text('Done!', timeout=20000)
            prompts = self.ai_prompts()
            self.assertEqual(before + 1, len(prompts))
            return prompts[-1]
        expect(page.locator('#analyze-uses')).to_have_text('Analyze uses: 1 log.')
        self.assertNotIn('Case notes kept by the analyst', analyze())
        expect(page.locator('#analysis-stale')).to_be_hidden()

        page.locator('#ask-btn').click()
        expect(page.locator('#chat-uses')).to_have_text('Uses: 1 log · the AI analysis · this conversation.')
        self.ask('Was alice seen on other hosts?')
        expect(page.locator('#case-notes-title')).to_have_text('Case notes · optional')
        page.locator('.chat-use').click()
        expect(page.locator('.chat-use')).to_have_text('In case notes ✓')
        expect(page.locator('#status-text')).to_contain_text('Added to case notes')
        # The note is listed under Case notes; the analyst's own text is untouched.
        expect(page.locator('#case-notes-title')).to_have_text('Case notes · 1 from Ask')
        expect(page.locator('#analyst-data-textarea')).to_have_value('')
        page.locator('#analyst-data-toggle').click()
        note = page.locator('.case-note')
        expect(note).to_have_count(1)
        expect(note.locator('.case-note-source')).to_have_text('From Ask · Was alice seen on other hosts?')
        expect(page.locator('#analyze-uses')).to_have_text('Analyze uses: 1 log · case notes (1 from Ask).')

        # The analysis is now out of date, and says why.
        page.locator('#tab-analysis').click()
        expect(page.locator('#analysis-stale')).to_be_visible()
        expect(page.locator('#analysis-stale-text')).to_have_text('The case changed since this analysis: 1 new note from Ask.')
        before = len(self.ai_prompts())
        page.locator('#status-text').evaluate("node => node.textContent = ''")
        page.locator('#analysis-stale-btn').click()
        expect(page.locator('#status-text')).to_contain_text('Done!', timeout=20000)
        expect(page.locator('#analysis-stale')).to_be_hidden()
        prompt = self.ai_prompts()[-1]
        self.assertEqual(before + 1, len(self.ai_prompts()))
        self.assertIn('Case notes kept by the analyst from follow-up questions', prompt)
        self.assertIn('- On "Was ⟦', prompt)
        self.assertIn('the activity involves ⟦', prompt)
        self.assertNotIn('alice', prompt)
        # Sent once, even when the sanitized preview of the notes is reused.
        page.locator('#sanitized-analyst-textarea').evaluate("node => { node.value += ' '; node.dispatchEvent(new Event('input')); }")
        self.assertEqual(1, analyze().count('Case notes kept by the analyst'))

        # Notes outlive the conversation, and later questions receive them.
        page.locator('#tab-chat').click()
        page.locator('#chat-reset').click()
        page.locator('#chat-reset').click()
        expect(page.locator('.chat-exchange')).to_have_count(0)
        expect(note).to_have_count(1)
        self.ask('What next?')
        self.assertIn('Case notes kept by the analyst from follow-up questions', self.ai_prompts()[-1])

        # A note can be edited, which the analysis notices, and removed.
        page.locator('#analyst-data-toggle').click()
        note.get_by_role('button', name='Edit').click()
        note.locator('textarea').fill('Confirmed with the client: planned maintenance.')
        note.get_by_role('button', name='Save note').click()
        expect(note.locator('.case-note-text')).to_have_text('Confirmed with the client: planned maintenance.')
        page.locator('#tab-analysis').click()
        expect(page.locator('#analysis-stale-text')).to_have_text('The case changed since this analysis: 1 note edited.')
        page.reload()
        self.install_background()
        expect(page.locator('.case-note')).to_have_count(1)
        page.locator('#tab-analysis').click()
        expect(page.locator('#analysis-stale')).to_be_visible()
        if 'collapsed' in (page.locator('#analyst-data-preview').get_attribute('class') or ''):
            page.locator('#analyst-data-toggle').click()
        page.locator('.case-note').get_by_role('button', name=re.compile('^Remove note')).click()
        expect(page.locator('.case-note')).to_have_count(0)
        expect(page.locator('#analysis-stale-text')).to_have_text('The case changed since this analysis: 1 note removed.')
        self.assertIsNone(self.case_value('caseNotes'))

    def test_analysis_notice_follows_new_logs_and_typed_notes(self):
        page = self.page
        self.prepare()
        page.locator('#analyze-btn').click()
        expect(page.locator('#status-text')).to_contain_text('Done!', timeout=20000)
        expect(page.locator('#analysis-stale')).to_be_hidden()
        if 'collapsed' in (page.locator('#analyst-data-preview').get_attribute('class') or ''):
            page.locator('#analyst-data-toggle').click()
        page.locator('#analyst-data-textarea').fill('The user is travelling this week.')
        expect(page.locator('#analysis-stale-text')).to_have_text('The case changed since this analysis: case notes edited.')
        expect(page.locator('#analyze-uses')).to_have_text('Analyze uses: 1 log · case notes.')
        page.locator('#logs-textarea').fill(LOG + ' ')
        expect(page.locator('#analysis-stale-text')).to_contain_text('case notes edited')
        page.locator('#logs-textarea').fill(LOG.replace('alice', 'bob'))
        expect(page.locator('#analysis-stale-text')).to_have_text(
            'The case changed since this analysis: logs changed, case notes edited.')
        # Clearing the case clears the notice with it.
        page.locator('#clear-btn').click()
        expect(page.locator('#analysis-stale')).to_be_hidden()

    def test_answers_marked_by_an_earlier_version_become_case_notes(self):
        page = self.page
        self.prepare()
        page.evaluate("""() => caseStorage.set({chatState: {exchanges: [
            {question: 'Old question', answer: 'Old answer', askedAt: Date.now(), inReport: true, inAnalysis: false},
            {question: 'Other', answer: 'Not kept', askedAt: Date.now(), inReport: false}]}})""")
        page.reload()
        expect(page.locator('#case-notes-title')).to_have_text('Case notes · 1 from Ask')
        page.locator('#tab-chat').click()
        expect(page.locator('.chat-use')).to_have_text(['In case notes ✓', 'Add to case notes'])
        self.assertNotIn('inReport', self.case_value('chatState')['exchanges'][0])

    def test_quick_questions_are_edited_in_settings(self):
        page = self.page
        page.goto(self.url + '/extension/settings.html#prompts')
        expect(page.locator('#quick-questions')).to_have_value('\n'.join([
            'Build a timeline of the key events.', 'Write a containment plan for this case.',
            'Could this be a false positive? Explain why or why not.', 'Draft a short reply to the client about this alert.']))
        page.locator('#quick-questions').fill('Which accounts are involved?\n\n  List the IOCs.  ')
        page.locator('#quick-questions-save').click()
        expect(page.locator('#quick-questions-status')).to_contain_text('saved')
        expect(page.locator('#quick-questions')).to_have_value('Which accounts are involved?\nList the IOCs.')
        page.goto(self.url + '/extension/popup.html')
        page.locator('#ask-btn').click()
        expect(page.locator('#chat-quick .chat-chip')).to_have_text(['Which accounts are involved?', 'List the IOCs.'])
        page.goto(self.url + '/extension/settings.html#prompts')
        page.locator('#quick-questions-reset').click()
        expect(page.locator('#quick-questions-status')).to_contain_text('Default questions restored')


if __name__ == '__main__':
    unittest.main()
