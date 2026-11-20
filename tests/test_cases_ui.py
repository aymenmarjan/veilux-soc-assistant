"""Cases: each popup slot is an independent investigation; nothing crosses between cases."""
import json
import re
import time
import unittest
from playwright.sync_api import expect
import test_extension_ui as harness


class CaseTests(unittest.TestCase):
    setUpClass = classmethod(harness.ExtensionUITests.setUpClass.__func__)
    tearDownClass = classmethod(harness.ExtensionUITests.tearDownClass.__func__)
    setUp = harness.ExtensionUITests.setUp
    tearDown = harness.ExtensionUITests.tearDown
    install_background = harness.ExtensionUITests.install_background
    native_extension = harness.ExtensionUITests.native_extension

    def storage(self):
        return self.page.evaluate('() => browser.storage.local.get(null)')

    def index(self):
        return self.storage()['casesIndex']

    def analyst(self):
        if 'collapsed' in (self.page.locator('#analyst-data-preview').get_attribute('class') or ''):
            self.page.locator('#analyst-data-toggle').click()
        return self.page.locator('#analyst-data-textarea')

    def switch(self, button):
        with self.page.expect_navigation():
            self.page.locator(button).click()
        expect(self.page.locator('#case-label')).to_be_visible()

    def test_each_case_keeps_its_own_inputs_and_choices(self):
        page = self.page
        expect(page.locator('#case-label')).to_have_text('Case 1 of 2')
        expect(page.locator('.case-dot')).to_have_count(2)
        self.analyst().fill('Case one context')
        page.locator('#enable-ti').check()
        page.wait_for_timeout(400)  # analyst context is saved after a short pause

        self.switch('#case-next')
        expect(page.locator('#case-label')).to_have_text('Case 2 of 2')
        expect(page.locator('#logs-textarea')).to_have_value('')
        expect(self.analyst()).to_have_value('')
        # A new case starts from the choices of the case it was created from.
        expect(page.locator('#enable-ti')).not_to_be_checked()
        page.locator('#logs-textarea').fill('case two event')
        self.analyst().fill('Case two context')
        page.locator('input[value="sanitize_only"]').check()
        page.wait_for_timeout(400)

        self.switch('#case-prev')
        expect(page.locator('#logs-textarea')).to_have_value('password=synthetic-initial')
        expect(self.analyst()).to_have_value('Case one context')
        expect(page.locator('#enable-ti')).to_be_checked()
        expect(page.locator('input[value="ai"]')).to_be_checked()

        # Reopening the popup returns to the last case viewed, with its state intact.
        self.switch('#case-next')
        page.reload()
        expect(page.locator('#case-label')).to_have_text('Case 2 of 2')
        expect(page.locator('#logs-textarea')).to_have_value('case two event')
        expect(self.analyst()).to_have_value('Case two context')
        expect(page.locator('input[value="sanitize_only"]')).to_be_checked()

        stored = self.storage()
        second = self.index()['slots'][1]
        self.assertEqual('Case one context', stored['analystData'])
        self.assertEqual('Case two context', stored['case.' + second + '.analystData'])
        self.assertEqual(['case two event'], stored['case.' + second + '.capturedLogs'])
        self.assertEqual([], self.errors)

    def test_cases_can_be_named_and_keep_private_notes(self):
        page = self.page
        page.locator('#case-menu summary').click()
        page.locator('#case-name').fill('Phishing, finance team')
        page.locator('#case-private-notes').fill('Ticket SR-7741; called the helpdesk at 10:20.')
        expect(page.locator('#case-label')).to_have_text('Case 1 · Phishing, finance team')
        expect(page.locator('.case-dot').first).to_have_attribute('aria-label', re.compile('^Case 1 · Phishing, finance team: '))
        page.wait_for_timeout(500)  # saved after a short pause
        page.reload()
        expect(page.locator('#case-label')).to_have_text('Case 1 · Phishing, finance team')
        page.locator('#case-menu summary').click()
        expect(page.locator('#case-private-notes')).to_have_value('Ticket SR-7741; called the helpdesk at 10:20.')
        page.locator('#case-menu summary').click()

        # Each case has its own; an unnamed case keeps its number.
        self.switch('#case-next')
        expect(page.locator('#case-label')).to_have_text('Case 2 of 2')
        page.locator('#case-menu summary').click()
        expect(page.locator('#case-name')).to_have_value('')
        expect(page.locator('#case-private-notes')).to_have_value('')
        page.locator('#case-menu summary').click()
        self.switch('#case-prev')
        expect(page.locator('#case-label')).to_have_text('Case 1 · Phishing, finance team')

        # Private notes are never sent: not in the analysis request.
        page.locator('#logs-textarea').fill('{"event":"failed logon"}')
        page.locator('#analyze-btn').click()
        expect(page.locator('#status-text')).to_contain_text('Done!', timeout=20000)
        sent = json.dumps(page.request.get(self.url + '/test/sent').json())
        self.assertNotIn('SR-7741', sent)

        # The archive lists the case by name.
        page.locator('#case-menu summary').click()
        with page.expect_navigation():
            page.locator('#case-archive').click()
        page.locator('#case-menu summary').click()
        expect(page.locator('.case-archive-item')).to_contain_text('A1 · Phishing, finance team')

        # Clearing a case starts it over, name and notes included (the menu is still open).
        page.locator('#case-name').fill('Short-lived')
        expect(page.locator('#case-label')).to_have_text('Case 1 · Short-lived')
        page.locator('#case-menu summary').click()
        page.locator('#clear-btn').click()
        expect(page.locator('#case-label')).to_have_text('Case 1 of 2')
        meta = page.evaluate("() => caseStorage.get('caseMeta').then(stored => stored.caseMeta)")
        self.assertNotIn('name', meta)
        self.assertNotIn('privateNotes', meta)

    def test_archive_is_read_only_and_can_be_restored_or_deleted(self):
        page = self.page
        self.analyst().fill('Archived context')
        page.locator('#enable-ti').check()
        page.wait_for_timeout(400)
        page.locator('#case-menu summary').click()
        with page.expect_navigation():
            page.locator('#case-archive').click()
        # The slot starts a fresh case that keeps the archived case's choices.
        expect(page.locator('#case-label')).to_have_text('Case 1 of 2')
        expect(page.locator('#logs-textarea')).to_have_value('')
        expect(page.locator('#enable-ti')).to_be_checked()

        page.locator('#case-menu summary').click()
        expect(page.locator('.case-archive-item')).to_have_count(1)
        expect(page.locator('.case-archive-item')).to_contain_text('A1')
        expect(page.locator('.case-archive-item')).to_contain_text('1 log')
        with page.expect_navigation():
            page.locator('.case-archive-item').click()
        expect(page.locator('#case-label')).to_have_text('Archived A1')
        expect(page.locator('#archived-banner')).to_be_visible()
        expect(page.locator('#logs-textarea')).to_have_value('password=synthetic-initial')
        expect(self.analyst()).to_have_js_property('readOnly', True)
        for hidden in ('#extract-btn', '#extract-stats-btn', '#clear-btn', '#analyze-btn'):
            expect(page.locator(hidden)).to_be_hidden()
        before = self.storage()
        page.evaluate("() => { document.getElementById('enable-pattern').checked = false; }")
        page.evaluate("() => savePopupPreferences()")
        self.assertEqual(before.get('popupPreferences'), self.storage().get('popupPreferences'))

        # Restoring needs an empty slot: Case 1 is empty after archiving.
        with page.expect_navigation():
            page.locator('#archived-restore').click()
        expect(page.locator('#case-label')).to_have_text('Case 1 of 2')
        expect(page.locator('#logs-textarea')).to_have_value('password=synthetic-initial')
        expect(self.analyst()).to_have_value('Archived context')
        self.assertEqual([], self.index()['archive'])

        # Archive again, then delete it with a confirming second click.
        page.locator('#case-menu summary').click()
        with page.expect_navigation():
            page.locator('#case-archive').click()
        page.locator('#case-menu summary').click()
        with page.expect_navigation():
            page.locator('.case-archive-item').click()
        page.locator('#archived-delete').click()
        expect(page.locator('#archived-delete')).to_have_text('Click again to delete')
        with page.expect_navigation():
            page.locator('#archived-delete').click()
        expect(page.locator('#case-label')).to_have_text('Case 1 of 2')
        self.assertEqual([], self.index()['archive'])
        # The deleted case's data is gone (the test browser re-adds a sample log on every load).
        remaining = self.storage()
        for key in ('analystData', 'popupPreferences', 'caseMeta'):
            self.assertNotIn(key, remaining)
        self.assertEqual([], self.errors)

    def test_restore_needs_an_empty_slot(self):
        page = self.page
        page.locator('#case-menu summary').click()
        with page.expect_navigation():
            page.locator('#case-archive').click()
        page.locator('#logs-textarea').fill('new work in case one')
        self.switch('#case-next')
        page.locator('#logs-textarea').fill('new work in case two')
        page.wait_for_timeout(300)
        page.locator('#case-menu summary').click()
        with page.expect_navigation():
            page.locator('.case-archive-item').click()
        page.locator('#archived-restore').click()
        expect(page.locator('#status-text')).to_contain_text('Every case slot holds work')
        expect(page.locator('#case-label')).to_have_text('Archived A1')

    def test_slot_count_follows_settings_and_keeps_work(self):
        page = self.page
        page.evaluate("() => browser.storage.local.set({caseSlots: 4})")
        page.reload()
        expect(page.locator('#case-label')).to_have_text('Case 1 of 4')
        expect(page.locator('.case-dot')).to_have_count(4)
        page.locator('.case-dot').nth(3).click()
        page.wait_for_load_state()
        expect(page.locator('#case-label')).to_have_text('Case 4 of 4')
        page.locator('#logs-textarea').fill('work in case four')
        page.wait_for_timeout(300)
        self.switch('#case-next')  # wraps around to Case 1
        expect(page.locator('#case-label')).to_have_text('Case 1 of 4')
        page.evaluate("() => browser.storage.local.set({caseSlots: 2})")
        page.reload()
        expect(page.locator('#case-label')).to_have_text('Case 1 of 2')
        page.locator('#case-menu summary').click()
        # Case 4 held work, so it was archived; the empty Case 3 was discarded.
        expect(page.locator('.case-archive-item')).to_have_count(1)
        expect(page.locator('.case-archive-item')).to_contain_text('1 log')

    def test_a_click_survives_a_status_update_of_the_dots(self):
        # Status changes in other cases refresh the dots. A refresh between the
        # press and the release of a click must not swallow the click.
        page = self.page
        expect(page.locator('.case-dot')).to_have_count(2)
        box = page.locator('.case-dot').nth(1).bounding_box()
        page.mouse.move(box['x'] + box['width'] / 2, box['y'] + box['height'] / 2)
        page.mouse.down()
        page.evaluate("() => VeiluxCases.readIndex().then(index => VeiluxCases.storage(index.slots[1]).set({ caseUnseen: true }))")
        expect(page.locator('.case-dot').nth(1)).to_have_attribute('data-state', 'done')
        with page.expect_navigation():
            page.mouse.up()
        expect(page.locator('#case-label')).to_have_text('Case 2 of 2')

    def test_switching_waits_for_an_open_credential_review(self):
        page = self.page
        page.evaluate("() => { reviewReject = () => {}; }")
        page.locator('#case-next').click()
        expect(page.locator('#status-text')).to_contain_text('before switching')
        expect(page.locator('#case-label')).to_have_text('Case 1 of 2')

    def test_native_analysis_finishes_in_its_own_case_while_another_is_open(self):
        with self.native_extension() as native:
            worker = native.service_workers[0] if native.service_workers else native.wait_for_event('serviceworker', timeout=10000)
            extension_id = worker.url.split('/')[2]
            native.route('http://localhost:8000/**', lambda route: route.continue_(
                url=route.request.url.replace('http://localhost:8000', self.url)))
            held = []
            native.route('**/analyze', lambda route: held.append(route))
            worker.evaluate("""() => chrome.storage.local.set({capturedLogs: ['case one event'],
                popupPreferences: {mode: 'sanitize_only', aiProvider: 'groq'}})""")
            popup = native.new_page()
            popup.goto(f'chrome-extension://{extension_id}/popup.html')
            expect(popup.locator('#case-label')).to_have_text('Case 1 of 2')
            popup.locator('#analyze-btn').click()
            for _ in range(100):
                if held:
                    break
                popup.wait_for_timeout(100)
            self.assertTrue(held, 'the analysis request was not sent')
            # The analysis is running in the background; move to Case 2 and work there.
            with popup.expect_navigation():
                popup.locator('#case-next').click()
            expect(popup.locator('#case-label')).to_have_text('Case 2 of 2')
            expect(popup.locator('.case-dot').first).to_have_attribute('data-state', 'running')
            expect(popup.locator('#logs-textarea')).to_have_value('')
            popup.locator('#logs-textarea').fill('case two event')
            held[0].fulfill(json={'analysis': '[Sanitization completed]', 'sanitized_log': 'case one sanitized', 'mapping_table': {}, 'timings_ms': {}})
            expect(popup.locator('.case-dot').first).to_have_attribute('data-state', 'done', timeout=10000)
            expect(popup.locator('#sanitized-textarea')).to_have_value('')
            stored = worker.evaluate('() => chrome.storage.local.get(null)')
            second = stored['casesIndex']['slots'][1]
            self.assertEqual('case one sanitized', stored['lastSanitizedLog'])
            self.assertNotIn('case.' + second + '.lastSanitizedLog', stored)
            self.assertEqual('1', worker.evaluate('() => chrome.action.getBadgeText({})'))
            with popup.expect_navigation():
                popup.locator('#case-prev').click()
            expect(popup.locator('#sanitized-textarea')).to_have_value('case one sanitized')
            expect(popup.locator('.case-dot').first).to_have_attribute('data-state', 'idle')
            self.assertEqual('', worker.evaluate('() => chrome.action.getBadgeText({})'))


if __name__ == '__main__':
    unittest.main()
