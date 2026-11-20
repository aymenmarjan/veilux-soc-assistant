"""Settings -> Lessons: approve, edit and delete corrections sent from the popup."""
import unittest
from playwright.sync_api import expect
import test_extension_ui as harness
from backend_key import AUTH


class LessonsUITests(unittest.TestCase):
    setUpClass = classmethod(harness.ExtensionUITests.setUpClass.__func__)
    tearDownClass = classmethod(harness.ExtensionUITests.tearDownClass.__func__)
    setUp = harness.ExtensionUITests.setUp
    tearDown = harness.ExtensionUITests.tearDown
    install_background = harness.ExtensionUITests.install_background

    def test_lessons_can_be_approved_edited_and_deleted(self):
        self.page.request.post(self.url + '/feedback', data={'original_log': 'event', 'ai_response': 'answer',
                                                             'user_correction': 'Backups at 02:00 are expected'}, headers=AUTH)
        page = self.page
        page.goto(self.url + '/extension/settings.html#lessons')
        pending = page.locator('#lessons-pending .lesson-card')
        expect(pending).to_have_count(1)
        expect(pending).to_contain_text('Backups at 02:00 are expected')
        expect(page.locator('#lessons-approved')).to_contain_text('No approved lessons yet')
        pending.get_by_role('button', name='Approve').click()
        approved = page.locator('#lessons-approved .lesson-card')
        expect(approved).to_have_count(1)
        expect(page.locator('#lessons-status')).to_contain_text('approved')
        expect(page.locator('#lessons-pending')).to_contain_text('No corrections are waiting')
        approved.get_by_role('button', name='Edit').click()
        page.locator('.lesson-edit').fill('Nightly backups at 02:00 are expected maintenance')
        page.get_by_role('button', name='Save', exact=True).click()
        expect(approved).to_contain_text('Nightly backups at 02:00 are expected maintenance')
        lessons = page.request.get(self.url + '/lessons', headers=AUTH).json()['lessons']
        self.assertEqual(['approved'], [lesson['status'] for lesson in lessons])
        approved.get_by_role('button', name='Delete').click()
        approved.get_by_role('button', name='Click again to delete').click()
        expect(page.locator('#lessons-approved')).to_contain_text('No approved lessons yet')
        self.assertEqual([], page.request.get(self.url + '/lessons', headers=AUTH).json()['lessons'])

    def test_popup_correction_is_saved_as_a_pending_lesson(self):
        page = self.page
        page.evaluate("() => applyAnalysisState({lastAnalysis: 'answer', lastAnalysisMode: 'groq'})")
        page.locator('#feedback-details summary').click()
        page.locator('#correction-textarea').fill('This host is a scanner')
        page.locator('#submit-feedback-btn').click()
        expect(page.locator('#status-text')).to_contain_text('pending lesson')
        lessons = page.request.get(self.url + '/lessons', headers=AUTH).json()['lessons']
        self.assertEqual([('pending', 'This host is a scanner')], [(l['status'], l['lesson']) for l in lessons])


if __name__ == '__main__':
    unittest.main()
