"""The popup shows one stage at a time: Case, Options, Results and Tools.

Other UI tests reach controls through the harness (tests/conftest.py). This
file moves around the way an analyst does and checks what is on screen."""
import re
import unittest
from playwright.sync_api import expect
import test_extension_ui as harness

HASH = '0123456789abcdef' * 4
STATISTIC = """() => appendFieldStatistics({indexPattern: 'auth-*', sampled: 10, total: 10, fields: [{field: 'event.outcome',
    count: 10, percentage: 100, topValues: [{value: 'failure', count: 10, percentage: 100}]}],
    summary: {query: '', filters: [], timeFrame: []}})"""


class StageTests(unittest.TestCase):
    setUpClass = classmethod(harness.ExtensionUITests.setUpClass.__func__)
    tearDownClass = classmethod(harness.ExtensionUITests.tearDownClass.__func__)
    setUp = harness.ExtensionUITests.setUp
    tearDown = harness.ExtensionUITests.tearDown
    install_background = harness.ExtensionUITests.install_background

    def selected(self, name):
        return expect(self.page.locator('#stage-tab-' + name)).to_have_attribute('aria-selected', 'true')

    def test_one_stage_is_shown_and_the_rail_summarizes_the_rest(self):
        page = self.page
        page.set_viewport_size({'width': 760, 'height': 600})
        self.selected('case')
        expect(page.locator('#logs-textarea')).to_be_visible()
        for elsewhere in ('#ai-provider', '#enable-secret-protection', '#ioc-lookup-input', '#results-empty'):
            expect(page.locator(elsewhere)).to_be_hidden()
        expect(page.locator('#stage-sum-case')).to_have_text('1 log')
        expect(page.locator('#stage-sum-options')).to_have_text('Groq')
        expect(page.locator('#stage-sum-results')).to_have_text('None yet')
        # The whole popup fits its window; only the stage scrolls.
        self.assertEqual([600, 600], page.evaluate('[document.scrollingElement.scrollHeight, innerHeight]'))

        page.locator('#stage-tab-options').click()
        self.selected('options')
        expect(page.locator('#ai-provider')).to_be_visible()
        expect(page.locator('#logs-textarea')).to_be_hidden()
        page.locator('input[value="sanitize_only"]').check()
        expect(page.locator('#stage-sum-options')).to_have_text('Sanitize locally')
        page.locator('input[value="ai"]').check()
        page.locator('#enable-ti').check()
        expect(page.locator('#stage-sum-options')).to_have_text('Groq · threat intel')
        page.locator('label[for="enable-secret-protection"]').click()
        expect(page.locator('#stage-sum-options')).to_have_text('Groq · secrets not protected')

        page.locator('#stage-tab-tools').click()
        # Case indicators comes first; the other tools are one tab away.
        expect(page.locator('#indicators-list')).to_be_attached()
        expect(page.locator('#indicators-toggle')).to_have_attribute('aria-selected', 'true')
        expect(page.locator('#ioc-lookup-input')).to_be_hidden()
        page.locator('#ioc-lookup-toggle').click()
        expect(page.locator('#ioc-lookup-input')).to_be_visible()
        expect(page.locator('#defang-input')).to_be_hidden()
        page.locator('#defang-toggle').click()
        expect(page.locator('#defang-input')).to_be_visible()
        expect(page.locator('#ioc-lookup-input')).to_be_hidden()

        # Results explains itself while empty, and leads to Ask and Report.
        page.locator('#stage-tab-results').click()
        expect(page.locator('#results-empty')).to_be_visible()
        expect(page.locator('#results-workspace')).to_be_hidden()
        page.locator('#results-empty-ask').click()
        expect(page.locator('#chat-question')).to_be_focused()
        expect(page.locator('#tab-chat')).to_have_attribute('aria-selected', 'true')
        expect(page.locator('#results-empty')).to_be_hidden()
        # Report is one click away, and details that do not exist are not listed.
        expect(page.locator('#tab-report')).to_be_enabled()
        expect(page.locator('#tab-analysis')).to_be_disabled()
        expect(page.locator('#result-tabs-more')).to_be_hidden()
        page.locator('#tab-report').click()
        expect(page.locator('#report-title')).to_be_visible()

        # The stage is remembered with the case.
        page.reload()
        self.selected('results')
        page.locator('#stage-tab-case').click()
        page.reload()
        self.selected('case')

    def test_buttons_do_not_move_under_the_pointer(self):
        # A button that lifts on hover can flicker between hovered and not
        # hovered under a resting pointer, and never settle for a click.
        page = self.page
        for selector in ('#extract-btn', '#analyze-btn', '#stage-tab-tools'):
            button = page.locator(selector)
            before = button.bounding_box()
            for offset in (before['height'] / 2, before['height'] - 1):
                page.mouse.move(before['x'] + before['width'] / 2, before['y'] + offset)
                page.wait_for_timeout(50)
                self.assertEqual('none', button.evaluate('b => getComputedStyle(b).transform'), selector)
                self.assertEqual(before['y'], button.bounding_box()['y'], selector)

    def test_case_inputs_are_tabs_with_counts(self):
        page = self.page
        expect(page.locator('#logs-toggle')).to_have_attribute('aria-selected', 'true')
        expect(page.locator('#case-count-logs')).to_have_text('1')
        expect(page.locator('#case-count-statistics')).to_be_hidden()
        page.locator('#statistics-toggle').click()
        expect(page.locator('#statistics-empty')).to_be_visible()
        expect(page.locator('#statistics-sample-size')).to_be_visible()
        expect(page.locator('#logs-textarea')).to_be_hidden()
        page.locator('#analyst-data-toggle').click()
        expect(page.locator('#analyst-data-textarea')).to_be_visible()
        expect(page.locator('#statistics-empty')).to_be_hidden()
        page.locator('#analyst-data-textarea').fill('Known scanner.')
        expect(page.locator('#stage-sum-case')).to_have_text('1 log · notes')

        # New statistics bring their tab forward, from any stage.
        page.locator('#stage-tab-options').click()
        page.evaluate(STATISTIC)
        self.selected('case')
        expect(page.locator('#statistics-toggle')).to_have_attribute('aria-selected', 'true')
        expect(page.locator('#statistics-list')).to_be_visible()
        expect(page.locator('#statistics-empty')).to_be_hidden()
        expect(page.locator('#case-count-statistics')).to_have_text('1')
        expect(page.locator('#stage-sum-case')).to_have_text('1 log · 1 statistics · notes')

    def test_credential_review_takes_its_own_stage(self):
        page = self.page
        page.locator('#logs-textarea').fill('{"user":"alice","hash":"' + HASH + '"}')
        expect(page.locator('#stage-tab-review')).to_be_hidden()
        page.locator('#analyze-btn').click()
        expect(page.locator('#secret-review')).to_be_visible(timeout=15000)
        self.selected('review')
        expect(page.locator('#stage-sum-review')).to_have_text('1 value')
        expect(page.locator('#logs-textarea')).to_be_hidden()
        expect(page.locator('#secret-review-continue')).to_be_visible()
        expect(page.locator('#analyze-btn')).to_be_hidden()
        expect(page.locator('#secret-review-decisions')).to_have_text('1 kept · 0 to hide')

        # The case stays reachable while the review waits.
        page.locator('#stage-tab-case').click()
        expect(page.locator('#logs-textarea')).to_be_visible()
        expect(page.locator('#secret-review')).to_be_hidden()
        expect(page.locator('#stage-tab-review')).to_be_visible()
        expect(page.locator('#secret-review-continue')).to_be_visible()
        page.locator('#stage-tab-review').click()
        expect(page.locator('#secret-review')).to_be_visible()

        page.locator('#secret-review-continue').click()
        expect(page.locator('#status-text')).to_contain_text('Done!', timeout=20000)
        expect(page.locator('#stage-tab-review')).to_be_hidden()
        self.selected('results')
        expect(page.locator('#tab-analysis')).to_have_attribute('aria-selected', 'true')
        expect(page.locator('#analysis-output')).to_be_visible()
        expect(page.locator('#stage-sum-results')).to_have_text('Analysis')
        expect(page.locator('#analyze-btn')).to_be_visible()

        # Cancelling a review returns to where the analyst was.
        page.locator('#stage-tab-case').click()
        page.locator('#logs-textarea').fill('{"user":"alice","hash":"' + HASH[::-1] + '"}')
        page.locator('#analyze-btn').click()
        self.selected('review')
        page.locator('#secret-review-cancel').click()
        self.selected('case')
        expect(page.locator('#stage-tab-review')).to_be_hidden()

    def test_dock_shows_only_what_applies(self):
        page = self.page
        expect(page.locator('.manual-actions')).to_be_hidden()
        expect(page.locator('#copy-result-action')).to_be_hidden()
        page.locator('#logs-textarea').fill('authentication for alice from host-7')
        page.locator('#logs-textarea').evaluate(
            "el => { el.focus(); const i = el.value.indexOf('alice'); el.setSelectionRange(i, i + 5); el.dispatchEvent(new Event('select')); }")
        expect(page.locator('#hide-selection-btn')).to_be_visible()
        page.locator('#hide-selection-btn').click()
        expect(page.locator('#undo-hide-btn')).to_be_enabled()
        expect(page.locator('#manual-hide-status')).to_contain_text('replacements')
        page.locator('#undo-hide-btn').click()

        page.locator('#stage-tab-options').click()
        page.locator('input[value="sanitize_only"]').check()
        page.locator('#analyze-btn').click()
        expect(page.locator('#status-text')).to_contain_text('Sanitized!', timeout=20000)
        self.selected('results')
        expect(page.locator('#copy-result-action')).to_be_visible()
        expect(page.locator('#stage-sum-results')).to_have_text('Sanitized')
        # Details appear as they exist; the missing analysis is greyed, not hidden.
        expect(page.locator('#result-tabs-more')).to_be_visible()
        expect(page.locator('#tab-sanitized')).to_be_visible()
        expect(page.locator('#tab-analysis')).to_be_disabled()
        page.locator('#compare-source').click()
        self.selected('case')
        expect(page.locator('#logs-textarea')).to_be_focused()
        expect(page.locator('#copy-result-action')).to_be_hidden()

    def test_long_status_is_short_with_a_more_button(self):
        page = self.page
        page.evaluate("""() => updateStatus('Done! 29.6s · AI 27.2s · protection 1.0s', 'success',
            'Timing: ai: 27.16s · detection: 0.84s · privacy masking: 0.15s · replacement: 0.05s · review: 1.65s · threat intelligence: 0.40s')""")
        more = page.locator('#status-more')
        expect(more).to_be_visible()
        expect(page.locator('#status-text')).to_have_text('Done! 29.6s · AI 27.2s · protection 1.0s')
        more.click()
        expect(page.locator('#status-text')).to_contain_text('threat intelligence: 0.40s')
        expect(more).to_have_text('Less')
        more.click()
        expect(page.locator('#status-text')).not_to_contain_text('threat intelligence')
        # A short message needs no button.
        page.evaluate("() => updateStatus('Ready', 'info')")
        expect(more).to_be_hidden()
        # A long error is clipped to two lines and opens in full.
        page.evaluate("() => updateStatus('Statistics: ' + 'None of the records could be read. '.repeat(8), 'error')")
        expect(more).to_be_visible()
        more.click()
        self.assertEqual(8, page.locator('#status-text').text_content().count('None of the records'))

    def test_analysis_status_is_one_short_line(self):
        page = self.page
        page.locator('#analyze-btn').click()
        expect(page.locator('#status-text')).to_contain_text('Done!', timeout=20000)
        text = page.locator('#status-text').text_content()
        self.assertRegex(text, r'^Done! \d+\.\ds')
        self.assertNotIn('replacement', text)
        page.locator('#status-more').click()
        expect(page.locator('#status-text')).to_contain_text('replacement:')

    def test_interrupted_review_is_offered_back_and_can_be_dropped(self):
        page = self.page
        page.evaluate("""() => caseSession.set({reviewDraft: {kind: 'analysis', savedAt: Date.now(), values: ['a', 'b'], unchecked: ['b'], pages: []}})""")
        page.reload()
        banner = page.locator('#review-interrupted')
        expect(banner).to_be_visible()
        expect(page.locator('#review-interrupted-text')).to_contain_text('2 values still to check')
        page.locator('#review-interrupted-drop').click()
        expect(banner).to_be_hidden()
        self.assertIsNone(page.evaluate("() => caseSession.get('reviewDraft').then(s => s.reviewDraft)"))
        page.reload()
        expect(banner).to_be_hidden()

    def test_site_access_banner_asks_the_browser_again(self):
        page = self.page
        banner = page.locator('#site-access')
        expect(banner).to_be_hidden()
        # Firefox lets people switch off an add-on's site access.
        page.evaluate("""() => { window.granted = false; browser.permissions = {
            contains: async () => window.granted,
            request: async request => { window.requested = request.origins; window.granted = true; return true; } };
            return VeiluxSiteAccess.banner(document.getElementById('site-access')); }""")
        expect(banner).to_be_visible()
        expect(banner).to_contain_text('does not have access to websites')
        banner.get_by_role('button', name='Allow site access').click()
        expect(banner).to_be_hidden()
        self.assertEqual(['https://*/*', 'http://*/*'], page.evaluate('window.requested'))

    def test_popup_fills_whatever_window_the_browser_opens(self):
        # VEILUX asks for 720x600. Firefox can open the popup narrower (little
        # room on screen) or wider, and any browser can make it shorter. The
        # content is pinned to the real window, so nothing is cut off or left blank.
        page = self.page
        box = "() => { const r = document.querySelector('.container').getBoundingClientRect(); return [r.width, r.height, r.left, r.top]; }"
        for width, height in ((800, 600), (720, 600), (580, 600), (460, 600), (460, 480), (380, 560)):
            with self.subTest(width=width, height=height):
                page.set_viewport_size({'width': width, 'height': height})
                self.assertEqual([width, height, 0, 0], page.evaluate(box))
                for control in ('#settings-btn', '#case-next', '#stage-tab-tools', '#analyze-btn', '#ask-btn', '#extract-btn', '#clear-btn'):
                    expect(page.locator(control)).to_be_in_viewport(ratio=1)
                # The toolbar and the action bar each stay on one row.
                tops = page.evaluate("""() => ['extract-btn', 'extract-stats-btn', 'clear-btn', 'ask-btn', 'report-btn', 'analyze-btn']
                    .map(id => Math.round(document.getElementById(id).getBoundingClientRect().top))""")
                if width >= 460:
                    self.assertEqual(1, len(set(tops[:3])), tops)
                self.assertEqual(1, len(set(tops[3:])), tops)
                # The size the popup asks the browser for does not follow the window.
                self.assertEqual([720, 600], page.evaluate('[document.documentElement.offsetWidth, document.documentElement.offsetHeight]'))
        # Never larger than the biggest popup browsers allow.
        page.set_viewport_size({'width': 1000, 'height': 900})
        self.assertEqual([800, 600], page.evaluate(box)[:2])

    def test_popup_has_the_natural_size_firefox_measures(self):
        """Firefox opens a toolbar popup at the natural size of its content,
        which shows when the page shrinks to fit it. Content that is only
        position: fixed measures as zero and Firefox opened an empty sliver;
        content in normal flow without a fixed size measured 470-520px wide.
        It must be the requested 720x600 at any window size."""
        page = self.page
        natural = """() => { const html = document.documentElement, old = [html.style.width, html.style.height];
            html.style.width = 'max-content'; html.style.height = 'max-content';
            const box = html.getBoundingClientRect(); html.style.width = old[0]; html.style.height = old[1];
            return [Math.round(box.width), Math.round(box.height)]; }"""
        for width, height in ((800, 600), (720, 600), (460, 480)):
            with self.subTest(width=width, height=height):
                page.set_viewport_size({'width': width, 'height': height})
                self.assertEqual([720, 600], page.evaluate(natural))

    def test_long_status_opens_on_its_own_row(self):
        page = self.page
        page.evaluate("() => updateStatus('Extracted 6 log(s) from Test page (1 failed: For id=2F3F71931EDA9ABB: API returned HTTP 404. '"
                      " + 'Check the address, sign-in and request settings.) [configured API request]', 'success')")
        expect(page.locator('#status-text')).not_to_have_attribute('title', re.compile('.'))
        page.locator('#status-more').click()
        status, buttons = page.locator('#status-text').bounding_box(), page.locator('#main-actions').bounding_box()
        # The full message sits above the buttons instead of squeezing them.
        self.assertLessEqual(status['y'] + status['height'], buttons['y'])
        expect(page.locator('#analyze-btn')).to_be_in_viewport(ratio=1)

    def test_ai_answers_cannot_add_markup(self):
        page = self.page
        page.evaluate("""() => applyAnalysisState({lastAnalysisMode: 'groq',
            lastAnalysis: '**Verdict** <img src=x id=injected><b id=bold>raw</b>\\n- item'})""")
        output = page.locator('#analysis-output')
        expect(output.locator('strong')).to_have_text('Verdict')
        expect(output.locator('li')).to_have_text('item')
        expect(output.locator('#injected')).to_have_count(0)
        expect(output.locator('#bold')).to_have_count(0)
        expect(output).to_contain_text('<img src=x id=injected>')

    def test_rail_works_from_the_keyboard(self):
        page = self.page
        page.locator('#stage-tab-case').focus()
        page.keyboard.press('ArrowRight')
        self.selected('options')
        expect(page.locator('#stage-tab-options')).to_be_focused()
        page.keyboard.press('End')
        self.selected('tools')
        page.keyboard.press('Home')
        self.selected('case')


if __name__ == '__main__':
    unittest.main()
