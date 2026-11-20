"""Appearance: light theme by default; Settings switches the popup and Settings to dark."""
import unittest
from playwright.sync_api import expect
import test_extension_ui as harness


class ThemeTests(unittest.TestCase):
    setUpClass = classmethod(harness.ExtensionUITests.setUpClass.__func__)
    tearDownClass = classmethod(harness.ExtensionUITests.tearDownClass.__func__)
    setUp = harness.ExtensionUITests.setUp
    tearDown = harness.ExtensionUITests.tearDown
    install_background = harness.ExtensionUITests.install_background

    def background(self, page):
        return page.evaluate("getComputedStyle(document.body).backgroundColor")

    def test_light_by_default_and_dark_from_settings(self):
        page = self.page
        expect(page.locator('html')).to_have_attribute('data-theme', 'light')
        self.assertEqual('rgb(241, 245, 249)', self.background(page))
        page.goto(self.url + '/extension/settings.html#appearance')
        expect(page.locator('#dark-mode')).not_to_be_checked()
        page.locator('label.toggle-switch:has(#dark-mode)').click()
        expect(page.locator('html')).to_have_attribute('data-theme', 'dark')
        self.assertEqual('rgb(11, 18, 32)', self.background(page))
        self.assertEqual('dark', page.evaluate("() => browser.storage.local.get('theme').then(s => s.theme)"))
        # Settings "Save settings" is not needed and nothing reads as unsaved.
        expect(page.locator('#settings-save-state')).to_have_text('Settings saved')
        page.goto(self.url + '/extension/popup.html')
        expect(page.locator('html')).to_have_attribute('data-theme', 'dark')
        page.goto(self.url + '/extension/settings.html#appearance')
        expect(page.locator('#dark-mode')).to_be_checked()
        page.locator('label.toggle-switch:has(#dark-mode)').click()
        expect(page.locator('html')).to_have_attribute('data-theme', 'light')

    def test_logo_is_a_framed_portrait_and_settings_has_no_about_section(self):
        page = self.page
        logo = page.locator('.brand-logo')
        self.assertEqual('icons/logo-portrait.png', logo.get_attribute('src'))
        # A portrait: the bust fills the framed box and meets its bottom edge.
        style = logo.evaluate("e => { const s = getComputedStyle(e); return [s.objectFit, s.objectPosition, s.paddingTop, s.borderTopWidth]; }")
        self.assertEqual(['cover', '50% 100%', '0px', '1px'], style)
        page.goto(self.url + '/extension/settings.html')
        expect(page.locator('#about')).to_have_count(0)
        expect(page.locator('.settings-nav')).not_to_contain_text('About')


if __name__ == '__main__':
    unittest.main()
