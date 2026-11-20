/* Site access. VEILUX reads logs from SIEM pages and talks to its backend
   through the site access ("host permissions") granted to the add-on.
   Firefox lets people switch that off per add-on, and Chrome-based browsers
   let them limit it to "on click" or chosen sites. Without it, extraction,
   page highlighting and connection tests fail with errors that look like
   CORS or permission problems. This shows a banner with a button that asks
   the browser for access again, in the popup and in Settings. */
globalThis.VeiluxSiteAccess = (() => {
  const ORIGINS = ['https://*/*', 'http://*/*'];
  async function granted() {
    try { return !browser.permissions || await browser.permissions.contains({ origins: ORIGINS }); }
    catch (_) { return true; } // a browser that cannot answer is not blocked by us
  }
  // Must run straight from a click: browsers only show the prompt for a user gesture.
  function request() {
    try { return browser.permissions.request({ origins: ORIGINS }); }
    catch (error) { return Promise.reject(error); }
  }
  async function banner(element) {
    if (!element) return;
    const allowed = await granted();
    element.hidden = allowed;
    if (allowed) return;
    element.replaceChildren();
    const text = Object.assign(document.createElement('span'), {
      textContent: 'VEILUX does not have access to websites in this browser, so it cannot read SIEM pages or highlight values. '
        + 'Allow it here, or in your browser\'s extension settings.' });
    const button = Object.assign(document.createElement('button'), { type: 'button', className: 'btn btn-primary btn-small', textContent: 'Allow site access' });
    button.addEventListener('click', () => {
      request().then(ok => { if (ok) element.hidden = true; }).catch(() => {});
    });
    element.append(text, button);
  }
  // Pages that load this file mark their banner with data-site-access.
  const recheck = () => document.querySelectorAll('[data-site-access]').forEach(banner);
  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', recheck); else recheck();
    if (browser.permissions && browser.permissions.onAdded) {
      browser.permissions.onAdded.addListener(recheck);
      browser.permissions.onRemoved?.addListener(recheck);
    }
  }
  return { ORIGINS, granted, request, banner };
})();
