/* Light theme by default; Settings -> Appearance switches to dark. The choice
   is saved in extension storage ("theme"), with a copy in this page's
   localStorage so it applies before the page first paints. Open pages follow
   a change straight away. */
(() => {
  const api = globalThis.browser || globalThis.chrome;
  const apply = theme => {
    const value = theme === 'dark' ? 'dark' : 'light';
    document.documentElement.dataset.theme = value;
    try { localStorage.setItem('veiluxTheme', value); } catch (_) {}
  };
  let cached = null;
  try { cached = localStorage.getItem('veiluxTheme'); } catch (_) {}
  apply(cached);
  if (!api || !api.storage) return;
  Promise.resolve(api.storage.local.get('theme')).then(stored => apply(stored && stored.theme)).catch(() => {});
  api.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes.theme) apply(changes.theme.newValue);
  });
})();
