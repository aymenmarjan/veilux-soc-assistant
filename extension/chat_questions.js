/* Quick questions offered above the Ask box in the popup. Edited in
   Settings -> Prompts and stored in this browser; the defaults apply until
   the list is changed. */
globalThis.VeiluxQuickQuestions = (() => {
  const KEY = 'chatQuickQuestions';
  const DEFAULTS = [
    'Build a timeline of the key events.',
    'Write a containment plan for this case.',
    'Could this be a false positive? Explain why or why not.',
    'Draft a short reply to the client about this alert.'];
  const clean = list => (Array.isArray(list) ? list : []).map(q => String(q || '').trim()).filter(Boolean).slice(0, 12);
  async function load() {
    const stored = await browser.storage.local.get(KEY);
    return Array.isArray(stored[KEY]) ? clean(stored[KEY]) : DEFAULTS.slice();
  }
  const save = list => browser.storage.local.set({ [KEY]: clean(list) });
  const reset = () => browser.storage.local.remove(KEY);
  return { KEY, DEFAULTS, load, save, reset };
})();
