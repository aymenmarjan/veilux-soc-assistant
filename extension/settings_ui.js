/* Settings page navigation, accessibility, field errors and the "unsaved changes"
   indicator. Each editor saves its own data. */
window.VeiluxSettingsUI = (() => {
  let baseline = null;
  const editors = new Map();
  const main = document.getElementById('settings-main');
  const status = document.getElementById('settings-save-state');
  function snapshot(settings = collectMainSettings()) {
    // Prompts already save through their own controls; they must not conceal
    // unrelated unsaved changes to API keys or protection settings.
    const { customPrompts, defaultPromptId, ...general } = settings;
    return JSON.stringify(general);
  }
  const fields = editor => JSON.stringify(Array.from(editor.querySelectorAll('input,select,textarea')).map(el =>
    [el.id, el.type === 'checkbox' || el.type === 'radio' ? el.checked : el.value]));
  function editorChanges() {
    const visible = new Set(main.querySelectorAll('#connector-form.visible,#custom-model-form.visible,#add-prompt-form.visible,.prompt-item.editing,#report-editor.visible'));
    for (const editor of visible) if (!editors.has(editor)) editors.set(editor, fields(editor));
    for (const editor of editors.keys()) if (!visible.has(editor)) editors.delete(editor);
    return Array.from(editors).some(([editor, initial]) => fields(editor) !== initial);
  }
  const pendingEntry = () => ['new-cidr','new-domain','new-json-key','new-statistics-field','new-keyword','new-replacement','regex-name','rule-target']
    .some(id => document.getElementById(id).value.trim());
  function dirty() { return baseline !== null && (snapshot() !== baseline || editorChanges() || pendingEntry()); }
  function sync() {
    enhanceLabels();
    if (baseline === null) return;
    const general = snapshot() !== baseline, editor = editorChanges(), entry = pendingEntry();
    status.textContent = general ? 'Unsaved settings changes' + (editor || entry ? ' · Finish open editors too' : '')
      : editor ? 'Unsaved editor changes — use its Save button'
      : entry ? 'Draft entry — use Add / Save changes to apply it, then Save settings'
      : 'Settings saved';
    status.style.color = general || editor || entry ? 'var(--warning)' : 'var(--text)';
  }
  function saved(value = snapshot()) { baseline = value; sync(); }
  // One setting saved on its own (such as the backend key after pairing),
  // without marking other unsaved edits as saved.
  function savedField(name, value) {
    if (baseline === null) return;
    const parsed = JSON.parse(baseline);
    parsed[name] = value;
    baseline = JSON.stringify(parsed);
    sync();
  }
  function enhanceLabels() {
    main.querySelectorAll('.form-group').forEach(group => {
      const label = group.querySelector('label'), field = group.querySelector('input[id],textarea[id],select[id]');
      if (label && field && !label.htmlFor && !label.querySelector('input')) label.htmlFor = field.id;
    });
    main.querySelectorAll('.list-item,.prompt-item').forEach(row => {
      const name = row.querySelector('.list-item-key,.prompt-title')?.textContent || 'item';
      row.querySelectorAll('input[type=checkbox]').forEach(input => {
        if (!input.labels?.length && !input.hasAttribute('aria-label')) input.setAttribute('aria-label', 'Enable ' + name);
      });
      row.querySelectorAll('button').forEach(button => {
        if (button.hasAttribute('aria-label')) return;
        if (/🗑|remove-|delete-/.test(button.textContent + button.className)) button.setAttribute('aria-label', 'Remove ' + name);
        else if (/✏|edit-/.test(button.textContent + button.className)) button.setAttribute('aria-label', 'Edit ' + name);
      });
    });
  }
  const observer = new MutationObserver(sync);
  observer.observe(main, { subtree:true, childList:true, attributes:true, attributeFilter:['class','style'] });
  document.addEventListener('input', sync);
  document.addEventListener('change', sync);
  document.addEventListener('click', () => queueMicrotask(sync));
  window.addEventListener('beforeunload', event => {
    if (dirty()) { event.preventDefault(); event.returnValue = ''; }
  });
  window.addEventListener('pagehide', () => observer.disconnect(), { once:true });
  const links = Array.from(document.querySelectorAll('.settings-nav a'));
  function markSection() {
    const hash = location.hash || '#connections';
    links.forEach(link => {
      if (link.hash === hash) link.setAttribute('aria-current','location');
      else link.removeAttribute('aria-current');
    });
  }
  window.addEventListener('hashchange', markSection); markSection();
  return { snapshot, saved, savedField, sync };
})();

function fieldError(field, message) {
  const el = typeof field === 'string' ? document.getElementById(field) : field;
  if (!el) return;
  for (let parent = el.parentElement; parent; parent = parent.parentElement) if (parent.tagName === 'DETAILS') parent.open = true;
  const id = el.id + '-error';
  let error = document.getElementById(id);
  if (!error) {
    error = document.createElement('p'); error.id = id; error.className = 'field-error'; error.setAttribute('role','alert');
    el.insertAdjacentElement('afterend',error);
  }
  error.textContent = message;
  el.setAttribute('aria-invalid','true');
  el.setAttribute('aria-describedby', Array.from(new Set((el.getAttribute('aria-describedby') || '').split(' ').filter(Boolean).concat(id))).join(' '));
  el.focus();
  el.scrollIntoView({ block:'center' });
}
function clearFieldError(field) {
  const el = typeof field === 'string' ? document.getElementById(field) : field;
  if (!el.id || !el.hasAttribute('aria-invalid')) return;
  const id = el.id + '-error';
  document.getElementById(id)?.remove();
  el.removeAttribute('aria-invalid');
  const remaining = (el.getAttribute('aria-describedby') || '').split(' ').filter(name => name !== id).join(' ');
  if (remaining) el.setAttribute('aria-describedby',remaining); else el.removeAttribute('aria-describedby');
}
document.addEventListener('input', event => clearFieldError(event.target));
