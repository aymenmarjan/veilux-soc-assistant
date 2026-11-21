/* Model choice for the built-in AI providers (Groq, DeepSeek, Together AI,
   Gemini and Claude), shared by Settings and the popup.
   VEILUX has no built-in model IDs: providers retire and rename models, so a
   fixed ID eventually fails for everyone. "Load models" asks the local backend,
   which reads the provider's own model list using only the API key: no logs,
   notes or prompts are sent. The analyst's choice is saved as
   providerModels[provider] = {id, name}; nothing is ever chosen or swapped
   automatically. */
globalThis.VeiluxProviderModels = (() => {
  const KEY = 'providerModels';
  const PROVIDERS = { groq: 'Groq', deepseek: 'DeepSeek', together: 'Together AI', gemini: 'Gemini', claude: 'Claude' };
  const VALID_ID = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$/;

  async function all(store = browser.storage.local) {
    const stored = await store.get([KEY]);
    const value = stored[KEY];
    return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  }
  async function current(provider, store = browser.storage.local) {
    const model = (await all(store))[provider];
    return model && typeof model.id === 'string' && VALID_ID.test(model.id) ? model : null;
  }
  async function choose(provider, model, store = browser.storage.local) {
    const models = { ...(await all(store)) };
    if (model) models[provider] = { id: model.id, name: model.name || model.id };
    else delete models[provider];
    await store.set({ [KEY]: models });
  }
  function missingMessage(provider) {
    const name = PROVIDERS[provider] || provider;
    return 'Choose a ' + name + ' model first: Settings → Providers and API keys → ' + name + ' model → Load models.';
  }

  // The provider's current model list for this key. `extra` carries a custom
  // model's connection details (provider "custom").
  async function list(provider, apiKey, extra = {}) {
    const response = await VeiluxBackend.fetch('/providers/' + encodeURIComponent(provider) + '/models', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ api_key: apiKey || null, ...extra }), signal: AbortSignal.timeout(30000)
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = typeof data.detail === 'string' ? data.detail
        : Array.isArray(data.detail) ? data.detail.map(item => item.msg || 'Invalid setting').join('; ') : '';
      throw new Error(detail || 'The model list could not be read (HTTP ' + response.status + ').');
    }
    return Array.isArray(data.models) ? data.models : [];
  }
  function failureText(error) {
    return error.name === 'TimeoutError' ? 'The provider did not answer in time.'
      : error instanceof TypeError ? 'Could not reach the VEILUX backend. Start it and check Settings → Backend.'
      : error.message;
  }
  const label = m => (m.name && m.name !== m.id ? m.name + ' — ' : '') + m.id
    + (Number.isInteger(m.context_length) ? ' · ' + Math.round(m.context_length / 1000) + 'K context' : '');

  function el(tag, props = {}, ...children) {
    const node = Object.assign(document.createElement(tag), props);
    node.append(...children);
    return node;
  }

  // Builds the picker for one provider inside `root`; `keyInput` is the
  // provider's API key field (the key is read when Load models is pressed).
  function mount(root, { provider, keyInput, onChange = () => {} }) {
    const name = PROVIDERS[provider];
    const id = part => provider + '-model-' + part;
    let models = [];
    const currentLine = el('p', { className: 'or-current', id: id('current'), role: 'status' });
    const load = el('button', { type: 'button', className: 'btn btn-secondary btn-small', id: id('load'), textContent: 'Load models' });
    const status = el('p', { className: 'field-hint', id: id('status'), role: 'status' });
    const select = el('select', { id: id('list') });
    const use = el('button', { type: 'button', className: 'btn btn-primary btn-small', id: id('use'), textContent: 'Use this model' });
    const results = el('div', { className: 'or-results', hidden: true },
      el('label', { htmlFor: id('list'), textContent: name + ' models for this key' }), select, use);
    const manualInput = el('input', { type: 'text', id: id('manual'), placeholder: 'Model ID exactly as ' + name + ' lists it' });
    const manualUse = el('button', { type: 'button', className: 'btn btn-secondary btn-small', id: id('manual-use'), textContent: 'Use this ID' });
    const manual = el('details', { className: 'or-manual' },
      el('summary', { textContent: 'Enter a model ID' }),
      el('label', { htmlFor: id('manual'), textContent: name + ' model ID' }), manualInput, manualUse);
    const note = el('p', { className: 'field-hint', textContent:
      'Load models sends only the API key to ' + name + ', never logs. The list shows what this key can use today.' });
    root.replaceChildren(el('div', { className: 'or-row' }, el('strong', { textContent: name + ' model' })),
      currentLine, el('div', { className: 'or-actions' }, load), status, results, manual, note);

    async function showCurrent() {
      const chosen = await current(provider);
      currentLine.replaceChildren(chosen
        ? el('span', {}, 'Current model: ', el('code', { textContent: chosen.id }))
        : el('span', { textContent: 'No ' + name + ' model chosen yet. Load models and choose one.' }));
    }
    async function set(model) {
      await choose(provider, model);
      await showCurrent();
      status.textContent = 'Saved. Analyses with ' + name + ' now use ' + model.id + '.';
      onChange(provider, model);
    }
    async function lookup() {
      const apiKey = keyInput.value.trim();
      if (!apiKey) { status.textContent = 'Enter the ' + name + ' API key first.'; keyInput.focus(); return; }
      load.disabled = true; status.textContent = 'Asking ' + name + ' which models this key can use…';
      try {
        models = await list(provider, apiKey);
        const chosen = await current(provider);
        select.replaceChildren(...models.map(m => new Option(label(m), m.id)));
        if (chosen && models.some(m => m.id === chosen.id)) select.value = chosen.id;
        results.hidden = !models.length;
        status.textContent = !models.length ? name + ' listed no chat models for this key.'
          : models.length + ' model' + (models.length === 1 ? '' : 's') + ' available.'
            + (chosen && !models.some(m => m.id === chosen.id)
              ? ' The current model ' + chosen.id + ' is not in the list any more: choose another one.' : '');
      } catch (error) {
        status.textContent = failureText(error);
      } finally { load.disabled = false; }
    }
    load.addEventListener('click', lookup);
    use.addEventListener('click', () => { const m = models.find(x => x.id === select.value); if (m) set(m); });
    manualUse.addEventListener('click', () => {
      const value = manualInput.value.trim();
      if (!VALID_ID.test(value)) { status.textContent = 'Enter the model ID exactly as ' + name + ' lists it.'; manualInput.focus(); return; }
      set(models.find(m => m.id === value) || { id: value, name: value });
      manualInput.value = '';
    });
    showCurrent();
    return { lookup, refresh: showCurrent };
  }

  return { KEY, PROVIDERS, VALID_ID, all, current, choose, list, failureText, missingMessage, mount };
})();
