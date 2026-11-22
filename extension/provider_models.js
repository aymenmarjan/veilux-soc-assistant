/* Model choice and generation settings for the built-in AI providers (Groq,
   DeepSeek, Together AI, Gemini and Claude), shared by Settings and the popup.
   VEILUX has no built-in model IDs: providers retire and rename models, so a
   fixed ID eventually fails for everyone. "Load models" asks the local backend,
   which reads the provider's own model list using only the API key: no logs,
   notes or prompts are sent. The analyst's choice is saved as
   providerModels[provider] = {id, name, and the limits the list reported};
   nothing is ever chosen or swapped automatically.
   Advanced settings are saved as providerGeneration[provider] =
   {max_output_tokens, thinking, effort}; see generationFor. */
globalThis.VeiluxProviderModels = (() => {
  const KEY = 'providerModels', GENERATION_KEY = 'providerGeneration';
  const PROVIDERS = { groq: 'Groq', deepseek: 'DeepSeek', together: 'Together AI', gemini: 'Gemini', claude: 'Claude' };
  const VALID_ID = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$/;
  // Reasoning models count their thinking in the output limit, so the old
  // 4,000 could be spent before any answer. Lowered to the model's own maximum
  // when its provider reports a smaller one. Matches the backend's default.
  const DEFAULT_OUTPUT_TOKENS = 16384, MAX_OUTPUT_TOKENS = 1000000;
  // What the provider's model list says about a model, kept with the choice.
  const REPORTED = ['max_output_tokens', 'efforts', 'default_effort', 'thinking_switch'];

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
    if (model) {
      models[provider] = { id: model.id, name: model.name || model.id };
      REPORTED.forEach(field => { if (model[field] != null) models[provider][field] = model[field]; });
    } else delete models[provider];
    await store.set({ [KEY]: models });
  }
  function missingMessage(provider) {
    const name = PROVIDERS[provider] || provider;
    return 'Choose a ' + name + ' model first: Settings → Providers and API keys → ' + name + ' → Load models.';
  }

  async function savedGeneration(provider, store = browser.storage.local) {
    const value = (await store.get([GENERATION_KEY]))[GENERATION_KEY];
    const saved = value && typeof value === 'object' && !Array.isArray(value) ? value[provider] : null;
    return saved && typeof saved === 'object' ? saved : {};
  }
  async function saveGeneration(provider, settings, store = browser.storage.local) {
    const value = (await store.get([GENERATION_KEY]))[GENERATION_KEY];
    const next = { ...(value && typeof value === 'object' && !Array.isArray(value) ? value : {}) };
    const kept = Object.fromEntries(Object.entries(settings).filter(([, v]) => v !== '' && v != null && v !== 'default'));
    if (Object.keys(kept).length) next[provider] = kept; else delete next[provider];
    await store.set({ [GENERATION_KEY]: next });
  }

  const reportedMax = model => Number.isInteger(model?.max_output_tokens) && model.max_output_tokens > 0 ? model.max_output_tokens : null;
  const efforts = model => Array.isArray(model?.efforts) ? model.efforts.filter(e => typeof e === 'string') : [];

  // What the analysis sends: the saved settings that the chosen model
  // supports. A saved limit above the model's reported maximum is lowered to
  // it (the provider would refuse the request); nothing is ever raised.
  function generationFor(model, saved = {}) {
    const max = reportedMax(model);
    const chosen = Number.isInteger(saved.max_output_tokens) && saved.max_output_tokens > 0 ? saved.max_output_tokens : null;
    const result = { max_output_tokens: Math.min(chosen || DEFAULT_OUTPUT_TOKENS, max || MAX_OUTPUT_TOKENS) };
    if (model?.thinking_switch && (saved.thinking === 'on' || saved.thinking === 'off')) result.thinking = saved.thinking;
    if (result.thinking !== 'off' && efforts(model).includes(saved.effort)) result.effort = saved.effort;
    return result;
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

  // Test connection: the key must list models, and the chosen model must be
  // one of them. No prompt or log is sent.
  async function check(provider, apiKey) {
    if (!apiKey) return { state: 'skip', message: 'No key' };
    try {
      const models = await list(provider, apiKey);
      const chosen = await current(provider);
      if (!chosen) return { state: 'skip', message: '⚠ Key works · ' + models.length + ' models · choose a model' };
      if (models.some(m => m.id === chosen.id)) return { state: 'success', message: '✓ OK · ' + chosen.id };
      return { state: 'error', message: '✗ Key works, but ' + chosen.id + ' is not available. Choose another model.' };
    } catch (error) {
      return { state: 'error', message: '✗ ' + failureText(error) };
    }
  }

  const thousands = n => n.toLocaleString('en-US');
  const label = m => (m.name && m.name !== m.id ? m.name + ' — ' : '') + m.id
    + (Number.isInteger(m.context_length) ? ' · ' + Math.round(m.context_length / 1000) + 'K context' : '');

  function el(tag, props = {}, ...children) {
    const node = Object.assign(document.createElement(tag), props);
    node.append(...children);
    return node;
  }

  // Advanced settings for one provider inside `root`. `model()` returns the
  // chosen model (with what its list reported), or null. Thinking and effort
  // appear only when the model reports that it supports them. Saves on change.
  function mountAdvanced(root, { provider, name, model }) {
    const id = part => provider + '-gen-' + part;
    const status = el('p', { className: 'field-hint', id: id('status'), role: 'status' });
    const maxInput = el('input', { type: 'number', id: id('max'), min: 1, max: MAX_OUTPUT_TOKENS, step: 1, inputMode: 'numeric' });
    const maxHint = el('p', { className: 'field-hint', id: id('max-hint') });
    maxInput.setAttribute('aria-describedby', maxHint.id);
    const thinking = el('select', { id: id('thinking') });
    [['default', 'Model default'], ['on', 'On'], ['off', 'Off']].forEach(([v, t]) => thinking.add(new Option(t, v)));
    const thinkingRow = el('div', { className: 'form-group', hidden: true },
      el('label', { htmlFor: id('thinking'), textContent: 'Thinking' }), thinking);
    const effort = el('select', { id: id('effort') });
    const effortRow = el('div', { className: 'form-group', hidden: true },
      el('label', { htmlFor: id('effort'), textContent: 'Reasoning effort' }), effort,
      el('p', { className: 'field-hint', textContent: 'More effort can give a better answer, but uses more of the output limit and takes longer.' }));
    const unknown = el('p', { className: 'field-hint', hidden: true });
    root.replaceChildren(el('details', { className: 'provider-advanced', id: id('details') },
      el('summary', { textContent: 'Advanced' }),
      el('div', { className: 'form-group' },
        el('label', { htmlFor: id('max'), textContent: 'Maximum output tokens' }), maxInput, maxHint),
      thinkingRow, effortRow, unknown, status));

    async function render() {
      const chosen = await model();
      const saved = await savedGeneration(provider);
      const max = reportedMax(chosen);
      const sent = generationFor(chosen, saved).max_output_tokens;
      maxInput.max = max || MAX_OUTPUT_TOKENS;
      maxInput.placeholder = thousands(Math.min(DEFAULT_OUTPUT_TOKENS, max || MAX_OUTPUT_TOKENS)) + ' (default)';
      maxInput.value = Number.isInteger(saved.max_output_tokens) ? saved.max_output_tokens : '';
      maxHint.textContent = 'Includes any thinking the model does before it answers. '
        + (max ? (chosen.id + ' allows up to ' + thousands(max) + '. ') : '')
        + (saved.max_output_tokens && sent < saved.max_output_tokens ? 'Analyses use ' + thousands(sent) + ', this model\'s maximum. ' : '')
        + 'Leave empty for the default.';
      thinkingRow.hidden = !chosen?.thinking_switch;
      thinking.value = ['on', 'off'].includes(saved.thinking) ? saved.thinking : 'default';
      const levels = efforts(chosen);
      effort.replaceChildren(new Option('Model default' + (chosen?.default_effort ? ' (' + chosen.default_effort + ')' : ''), ''),
        ...levels.map(level => new Option(level[0].toUpperCase() + level.slice(1), level)));
      effort.value = levels.includes(saved.effort) ? saved.effort : '';
      effortRow.hidden = !levels.length;
      effort.disabled = thinking.value === 'off' && !thinkingRow.hidden;
      unknown.hidden = !chosen || !!(levels.length || chosen.thinking_switch || max);
      unknown.textContent = 'Load models and choose the model from the list to see its limits and reasoning settings.';
    }
    async function save() {
      const value = maxInput.value.trim();
      const number = Number(value);
      const limit = Number(maxInput.max);
      if (value && (maxInput.validity.badInput || !Number.isInteger(number) || number < 1 || number > limit)) {
        status.textContent = 'Enter a whole number from 1 to ' + thousands(limit) + ', or leave it empty for the default.';
        return;
      }
      await saveGeneration(provider, { max_output_tokens: value ? number : null,
        thinking: thinkingRow.hidden ? null : thinking.value, effort: effortRow.hidden ? null : effort.value });
      await render();
      status.textContent = 'Saved. Analyses with ' + name + ' use these settings.';
    }
    maxInput.addEventListener('change', save);
    thinking.addEventListener('change', save);
    effort.addEventListener('change', save);
    render();
    return { refresh: render };
  }

  // Builds the picker for one provider inside `root`; `keyInput` is the
  // provider's API key field (the key is read when Load models or Test
  // connection is pressed). `advanced`, when given, is where the Advanced
  // settings go.
  function mount(root, { provider, keyInput, advanced = null, onChange = () => {} }) {
    const name = PROVIDERS[provider];
    const id = part => provider + '-model-' + part;
    let models = [];
    const currentLine = el('p', { className: 'or-current', id: id('current'), role: 'status' });
    const load = el('button', { type: 'button', className: 'btn btn-secondary btn-small', id: id('load'), textContent: 'Load models' });
    const test = el('button', { type: 'button', className: 'btn btn-secondary btn-small', id: id('test'), textContent: 'Test connection' });
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
    root.replaceChildren(currentLine, el('div', { className: 'or-actions' }, load, test), status, results, manual);
    const settings = advanced ? mountAdvanced(advanced, { provider, name, model: () => current(provider) }) : null;

    async function showCurrent() {
      const chosen = await current(provider);
      currentLine.replaceChildren(chosen
        ? el('span', {}, 'Model: ', el('code', { textContent: chosen.id }))
        : el('span', { textContent: 'No model chosen yet. Load models and choose one.' }));
      if (settings) await settings.refresh();
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
    test.addEventListener('click', async () => {
      test.disabled = true; status.textContent = 'Testing the ' + name + ' key…';
      status.textContent = (await check(provider, keyInput.value.trim())).message.replace(/^No key$/, 'Enter the ' + name + ' API key first.');
      test.disabled = false;
    });
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

  return { KEY, GENERATION_KEY, PROVIDERS, VALID_ID, DEFAULT_OUTPUT_TOKENS, all, current, choose, list, check, failureText,
           missingMessage, savedGeneration, saveGeneration, generationFor, mountAdvanced, mount };
})();
