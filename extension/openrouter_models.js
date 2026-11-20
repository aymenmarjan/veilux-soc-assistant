/* OpenRouter model picker, shared by Settings and the popup.
   "Find free models" asks the local backend, which reads OpenRouter's current
   model list. The chosen model is stored as openrouterModel (its ID) and
   openrouterModelInfo (the facts shown when it was chosen). Settings saves the
   default; the popup passes its case storage, so each case can use its own model. */
globalThis.VeiluxOpenRouter = (() => {
  const MODEL_KEY = 'openrouterModel', INFO_KEY = 'openrouterModelInfo';

  async function current(store = browser.storage.local) {
    const stored = await store.get([MODEL_KEY, INFO_KEY]);
    return { id: stored[MODEL_KEY] || '', info: stored[INFO_KEY] || null };
  }
  async function choose(id, info = null, store = browser.storage.local) {
    await store.set({ [MODEL_KEY]: id, [INFO_KEY]: info });
  }

  const tokens = n => !Number.isInteger(n) ? 'unknown'
    : n >= 1e6 ? +(n / 1e6).toFixed(1) + 'M tokens' : n >= 1000 ? Math.round(n / 1000) + 'K tokens' : n + ' tokens';
  const day = seconds => Number.isInteger(seconds) ? new Date(seconds * 1000).toISOString().slice(0, 10) : 'unknown';
  const REASONING = { always: 'Always reasons first (slower)', optional: 'Can reason when asked', none: 'No reasoning step' };
  const reads = m => (m.input_modalities || []).join(', ') || 'text';

  // One line per model in the dropdown.
  function summary(m) {
    const parts = [tokens(m.context_length).replace(' tokens', '') + ' context'];
    if (m.reasoning === 'always') parts.push('always reasons');
    const extra = (m.input_modalities || []).filter(x => x !== 'text');
    if (extra.length) parts.push('reads ' + extra.join(', '));
    if (m.expiration_date) parts.push('until ' + m.expiration_date);
    return m.name + ' — ' + parts.join(' · ');
  }

  function details(m) {
    return [
      ['Model ID', m.id],
      ['Context window', tokens(m.context_length)],
      ['Longest answer', tokens(m.max_completion_tokens)],
      ['Reads', reads(m)],
      ['Reasoning', REASONING[m.reasoning] || 'Unknown'],
      ['Tool use', m.supports_tools ? 'Supported' : 'Not supported'],
      ['Content moderation', m.moderated ? 'Moderated by the provider' : 'Not moderated'],
      ['Added to OpenRouter', day(m.created)],
      ['Available until', m.expiration_date || 'No end date announced'],
      ['Knowledge cutoff', m.knowledge_cutoff || 'Not published'],
    ];
  }

  function el(tag, props = {}, ...children) {
    const node = Object.assign(document.createElement(tag), props);
    node.append(...children);
    return node;
  }

  // Builds the picker inside `root`. `prefix` keeps element IDs unique per page.
  function mount(root, { prefix = 'openrouter', onChange = () => {}, storage = browser.storage.local } = {}) {
    const id = name => prefix + '-' + name;
    let models = [];

    const currentLine = el('p', { className: 'or-current', role: 'status' });
    const find = el('button', { type: 'button', className: 'btn btn-secondary btn-small', id: id('find'), textContent: 'Find free models' });
    const status = el('p', { className: 'field-hint', id: id('status'), role: 'status' });
    const sort = el('select', { id: id('sort') });
    [['name', 'Name'], ['context', 'Largest context first'], ['newest', 'Newest first']].forEach(([v, t]) => sort.add(new Option(t, v)));
    const list = el('select', { id: id('list') });
    const info = el('dl', { className: 'or-details', id: id('details') });
    const description = el('p', { className: 'or-description' });
    const use = el('button', { type: 'button', className: 'btn btn-primary btn-small', id: id('use'), textContent: 'Use this model' });
    const results = el('div', { className: 'or-results', hidden: true },
      el('div', { className: 'or-row' },
        el('label', { htmlFor: id('list'), textContent: 'Free models' }),
        el('label', { className: 'or-sort', htmlFor: id('sort') }, 'Sort ', sort)),
      list, info, description, use);
    const manualInput = el('input', { type: 'text', id: id('manual'), placeholder: 'For example, google/gemma-4-31b-it:free' });
    const manualUse = el('button', { type: 'button', className: 'btn btn-secondary btn-small', textContent: 'Use this ID' });
    const manual = el('details', { className: 'or-manual' },
      el('summary', { textContent: 'Use another model ID' }),
      el('label', { htmlFor: id('manual'), textContent: 'OpenRouter model ID' }), manualInput,
      el('p', { className: 'field-hint', textContent: 'Any model listed on openrouter.ai/models, free or paid. Paid models are billed to your OpenRouter account.' }),
      manualUse);
    const note = el('p', { className: 'field-hint', textContent:
      'Free models have low rate limits and can change or disappear, so look them up again whenever you need. ' +
      'Some free providers may keep prompts; VEILUX still hides sensitive values before anything is sent.' });
    root.replaceChildren(currentLine, el('div', { className: 'or-actions' }, find), status, results, manual, note);

    async function showCurrent() {
      const { id: chosen, info: chosenInfo } = await current(storage);
      currentLine.replaceChildren(chosen
        ? el('span', {}, 'Current model: ', el('strong', { textContent: chosenInfo?.name || chosen }), ' ', el('code', { textContent: chosen }))
        : el('span', { textContent: 'No OpenRouter model chosen yet. Find a free model or enter a model ID.' }));
    }

    function showDetails() {
      const m = models.find(x => x.id === list.value);
      info.replaceChildren(...(m ? details(m).flatMap(([k, v]) => [el('dt', { textContent: k }), el('dd', { textContent: v })]) : []));
      description.textContent = m?.description || '';
      use.disabled = !m;
    }

    function render() {
      const order = { name: (a, b) => a.name.localeCompare(b.name),
        context: (a, b) => (b.context_length || 0) - (a.context_length || 0) || a.name.localeCompare(b.name),
        newest: (a, b) => (b.created || 0) - (a.created || 0) || a.name.localeCompare(b.name) }[sort.value];
      const selected = list.value;
      list.replaceChildren(...[...models].sort(order).map(m => new Option(summary(m), m.id)));
      if (models.some(m => m.id === selected)) list.value = selected;
      showDetails();
    }

    async function lookup() {
      find.disabled = true; status.textContent = 'Looking up free models on OpenRouter…';
      try {
        const response = await VeiluxBackend.fetch('/providers/openrouter/free-models', { signal: AbortSignal.timeout(30000) });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw Error(typeof data.detail === 'string' ? data.detail : 'OpenRouter lookup failed (HTTP ' + response.status + ').');
        models = Array.isArray(data.models) ? data.models : [];
        const checked = data.checked_at ? new Date(data.checked_at).toLocaleString() : 'now';
        status.textContent = models.length
          ? models.length + ' free model' + (models.length === 1 ? '' : 's') + ' available (checked ' + checked + ').'
          : 'OpenRouter has no free text models right now (checked ' + checked + ').';
        results.hidden = !models.length;
        const { id: chosen } = await current(storage);
        render();
        if (models.some(m => m.id === chosen)) { list.value = chosen; showDetails(); }
      } catch (error) {
        status.textContent = (error.name === 'TimeoutError' ? 'OpenRouter did not answer in time.'
          : error instanceof TypeError ? 'Could not reach the VEILUX backend. Start it with "python server.py" and check Settings → Backend.'
          : error.message);
      } finally { find.disabled = false; }
    }

    async function set(modelId, modelInfo) {
      await choose(modelId, modelInfo, storage);
      await showCurrent();
      status.textContent = 'Saved. Analyses with OpenRouter now use ' + (modelInfo?.name || modelId) + '.';
      onChange(modelId);
    }

    find.addEventListener('click', lookup);
    sort.addEventListener('change', render);
    list.addEventListener('change', showDetails);
    use.addEventListener('click', () => { const m = models.find(x => x.id === list.value); if (m) set(m.id, m); });
    manualUse.addEventListener('click', () => {
      const value = manualInput.value.trim();
      if (!/^[\w.-]+\/[\w.:-]+$/.test(value)) { status.textContent = 'Enter a model ID such as google/gemma-4-31b-it:free.'; manualInput.focus(); return; }
      set(value, models.find(m => m.id === value) || null);
      manualInput.value = '';
    });
    showCurrent();
    return { lookup, refresh: showCurrent };
  }

  return { current, choose, summary, details, mount };
})();
