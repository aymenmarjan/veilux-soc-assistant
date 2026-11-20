/* Popup -> Results -> Ask: follow-up questions on the open case.

   Each question goes through the same protected request as an analysis
   (popup.js analyzeWithAI). The whole case is sent again, with the last
   exchanges and the new question added as analyst context, so everything is
   masked together in one request and the markers stay consistent. Answers are
   kept per case (chatState) with real values restored, on this computer only.
   "Add to case notes" keeps an answer as a case note (case_notes.js), which
   every later analysis, question and report then receives.
   Decisions from the credential review are remembered for the case, so the
   review only comes back for values it has not seen. */
window.VeiluxChatPanel = (() => {
  const KEEP = 8;
  const Quick = VeiluxQuickQuestions, Notes = window.VeiluxCaseNotes;
  const INSTRUCTIONS = [
    'You are a senior SOC analyst helping a colleague investigate the case below.',
    'Answer the latest question from the analyst, found at the end of the Additional Analyst Context, after the conversation so far.',
    'Base your answer on the logs, statistics, analyst context (including the case notes kept by the analyst), threat intelligence and earlier analysis provided. When they do not show something, say so plainly; you cannot run new searches.',
    'Be concise and concrete. Use short paragraphs or bullet lists, and Markdown headings only when the answer is long.',
    'Copy protected markers (text inside ⟦ ⟧ brackets) exactly as written; they stand for values hidden before sending.'].join('\n');

  const byId = id => document.getElementById(id);
  let state = null, opened = false;
  const exchanges = () => (state && Array.isArray(state.exchanges) ? state.exchanges : []);

  async function save() {
    if (state && (exchanges().length || state.pending || state.model)) await caseStorage.set({ chatState: state });
    else await caseStorage.remove('chatState');
  }

  // Markdown from the AI, escaped first so an answer can never add markup.
  function renderAnswer(markdown) {
    const inline = text => text.replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    const lines = escapeHtml(String(markdown || '')).split(/\r?\n/);
    let html = '', list = null, code = null;
    const closeList = () => { if (list) { html += '</' + list + '>'; list = null; } };
    for (const line of lines) {
      if (/^```/.test(line)) {
        if (code === null) { closeList(); code = []; } else { html += '<pre><code>' + code.join('\n') + '</code></pre>'; code = null; }
        continue;
      }
      if (code !== null) { code.push(line); continue; }
      const heading = /^#{1,4}\s+(.*)$/.exec(line);
      const bullet = /^\s*[-*•]\s+(.*)$/.exec(line);
      const numbered = /^\s*\d+[.)]\s+(.*)$/.exec(line);
      if (heading) { closeList(); html += '<h4>' + inline(heading[1]) + '</h4>'; }
      else if (bullet || numbered) {
        const kind = bullet ? 'ul' : 'ol';
        if (list !== kind) { closeList(); html += '<' + kind + '>'; list = kind; }
        html += '<li>' + inline((bullet || numbered)[1]) + '</li>';
      } else if (!line.trim()) closeList();
      else { closeList(); html += '<p>' + inline(line) + '</p>'; }
    }
    if (code !== null) html += '<pre><code>' + code.join('\n') + '</code></pre>';
    closeList();
    return html;
  }

  // The model list follows the popup's provider list, so custom models and
  // providers with saved keys appear here too.
  function renderModels() {
    const select = byId('chat-model');
    const chosen = state && state.model !== undefined ? state.model : select.value;
    const current = providerSelect.options[providerSelect.selectedIndex];
    select.replaceChildren(new Option('Same as analysis' + (current ? ' (' + current.textContent.split(' · ')[0] + ')' : ''), ''),
      ...Array.from(providerSelect.options).map(option => new Option(option.textContent, option.value)));
    select.value = Array.from(select.options).some(option => option.value === chosen) ? chosen : '';
  }
  const modelLabel = value => {
    const option = Array.from(byId('chat-model').options).find(o => o.value === value);
    return option ? option.textContent.replace(/ · .*$/, '').replace(/^Same as analysis \((.*)\)$/, '$1') : value;
  };

  function render() {
    const log = byId('chat-log');
    const items = exchanges().map((exchange, index) => {
      const article = document.createElement('article');
      article.className = 'chat-exchange';
      const question = document.createElement('p');
      question.className = 'chat-question';
      question.textContent = exchange.question;
      const answer = document.createElement('div');
      answer.className = 'chat-answer';
      setHTML(answer, renderAnswer(exchange.answer));
      const meta = document.createElement('div');
      meta.className = 'chat-meta';
      const info = document.createElement('span');
      info.textContent = [exchange.modelLabel, exchange.askedAt ? new Date(exchange.askedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '']
        .filter(Boolean).join(' · ');
      const copy = Object.assign(document.createElement('button'), { type: 'button', className: 'btn btn-secondary btn-small', textContent: 'Copy' });
      copy.addEventListener('click', () => copyToClipboard(exchange.answer, 'Answer'));
      // One button keeps the answer for the whole case: analyses, later
      // questions and reports all receive case notes.
      const kept = !!exchange.noteId && Notes.has(exchange.noteId);
      const keep = Object.assign(document.createElement('button'), { type: 'button', className: 'btn btn-secondary btn-small chat-use',
        textContent: kept ? 'In case notes ✓' : 'Add to case notes',
        title: kept ? 'Click to remove it from the case notes.' : 'Keep this answer as a case note. Every analysis, question and report on this case will use it.' });
      keep.setAttribute('aria-pressed', String(kept));
      keep.addEventListener('click', async () => {
        if (kept) { const id = exchange.noteId; exchange.noteId = null; await save(); await Notes.remove(id); }
        else {
          exchange.noteId = await Notes.add({ question: exchange.question, text: exchange.answer });
          await save(); render();
          updateStatus('Added to case notes. The next analysis, questions and reports will use it.', 'success');
        }
      });
      meta.append(info, copy, keep);
      article.dataset.index = index;
      article.append(question, answer, meta);
      return article;
    });
    if (state && state.pending) {
      const article = document.createElement('article');
      article.className = 'chat-exchange pending';
      const question = Object.assign(document.createElement('p'), { className: 'chat-question', textContent: state.pending.question });
      const waiting = Object.assign(document.createElement('p'), { className: 'field-hint', textContent: 'Waiting for the answer…' });
      article.append(question, waiting);
      items.push(article);
    }
    log.replaceChildren(...items);
    byId('chat-empty').hidden = items.length > 0;
    byId('chat-reset').hidden = !items.length;
    byId('chat-copy-last').hidden = !exchanges().length;
    window.VeiluxUI?.syncResults();
  }

  async function renderQuick() {
    const questions = await Quick.load();
    byId('chat-quick').replaceChildren(...questions.map(text => {
      const chip = Object.assign(document.createElement('button'), { type: 'button', className: 'chat-chip', textContent: text });
      chip.addEventListener('click', () => { byId('chat-question').value = text; byId('chat-question').focus(); });
      return chip;
    }));
  }

  function hint(message, error = false) {
    byId('chat-hint').textContent = message;
    byId('chat-hint').classList.toggle('field-error', error);
  }
  const HINT = 'Each question goes through the same protection as an analysis. The conversation keeps its last ' + KEEP + ' exchanges; add an answer to the case notes to keep it for good.';

  function context(question) {
    return caseStorage.get(['lastAnalysis', 'lastThreatIntelFindings']).then(saved => {
      const history = exchanges().slice(-KEEP).map(e => 'Analyst: ' + e.question + '\nAssistant: ' + e.answer).join('\n\n');
      return [
        saved.lastAnalysis && 'Earlier AI analysis of this case (background; the logs remain the source of truth):\n' + saved.lastAnalysis,
        window.VeiluxReportPanel.threatIntelContext(saved.lastThreatIntelFindings, 'Threat intelligence already gathered for this case:'),
        history && 'Conversation so far (oldest first):\n' + history,
        'Latest question from the analyst:\n' + question
      ].filter(Boolean).join('\n\n');
    });
  }

  async function ask() {
    const input = byId('chat-question');
    const question = input.value.trim();
    if (!question || (state && state.pending)) return;
    if (!capturedLogs.some(log => typeof log === 'string' && log.trim()) && !fieldStatistics.length) {
      hint('Add logs or statistics to this case first.', true);
      return;
    }
    const model = byId('chat-model').value;
    state = { ...(state || { exchanges: [] }), model, pending: { question, model, modelLabel: modelLabel(model), askedAt: Date.now() } };
    input.value = '';
    hint(HINT);
    await save(); render();
    byId('chat-send').disabled = true;
    try { await analyzeWithAI({ purpose: 'chat', instructions: INSTRUCTIONS, context: await context(question), provider: model || null, trusted: INSTRUCTIONS }); }
    finally { byId('chat-send').disabled = false; }
  }

  // Called by popup.js with the AI's answer, real values already restored.
  async function applyAnswer(raw) {
    const { chatState } = await caseStorage.get('chatState');
    state = chatState || state || { exchanges: [] };
    const pending = state.pending || { question: '(question not kept)', askedAt: Date.now() };
    state.exchanges = exchanges().concat([{ question: pending.question, answer: String(raw || '').trim(),
      modelLabel: pending.modelLabel || '', askedAt: pending.askedAt, noteId: null }]).slice(-KEEP);
    state.pending = null;
    await save();
    opened = true;
    render(); open(false);
    byId('chat-log').lastElementChild?.scrollIntoView({ block: 'nearest' });
  }

  // A question that could not be answered goes back into the box.
  async function showError(message) {
    const { chatState } = await caseStorage.get('chatState');
    state = chatState || state;
    if (state && state.pending) {
      if (!byId('chat-question').value.trim()) byId('chat-question').value = state.pending.question;
      state.pending = null;
      await save();
    }
    render();
    hint('Ask: ' + message, true);
  }

  function open(focus = true) {
    opened = true;
    window.VeiluxUI.syncResults('chat');
    window.VeiluxUI.selectView('chat');
    window.VeiluxUI.revealResults();
    if (focus) byId('chat-question').focus({ preventScroll: true });
  }

  async function init() {
    const stored = await caseStorage.get(['chatState', 'analysisInProgress', 'analysisPurpose', 'pendingAnswer']);
    state = stored.chatState || null;
    // A question whose request ended without an answer (for example the popup
    // was closed during the credential review) returns to the box.
    if (state && state.pending && !(stored.analysisInProgress && stored.analysisPurpose === 'chat')
        && !(stored.pendingAnswer && stored.pendingAnswer.purpose === 'chat')) {
      byId('chat-question').value = state.pending.question;
      state.pending = null;
      await save();
    }
    // Answers marked for the analysis or the report by an earlier version
    // become case notes, which serve both.
    let migrated = false;
    for (const exchange of exchanges()) {
      if ((exchange.inAnalysis || exchange.inReport) && !exchange.noteId) exchange.noteId = await Notes.add({ question: exchange.question, text: exchange.answer });
      if ('inAnalysis' in exchange || 'inReport' in exchange) { delete exchange.inAnalysis; delete exchange.inReport; migrated = true; }
    }
    if (migrated) await save();
    Notes.onChange(render);
    opened = !!(state && (exchanges().length || state.pending));
    renderModels(); render(); hint(HINT);
    await renderQuick();

    byId('ask-btn').addEventListener('click', () => open());
    byId('chat-send').addEventListener('click', ask);
    byId('chat-question').addEventListener('keydown', event => {
      if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) { event.preventDefault(); ask(); }
    });
    byId('chat-model').addEventListener('change', async () => {
      state = { ...(state || { exchanges: [] }), model: byId('chat-model').value };
      await save();
    });
    providerSelect.addEventListener('change', renderModels);
    byId('chat-copy-last').addEventListener('click', () => {
      const last = exchanges()[exchanges().length - 1];
      if (last) copyToClipboard(last.answer, 'Answer');
    });
    let armed = null;
    byId('chat-reset').addEventListener('click', async event => {
      const button = event.currentTarget;
      if (!armed) {
        button.textContent = 'Click again to start over';
        armed = setTimeout(() => { armed = null; button.textContent = 'Start over'; }, 4000);
        return;
      }
      clearTimeout(armed); armed = null; button.textContent = 'Start over';
      await reset(true);
      updateStatus('Conversation cleared for this case.', 'info');
    });
    browser.storage.onChanged.addListener((changes, area) => { if (area === 'local' && changes[Quick.KEY]) renderQuick(); });
  }

  async function reset(keepOpen = false) {
    state = null;
    opened = keepOpen;
    await caseStorage.remove('chatState');
    byId('chat-question').value = '';
    render(); hint(HINT);
  }

  return { init, open, isOpen: () => opened, applyAnswer, showError, reset, renderAnswer,
    count: () => exchanges().length };
})();
