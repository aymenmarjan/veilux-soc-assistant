/* Popup: the case's shared memory and how the three AI actions use it.

   "Case notes" is the one place for what the analyst knows about a case: the
   free text they type, plus answers they keep from Ask. Notes are sent with
   every analysis, question and report (popup.js analyzeWithAI adds them to
   the analyst context, so they are protected like it).

   This file also keeps the popup honest about what each action will use
   ("Uses: …" under Analyze, Ask and Report) and about an analysis that no
   longer matches the case ("The case changed since this analysis"). */
window.VeiluxCaseNotes = (() => {
  const byId = id => document.getElementById(id);
  const HEADER = 'Case notes kept by the analyst from follow-up questions (AI-derived findings the analyst chose to keep; weigh them with the logs):';
  // Header used before case notes existed; an edited sanitized preview may still hold it.
  const OLD_HEADER = 'Findings from follow-up questions on this case (evidence gathered by the analyst; weigh them with the logs):';
  let notes = [], basis = null, timer = null;
  const listeners = [];

  // Short fingerprint of a text, to notice changes; not a security hash.
  function fingerprint(text) {
    let hash = 2166136261;
    for (let i = 0; i < text.length; i++) hash = Math.imul(hash ^ text.charCodeAt(i), 16777619);
    return (hash >>> 0).toString(36) + ':' + text.length;
  }
  const plural = (count, one, many) => count + ' ' + (count === 1 ? one : many);

  async function save() {
    if (notes.length) await caseStorage.set({ caseNotes: notes });
    else await caseStorage.remove('caseNotes');
    render(); refresh();
    listeners.forEach(listener => listener());
  }

  async function add(note) {
    const entry = { id: crypto.randomUUID(), question: String(note.question || '').trim(), text: String(note.text || '').trim(), addedAt: Date.now() };
    notes = notes.concat([entry]);
    await save();
    return entry.id;
  }
  async function remove(id) { notes = notes.filter(note => note.id !== id); await save(); }
  const has = id => notes.some(note => note.id === id);

  // The analyst context with the kept notes appended. An earlier copy (in an
  // edited sanitized preview) is replaced, so notes are never sent twice.
  function withNotes(context) {
    const starts = [HEADER, OLD_HEADER].map(header => context.indexOf(header)).filter(at => at >= 0);
    const base = (starts.length ? context.slice(0, Math.min(...starts)) : context).trim();
    if (!notes.length) return base;
    return [base, HEADER + '\n' + notes.map(note => '- ' + (note.question ? 'On "' + note.question + '":\n' : '') + note.text).join('\n\n')]
      .filter(Boolean).join('\n\n');
  }

  function title() {
    byId('case-notes-title').textContent = 'Case notes' + (notes.length ? ' · ' + notes.length + ' from Ask'
      : analystDataTextarea.value.trim() ? '' : ' · optional');
  }
  function render() {
    title();
    byId('case-notes-list').replaceChildren(...notes.map(note => {
      const item = document.createElement('article');
      item.className = 'case-note';
      const source = Object.assign(document.createElement('p'), { className: 'case-note-source', textContent: 'From Ask' + (note.question ? ' · ' + note.question : '') });
      const text = Object.assign(document.createElement('p'), { className: 'case-note-text', textContent: note.text });
      const actions = document.createElement('div');
      actions.className = 'case-note-actions';
      const edit = Object.assign(document.createElement('button'), { type: 'button', className: 'btn btn-secondary btn-small', textContent: 'Edit' });
      const drop = Object.assign(document.createElement('button'), { type: 'button', className: 'btn btn-secondary btn-small', textContent: 'Remove' });
      drop.setAttribute('aria-label', 'Remove note: ' + (note.question || note.text.slice(0, 40)));
      drop.addEventListener('click', () => remove(note.id));
      edit.addEventListener('click', () => {
        const box = Object.assign(document.createElement('textarea'), { value: note.text, rows: 5 });
        box.setAttribute('aria-label', 'Note text');
        const keep = Object.assign(document.createElement('button'), { type: 'button', className: 'btn btn-primary btn-small', textContent: 'Save note' });
        const cancel = Object.assign(document.createElement('button'), { type: 'button', className: 'btn btn-secondary btn-small', textContent: 'Cancel' });
        keep.addEventListener('click', async () => {
          const value = box.value.trim();
          if (!value) return remove(note.id);
          note.text = value;
          await save();
        });
        cancel.addEventListener('click', render);
        text.replaceWith(box);
        actions.replaceChildren(keep, cancel);
        box.focus();
      });
      actions.append(edit, drop);
      item.append(source, text, actions);
      return item;
    }));
  }

  // ---- What each action uses ----
  function inputs() {
    const logs = capturedLogs.filter(log => typeof log === 'string' && log.trim()).length;
    const typed = analystDataTextarea.value.trim();
    return [
      logs && plural(logs, 'log', 'logs'),
      fieldStatistics.length && plural(fieldStatistics.length, 'statistics query', 'statistics queries'),
      (typed || notes.length) && 'case notes' + (notes.length ? ' (' + notes.length + ' from Ask)' : '')
    ].filter(Boolean);
  }
  async function results() {
    const saved = await caseStorage.get(['lastAnalysis', 'lastAnalysisMode', 'lastThreatIntelFindings']);
    const findings = Array.isArray(saved.lastThreatIntelFindings) ? saved.lastThreatIntelFindings : [];
    return { analysis: saved.lastAnalysisMode !== 'sanitize_only' && saved.lastAnalysis ? saved.lastAnalysis : '', findings,
      parts: [findings.length && 'threat intel for ' + plural(findings.length, 'indicator', 'indicators'),
        saved.lastAnalysisMode !== 'sanitize_only' && saved.lastAnalysis && 'the AI analysis'].filter(Boolean) };
  }

  // ---- Has the case changed since the analysis? ----
  function basisNow() {
    return { logs: capturedLogs.length, logsKey: fingerprint(logsTextarea.value.trim()),
      stats: fieldStatistics.length, statsKey: fingerprint(JSON.stringify(fieldStatistics)),
      text: fingerprint(analystDataTextarea.value.trim()),
      notes: Object.fromEntries(notes.map(note => [note.id, fingerprint(note.text)])) };
  }
  function changesSince(then) {
    const now = basisNow(), changes = [];
    if (now.logs > then.logs) changes.push(plural(now.logs - then.logs, 'new log', 'new logs'));
    else if (now.logsKey !== then.logsKey) changes.push('logs changed');
    if (now.stats > then.stats) changes.push(plural(now.stats - then.stats, 'new statistics query', 'new statistics queries'));
    else if (now.statsKey !== then.statsKey) changes.push('statistics changed');
    const before = then.notes || {};
    const added = Object.keys(now.notes).filter(id => !(id in before)).length;
    const removed = Object.keys(before).filter(id => !(id in now.notes)).length;
    const edited = Object.keys(now.notes).filter(id => id in before && before[id] !== now.notes[id]).length;
    if (added) changes.push(plural(added, 'new note from Ask', 'new notes from Ask'));
    if (removed) changes.push(plural(removed, 'note removed', 'notes removed'));
    if (edited) changes.push(plural(edited, 'note edited', 'notes edited'));
    if (now.text !== then.text) changes.push('case notes edited');
    return changes;
  }

  async function update() {
    const used = inputs(), made = await results();
    byId('analyze-uses').textContent = used.length ? 'Analyze uses: ' + used.join(' · ') + '.' : '';
    byId('chat-uses').textContent = used.length
      ? 'Uses: ' + used.concat(made.parts, ['this conversation']).join(' · ') + '.'
      : 'Add logs or statistics to this case first.';
    window.VeiluxReportPanel?.refreshIncluded();
    window.VeiluxUI?.summaries();
    const changes = basis && made.analysis ? changesSince(basis) : [];
    byId('analysis-stale').hidden = !changes.length;
    if (changes.length) byId('analysis-stale-text').textContent = 'The case changed since this analysis: ' + changes.join(', ') + '.';
    title();
  }
  function refresh() { clearTimeout(timer); timer = setTimeout(() => update().catch(() => {}), 120); }

  async function init() {
    const stored = await caseStorage.get(['caseNotes', 'analysisBasis']);
    notes = Array.isArray(stored.caseNotes) ? stored.caseNotes.filter(note => note && note.id && note.text) : [];
    basis = stored.analysisBasis || null;
    render();
    await update();
    [logsTextarea, analystDataTextarea].forEach(field => field.addEventListener('input', refresh));
    byId('analysis-stale-btn').addEventListener('click', () => { if (!analyzeBtn.disabled) analyzeBtn.click(); });
    caseStorage.onChanged.addListener((changes, area) => {
      if (area !== 'local') return;
      if ('analysisBasis' in changes) basis = changes.analysisBasis.newValue || null;
      if (['analysisBasis', 'capturedLogs', 'fieldStatistics', 'lastAnalysis', 'lastAnalysisMode', 'lastThreatIntelFindings', 'analystData']
        .some(key => key in changes)) refresh();
    });
  }

  async function reset() {
    notes = []; basis = null;
    await caseStorage.remove(['caseNotes', 'analysisBasis']);
    render(); refresh();
    listeners.forEach(listener => listener());
  }

  return { init, add, remove, has, withNotes, reset, refresh, basisNow, inputs, results,
    count: () => notes.length, onChange: listener => listeners.push(listener) };
})();
