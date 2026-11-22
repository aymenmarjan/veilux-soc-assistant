/* Popup -> Results -> Report: an escalation email for the open case.

   The analyst picks a template and may set the title, case ID, severity and
   the template's own fields (variables of its subject pattern, such as
   {{team}}). "Generate report" sends the whole case through the same
   protected request as an analysis (popup.js analyzeWithAI): logs,
   statistics and case notes as usual, plus the case's AI analysis, its
   threat-intelligence results and any instructions for the email typed here. The answer is kept per case
   (reportState) and can be edited and re-rendered without a new AI request. */
window.VeiluxReportPanel = (() => {
  const R = VeiluxReports;
  const byId = id => document.getElementById(id);
  const AUTO = '';
  let opened = false, state = null, template = null, saveTimer = null;

  const fields = () => {
    const values = { title: byId('report-title').value.trim(), case_id: byId('report-case-id').value.trim(),
      severity: byId('report-severity').value };
    byId('report-custom-fields').querySelectorAll('input[data-field]').forEach(input => { values[input.dataset.field] = input.value.trim(); });
    return values;
  };

  function persist() {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
      state = { ...(state || {}), templateId: template ? template.id : null, fields: fields(),
        extraContext: byId('report-extra-context').value };
      caseStorage.set({ reportState: state }).catch(() => {});
    }, 250);
  }

  // Fields follow the template: its severity scale and its own variables.
  function renderFields(values = {}) {
    const severity = byId('report-severity');
    severity.replaceChildren(new Option('Auto (the AI decides)', AUTO), ...template.severities.map(level => new Option(level.name, level.name)));
    severity.value = template.severities.some(level => level.name === values.severity) ? values.severity : AUTO;
    byId('report-title').value = values.title || '';
    byId('report-case-id').value = values.case_id || '';
    byId('report-case-id').placeholder = template.caseIdPlaceholder ? 'Shown as ' + template.caseIdPlaceholder + ' when left empty' : 'Left empty in the report';
    const custom = byId('report-custom-fields');
    custom.replaceChildren(...R.customFields(template).map(name => {
      const group = document.createElement('div');
      group.className = 'form-group';
      const label = Object.assign(document.createElement('label'), { htmlFor: 'report-field-' + name, textContent: R.fieldLabel(name) });
      const input = Object.assign(document.createElement('input'), { type: 'text', id: 'report-field-' + name, value: values[name] || '' });
      input.dataset.field = name;
      group.append(label, input);
      return group;
    }));
    updateSubject();
  }

  function updateSubject() {
    const values = fields();
    const level = template.severities.find(l => l.name === values.severity);
    byId('report-subject-line').textContent = R.fillText(template.subjectPattern, {
      ...values, title: values.title || (state && state.content && state.content.title) || '…',
      case_id: values.case_id || template.caseIdPlaceholder, severity: level ? level.name : (state && state.content && state.content.severity) || '…',
      date: new Date().toLocaleDateString() });
  }

  function current() {
    const content = template.keepMasked ? R.remask(state.content, state.mapping) : state.content;
    const values = fields();
    return R.assemble(template, content, { ...values, severity: values.severity || '' });
  }

  function renderOutput() {
    const output = byId('report-output');
    if (!state || !state.content) { output.hidden = true; window.VeiluxUI?.syncResults(); return; }
    try {
      const report = current();
      byId('report-frame').srcdoc = report.html;
      byId('report-content').value = JSON.stringify(state.content, null, 2);
      byId('report-subject-line').textContent = report.subject;
      output.hidden = false;
    } catch (error) { showError(error.message); }
    window.VeiluxUI?.syncResults();
  }

  function showError(message) {
    byId('report-hint').textContent = 'Report: ' + message;
    byId('report-hint').classList.add('field-error');
  }
  const HINT = 'Everything listed below is sent through the same protection as an analysis before the AI sees it.';
  function clearError() {
    byId('report-hint').classList.remove('field-error');
    byId('report-hint').textContent = HINT;
  }

  // Threat-intelligence results already gathered for the case, as short facts.
  // The header tells the AI how to use them (the chat passes its own).
  const TI_FOR_REPORT = 'Threat intelligence already gathered for this case (background for your assessment only: let it inform the severity, '
    + 'summary, risks and recommendations in your own words, but do not list these results, scores, hashes or source names '
    + 'in the report and do not give them a section of their own):';
  function threatIntelContext(findings, header = TI_FOR_REPORT) {
    if (!Array.isArray(findings) || !findings.length) return '';
    const facts = data => Object.entries(data || {})
      .filter(([key, value]) => !['status', 'link', 'cached', 'detail'].includes(key) && value !== null && value !== '' && typeof value !== 'object')
      .slice(0, 8).map(([key, value]) => key.replace(/_/g, ' ') + ' ' + value).join(', ');
    const lines = findings.slice(0, 40).map(finding => {
      const sources = Object.entries(finding.sources || {}).map(([name, data]) =>
        name + ': ' + (data && data.status === 'ok' ? facts(data) || 'no details' : (data && data.status) || 'unavailable'));
      return '- ' + finding.ioc + ' (' + (finding.type || 'indicator') + '): ' + (finding.verdict || 'unknown') + (sources.length ? '; ' + sources.join('; ') : '');
    });
    return header + '\n' + lines.join('\n');
  }

  // What the report request contains, shown before generating. Logs,
  // statistics and case notes are the shared inputs (case_notes.js).
  async function caseMaterial() {
    const Notes = window.VeiluxCaseNotes;
    const made = await Notes.results();
    const extra = byId('report-extra-context').value.trim();
    const missing = [!made.findings.length && 'threat intel', !made.analysis && 'the AI analysis'].filter(Boolean);
    return { analysis: made.analysis, findings: made.findings, extra, notes: Notes.count(), missing,
      included: Notes.inputs().concat(made.parts, extra ? ['email instructions'] : []) };
  }

  async function showIncluded() {
    const material = await caseMaterial();
    byId('report-included').textContent = (material.included.length ? 'Uses: ' + material.included.join(' · ') + '.' : 'Nothing to use yet.')
      + (material.missing.length ? ' Not available: ' + material.missing.join(', ') + '.' : '');
  }

  async function chooseTemplate(id) {
    const { templates, defaultId } = await R.all();
    const select = byId('report-template');
    select.replaceChildren(...templates.map(t => new Option(t.name, t.id)));
    template = templates.find(t => t.id === id) || templates.find(t => t.id === defaultId) || R.BUILTIN;
    select.value = template.id;
  }

  function open(focus = true) {
    opened = true;
    window.VeiluxUI.syncResults('report');
    window.VeiluxUI.selectView('report');
    window.VeiluxUI.revealResults();
    if (focus) byId('report-title').focus({ preventScroll: true });
  }

  async function generate() {
    if (!capturedLogs.some(log => typeof log === 'string' && log.trim()) && !fieldStatistics.length) {
      showError('Add logs or statistics to this case first.');
      return;
    }
    clearError();
    const values = fields();
    state = { ...(state || {}), templateId: template.id, fields: values, extraContext: byId('report-extra-context').value };
    await caseStorage.set({ reportState: state });
    // Logs, statistics and case notes travel as in an analysis; the rest of
    // the case is added as context.
    const material = await caseMaterial();
    const context = [
      material.analysis && 'Earlier AI analysis of this case (background for your assessment; the logs remain the source of truth, and the report should not repeat this analysis as a section):\n' + material.analysis,
      threatIntelContext(material.findings),
      // Notes kept from Ask read as the case's own findings, not as a conversation.
      material.notes && 'The case notes in the analyst context are findings of this case: state them as your own conclusions, '
        + 'and never mention questions, a chat, an assistant or a conversation.',
      material.extra && 'Instructions from the analyst for this email (follow them; they are not facts about the case):\n' + material.extra
    ].filter(Boolean).join('\n\n');
    byId('report-generate').disabled = true;
    // The answer format VEILUX adds is trusted text; the template's own
    // instructions and the analyst's fields are still reviewed.
    const trusted = R.instructionsFor({ ...template, instructions: '' }, {});
    try { await analyzeWithAI({ purpose: 'report', instructions: R.instructionsFor(template, values), context, trusted }); }
    finally { byId('report-generate').disabled = false; }
  }

  // `cutOff`: the AI reached its output limit, so an unreadable report is
  // explained by that limit rather than by the model.
  async function applyAnswer(raw, mapping, cutOff = false) {
    const { reportState } = await caseStorage.get('reportState');
    let content;
    try { content = R.parseAnswer(raw); }
    catch (error) {
      if (!cutOff) throw error;
      throw new Error('The report was cut off at the output limit before it was complete. Raise Maximum output tokens ' +
        '(Settings → Providers and API keys → the provider → Advanced) or a custom model\'s Response length limit, then generate it again.');
    }
    state = { ...(reportState || state || {}), content, mapping: mapping || null, generatedAt: Date.now() };
    await caseStorage.set({ reportState: state });
    if (!template) await chooseTemplate(state.templateId);
    opened = true;
    renderOutput();
    open(false);
  }

  // Copies the email body as formatted HTML (with a plain-text copy for clients
  // that cannot paste HTML), ready to paste into a new message. The subject is
  // copied separately, so only the body goes here.
  async function copyEmail() {
    const body = R.emailBody(current().html);
    try {
      if (!window.ClipboardItem) throw new Error('no ClipboardItem');
      const text = new DOMParser().parseFromString(body, 'text/html').body.innerText;
      await navigator.clipboard.write([new ClipboardItem({
        'text/html': new Blob([body], { type: 'text/html' }), 'text/plain': new Blob([text], { type: 'text/plain' }) })]);
    } catch (_) {
      // Older browsers: copy a rendered copy of the email from the page itself.
      const holder = document.createElement('div');
      holder.style.cssText = 'position:fixed;left:-10000px;top:0;width:720px;';
      holder.setAttribute('contenteditable', 'true');
      setHTML(holder, body);
      document.body.append(holder);
      const range = document.createRange(); range.selectNodeContents(holder);
      const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range);
      const copied = document.execCommand('copy');
      selection.removeAllRanges(); holder.remove();
      if (!copied) { updateStatus('Copy failed. Open the report in a new tab and copy it from there.', 'error'); return; }
    }
    updateStatus('Email copied. Paste it into a new message in your mail client.', 'success');
  }

  async function init() {
    const { reportState } = await caseStorage.get('reportState');
    state = reportState || null;
    await chooseTemplate(state && state.templateId);
    renderFields((state && state.fields) || {});
    byId('report-extra-context').value = (state && state.extraContext) || '';
    opened = !!state;
    renderOutput();
    clearError();
    showIncluded();

    byId('report-btn').addEventListener('click', () => { open(); showIncluded(); });
    byId('report-template').addEventListener('change', async event => {
      const values = fields();
      await chooseTemplate(event.target.value);
      renderFields(values);
      persist(); renderOutput();
    });
    byId('report-section').addEventListener('input', event => {
      if (event.target.id === 'report-extra-context') { persist(); showIncluded(); return; }
      if (event.target.closest('.report-form')) { persist(); updateSubject(); if (state && state.content) renderOutput(); }
    });
    byId('report-severity').addEventListener('change', () => { persist(); updateSubject(); if (state && state.content) renderOutput(); });
    byId('report-generate').addEventListener('click', generate);
    byId('report-copy-email').addEventListener('click', copyEmail);
    byId('report-copy-subject').addEventListener('click', () => copyToClipboard(current().subject, 'Subject'));
    byId('report-open').addEventListener('click', async () => {
      browser.tabs.create({ url: browser.runtime.getURL('report_view.html?case=' + encodeURIComponent(await caseStorage.caseId())) });
    });
    byId('report-apply').addEventListener('click', async () => {
      try {
        state = { ...state, content: R.parseAnswer(byId('report-content').value) };
        await caseStorage.set({ reportState: state });
        renderOutput();
        updateStatus('Report updated.', 'success');
      } catch (error) { updateStatus('Edit content: the text is not valid report JSON. ' + error.message, 'error'); }
    });
  }

  async function reset() {
    state = null; opened = false;
    await caseStorage.remove('reportState');
    byId('report-extra-context').value = '';
    renderFields({}); renderOutput(); clearError(); showIncluded();
  }

  return { init, open, isOpen: () => opened, applyAnswer, showError, reset, threatIntelContext,
    refreshIncluded: () => showIncluded(), current: () => (state && state.content ? current() : null) };
})();
