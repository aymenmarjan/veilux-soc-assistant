/* Full-page view of a case's email report, opened from the popup. It reads the
   case's saved report and template, and changes nothing. */
(async () => {
  const byId = id => document.getElementById(id);
  const status = text => { byId('report-view-status').textContent = text; };
  const caseId = new URLSearchParams(location.search).get('case') || '';
  const store = VeiluxCases.storage(caseId, { readOnly: true });
  const { reportState: state } = await store.get('reportState');
  if (!state || !state.content) { byId('report-view-subject').textContent = 'This case has no report yet. Generate one from the popup.'; return; }
  const template = await VeiluxReports.get(state.templateId);
  const content = template.keepMasked ? VeiluxReports.remask(state.content, state.mapping) : state.content;
  const report = VeiluxReports.assemble(template, content, state.fields || {});
  document.title = report.subject;
  byId('report-view-subject').textContent = report.subject;
  byId('report-view-frame').srcdoc = report.html;
  byId('report-view-copy-subject').addEventListener('click', async () => {
    await navigator.clipboard.writeText(report.subject); status('Subject copied.');
  });
  byId('report-view-copy').addEventListener('click', async () => {
    // Only the body: the subject is copied on its own.
    const body = VeiluxReports.emailBody(report.html);
    const text = new DOMParser().parseFromString(body, 'text/html').body.innerText;
    try {
      await navigator.clipboard.write([new ClipboardItem({ 'text/html': new Blob([body], { type: 'text/html' }), 'text/plain': new Blob([text], { type: 'text/plain' }) })]);
      status('Email copied. Paste it into a new message.');
    } catch (_) { status('Copy is not available here. Click inside the report, press Ctrl+A, then Ctrl+C.'); }
  });
})();
