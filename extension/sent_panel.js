/* Popup -> Results -> Sent: what left this computer for the open case.

   The backend reports, for every request, what it sent to outside services:
   the AI provider with the exact protected prompt, and each threat-
   intelligence lookup with whether it was sent or answered from the local
   cache (server.py, _record_ai_request). background.js and the indicator
   check save that account with the case (VeiluxCases.recordSend); this panel
   shows it and exports it. API keys are never part of it. */
window.VeiluxSentPanel = (() => {
  const byId = id => document.getElementById(id);
  const PURPOSES = { analysis: 'Analysis', report: 'Email report', chat: 'Ask', 'ioc-check': 'Indicator check' };
  const SERVICES = { virustotal: 'VirusTotal', abuseipdb: 'AbuseIPDB', whois: 'WHOIS / RDAP' };
  let record = [];

  const when = iso => { const date = new Date(iso); return isNaN(date) ? '' : date.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }); };
  const el = (tag, className, text) => Object.assign(document.createElement(tag), className ? { className } : {}, text !== undefined ? { textContent: text } : {});

  function summary(entry) {
    const sent = (entry.lookups || []).filter(l => l.sent).length;
    const cached = (entry.lookups || []).length - sent;
    const parts = [];
    if (entry.ai) parts.push(entry.ai.provider + ' · ' + entry.ai.model);
    if (sent) parts.push(sent + ' lookup' + (sent === 1 ? '' : 's') + ' sent');
    if (cached) parts.push(cached + ' from cache');
    if (!parts.length) parts.push(entry.localOnly ? 'Nothing left this computer (sanitize only)' : 'Nothing left this computer');
    return parts.join(' · ');
  }

  function renderEntry(entry) {
    const item = el('details', 'sent-entry');
    const head = el('summary');
    head.append(el('span', 'sent-when', when(entry.at)), el('strong', '', PURPOSES[entry.purpose] || entry.purpose),
      el('span', 'sent-what', summary(entry)));
    if (entry.outcome === 'failed') head.append(el('span', 'sent-failed', 'failed'));
    item.append(head);
    const body = el('div', 'sent-body');
    if (entry.error) body.append(el('p', 'field-hint', 'Error: ' + entry.error));
    if (entry.ai) {
      const ai = entry.ai;
      const facts = el('dl', 'sent-facts');
      [['Provider', ai.provider], ['Model', ai.model], ['Address', ai.endpoint], ['Sent at', when(ai.sent_at)],
        ['Size', Number(ai.characters || 0).toLocaleString() + ' characters'], ['Result', ai.outcome]].forEach(([label, value]) => {
        facts.append(el('dt', '', label), el('dd', '', value || ''));
      });
      const prompt = el('pre', 'sent-prompt', ai.prompt || '');
      prompt.setAttribute('aria-label', 'Prompt as sent');
      prompt.tabIndex = 0;
      const copy = el('button', 'btn btn-secondary btn-small', 'Copy prompt');
      copy.type = 'button';
      copy.addEventListener('click', () => copyToClipboard(ai.prompt || '', 'Prompt as sent'));
      body.append(el('p', 'sent-label', 'AI request'), facts, el('p', 'field-hint',
        'The prompt exactly as the provider received it. The request also carried the model name, answer settings and your API key, which is not recorded.'),
        prompt, copy);
    }
    if ((entry.lookups || []).length) {
      const table = el('table', 'sent-lookups');
      const header = el('tr');
      ['Service', 'Indicator', 'Type', 'Result'].forEach(label => header.append(el('th', '', label)));
      table.append(header);
      entry.lookups.forEach(lookup => {
        const row = el('tr', lookup.sent ? 'sent-out' : 'sent-cached');
        [SERVICES[lookup.service] || lookup.service, lookup.indicator, lookup.type, lookup.status].forEach(value => row.append(el('td', '', value)));
        table.append(row);
      });
      body.append(el('p', 'sent-label', 'Threat-intelligence lookups'), el('p', 'field-hint',
        'Indicators are sent as they appear in the logs: public addresses, domains, URLs and hashes only. Lookups answered from the cache sent nothing.'), table);
    }
    if (!entry.ai && !(entry.lookups || []).length)
      body.append(el('p', 'field-hint', 'This request was handled by the VEILUX backend alone.'));
    item.append(body);
    return item;
  }

  async function render() {
    const { sendRecord } = await caseStorage.get('sendRecord');
    record = Array.isArray(sendRecord) ? sendRecord : [];
    const list = byId('sent-list');
    list.replaceChildren(...record.slice().reverse().map(renderEntry));
    const backend = await VeiluxBackend.base();
    let local = false;
    try { local = ['localhost', '127.0.0.1', '[::1]'].includes(new URL(backend).hostname); } catch (_) {}
    byId('sent-backend').textContent = local
      ? 'Requests made by the VEILUX backend on this computer (' + backend + '). Extraction requests to your own SIEM are not listed.'
      : 'Your backend address is ' + backend + ', which is not this computer: the case is sent to it before protection runs. Below are the requests it made to outside services.';
    byId('sent-backend').classList.toggle('field-error', !local);
    window.VeiluxUI?.syncResults();
  }

  function exportRecord() {
    const text = JSON.stringify({ veiluxSendRecord: 1, exportedAt: new Date().toISOString(), entries: record }, null, 2);
    const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
    const link = Object.assign(document.createElement('a'), { href: url, download: 'veilux-sent-record-' + new Date().toISOString().slice(0, 10) + '.json' });
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    updateStatus('Record exported.', 'success');
  }

  async function init() {
    await render();
    byId('sent-export').addEventListener('click', exportRecord);
    byId('sent-copy').addEventListener('click', () =>
      copyToClipboard(JSON.stringify({ veiluxSendRecord: 1, entries: record }, null, 2), 'Record of what was sent'));
    caseStorage.onChanged.addListener((changes, area) => { if (area === 'local' && changes.sendRecord) render(); });
  }

  return { init, render, count: () => record.length };
})();
