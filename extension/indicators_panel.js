/* Popup -> Tools -> Case indicators.

   Every IP, domain, URL, hash, email, user, host and SID found in the case's
   logs, in one list (backend /indicators, which runs locally and sends
   nothing). From the list the analyst can:
   - check all public indicators, or the selected ones, with threat
     intelligence (the same protected lookup as "Check an indicator"; results
     join the case's threat intelligence, so the Threat intel tab, Ask and the
     report see them);
   - copy them as they are, or defanged;
   - export them as CSV.
   The list is kept per case (caseIndicators) and recomputed when the logs
   change and the list is on screen. */
window.VeiluxIndicators = (() => {
  const byId = id => document.getElementById(id);
  const TYPES = { ip: 'IP', domain: 'Domain', url: 'URL', hash: 'Hash', email: 'Email', user: 'User', host: 'Host', sid: 'SID' };
  const CONCURRENT = 3;
  let state = null;            // { key, items, limited, results: { value: { verdict, status, detail } } }
  let selected = new Set(), loading = false, checking = false, refreshTimer = null;

  function fingerprint(text) {
    let hash = 2166136261;
    for (let i = 0; i < text.length; i++) hash = Math.imul(hash ^ text.charCodeAt(i), 16777619);
    return (hash >>> 0).toString(36) + ':' + text.length;
  }
  const logsKey = () => fingerprint(capturedLogs.filter(log => typeof log === 'string').join('\n'));
  const shown = () => !byId('stage-tools').hidden && !byId('tools-panel-indicators').hidden;
  const items = () => (state && Array.isArray(state.items) ? state.items : []);
  const visible = () => { const type = byId('indicators-type').value; return items().filter(item => !type || item.type === type); };

  // ---- Defanging, so values can be pasted without becoming links ----
  function defang(item) {
    const dots = text => text.replace(/\./g, '[.]');
    const value = item.value;
    if (item.type === 'url') {
      const match = /^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)(.*)$/i.exec(value);
      if (!match) return dots(value);
      return match[1].replace(/^http/i, scheme => scheme[0] === 'H' ? 'HXXP' : 'hxxp') + '://' + dots(match[2]) + match[3];
    }
    if (item.type === 'ip') return value.includes(':') ? value.replace(/:/g, '[:]') : dots(value);
    if (item.type === 'domain' || item.type === 'host') return dots(value);
    if (item.type === 'email') { const at = value.lastIndexOf('@'); return value.slice(0, at) + '[@]' + dots(value.slice(at + 1)); }
    return value;
  }

  // ---- CSV, with cells that a spreadsheet cannot run as formulas ----
  function csvCell(text) {
    let value = String(text === undefined || text === null ? '' : text);
    if (/^[=+\-@\t\r]/.test(value)) value = "'" + value;
    return '"' + value.replace(/"/g, '""') + '"';
  }
  function csv(list) {
    const rows = [['value', 'defanged', 'type', 'scope', 'occurrences', 'threat_intel']];
    list.forEach(item => {
      const result = state.results[item.value];
      rows.push([item.value, defang(item), TYPES[item.type] || item.type, item.scope, item.count,
        result ? result.verdict + (result.detail ? ' (' + result.detail + ')' : '') : '']);
    });
    return rows.map(row => row.map(csvCell).join(',')).join('\r\n') + '\r\n';
  }

  // What an action applies to: the selected rows, or every row shown.
  const target = () => { const chosen = visible().filter(item => selected.has(item.value)); return chosen.length ? chosen : visible(); };

  function render() {
    const list = byId('indicators-list');
    const all = items(), rows = visible();
    byId('indicators-count').textContent = all.length ? String(all.length) : '';
    byId('indicators-empty').hidden = all.length > 0 || loading;
    byId('indicators-empty').textContent = capturedLogs.some(log => typeof log === 'string' && log.trim())
      ? 'No indicators found in this case\'s logs.' : 'Add logs to this case to list their indicators.';
    byId('indicators-toolbar').hidden = !all.length;
    const types = Array.from(new Set(all.map(item => item.type)));
    const filter = byId('indicators-type'), current = filter.value;
    filter.replaceChildren(new Option('All types (' + all.length + ')', ''),
      ...types.map(type => new Option(TYPES[type] + ' (' + all.filter(item => item.type === type).length + ')', type)));
    filter.value = types.includes(current) ? current : '';
    list.replaceChildren(...rows.map(item => {
      const row = document.createElement('div');
      row.className = 'ind-row';
      row.setAttribute('role', 'listitem');
      const box = Object.assign(document.createElement('input'), { type: 'checkbox', checked: selected.has(item.value) });
      box.setAttribute('aria-label', 'Select ' + item.value);
      box.addEventListener('change', () => { if (box.checked) selected.add(item.value); else selected.delete(item.value); actions(); });
      const value = Object.assign(document.createElement('code'), { className: 'ind-value', textContent: item.value, title: item.value });
      const type = Object.assign(document.createElement('span'), { className: 'ind-type', textContent: TYPES[item.type] || item.type });
      row.append(box, value, type);
      if (item.scope === 'internal' && (item.type === 'ip' || item.type === 'domain'))
        row.append(Object.assign(document.createElement('span'), { className: 'ind-scope', textContent: 'internal' }));
      if (item.count > 1) row.append(Object.assign(document.createElement('span'), { className: 'ind-count', textContent: '×' + item.count }));
      const result = state.results[item.value];
      if (result) {
        const badge = Object.assign(document.createElement('span'), { className: 'ind-verdict ind-' + result.verdict, textContent: result.verdict });
        if (result.detail) badge.title = result.detail;
        row.append(badge);
      }
      return row;
    }));
    actions();
    window.VeiluxUI?.summaries();
  }

  function actions() {
    const rows = visible();
    const chosen = rows.filter(item => selected.has(item.value));
    const all = byId('indicators-select-all');
    all.checked = rows.length > 0 && chosen.length === rows.length;
    all.indeterminate = chosen.length > 0 && chosen.length < rows.length;
    const checkable = (chosen.length ? chosen : rows).filter(item => item.checkable);
    const check = byId('indicators-check');
    check.disabled = checking || !checkable.length;
    if (!checking) check.textContent = (chosen.length ? 'Check selected' : 'Check all') + (checkable.length ? ' (' + checkable.length + ')' : '');
    const which = chosen.length ? 'the selected indicators' : 'the indicators shown';
    byId('indicators-copy-plain').title = 'Copy ' + which + ' as they are';
    byId('indicators-copy').title = 'Copy ' + which + ', defanged';
  }

  async function save() { await caseStorage.set({ caseIndicators: state }); }

  // Lists the indicators again when the logs have changed since the last list.
  async function refresh(force = false) {
    const logs = capturedLogs.filter(log => typeof log === 'string' && log.trim());
    const key = logsKey();
    if (!force && state && state.key === key) { render(); return; }
    if (!logs.length) { state = { key, items: [], limited: false, results: {} }; selected.clear(); await save(); render(); return; }
    loading = true;
    byId('indicators-hint').textContent = 'Finding indicators in the logs…';
    render();
    try {
      const settings = await caseStorage.get(['customCidrsList', 'customDomainsList']);
      const response = await VeiluxBackend.fetch('/indicators', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ logs,
          internal_cidrs: (settings.customCidrsList || []).filter(c => c.enabled).map(c => c.cidr),
          internal_domains: (settings.customDomainsList || []).filter(d => d.enabled).map(d => d.domain) })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'The backend could not list the indicators.');
      // Lookups already made stay with the values that are still in the logs.
      const previous = (state && state.results) || {};
      const results = {};
      (data.indicators || []).forEach(item => { if (previous[item.value]) results[item.value] = previous[item.value]; });
      state = { key, items: data.indicators || [], limited: !!data.limited, results };
      selected = new Set(Array.from(selected).filter(value => state.items.some(item => item.value === value)));
      await save();
      hint();
    } catch (error) {
      byId('indicators-hint').textContent = 'Indicators: ' + error.message;
    } finally {
      loading = false;
      render();
    }
  }

  const HINT = 'Found in this case\'s logs. Public IPs, domains, URLs and hashes can be checked with threat intelligence; '
    + 'internal addresses, users and hosts are listed for reference.';
  function hint() { byId('indicators-hint').textContent = HINT + (state && state.limited ? ' Only the first 500 are listed.' : ''); }

  async function check() {
    const list = target().filter(item => item.checkable);
    if (!list.length || checking) return;
    if (!await lookupSourcesReady()) {
      updateStatus('No lookup source is ready: turn on WHOIS, or add a VirusTotal or AbuseIPDB key in Settings.', 'error');
      return;
    }
    checking = true;
    const button = byId('indicators-check');
    button.disabled = true;
    let done = 0;
    const findings = [], queue = list.slice();
    const progress = () => { button.textContent = 'Checking ' + done + ' of ' + list.length + '…'; };
    progress();
    async function worker() {
      while (queue.length) {
        const item = queue.shift();
        try {
          const result = await lookupIndicator(item.value);
          findings.push(result);
          state.results[item.value] = { verdict: result.verdict || 'unknown', status: result.lookup_status || '',
            detail: result.lookup_status === 'partial' ? 'some sources unavailable' : result.lookup_status === 'unavailable' ? 'sources unavailable' : '' };
        } catch (error) {
          state.results[item.value] = { verdict: 'error', status: 'error', detail: error.message };
        }
        done++; progress(); render();
      }
    }
    try {
      await Promise.all(Array.from({ length: Math.min(CONCURRENT, list.length) }, worker));
      await save();
      if (findings.length) await mergeThreatIntelFindings(findings);
      const flagged = list.filter(item => ['malicious', 'suspicious'].includes(state.results[item.value]?.verdict)).length;
      updateStatus('Checked ' + list.length + ' indicator' + (list.length === 1 ? '' : 's') + (flagged ? ': ' + flagged + ' flagged.' : '.')
        + ' Results are in Results → Threat intel too.', flagged ? 'info' : 'success');
    } finally {
      checking = false;
      render();
    }
  }

  function copy(defanged) {
    const list = target();
    if (list.length) copyToClipboard(list.map(item => defanged ? defang(item) : item.value).join('\n'),
      list.length + ' indicator' + (list.length === 1 ? '' : 's') + (defanged ? ' (defanged)' : ''));
  }

  async function exportCsv() {
    const list = target();
    if (!list.length) return;
    const url = URL.createObjectURL(new Blob([csv(list)], { type: 'text/csv' }));
    const name = 'veilux-indicators-' + (await caseStorage.caseId() || 'case-1').replace(/[^a-z0-9-]+/gi, '-') + '.csv';
    const link = Object.assign(document.createElement('a'), { href: url, download: name });
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    updateStatus('Exported ' + list.length + ' indicator' + (list.length === 1 ? '' : 's') + ' as CSV.', 'success');
  }

  async function init() {
    const stored = await caseStorage.get('caseIndicators');
    state = stored.caseIndicators && Array.isArray(stored.caseIndicators.items)
      ? { results: {}, ...stored.caseIndicators } : null;
    hint(); render();
    byId('indicators-select-all').addEventListener('change', event => {
      visible().forEach(item => { if (event.target.checked) selected.add(item.value); else selected.delete(item.value); });
      render();
    });
    byId('indicators-type').addEventListener('change', render);
    byId('indicators-check').addEventListener('click', check);
    byId('indicators-copy-plain').addEventListener('click', () => copy(false));
    byId('indicators-copy').addEventListener('click', () => copy(true));
    byId('indicators-csv').addEventListener('click', exportCsv);
    // Listed when the panel comes on screen, and again when the logs change.
    const observer = new MutationObserver(() => { if (shown()) refresh(); });
    ['stage-tools', 'tools-panel-indicators'].forEach(id => observer.observe(byId(id), { attributes: true, attributeFilter: ['hidden'] }));
    window.addEventListener('pagehide', () => observer.disconnect(), { once: true });
    caseStorage.onChanged.addListener((changes, area) => {
      if (area !== 'local' || !('capturedLogs' in changes) || !shown()) return;
      clearTimeout(refreshTimer); refreshTimer = setTimeout(() => refresh(), 800);
    });
    if (shown()) refresh();
  }

  async function reset() {
    state = null; selected.clear();
    await caseStorage.remove('caseIndicators');
    hint(); render();
  }

  return { init, refresh, reset, defang, csv: list => csv(list), count: () => items().length, items };
})();
