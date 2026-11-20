/* Shared, escaped presentation of provider facts. No network requests here. */
(function(root) {
  'use strict';
  const names = {virustotal:'VirusTotal', abuseipdb:'AbuseIPDB', whois:'WHOIS / RDAP'};
  const escape = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const present = value => value !== null && value !== undefined && value !== '';
  function valueText(value) {
    if (!present(value)) return 'Not available';
    if (typeof value === 'boolean') return value ? 'Yes' : 'No';
    if (Array.isArray(value)) return value.length ? value.join(', ') : 'None returned';
    if (typeof value === 'object') return Object.entries(value).map(([k,v]) => k + ': ' + v).join(', ') || 'None returned';
    return String(value);
  }
  function country(code, name) {
    let flag = '';
    if (/^[A-Z]{2}$/.test(code || '')) flag = String.fromCodePoint(...[...code].map(c => 127397 + c.charCodeAt(0))) + ' ';
    return present(name) ? flag + name + (code ? ' (' + code + ')' : '') : code ? flag + code : null;
  }
  function date(value, unix = false) {
    if (!present(value)) return null;
    const d = new Date(unix ? value * 1000 : value);
    return Number.isNaN(d.getTime()) ? String(value) : d.toISOString().replace('T',' ').replace('.000Z',' UTC');
  }
  function rows(entries) {
    return '<dl class="ti-facts">' + entries.map(([label, value]) =>
      '<dt>' + escape(label) + '</dt><dd>' + escape(valueText(value)) + '</dd>').join('') + '</dl>';
  }
  function source(name, src, iocType, ioc) {
    let content;
    if (src.status !== 'ok') {
      const state = {not_found:name === 'whois' ? 'No registration record available; registration status is unknown.' : 'No existing report found.',
        rate_limited:'Request limit reached. Try again later.', timeout:'The service timed out. Try again.',
        skipped:'Not checked: analysis lookup time limit reached.', unsupported:'Not queried.', error:'Lookup failed.'}[src.status] || 'No data returned.';
      content = '<p class="ti-source-status">' + escape(state) + (src.detail ? ' ' + escape(src.detail) : '') + '</p>';
    } else if (name === 'abuseipdb') {
      const score = present(src.abuse_confidence_score) ? src.abuse_confidence_score + '%' : null;
      content = rows([
        ['Abuse confidence', score], ['Reports in the last ' + (src.report_window_days || 90) + ' days', src.total_reports],
        ['Distinct reporters', src.distinct_reporters], ['Last reported', date(src.last_reported_at)],
        ['ISP', src.isp], ['Usage type', src.usage_type], ['Domain name', src.domain],
        ['Country', country(src.country, src.country_name)], ['ASN', 'Not provided by AbuseIPDB; see VirusTotal when available'],
        ['City / region', 'Not provided by the AbuseIPDB check API'], ['Hostnames', src.hostnames],
        ['IP version', src.ip_version], ['Public IP', src.is_public], ['Whitelisted', src.is_whitelisted], ['Tor exit node', src.is_tor]
      ]) + '<p class="field-hint">A 0% score is not a guarantee of safety. Report counts cover this lookup’s time window.</p>';
    } else if (name === 'virustotal') {
      const common = [
        ['Malicious detections', src.malicious], ['Suspicious detections', src.suspicious], ['Reporting engines', src.total_engines],
        ['Last analysis', date(src.last_analysis_date, true)]
      ];
      const details = iocType === 'hash' ? [
        ['File name', src.file_name], ['File type', src.file_type],
        ['File size', present(src.file_size) ? src.file_size + ' bytes' : null],
        ['First submitted', date(src.first_submission_date, true)], ['Submissions', src.times_submitted]
      ] : [
        ['ASN', present(src.asn) ? 'AS' + src.asn : null],
        ['Network owner', src.as_owner], ['Network range', src.network], ['Country', country(src.country)],
        ['Internet registry', src.registry], ['Categories', src.categories]
      ];
      content = rows([...common, ...details, ['Community reputation', src.reputation], ['Tags', src.tags]]);
    } else if (name === 'whois') {
      content = rows(src.queried_domain || src.domain ? [
        ['Requested hostname', src.requested_domain || src.domain], ['Registration lookup for', src.queried_domain || src.domain],
        ['Registrar', src.registrar], ['Registered', date(src.created)], ['Age in days', src.age_days],
        ['Expires', date(src.expires)], ['Last changed', date(src.last_changed)],
        ['Nameservers', src.nameservers], ['Registration status', src.status_flags], ['Abuse contact', src.abuse_contact]
      ] : [
        ['Network name', src.network_name], ['Organization', src.org], ['Address range', src.network_range],
        ['CIDR', src.cidr], ['Registry country', country(src.country)], ['Assigned', date(src.assigned)], ['Abuse contact', src.abuse_contact]
      ]) + '<p class="field-hint">Free registration data from RDAP. Ownership and registry country do not establish reputation or physical location.</p>';
      if (src.note) content += '<p>' + escape(src.note) + '</p>';
    } else content = '<p>No supported details returned.</p>';
    let link = '';
    try {
      const url = new URL(src.link);
      const host = {virustotal:'www.virustotal.com', abuseipdb:'www.abuseipdb.com'}[name];
      // A protected value must never become a report URL, including saved
      // responses produced by older backends. Do not try to restore it here.
      const protectedTarget = /[⟦⟧]/.test(decodeURIComponent(url.href)) || /[⟦⟧]/.test(ioc || '');
      if (host && url.protocol === 'https:' && url.hostname === host && !url.username && !url.password && !protectedTarget)
        link = '<a href="' + escape(url.href) + '" target="_blank" rel="noopener noreferrer">Open provider report ↗</a>';
    } catch (_) { /* Untrusted or absent provider link. */ }
    const stamp = src.checked_at ? '<p class="ti-timestamp">' + (src.cached ? 'Cached · checked ' : 'Checked ') + escape(date(src.checked_at)) + '</p>' : '';
    return '<details class="ti-provider"><summary>' + escape(names[name] || name) +
      (src.status === 'ok' ? '' : src.status === 'unsupported' ? ' — not queried' : ' — unavailable') +
      (src.cached ? ' · cached' : '') + '</summary>' + content + stamp + link + '</details>';
  }
  function renderSources(sources, iocType, ioc) {
    const entries = Object.entries(sources || {});
    return entries.length ? entries.map(([name, src]) => source(name, src || {}, iocType, ioc)).join('') : '<p>No enabled lookup source returned data.</p>';
  }
  function verdictBadge(verdict) {
    return {malicious:'🔴 Malicious signals', suspicious:'⚠️ Suspicious signals', clean:'No current reputation flags', unknown:'Reputation unknown'}[verdict] || 'Reputation unknown';
  }
  function renderFinding(f) {
    const verdict = ['malicious','suspicious','clean'].includes(f.verdict) ? f.verdict : 'unknown';
    return '<div class="ti-finding ti-' + verdict + '"><strong>' + escape(f.ioc || '') + '</strong> (' + escape(f.hash_algorithm || f.type || '') + ') — ' +
      verdictBadge(verdict) + (f.lookup_status === 'partial' ? '<p class="field-hint">Some sources are unavailable. Review each source below.</p>' : '') +
      '<div class="ti-sources">' + renderSources(f.sources, f.type, f.ioc) + '</div></div>';
  }
  const api = {renderSources, renderFinding, verdictBadge};
  root.VeiluxThreatIntel = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
