/* Email report templates, shared by Settings and the popup.

   A template is the analyst's own: a name, the language the AI writes in, a
   severity scale with colours, a subject pattern, AI instructions and an HTML
   body. Templates are stored in this browser ("reportTemplates"); only the
   built-in one ships with VEILUX.

   Template syntax (a small, safe subset of Mustache):
     {{name}}               a value, HTML-escaped; line breaks become <br>
     {{a.b}}                a nested value
     {{name|upper}}         the value in capitals ({{name|lower}}: in lower case)
     {{ai_name}}            a value the AI writes, such as {{ai_affected_asset}}
     {{#list}}...{{/list}}  repeats for each item ({{.}} is a plain item);
                            also shows the block when a value is true or set
     {{#has_list}}...{{/has_list}}  shows a block once when a list has items
     {{^name}}...{{/name}}  shows the block when a value is empty or false
   Values are always escaped, so text from logs can never add HTML. */
globalThis.VeiluxReports = (() => {
  const STORE_KEY = 'reportTemplates', DEFAULT_KEY = 'defaultReportTemplateId';
  const BUILTIN_ID = 'builtin';
  const MAX_TEMPLATE_CHARS = 300000;

  // Variables every report provides; any other variable in the subject pattern
  // or the HTML becomes a free-text field on the report page.
  const BUILTIN_VARIABLES = ['title', 'case_id', 'severity', 'severity_color', 'date', 'detection_time',
    'summary', 'details', 'context', 'risks', 'recommendations', 'annexes', 'extra_sections', 'subject', 'template_name',
    'has_details', 'has_risks', 'has_recommendations', 'has_annexes', 'has_extra_sections'];
  // Names used inside lists ({{#details}}{{label}}{{/details}}), never fields of their own.
  const ITEM_VARIABLES = ['label', 'value', 'highlight', 'name', 'color', 'content'];
  // Variables starting with ai_ are written by the AI, not typed by the analyst.
  const isAiVariable = name => /^ai_\w+$/.test(name);

  const DEFAULT_SEVERITIES = [
    { name: 'Low', color: '#2E7D32' }, { name: 'Medium', color: '#D97706' },
    { name: 'High', color: '#DC2626' }, { name: 'Critical', color: '#7F1D1D' }];

  const DEFAULT_INSTRUCTIONS = [
    'You are a senior SOC analyst writing an escalation email to the team that owns the affected systems.',
    'From the logs, statistics and analyst context, explain what happened, why it matters and what the recipient should check or do.',
    'Be factual: use only values present in the input, and say when something is unknown instead of guessing.',
    'Keep the summary to two or three sentences. List every relevant fact in "details" (any label: user, host, IP, process, rule, count, time range...) and mark the most important ones with "highlight": true.',
    'When a finding from the logs, statistics or analyst notes is important but fits no other key, add it under "extra_sections" with a short title.',
    'Write risks and recommendations as short, concrete actions suited to this alert.',
    'Copy protected markers (text inside ⟦ ⟧ brackets) exactly as written; they stand for values hidden before sending.'].join('\n');

  // Built-in template: a plain, left-aligned email with inline styles, because
  // many mail clients drop <style> blocks and outer backgrounds. Only the body
  // is copied into the email, so nothing outside it matters.
  const BUILTIN_HTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>{{subject}}</title></head>
<body style="margin:0;font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.5;color:#1F2937;">
<div style="max-width:680px;">
<p style="margin:0 0 12px;">Hello,</p>
<p style="margin:0 0 16px;">Please review the alert below and confirm whether this activity is expected, so we can close or escalate the case.</p>
<table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;max-width:680px;border-collapse:collapse;border-top:4px solid {{severity_color}};margin:0 0 16px;">
  <tr><td colspan="2" style="padding:10px 0 6px;font-size:18px;font-weight:bold;color:#111827;">{{title}}</td></tr>
  <tr><td style="width:120px;padding:3px 0;color:#6B7280;">Case</td><td style="padding:3px 0;font-weight:bold;">{{case_id}}</td></tr>
  <tr><td style="padding:3px 0;color:#6B7280;">Severity</td><td style="padding:3px 0;"><span style="display:inline-block;padding:1px 10px;border-radius:10px;background:{{severity_color}};color:#FFFFFF;font-weight:bold;font-size:12px;">{{severity}}</span></td></tr>
  <tr><td style="padding:3px 0;color:#6B7280;">Detected</td><td style="padding:3px 0;font-weight:bold;">{{detection_time}}</td></tr>
</table>
<p style="margin:0 0 6px;font-weight:bold;color:#111827;">Summary</p>
<p style="margin:0 0 16px;word-break:break-word;overflow-wrap:anywhere;">{{summary}}</p>
{{#has_details}}<p style="margin:0 0 6px;font-weight:bold;color:#111827;">Alert details</p>
<table cellpadding="0" cellspacing="0" style="width:100%;max-width:680px;border-collapse:collapse;margin:0 0 16px;font-size:13px;">
  <tr><th style="width:34%;padding:6px 10px;border:1px solid #D1D5DB;background:#F3F4F6;text-align:left;">Field</th><th style="padding:6px 10px;border:1px solid #D1D5DB;background:#F3F4F6;text-align:left;">Value</th></tr>
  {{#details}}<tr><td style="padding:6px 10px;border:1px solid #D1D5DB;color:#4B5563;{{#highlight}}background:#FFF4E5;{{/highlight}}">{{label}}</td><td style="padding:6px 10px;border:1px solid #D1D5DB;word-break:break-word;overflow-wrap:anywhere;{{#highlight}}background:#FFF4E5;font-weight:bold;{{/highlight}}">{{value}}</td></tr>{{/details}}
</table>{{/has_details}}
{{#context}}<p style="margin:0 0 6px;font-weight:bold;color:#111827;">Context</p>
<p style="margin:0 0 16px;word-break:break-word;overflow-wrap:anywhere;">{{context}}</p>{{/context}}
{{#extra_sections}}<p style="margin:0 0 6px;font-weight:bold;color:#111827;">{{title}}</p>
<p style="margin:0 0 16px;word-break:break-word;overflow-wrap:anywhere;">{{content}}</p>{{/extra_sections}}
{{#has_risks}}<p style="margin:0 0 6px;font-weight:bold;color:#111827;">Potential risks</p>
<ul style="margin:0 0 16px;padding-left:22px;">{{#risks}}<li style="margin:0 0 4px;">{{.}}</li>{{/risks}}</ul>{{/has_risks}}
{{#has_recommendations}}<p style="margin:0 0 6px;font-weight:bold;color:#111827;">Recommended actions</p>
<ol style="margin:0 0 16px;padding-left:22px;">{{#recommendations}}<li style="margin:0 0 4px;">{{.}}</li>{{/recommendations}}</ol>{{/has_recommendations}}
{{#has_annexes}}<p style="margin:0 0 6px;font-weight:bold;color:#111827;">Evidence</p>
{{#annexes}}<p style="margin:0 0 8px;"><b>{{label}}</b><br><i style="color:#6B7280;">[Insert screenshot here]</i></p>{{/annexes}}{{/has_annexes}}
<p style="margin:16px 0 0;">Thank you for your feedback.</p>
<p style="margin:4px 0 0;">Best regards,</p>
</div>
</body></html>`;

  const BUILTIN = Object.freeze({
    id: BUILTIN_ID, name: 'VEILUX standard', builtin: true, language: 'English',
    severities: DEFAULT_SEVERITIES, subjectPattern: 'Case #{{case_id}} - {{title}}',
    caseIdPlaceholder: '[Case ID]', instructions: DEFAULT_INSTRUCTIONS, keepMasked: false, html: BUILTIN_HTML
  });

  // ---- Template engine ----
  const escapeHtml = value => String(value).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  const asText = value => value === null || value === undefined ? '' : typeof value === 'object' ? JSON.stringify(value) : String(value);
  const isEmpty = value => value === undefined || value === null || value === false || value === '' || (Array.isArray(value) && !value.length);

  function lookup(name, stack) {
    if (name === '.') return stack[stack.length - 1];
    for (let i = stack.length - 1; i >= 0; i--) {
      const scope = stack[i];
      if (scope && typeof scope === 'object' && name.split('.')[0] in scope)
        return name.split('.').reduce((value, key) => value == null ? undefined : value[key], scope);
    }
    return undefined;
  }

  // Parses the template into a tree once; unbalanced sections are reported.
  function parse(template) {
    const root = [], stack = [{ children: root }];
    const tag = /\{\{\s*([#^/]?)\s*([\w.]+|\.)\s*(?:\|\s*(upper|lower)\s*)?\}\}/g;
    let cursor = 0, match;
    while ((match = tag.exec(template))) {
      const children = stack[stack.length - 1].children;
      if (match.index > cursor) children.push({ text: template.slice(cursor, match.index) });
      const [, kind, name, filter] = match;
      if (kind === '#' || kind === '^') {
        const node = { section: name, inverted: kind === '^', children: [] };
        children.push(node); stack.push(node);
      } else if (kind === '/') {
        const open = stack.pop();
        if (!open.section || open.section !== name) throw new Error('The template closes {{/' + name + '}} without a matching {{#' + name + '}}.');
      } else children.push({ value: name, filter });
      cursor = tag.lastIndex;
    }
    if (stack.length > 1) throw new Error('The template opens {{#' + stack[stack.length - 1].section + '}} without closing it.');
    if (cursor < template.length) root.push({ text: template.slice(cursor) });
    return root;
  }

  function renderNodes(nodes, stack) {
    let out = '';
    for (const node of nodes) {
      if (node.text !== undefined) out += node.text;
      else if (node.value !== undefined) out += escapeHtml(applyFilter(asText(lookup(node.value, stack)), node.filter)).replace(/\r?\n/g, '<br>');
      else {
        const value = lookup(node.section, stack);
        if (node.inverted) { if (isEmpty(value)) out += renderNodes(node.children, stack); }
        else if (Array.isArray(value)) value.forEach(item => { out += renderNodes(node.children, stack.concat([item])); });
        else if (!isEmpty(value)) out += renderNodes(node.children, typeof value === 'object' ? stack.concat([value]) : stack);
      }
    }
    return out;
  }

  const applyFilter = (text, filter) => filter === 'upper' ? text.toUpperCase() : filter === 'lower' ? text.toLowerCase() : text;

  function render(template, data) { return renderNodes(parse(template), [data]); }

  // Plain-text fill for the subject line (no HTML escaping, no sections).
  function fillText(pattern, data) {
    return String(pattern || '').replace(/\{\{\s*([\w.]+)\s*(?:\|\s*(upper|lower)\s*)?\}\}/g,
      (_, name, filter) => applyFilter(asText(lookup(name, [data])), filter).replace(/\s+/g, ' ').trim());
  }

  // Variables a template uses, in order of appearance.
  function variablesOf(text) {
    const seen = [];
    for (const match of String(text || '').matchAll(/\{\{\s*[#^/]?\s*([\w]+)(?:\.[\w.]+)?\s*(?:\|\s*\w+\s*)?\}\}/g))
      if (!seen.includes(match[1])) seen.push(match[1]);
    return seen;
  }

  // Free-text fields the report page asks for: variables of the subject pattern
  // and the HTML that VEILUX does not fill itself (for example {{team}}).
  function customFields(template) {
    return variablesOf(template.subjectPattern + ' ' + template.html)
      .filter(name => !BUILTIN_VARIABLES.includes(name) && !ITEM_VARIABLES.includes(name) && !isAiVariable(name));
  }

  // Placeholders the AI fills exactly, one value each ({{ai_affected_asset}}).
  const aiFields = template => variablesOf(template.subjectPattern + ' ' + template.html).filter(isAiVariable);

  const fieldLabel = name => name.replace(/_/g, ' ').replace(/^\w/, ch => ch.toUpperCase());

  // ---- Validation ----
  function validate(template) {
    const problems = [];
    if (!String(template.name || '').trim()) problems.push(['name', 'Give the template a name.']);
    if (!String(template.subjectPattern || '').trim()) problems.push(['subject', 'Enter a subject pattern, for example Case #{{case_id}} - {{title}}.']);
    if (!String(template.html || '').trim()) problems.push(['html', 'Paste or import the HTML of the email.']);
    else if (template.html.length > MAX_TEMPLATE_CHARS) problems.push(['html', 'The HTML is larger than 300,000 characters. Remove embedded images or unused markup.']);
    else { try { parse(template.html); parse(template.subjectPattern || ''); } catch (error) { problems.push(['html', error.message]); } }
    const severities = (template.severities || []).filter(level => String(level.name || '').trim());
    if (!severities.length) problems.push(['severities', 'Add at least one severity level.']);
    if (new Set(severities.map(level => level.name.trim().toLowerCase())).size !== severities.length)
      problems.push(['severities', 'Each severity level needs a different name.']);
    if (severities.some(level => !/^#[0-9a-fA-F]{6}$/.test(level.color || ''))) problems.push(['severities', 'Choose a colour for every severity level.']);
    return problems;
  }

  // ---- Storage ----
  async function all() {
    const stored = await browser.storage.local.get([STORE_KEY, DEFAULT_KEY]);
    // Normalized on every read, so a template from an older backup or a hand-edited file stays usable.
    const own = (Array.isArray(stored[STORE_KEY]) ? stored[STORE_KEY] : []).filter(t => t && typeof t === 'object').map(normalize);
    const templates = [BUILTIN, ...own];
    const defaultId = templates.some(t => t.id === stored[DEFAULT_KEY]) ? stored[DEFAULT_KEY] : BUILTIN_ID;
    return { templates, defaultId };
  }
  async function get(id) {
    const { templates, defaultId } = await all();
    return templates.find(t => t.id === id) || templates.find(t => t.id === defaultId) || BUILTIN;
  }
  async function saveOwn(templates) { await browser.storage.local.set({ [STORE_KEY]: templates.filter(t => !t.builtin) }); }
  async function setDefault(id) { await browser.storage.local.set({ [DEFAULT_KEY]: id }); }

  // A template file (.json) shares one template; ids are replaced on import.
  function exportFile(template) {
    const { id, builtin, ...portable } = template;
    return JSON.stringify({ veiluxReportTemplate: 1, template: portable }, null, 2);
  }
  function importFile(text) {
    let parsed;
    try { parsed = JSON.parse(text); } catch (_) { throw new Error('This file is not a VEILUX report template (it is not valid JSON).'); }
    const source = parsed && parsed.veiluxReportTemplate ? parsed.template : null;
    if (!source || typeof source !== 'object') throw new Error('This file is not a VEILUX report template.');
    const template = normalize({ ...source, id: crypto.randomUUID(), builtin: false });
    const problems = validate(template);
    if (problems.length) throw new Error(problems.map(p => p[1]).join(' '));
    return template;
  }
  function normalize(t) {
    return { id: t.id || crypto.randomUUID(), name: String(t.name || '').trim(), builtin: false,
      language: String(t.language || 'English').trim() || 'English',
      severities: (Array.isArray(t.severities) ? t.severities : DEFAULT_SEVERITIES)
        .map(level => ({ name: String(level.name || '').trim(), color: String(level.color || '#64748B') })).filter(level => level.name),
      subjectPattern: String(t.subjectPattern || ''), caseIdPlaceholder: String(t.caseIdPlaceholder ?? '[Case ID]'),
      instructions: String(t.instructions || DEFAULT_INSTRUCTIONS), keepMasked: !!t.keepMasked, html: String(t.html || '') };
  }

  // ---- AI request and response ----
  // The extension adds the answer format itself, so edited instructions cannot
  // break the report.
  function instructionsFor(template, fields) {
    const scale = template.severities.map(level => level.name).join(', ');
    const chosen = [];
    if (fields.title) chosen.push('- The alert title is fixed by the analyst: "' + fields.title + '". Use it as "title".');
    if (fields.severity) chosen.push('- The severity is fixed by the analyst: "' + fields.severity + '". Use it as "severity".');
    const own = aiFields(template);
    return [template.instructions.trim(), '',
      'Write every text value in ' + (template.language || 'English') + '.',
      'Choose "severity" from exactly one of: ' + scale + '.',
      ...chosen, '',
      'Answer with JSON only, no Markdown and no text before or after it, using exactly these keys:',
      '{"title": "short alert title", "severity": "one level from the list", "detection_time": "YYYY-MM-DD HH:MM from the logs, or \\"unknown\\"",',
      ' "summary": "2-3 sentences", "details": [{"label": "field", "value": "value from the logs", "highlight": true}],',
      ' "context": "2-4 sentences of technical context", "risks": ["risk"], "recommendations": ["action"], "annexes": [{"label": "evidence to attach"}],',
      ' "extra_sections": [{"title": "section title", "content": "text"}]' + (own.length ? ',' : '}'),
      ...(own.length ? [' ' + own.map(name => '"' + name + '": "' + name.slice(3).replace(/_/g, ' ') + '"').join(', ') + '}'] : []),
      '"details" may hold as many rows as the case needs, with any labels. "extra_sections" is optional and usually empty: use it only for findings from the logs, statistics or analyst notes that fit no other key, never for threat intelligence results or the earlier analysis.',
      ...(own.length ? ['Fill ' + own.map(name => '"' + name + '"').join(', ') + ' with one short value each, taken from the input; write "unknown" when the input does not say.'] : [])].join('\n');
  }

  // Dates from logs often arrive as epoch numbers; the email shows them readably.
  function readableTime(value) {
    const text = asText(value).trim();
    if (!/^\d{10}(\d{3})?$/.test(text)) return text;
    const date = new Date(Number(text) * (text.length === 10 ? 1000 : 1));
    return isNaN(date) ? text : date.toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
  }

  // Reads the AI's answer; tolerates a Markdown fence around the JSON.
  function parseAnswer(raw) {
    let text = String(raw || '').trim();
    const fenced = /```(?:json)?\s*\n([\s\S]*?)\n```/i.exec(text);
    if (fenced) text = fenced[1].trim();
    const start = text.indexOf('{'), end = text.lastIndexOf('}');
    if (start < 0 || end < start) throw new Error('The AI did not return the report in the expected format. Generate it again, or try another model.');
    let data;
    try { data = JSON.parse(text.slice(start, end + 1)); }
    catch (_) { throw new Error('The AI returned an incomplete report. Generate it again, or try another model.'); }
    const list = value => Array.isArray(value) ? value : value ? [value] : [];
    return {
      ...Object.fromEntries(Object.entries(data).filter(([key]) => isAiVariable(key)).map(([key, value]) => [key, asText(value).trim()])),
      title: asText(data.title).trim(), severity: asText(data.severity).trim(), detection_time: readableTime(data.detection_time),
      summary: asText(data.summary).trim(), context: asText(data.context).trim(),
      details: list(data.details).filter(d => d && typeof d === 'object')
        .map(d => ({ label: asText(d.label).trim(), value: asText(d.value).trim(), highlight: d.highlight === true })).filter(d => d.label || d.value),
      risks: list(data.risks).map(asText).map(s => s.trim()).filter(Boolean),
      recommendations: list(data.recommendations).map(asText).map(s => s.trim()).filter(Boolean),
      annexes: list(data.annexes).map(a => ({ label: asText(a && typeof a === 'object' ? a.label : a).trim() })).filter(a => a.label),
      extra_sections: list(data.extra_sections).filter(x => x && typeof x === 'object')
        .map(x => ({ title: asText(x.title).trim(), content: asText(x.content).trim() })).filter(x => x.title && x.content)
    };
  }

  // For templates that keep values masked: the backend restores real values in
  // the answer, and its restore map says which marker each value stood for.
  // Credentials are never restored, so they need no masking here.
  function remask(content, mapping) {
    const pairs = Object.entries(mapping || {})
      .filter(([marker, original]) => marker.startsWith('⟦') && original && !/^Protected credential/.test(original))
      .sort((a, b) => b[1].length - a[1].length);
    if (!pairs.length) return content;
    const mask = text => pairs.reduce((value, [marker, original]) => value.split(original).join(marker), text);
    const walk = value => Array.isArray(value) ? value.map(walk)
      : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).map(([key, inner]) => [key, walk(inner)]))
      : typeof value === 'string' ? mask(value) : value;
    return walk(content);
  }

  // Combines the AI's content with the analyst's fields and the template.
  function assemble(template, content, fields) {
    const levels = template.severities;
    const wanted = (fields.severity || content.severity || '').toLowerCase();
    const level = levels.find(l => l.name.toLowerCase() === wanted) || null;
    const data = { ...fields, ...content,
      template_name: template.name,
      title: fields.title || content.title || 'Security alert',
      case_id: fields.case_id || template.caseIdPlaceholder || '',
      severity: level ? level.name : (fields.severity || content.severity || levels[0].name),
      severity_color: level ? level.color : '#64748B',
      date: new Date().toLocaleDateString(),
      detection_time: readableTime(content.detection_time) || 'unknown',
      // Section switches: a list itself repeats its block, so "show this section" uses these.
      has_details: !!(content.details || []).length, has_risks: !!(content.risks || []).length,
      has_recommendations: !!(content.recommendations || []).length, has_annexes: !!(content.annexes || []).length,
      has_extra_sections: !!(content.extra_sections || []).length };
    aiFields(template).forEach(name => { if (!data[name]) data[name] = 'unknown'; });
    data.subject = fillText(template.subjectPattern, data);
    return { data, subject: data.subject, html: render(template.html, data) };
  }

  // What goes into the email: the body's content only. The page title and
  // anything in <head> would otherwise be pasted as text, and outer page
  // backgrounds show as padding around the message.
  function emailBody(html) {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    const body = doc.body;
    // Text styles set on <body> (font, size, colour) are kept on a wrapper.
    const kept = String(body.getAttribute('style') || '').split(';').map(rule => rule.trim())
      .filter(rule => /^(font(-[a-z]+)?|color|line-height)\s*:/i.test(rule)).join(';');
    return kept ? '<div style="' + escapeHtml(kept) + '">' + body.innerHTML.trim() + '</div>' : body.innerHTML.trim();
  }

  const SAMPLE = {
    title: 'Repeated failed sign-ins followed by a success', severity: 'High', detection_time: '2026-01-15 09:42 UTC',
    summary: 'The account j.doe failed to sign in 23 times from 203.0.113.45 within five minutes, then signed in successfully.\nThe source address is not used by the organization.',
    details: [{ label: 'User', value: 'j.doe', highlight: true }, { label: 'Source IP', value: '203.0.113.45', highlight: true },
      { label: 'Host', value: 'WS-0142', highlight: false }, { label: 'Event IDs', value: '4625, 4624', highlight: false }],
    context: 'The burst matches a password-guessing pattern. The successful sign-in came from the same address one minute later.',
    risks: ['Account takeover', 'Lateral movement from WS-0142'],
    recommendations: ['Reset the password of j.doe and revoke active sessions', 'Block 203.0.113.45 at the perimeter', 'Review sign-ins of j.doe for the last 7 days'],
    annexes: [{ label: 'Sign-in events 4625 and 4624' }],
    extra_sections: [{ title: 'Previous activity', content: 'No earlier alert involved j.doe or 203.0.113.45 in the last 30 days.' }]
  };
  function sample(template) {
    const fields = Object.fromEntries(customFields(template).map(name => [name, fieldLabel(name) + ' value']));
    const written = Object.fromEntries(aiFields(template).map(name => [name, fieldLabel(name.slice(3)) + ' (written by the AI)']));
    return assemble(template, { ...SAMPLE, ...written }, { ...fields, case_id: '12345' });
  }

  return { BUILTIN, BUILTIN_ID, DEFAULT_SEVERITIES, DEFAULT_INSTRUCTIONS, MAX_TEMPLATE_CHARS,
    render, fillText, variablesOf, customFields, aiFields, fieldLabel, validate, all, get, saveOwn, setDefault, remask,
    exportFile, importFile, normalize, instructionsFor, parseAnswer, readableTime, assemble, emailBody, sample, escapeHtml };
})();
