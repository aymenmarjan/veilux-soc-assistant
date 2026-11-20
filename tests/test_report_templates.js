// Email report templates: the safe placeholder engine, validation, the AI
// answer format and how the analyst's fields combine with the AI's content.
const assert = require('assert');
globalThis.crypto = globalThis.crypto || require('crypto').webcrypto;
globalThis.browser = {};
require('../extension/report_templates.js');
const R = globalThis.VeiluxReports;

// Values are escaped and keep their line breaks; lists repeat; empty values hide blocks.
assert.equal(R.render('<b>{{x}}</b>', { x: '<img src=x onerror=alert(1)>\nnext' }), '<b>&lt;img src=x onerror=alert(1)&gt;<br>next</b>');
assert.equal(R.render('{{#l}}[{{.}}]{{/l}}{{^e}}none{{/e}}', { l: ['a', '"b"'], e: [] }), '[a][&quot;b&quot;]none');
assert.equal(R.render('{{#d}}{{label}}={{value}}{{#highlight}}!{{/highlight}};{{/d}}', { d: [{ label: 'IP', value: '1', highlight: true }, { label: 'U', value: '2' }] }), 'IP=1!;U=2;');
assert.equal(R.render('{{a.b}}', { a: { b: 'deep' } }), 'deep');
assert.throws(() => R.render('{{#open}}x', {}), /without closing/);
assert.throws(() => R.render('{{/close}}', {}), /without a matching/);

// The subject is plain text; extra variables become fields on the report page.
assert.equal(R.fillText('Case #{{case_id}} - {{title}} ({{team}})', { team: 'Network', case_id: '7', title: 'Brute\nforce' }), 'Case #7 - Brute force (Network)');
assert.deepEqual(R.customFields({ subjectPattern: '{{team}} {{case_id}} {{title}}', html: '{{region}}{{#details}}{{label}}{{/details}}{{#has_risks}}{{/has_risks}}' }), ['team', 'region']);
assert.equal(R.fieldLabel('ticket_owner'), 'Ticket owner');

// The built-in template is valid and fills every section from sample data.
assert.deepEqual(R.validate(R.BUILTIN), []);
const sample = R.sample(R.BUILTIN);
assert.equal(sample.subject, 'Case #12345 - Repeated failed sign-ins followed by a success');
assert.equal((sample.html.match(/<tr><td style="padding:6px 10px/g) || []).length, 4, 'one row per detail, one table');
for (const text of ['Potential risks', 'Recommended actions', 'Evidence', '#DC2626', 'Previous activity']) assert.ok(sample.html.includes(text), text);
// No page background or dark header band: the email reads like a normal message.
assert.ok(!/background:#F1F5F9|background:#0B1220/.test(sample.html));

// Filters change case; ai_ variables are filled by the AI, not typed on the report page.
assert.equal(R.render('{{team|upper}}/{{team | lower}}', { team: 'NetWork' }), 'NETWORK/network');
assert.equal(R.fillText('{{title}} ({{team|upper}})', { team: 'network', title: 'T' }), 'T (NETWORK)');
const aiTemplate = { ...R.BUILTIN, subjectPattern: '{{title}} ({{team|upper}})', html: '<p>{{ai_affected_asset}} {{ai_business_impact}}</p>' };
assert.deepEqual(R.customFields(aiTemplate), ['team']);
assert.deepEqual(R.aiFields(aiTemplate), ['ai_affected_asset', 'ai_business_impact']);
const aiPrompt = R.instructionsFor(aiTemplate, {});
assert.ok(aiPrompt.includes('"ai_affected_asset": "affected asset"'), aiPrompt);
assert.ok(aiPrompt.includes('"extra_sections"'));
assert.ok(aiPrompt.includes('never for threat intelligence results'), 'threat intel informs the report but is not copied into it');
const aiAnswer = R.parseAnswer('{"title":"T","ai_affected_asset":"WS-1","extra_sections":[{"title":"Scope","content":"Two hosts"},{"title":""}]}');
assert.deepEqual(aiAnswer.extra_sections, [{ title: 'Scope', content: 'Two hosts' }]);
const aiReport = R.assemble(aiTemplate, aiAnswer, { team: 'network' });
assert.equal(aiReport.html, '<p>WS-1 unknown</p>');
assert.equal(aiReport.subject, 'T (NETWORK)');
assert.ok(R.sample(aiTemplate).html.includes('Affected asset (written by the AI)'));

// Epoch detection times become readable dates.
assert.equal(R.readableTime('1794095726'), '2026-11-07 23:55 UTC');
assert.equal(R.readableTime('1794095726910'), '2026-11-07 23:55 UTC');
assert.equal(R.readableTime('2026-01-15 09:42'), '2026-01-15 09:42');
assert.equal(R.parseAnswer('{"detection_time": 1794095726910}').detection_time, '2026-11-07 23:55 UTC');

// Validation names the problem.
const broken = { ...R.BUILTIN, name: '', subjectPattern: '', severities: [{ name: 'Low', color: '#000000' }, { name: 'low', color: '#111111' }] };
const problems = R.validate(broken).map(p => p[0]);
assert.deepEqual(problems, ['name', 'subject', 'severities']);
assert.deepEqual(R.validate({ ...R.BUILTIN, severities: [{ name: 'X', color: 'red' }] }).map(p => p[0]), ['severities']);
assert.deepEqual(R.validate({ ...R.BUILTIN, html: '{{#x}}' }).map(p => p[0]), ['html']);

// The AI's answer: JSON, optionally in a Markdown fence; anything else is reported.
const answer = R.parseAnswer('Here you go:\n```json\n{"title":"T","severity":"HIGH","details":[{"label":"IP","value":"10.0.0.1","highlight":true},"junk"],"risks":"one","annexes":["log"]}\n```');
assert.deepEqual(answer.details, [{ label: 'IP', value: '10.0.0.1', highlight: true }]);
assert.deepEqual(answer.risks, ['one']);
assert.deepEqual(answer.annexes, [{ label: 'log' }]);
assert.throws(() => R.parseAnswer('I cannot help with that.'), /expected format/);
assert.throws(() => R.parseAnswer('{"title": '), /incomplete|expected format/);

// The analyst's choices win; severity matches the scale regardless of case;
// an empty case ID shows the template's placeholder.
let report = R.assemble(R.BUILTIN, answer, { title: '', case_id: '', severity: '' });
assert.equal(report.data.title, 'T');
assert.equal(report.data.severity, 'High');
assert.equal(report.data.severity_color, '#DC2626');
assert.equal(report.subject, 'Case #[Case ID] - T');
report = R.assemble(R.BUILTIN, answer, { title: 'Chosen', case_id: 'INC-9', severity: 'Critical' });
assert.equal(report.subject, 'Case #INC-9 - Chosen');
assert.equal(report.data.severity, 'Critical');

// Masked templates put markers back in place of restored values.
const masked = R.remask({ summary: 'alice from 10.0.0.1', details: [{ label: 'User', value: 'alice', highlight: true }] },
  { '⟦USER#1⟧': 'alice', '⟦IP_INT#1⟧': '10.0.0.1', '⟦SECRET#1⟧': 'Protected credential (original withheld; not restorable)' });
assert.deepEqual(masked, { summary: '⟦USER#1⟧ from ⟦IP_INT#1⟧', details: [{ label: 'User', value: '⟦USER#1⟧', highlight: true }] });

// The AI request names the language, the scale and any fixed fields.
const instructions = R.instructionsFor({ ...R.BUILTIN, language: 'French' }, { title: 'Fixed title', severity: 'High' });
for (const text of ['Write every text value in French.', 'Low, Medium, High, Critical', '"Fixed title"', 'fixed by the analyst: "High"', 'Answer with JSON only'])
  assert.ok(instructions.includes(text), text);

// Template files: exported without an id, imported with a new one, validated.
const own = R.normalize({ ...R.BUILTIN, id: 'mine', name: 'Team template' });
const imported = R.importFile(R.exportFile(own));
assert.equal(imported.name, 'Team template');
assert.notEqual(imported.id, 'mine');
assert.equal(imported.builtin, false);
assert.throws(() => R.importFile('{"something":"else"}'), /not a VEILUX report template/);
assert.throws(() => R.importFile(JSON.stringify({ veiluxReportTemplate: 1, template: { name: 'x' } })), /subject pattern|HTML/);
console.log('report template tests passed');
