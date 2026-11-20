const assert = require('node:assert/strict');
const ti = require('../extension/threat_intel.js');
const abuse = ti.renderSources({abuseipdb:{status:'ok',abuse_confidence_score:0,total_reports:0,is_tor:false,hostnames:[]}});
assert.match(abuse, /<dd>0%<\/dd>/);
assert.match(abuse, /<dd>0<\/dd>/);
assert.match(abuse, /<dd>No<\/dd>/);
assert.match(abuse, /Not provided by the AbuseIPDB check API/);
assert.doesNotMatch(abuse, /undefined|null|NaN/);
for (const link of ['javascript:alert(1)', 'https://evil.test', 'https://www.abuseipdb.com.evil.test', 'https://user:pass@www.abuseipdb.com']) {
  assert.doesNotMatch(ti.renderSources({abuseipdb:{status:'ok',link}}), /<a /);
}
const xss = ti.renderFinding({ioc:'<script>alert(1)</script>', verdict:'" onclick="alert(1)',
  sources:{whois:{status:'error',detail:'<img src=x onerror=alert(1)>'}}});
assert.doesNotMatch(xss, /<script|<img|onclick=/);
assert.match(xss, /&lt;script&gt;/);
assert.match(ti.renderSources({whois:{status:'not_found'}}), /registration status is unknown/);
assert.match(ti.renderSources({virustotal:{status:'ok',asn:64500}}), /AS64500/);
assert.match(ti.renderSources({virustotal:{status:'ok',malicious:null}}), /Not available/);
const digest = 'de074eccf61f37b1c3259ac2209a07ef';
const file = ti.renderFinding({ioc:digest,type:'hash',verdict:'clean',sources:{virustotal:{status:'ok',
  malicious:0,suspicious:0,total_engines:74,file_name:'secedit.exe',file_type:'Win32 EXE',file_size:40960,
  first_submission_date:1500000000,times_submitted:12,link:'https://www.virustotal.com/gui/search/' + digest}}});
assert.match(file, /secedit.exe/);
assert.match(file, /40960 bytes/);
assert.match(file, /First submitted/);
assert.match(file, /<a /);
assert.doesNotMatch(file, /Network owner|Internet registry|ASN|Country|Categories/);
for (const link of ['https://www.virustotal.com/gui/search/⟦SECRET#1⟧',
  'https://www.virustotal.com/gui/search/%E2%9F%A6SECRET%231%E2%9F%A7',
  'https://www.virustotal.com/gui/search/%E2%9F%A6SECRET#1%E2%9F%A7']) {
  assert.doesNotMatch(ti.renderSources({virustotal:{status:'ok',link}},'hash'), /<a /);
}
assert.doesNotMatch(ti.renderFinding({ioc:'⟦SECRET#1⟧',type:'hash',sources:{virustotal:{status:'ok',
  link:'https://www.virustotal.com/gui/search/' + digest}}}), /<a /);
const importHash = ti.renderFinding({ioc:digest,type:'hash',hash_algorithm:'IMPHASH',
  sources:{virustotal:{status:'unsupported',detail:'Automatic file-report lookup supports MD5, SHA-1 and SHA-256.'}}});
assert.match(importHash, /\(IMPHASH\)/);
assert.match(importHash, /VirusTotal — not queried/);
assert.doesNotMatch(importHash, /No existing report found|<a /);
for (const rendered of [abuse, file, importHash, xss]) {
  assert.match(rendered, /<details class="ti-provider">/);
  assert.doesNotMatch(rendered, /<details[^>]*\bopen\b/);
}
console.log('Threat intel rendering checks passed');
