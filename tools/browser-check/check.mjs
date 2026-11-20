// Browser checks for the VEILUX extension, run before a release:
//   1. web-ext lint: Mozilla's add-on linter, the same checks addons.mozilla.org
//      runs on upload (manifest keys, APIs per Firefox version, CSP problems).
//   2. Compatibility lint: every web API the extension calls, checked against
//      the browsers it supports (the "browserslist" in eslint.config.mjs).
// Usage, from this folder: npm install, then npm run check.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ESLint } from 'eslint';
import webExt from 'web-ext';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..', '..');
// VEILUX_EXTENSION_DIR lints another copy, such as the files of a built XPI.
const extension = process.env.VEILUX_EXTENSION_DIR ? path.resolve(process.env.VEILUX_EXTENSION_DIR) : path.join(root, 'extension');
let failed = false;

console.log('\n1. Firefox add-on lint (web-ext)');
// The linter prints its own JSON report; keep the summary below readable.
const write = process.stdout.write.bind(process.stdout);
process.stdout.write = () => true;
let lint;
try { lint = await webExt.cmd.lint({ sourceDir: extension, output: 'json', boring: true }, { shouldExitProgram: false }); }
finally { process.stdout.write = write; }
// Expected and reviewed:
// - BACKGROUND_SERVICE_WORKER_IGNORED: Chromium's service_worker key, next to
//   the background scripts Firefox uses;
// - DANGEROUS_EVAL: a connection's own page script, which the analyst writes
//   and which runs in the page (connector_client.js, customScriptInjected);
// - the Android notes: VEILUX is not offered for Firefox on Android.
// Markup goes through setHTML (html.js), so an innerHTML warning is new and fails the check.
const known = new Set(['BACKGROUND_SERVICE_WORKER_IGNORED', 'DANGEROUS_EVAL',
  'KEY_FIREFOX_ANDROID_UNSUPPORTED_BY_MIN_VERSION', 'ANDROID_INCOMPATIBLE_API']);
for (const item of lint.errors) { failed = true; console.log('  ERROR', item.code, item.file || '', '-', item.message); }
for (const item of lint.warnings.filter(w => !known.has(w.code))) { failed = true; console.log('  WARNING', item.code, item.file || '', '-', item.message); }
console.log('  ' + lint.errors.length + ' errors, ' + lint.warnings.length + ' warnings ('
  + lint.warnings.filter(w => known.has(w.code)).length + ' of them known and reviewed).');

console.log('\n2. Web API compatibility (eslint-plugin-compat)');
const eslint = new ESLint({ cwd: root, overrideConfigFile: path.join(here, 'eslint.config.mjs') });
const results = await eslint.lintFiles(['extension/**/*.js']);
for (const result of results) for (const message of result.messages) {
  failed = true;
  console.log('  ' + path.relative(root, result.filePath) + ':' + message.line + '  ' + message.message);
}
if (!results.some(result => result.messages.length)) console.log('  No unsupported APIs for the supported browsers.');

console.log(failed ? '\nSome checks need attention.' : '\nAll browser checks passed.');
process.exitCode = failed ? 1 : 0;
