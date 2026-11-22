/**
 * Settings page: API keys, protection lists, prompts, AI models, backup, and
 * the connection list. The connection editor itself is connector_editor.js.
 */


// State
let customPrompts = [];
let jsonKeysList = [];      // [{key: string, enabled: boolean}]
let customKeywordsList = []; // [{keyword: string, replacement: string, enabled: boolean}]
let customRegexRules = [];
let heuristicFieldExclusions = [];
let customCidrsList = [];   // [{cidr: string, enabled: boolean}]
let customDomainsList = []; // [{domain: string, enabled: boolean}]
let statisticsFieldsList = []; // [{field: string, enabled: boolean}]
let defaultPromptId = 'default'; // 'default' or a custom prompt's stable id
let connectorProfiles = []; // Saved connections; connector_editor.js reads and writes their format
let setAsideConnections = []; // Saved in a format from before 1.0.0: kept, not used
let editingConnectorIndex = null;

// DOM Elements - API Keys
const groqApiKeyInput = document.getElementById('groq-api-key');
const deepseekApiKeyInput = document.getElementById('deepseek-api-key');
const togetherApiKeyInput = document.getElementById('together-api-key');
const openrouterApiKeyInput = document.getElementById('openrouter-api-key');
const geminiApiKeyInput = document.getElementById('gemini-api-key');
const claudeApiKeyInput = document.getElementById('claude-api-key');
const extractionModeSeparate = document.getElementById('extraction-mode-separate');
const extractionModeRaw = document.getElementById('extraction-mode-raw');

// DOM Elements - Threat Intelligence
const virustotalApiKeyInput = document.getElementById('virustotal-api-key');
const abuseipdbApiKeyInput = document.getElementById('abuseipdb-api-key');
const enableThreatIntel = document.getElementById('enable-threat-intel');
const testThreatIntelBtn = document.getElementById('test-threat-intel-btn');
const threatIntelTestResult = document.getElementById('threat-intel-test-result');

// DOM Elements - Sanitization Toggles
const enablePatternSanitization = document.getElementById('enable-pattern-sanitization');
const enableJsonKeySanitization = document.getElementById('enable-json-key-sanitization');
const enableCustomKeywords = document.getElementById('enable-custom-keywords');
const enableStatisticsFieldSanitization = document.getElementById('enable-statistics-field-sanitization');

// DOM Elements - Subsections
const jsonKeysSubsection = document.getElementById('json-keys-subsection');
const customKeywordsSubsection = document.getElementById('custom-keywords-subsection');
const statisticsFieldsSubsection = document.getElementById('statistics-fields-subsection');

// DOM Elements - Lists
const jsonKeysList_el = document.getElementById('json-keys-list');
const customKeywordsList_el = document.getElementById('custom-keywords-list');
// Custom rules: one list for regex rules (customRegexRules) and field rules
// (heuristicFieldExclusions). Both are still stored and sent separately, as
// the backend expects; only the editor is shared.
const customRulesListEl = document.getElementById('custom-rules-list');
const ruleKind = document.getElementById('rule-kind');
const ruleTarget = document.getElementById('rule-target');
const regexName = document.getElementById('regex-name');
const regexFlags = document.getElementById('regex-flags');
const regexAction = document.getElementById('regex-action');
const regexMode = document.getElementById('regex-mode');
const regexScope = document.getElementById('regex-scope');
const regexCapture = document.getElementById('regex-capture');
const heuristicFieldMode = document.getElementById('heuristic-field-mode');
const customCidrsList_el = document.getElementById('custom-cidrs-list');
const customDomainsList_el = document.getElementById('custom-domains-list');
const statisticsFieldsListEl = document.getElementById('statistics-fields-list');

// DOM Elements - Add inputs
const newJsonKeyInput = document.getElementById('new-json-key');
const addJsonKeyBtn = document.getElementById('add-json-key-btn');
const newStatisticsFieldInput = document.getElementById('new-statistics-field');
const addStatisticsFieldBtn = document.getElementById('add-statistics-field-btn');
const newKeywordInput = document.getElementById('new-keyword');
const newReplacementInput = document.getElementById('new-replacement');
const addKeywordBtn = document.getElementById('add-keyword-btn');
const newCidrInput = document.getElementById('new-cidr');
const addCidrBtn = document.getElementById('add-cidr-btn');
const newDomainInput = document.getElementById('new-domain');
const addDomainBtn = document.getElementById('add-domain-btn');

// DOM Elements - Connectors
const connectorList = document.getElementById('connector-list');
const addConnectorTrigger = document.getElementById('add-connector-trigger');
const connectorForm = document.getElementById('connector-form');
// OpenRouter model picker (openrouter_models.js) and its Advanced settings
// (output limit only); both save themselves.
const openRouterAdvanced = VeiluxProviderModels.mountAdvanced(document.getElementById('openrouter-advanced'), {
  provider: 'openrouter', name: 'OpenRouter',
  model: async () => {
    const { id, info } = await VeiluxOpenRouter.current();
    return id ? { id, max_output_tokens: info?.max_completion_tokens } : null;
  }
});
const openRouterPicker = VeiluxOpenRouter.mount(document.getElementById('openrouter-model-picker'), {
  prefix: 'openrouter', onChange: () => openRouterAdvanced.refresh()
});
// Model pickers for the other built-in providers (provider_models.js); each saves its choice itself.
const providerKeyInputs = {
  groq: document.getElementById('groq-api-key'), deepseek: document.getElementById('deepseek-api-key'),
  together: document.getElementById('together-api-key'), gemini: document.getElementById('gemini-api-key'),
  claude: document.getElementById('claude-api-key')
};
const providerModelPickers = Object.entries(providerKeyInputs).map(([provider, keyInput]) =>
  VeiluxProviderModels.mount(document.getElementById(provider + '-model-picker'),
    { provider, keyInput, advanced: document.getElementById(provider + '-advanced') }));

// Each provider card's summary says whether it is ready: key, then model.
async function showProviderStates() {
  const models = await VeiluxProviderModels.all();
  const openRouterModel = (await VeiluxOpenRouter.current()).id;
  const keys = { ...providerKeyInputs, openrouter: document.getElementById('openrouter-api-key') };
  for (const [provider, keyInput] of Object.entries(keys)) {
    const model = provider === 'openrouter' ? openRouterModel : models[provider]?.id;
    const state = !keyInput.value.trim() ? ['missing', 'No key'] : !model ? ['partial', 'Choose a model'] : ['ready', model];
    const badge = document.getElementById(provider + '-state');
    badge.dataset.state = state[0];
    badge.textContent = state[1];
  }
}
document.querySelectorAll('.provider-card input[type=password]').forEach(input => input.addEventListener('input', showProviderStates));
document.getElementById('openrouter-test').addEventListener('click', async event => {
  event.target.disabled = true;
  const status = document.getElementById('openrouter-test-status');
  status.textContent = 'Testing the OpenRouter key…';
  status.textContent = (await checkOpenRouter(document.getElementById('openrouter-api-key').value.trim()))
    .message.replace(/^No key$/, 'Enter the OpenRouter API key first.');
  event.target.disabled = false;
});

// DOM Elements - Local backend
const backendUrlInput = document.getElementById('backend-url');
const backendTokenInput = document.getElementById('backend-token');
document.getElementById('check-backend').addEventListener('click', async () => {
  const status = document.getElementById('backend-status');
  const address = VeiluxBackend.normalize(backendUrlInput.value) || (backendUrlInput.value.trim() ? '' : VeiluxBackend.DEFAULT);
  if (!address) { fieldError(backendUrlInput, 'Enter an HTTP or HTTPS address, such as http://localhost:8000.'); return; }
  status.textContent = 'Checking ' + address + '…';
  try {
    const response = await fetch(address + '/health', { signal: AbortSignal.timeout(5000) });
    if (response.status === 403) {
      const refusal = await response.json().catch(() => ({}));
      status.textContent = 'The backend at ' + address + ' refused this browser: ' + (refusal.detail || 'access denied.');
      return;
    }
    const data = await response.json();
    if (!response.ok || data.status !== 'healthy') {
      status.textContent = 'Something answered at ' + address + ', but it is not the VEILUX backend.';
      return;
    }
    const running = 'The backend is running at ' + address + ' (version ' + (data.version || 'unknown') + ')';
    const check = await fetch(address + '/auth/check',
      VeiluxBackend.withToken({ signal: AbortSignal.timeout(5000) }, backendTokenInput.value.trim()));
    status.textContent = check.ok
      ? running + ' and this browser is paired with it. Save settings to use this address.'
      : running + ', but this browser is not paired with it yet. Enter the pairing code the backend shows when it starts, and choose Pair.';
  } catch (_) {
    status.textContent = 'No backend answered at ' + address + '. Start it with "python server.py" and check the address and port.';
  }
});

// Pairing: the code shown by the backend at start-up is exchanged for the
// backend key, which is saved at once and sent with every backend request.
const backendPairingInput = document.getElementById('backend-pairing-code');
document.getElementById('pair-backend').addEventListener('click', async () => {
  const status = document.getElementById('backend-status');
  const address = VeiluxBackend.normalize(backendUrlInput.value) || (backendUrlInput.value.trim() ? '' : VeiluxBackend.DEFAULT);
  if (!address) { fieldError(backendUrlInput, 'Enter an HTTP or HTTPS address, such as http://localhost:8000.'); return; }
  const code = backendPairingInput.value.trim();
  if (!code) { fieldError(backendPairingInput, 'Enter the pairing code the backend shows when it starts.'); return; }
  clearFieldError(backendPairingInput);
  status.textContent = 'Pairing with ' + address + '…';
  try {
    const response = await fetch(address + '/pair', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }), signal: AbortSignal.timeout(5000) });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || typeof data.token !== 'string' || !data.token) {
      status.textContent = 'Pairing failed: ' + (data.detail || 'HTTP ' + response.status);
      return;
    }
    backendTokenInput.value = data.token;
    backendPairingInput.value = '';
    await browser.storage.local.set({ backendToken: data.token });
    window.VeiluxSettingsUI.savedField('backendToken', data.token);
    status.textContent = 'Paired with the backend at ' + address + '. VEILUX now signs every request to it.';
  } catch (_) {
    status.textContent = 'No backend answered at ' + address + '. Start it with "python server.py" and check the address and port.';
  }
});

// DOM Elements - Custom AI Models
const customModelList = document.getElementById('custom-model-list');
const addCustomModelTrigger = document.getElementById('add-custom-model-trigger');
const customModelForm = document.getElementById('custom-model-form');
const cmPreset = document.getElementById('cm-preset');
const cmName = document.getElementById('cm-name');
const cmFormat = document.getElementById('cm-format');
const cmEndpoint = document.getElementById('cm-endpoint');
const cmModel = document.getElementById('cm-model');
const cmKey = document.getElementById('cm-key');
const cmTemperature = document.getElementById('cm-temperature');
const cmMaxTokens = document.getElementById('cm-max-tokens');
const cmExtraHeaders = document.getElementById('cm-extra-headers');
const saveCustomModelBtn = document.getElementById('save-custom-model');
const testCustomModelBtn = document.getElementById('test-custom-model');
const cancelCustomModelBtn = document.getElementById('cancel-custom-model');
const customModelTestResult = document.getElementById('custom-model-test-result');

let customAiProviders = [];
let editingCustomModelIndex = null;

// Endpoint/model shapes for services analysts are most likely to reach for.
// Everything here is just a starting point the analyst can edit.
const CUSTOM_MODEL_PRESETS = {
  ollama:     { format: 'openai',    endpoint: 'http://localhost:11434/v1/chat/completions', model: '',             name: 'Local Llama (Ollama)' },
  lmstudio:   { format: 'openai',    endpoint: 'http://localhost:1234/v1/chat/completions',  model: '',        name: 'LM Studio' },
  openai:     { format: 'openai',    endpoint: 'https://api.openai.com/v1/chat/completions', model: '',             name: 'OpenAI' },
  mistral:    { format: 'openai',    endpoint: 'https://api.mistral.ai/v1/chat/completions', model: '', name: 'Mistral' },
  perplexity: { format: 'openai',    endpoint: 'https://api.perplexity.ai/chat/completions', model: '',              name: 'Perplexity' },
  anthropic:  { format: 'anthropic', endpoint: 'https://api.anthropic.com/v1/messages',      model: '', name: 'Claude' },
  gemini:     { format: 'gemini',    endpoint: 'https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent', model: '', name: 'Gemini' },
  azure:      { format: 'openai',    endpoint: 'https://<resource>.openai.azure.com/openai/deployments/<deployment>/chat/completions?api-version=2024-02-01', model: '', name: 'Azure OpenAI' }
};

const saveConnectorBtn = document.getElementById('save-connector');
const cancelConnectorBtn = document.getElementById('cancel-connector');

// DOM Elements - Prompts
const promptList = document.getElementById('prompt-list');
const addPromptTrigger = document.getElementById('add-prompt-trigger');
const addPromptForm = document.getElementById('add-prompt-form');
const newPromptTitle = document.getElementById('new-prompt-title');
const newPromptContent = document.getElementById('new-prompt-content');
const saveNewPromptBtn = document.getElementById('save-new-prompt');
const cancelNewPromptBtn = document.getElementById('cancel-new-prompt');
const defaultPromptSelect = document.getElementById('default-prompt-select');

/**
 * Stable ID for a custom prompt — referenced by the popup's selector and by
 * the "default prompt" setting instead of array position, so adding/editing/
 * deleting other prompts never silently repoints an existing reference.
 */
function generatePromptId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

// DOM Elements - Buttons
const testApisBtn = document.getElementById('test-apis-btn');
const testSanitizationBtn = document.getElementById('test-sanitization');
const saveSettingsBtn = document.getElementById('save-settings');
const resetAllBtn = document.getElementById('reset-all');

// DOM Elements - Import/Export
const exportSettingsBtn = document.getElementById('export-settings-btn');
const importSettingsBtn = document.getElementById('import-settings-btn');
const importSettingsFile = document.getElementById('import-settings-file');
const exportIncludeKeys = document.getElementById('export-include-keys');

// All keys this extension stores, grouped so export/import can treat
// API keys separately (excluded by default — they're secrets).
const SETTINGS_KEYS = [
  'enablePatternSanitization', 'enableJsonKeySanitization', 'enableCustomKeywords', 'enableStatisticsFieldSanitization',
  'jsonKeysList', 'statisticsFieldsList', 'customKeywordsList', 'customRegexRules', 'heuristicFieldExclusions', 'heuristicSettings', 'customCidrsList', 'customDomainsList', 'customPrompts', 'extractionOutputMode',
  'defaultPromptId', 'enableThreatIntel', 'connectorProfiles', 'customAiProviders', 'backendUrl',
  'openrouterModel', 'openrouterModelInfo', 'providerModels', 'providerGeneration', 'caseSlots', 'maxRunningAnalyses', 'theme',
  'reportTemplates', 'defaultReportTemplateId', 'chatQuickQuestions'
];
const API_KEY_SETTINGS = [
  'groqApiKey', 'deepseekApiKey', 'togetherApiKey', 'openrouterApiKey', 'geminiApiKey', 'claudeApiKey',
  'virustotalApiKey', 'abuseipdbApiKey', 'backendToken'
];

// DOM Elements - Results
const apiTestResults = document.getElementById('api-test-results');
const sanitizationTestResult = document.getElementById('sanitization-test-result');
const successMsg = document.getElementById('success-msg');

// Initialize
document.addEventListener('DOMContentLoaded', loadSettings);

// Event Listeners - Main
testApisBtn.addEventListener('click', testAllApis);
testSanitizationBtn.addEventListener('click', testSanitization);
testThreatIntelBtn.addEventListener('click', testThreatIntel);
saveSettingsBtn.addEventListener('click', saveAllSettings);
resetAllBtn.addEventListener('click', resetAllSettings);

exportSettingsBtn.addEventListener('click', exportSettings);
importSettingsBtn.addEventListener('click', () => importSettingsFile.click());
importSettingsFile.addEventListener('change', (e) => {
  const file = e.target.files && e.target.files[0];
  if (file) importSettingsFromFile(file);
  importSettingsFile.value = ''; // allow re-selecting the same file later
});

// Event Listeners - Toggle subsections
enableJsonKeySanitization.addEventListener('change', () => {
  jsonKeysSubsection.classList.toggle('disabled', !enableJsonKeySanitization.checked);
});

enableCustomKeywords.addEventListener('change', () => {
  customKeywordsSubsection.classList.toggle('disabled', !enableCustomKeywords.checked);
});
enableStatisticsFieldSanitization.addEventListener('change', () => {
  statisticsFieldsSubsection.classList.toggle('disabled', !enableStatisticsFieldSanitization.checked);
});

// Event Listeners - Add items
addJsonKeyBtn.addEventListener('click', addJsonKey);
newJsonKeyInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') addJsonKey(); });
addStatisticsFieldBtn.addEventListener('click', addStatisticsField);
newStatisticsFieldInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') addStatisticsField(); });

addKeywordBtn.addEventListener('click', addCustomKeyword);
newReplacementInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') addCustomKeyword(); });

addCidrBtn.addEventListener('click', addCustomCidr);
newCidrInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') addCustomCidr(); });

addDomainBtn.addEventListener('click', addCustomDomain);
newDomainInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') addCustomDomain(); });

// Event Listeners - List toggle/remove (delegated: MV3's default CSP blocks
// inline onclick/onchange attributes, so rows are wired up via delegation
// on the list container instead of inline handlers).
jsonKeysList_el.addEventListener('change', (e) => {
  if (e.target.classList.contains('toggle-item')) toggleJsonKey(Number(e.target.dataset.index));
});
jsonKeysList_el.addEventListener('click', (e) => {
  const btn = e.target.closest('.remove-item');
  if (btn) removeJsonKey(Number(btn.dataset.index));
});
statisticsFieldsListEl.addEventListener('change', (e) => {
  if (e.target.classList.contains('toggle-item')) toggleStatisticsField(Number(e.target.dataset.index));
});
statisticsFieldsListEl.addEventListener('click', (e) => {
  const btn = e.target.closest('.remove-item');
  if (btn) removeStatisticsField(Number(btn.dataset.index));
});

customKeywordsList_el.addEventListener('change', (e) => {
  if (e.target.classList.contains('toggle-item')) toggleCustomKeyword(Number(e.target.dataset.index));
});
customKeywordsList_el.addEventListener('click', (e) => {
  const btn = e.target.closest('.remove-item');
  if (btn) removeCustomKeyword(Number(btn.dataset.index));
});

const RULE_ACTIONS = { hide_secret: 'Hide · credential', hide_privacy: 'Hide · restorable', review: 'Review', exclude: 'Keep' };
const RULE_SCOPES = { heuristics: 'uncertain heuristics', privacy: 'automatic privacy findings', all: 'all uncertain findings' };
const RULE_MODES = { full_value: 'full value', token: 'whole token', substring: 'substring' };
let editingRule = null; // { kind: 'regex' | 'field', index }

function ruleRow(kind, index, enabled, title, detail, action) {
  return `<div class="list-item rule-item" data-kind="${kind}" data-index="${index}">
    <input type="checkbox" class="toggle-rule" ${enabled ? 'checked' : ''}>
    <span class="rule-action rule-action-${action}">${RULE_ACTIONS[action]}</span>
    <div class="list-item-content"><span class="list-item-key">${escapeHtml(title)}</span><span class="list-item-value">${escapeHtml(detail)}</span></div>
    <button class="btn btn-secondary btn-icon edit-rule" title="Edit">✏️</button><button class="btn btn-danger btn-icon remove-rule" title="Remove">🗑️</button></div>`;
}
function renderCustomRules() {
  const rows = customRegexRules.map((rule, index) => ruleRow('regex', index, rule.enabled, rule.name,
      'Regex /' + rule.pattern + '/' + (rule.flags || '') + ' · ' + (RULE_SCOPES[rule.scope] || rule.scope) + ' · ' + (RULE_MODES[rule.mode] || rule.mode)
      + (Number(rule.capture_group) ? ' · group ' + rule.capture_group : ''), rule.action))
    .concat(heuristicFieldExclusions.map((item, index) => ruleRow('field', index, item.enabled, item.path,
      'JSON field · ' + (item.match_mode === 'exact_path' ? 'exact path' : 'key at any depth') + ' · never flagged by entropy review', 'exclude')));
  setHTML(customRulesListEl, rows.length ? rows.join('') : '<div class="empty-list">No custom rules yet</div>');
}

// A field rule can only keep values: hiding a field's value is done with
// "JSON keys to hide" in Privacy masking.
function syncRuleForm() {
  const field = ruleKind.value === 'field';
  document.getElementById('rule-name-control').hidden = field;
  document.getElementById('rule-target-label').textContent = field ? 'Field or path' : 'Regex pattern';
  ruleTarget.placeholder = field ? '_id or _source.tags' : 'e.g. TCK-\\d{6}';
  Array.from(regexAction.options).forEach(option => { option.disabled = field && option.value !== 'exclude'; });
  if (field) regexAction.value = 'exclude';
  document.getElementById('rule-regex-options').hidden = field;
  document.getElementById('rule-field-options').hidden = !field;
}
ruleKind.addEventListener('change', syncRuleForm);

function resetRuleForm() {
  editingRule = null;
  regexName.value = ''; ruleTarget.value = '';
  ruleKind.disabled = false;
  document.getElementById('add-rule').textContent = 'Add rule';
  document.getElementById('cancel-rule-edit').hidden = true;
  syncRuleForm();
}

customRulesListEl.addEventListener('change', event => {
  if (!event.target.classList.contains('toggle-rule')) return;
  const row = event.target.closest('.rule-item');
  const list = row.dataset.kind === 'regex' ? customRegexRules : heuristicFieldExclusions;
  list[Number(row.dataset.index)].enabled = event.target.checked;
});
customRulesListEl.addEventListener('click', event => {
  const row = event.target.closest('.rule-item');
  if (!row) return;
  const kind = row.dataset.kind, index = Number(row.dataset.index);
  if (event.target.closest('.remove-rule')) {
    (kind === 'regex' ? customRegexRules : heuristicFieldExclusions).splice(index, 1);
    if (editingRule && editingRule.kind === kind) resetRuleForm();
    renderCustomRules();
    return;
  }
  if (!event.target.closest('.edit-rule')) return;
  editingRule = { kind, index };
  ruleKind.value = kind; ruleKind.disabled = true;
  syncRuleForm();
  if (kind === 'regex') {
    const rule = customRegexRules[index];
    regexName.value = rule.name; ruleTarget.value = rule.pattern; regexFlags.value = rule.flags || '';
    regexAction.value = rule.action; regexMode.value = rule.mode; regexScope.value = rule.scope; regexCapture.value = rule.capture_group || 0;
  } else {
    const item = heuristicFieldExclusions[index];
    ruleTarget.value = item.path;
    heuristicFieldMode.value = item.match_mode || (item.path.includes('.') ? 'exact_path' : 'key_anywhere');
  }
  document.getElementById('add-rule').textContent = 'Save changes';
  document.getElementById('cancel-rule-edit').hidden = false;
  ruleTarget.focus();
});

document.getElementById('add-rule').addEventListener('click', () => {
  const editing = editingRule;
  if (ruleKind.value === 'field') {
    const path = ruleTarget.value.trim();
    if (!path) return fieldError(ruleTarget, 'Enter a field name or a dotted path.');
    if (heuristicFieldExclusions.some((item, index) => item.path === path && !(editing && editing.index === index)))
      return fieldError(ruleTarget, 'There is already a rule for this field.');
    const item = { ...(editing ? heuristicFieldExclusions[editing.index] : { enabled: true, scope: 'heuristics' }), path, match_mode: heuristicFieldMode.value };
    if (editing) heuristicFieldExclusions[editing.index] = item; else heuristicFieldExclusions.push(item);
  } else {
    if (!regexName.value.trim() || !ruleTarget.value) return fieldError(!regexName.value.trim() ? regexName : ruleTarget, 'Rule name and regex are required.');
    const existing = editing ? customRegexRules[editing.index] : null;
    const rule = { id: existing ? existing.id : crypto.randomUUID(), name: regexName.value.trim(), enabled: existing ? existing.enabled : true,
      pattern: ruleTarget.value, flags: regexFlags.value.replace(/\s/g, ''), action: regexAction.value, mode: regexMode.value,
      scope: regexScope.value, capture_group: Number(regexCapture.value || 0) };
    if (existing) customRegexRules[editing.index] = rule; else customRegexRules.push(rule);
  }
  resetRuleForm();
  renderCustomRules();
});
document.getElementById('cancel-rule-edit').addEventListener('click', resetRuleForm);
syncRuleForm();
document.getElementById('test-regex-rule').addEventListener('click', async () => {
  const out = document.getElementById('regex-test-result'); out.textContent = 'Testing…';
  try {
    const response = await VeiluxBackend.fetch('/sanitize', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ logs: [document.getElementById('regex-test-text').value], enable_pattern_sanitization: false, custom_regex_rules: customRegexRules, heuristic_field_exclusions: heuristicFieldExclusions, heuristic_settings: { min_length: Number(document.getElementById('heuristic-min-length').value), lowercase_min_length: Number(document.getElementById('heuristic-lowercase-min-length').value), entropy_threshold: Number(document.getElementById('heuristic-entropy').value), lowercase_entropy_threshold: Number(document.getElementById('heuristic-lowercase-entropy').value) } }) });
    const data = await response.json();
    out.textContent = response.ok ? `Sanitized preview: ${data.sanitized_logs[0]} · ${(data.secret_findings || []).length} credential/review finding(s)` : (data.detail || 'Rule test failed');
  } catch (_) { out.textContent = 'Backend unavailable; rules are not saved as validated.'; }
});

customCidrsList_el.addEventListener('change', (e) => {
  if (e.target.classList.contains('toggle-item')) toggleCustomCidr(Number(e.target.dataset.index));
});
customCidrsList_el.addEventListener('click', (e) => {
  const btn = e.target.closest('.remove-item');
  if (btn) removeCustomCidr(Number(btn.dataset.index));
});

customDomainsList_el.addEventListener('change', (e) => {
  if (e.target.classList.contains('toggle-item')) toggleCustomDomain(Number(e.target.dataset.index));
});
customDomainsList_el.addEventListener('click', (e) => {
  const btn = e.target.closest('.remove-item');
  if (btn) removeCustomDomain(Number(btn.dataset.index));
});

// Event Listeners - Connectors (the form itself lives in connector_editor.js)
addConnectorTrigger.addEventListener('click', () => { openConnectorForm(null); });
cancelConnectorBtn.addEventListener('click', closeConnectorForm);
saveConnectorBtn.addEventListener('click', saveConnector);

// Accept a full URL or bare hostname wherever a hostname is expected.
function normalizeHostInput(value) {
  value = (value || '').trim();
  if (!value) return '';
  try { return new URL(value.includes('://') ? value : 'https://' + value).hostname; } catch (e) { return value; }
}

// Event Listeners - Prompts
addPromptTrigger.addEventListener('click', () => {
  addPromptForm.classList.add('visible');
  addPromptTrigger.style.display = 'none';
  newPromptTitle.focus();
});

cancelNewPromptBtn.addEventListener('click', () => {
  addPromptForm.classList.remove('visible');
  addPromptTrigger.style.display = 'block';
  newPromptTitle.value = '';
  newPromptContent.value = '';
});

saveNewPromptBtn.addEventListener('click', saveNewPrompt);

// Appearance: the theme switch saves at once (theme.js applies it to open pages).
const darkModeInput = document.getElementById('dark-mode');
browser.storage.local.get('theme').then(({ theme }) => { darkModeInput.checked = theme === 'dark'; });
darkModeInput.addEventListener('change', () => browser.storage.local.set({ theme: darkModeInput.checked ? 'dark' : 'light' }));
browser.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.theme) darkModeInput.checked = changes.theme.newValue === 'dark';
  if (area === 'local' && (changes.providerModels || changes.openrouterModel)) showProviderStates();
});

// A whole number within [min, max] from a number field; out-of-range values are clamped.
function boundedInteger(id, min, max, fallback) {
  const value = Math.round(Number(document.getElementById(id).value));
  return Number.isFinite(value) ? Math.min(max, Math.max(min, value)) : fallback;
}

async function loadSettings() {
  const settings = await browser.storage.local.get([
    'groqApiKey', 'deepseekApiKey', 'togetherApiKey', 'openrouterApiKey', 'geminiApiKey', 'claudeApiKey',
    'virustotalApiKey', 'abuseipdbApiKey', 'enableThreatIntel',
    'enablePatternSanitization', 'enableJsonKeySanitization', 'enableCustomKeywords', 'enableStatisticsFieldSanitization',
    'jsonKeysList', 'statisticsFieldsList', 'customKeywordsList', 'customRegexRules', 'heuristicFieldExclusions', 'heuristicSettings', 'customCidrsList', 'customDomainsList', 'customPrompts', 'extractionOutputMode',
    'defaultPromptId', 'connectorProfiles', 'customAiProviders', 'backendUrl', 'backendToken', 'caseSlots', 'maxRunningAnalyses'
  ]);

  backendUrlInput.value = settings.backendUrl || '';
  backendTokenInput.value = settings.backendToken || '';
  document.getElementById('case-slots').value = settings.caseSlots || 2;
  document.getElementById('max-running-analyses').value = settings.maxRunningAnalyses || 3;

  // API Keys
  groqApiKeyInput.value = settings.groqApiKey || '';
  deepseekApiKeyInput.value = settings.deepseekApiKey || '';
  togetherApiKeyInput.value = settings.togetherApiKey || '';
  openrouterApiKeyInput.value = settings.openrouterApiKey || '';
  geminiApiKeyInput.value = settings.geminiApiKey || '';
  claudeApiKeyInput.value = settings.claudeApiKey || '';
  providerModelPickers.forEach(picker => picker.refresh());
  openRouterAdvanced.refresh();
  showProviderStates();
  virustotalApiKeyInput.value = settings.virustotalApiKey || '';
  abuseipdbApiKeyInput.value = settings.abuseipdbApiKey || '';
  // Off by default — free-tier reputation APIs are rate-limited, and unlike
  // sanitization this makes outbound calls to third-party services, so it
  // should be an explicit opt-in rather than silently on.
  enableThreatIntel.checked = settings.enableThreatIntel === true;

  const extractionOutputMode = settings.extractionOutputMode === 'raw_request' ? 'raw_request' : 'separate_logs';
  extractionModeSeparate.checked = extractionOutputMode === 'separate_logs';
  extractionModeRaw.checked = extractionOutputMode === 'raw_request';

  // Sanitization toggles — default to protective (on) when nothing has been
  // saved yet, since these ARE the user's default going forward: whatever
  // is set here is what a fresh popup/reset starts from.
  enablePatternSanitization.checked = settings.enablePatternSanitization !== false;
  enableJsonKeySanitization.checked = settings.enableJsonKeySanitization !== false;
  enableCustomKeywords.checked = settings.enableCustomKeywords !== false;
  enableStatisticsFieldSanitization.checked = settings.enableStatisticsFieldSanitization !== false;

  jsonKeysSubsection.classList.toggle('disabled', !enableJsonKeySanitization.checked);
  customKeywordsSubsection.classList.toggle('disabled', !enableCustomKeywords.checked);
  statisticsFieldsSubsection.classList.toggle('disabled', !enableStatisticsFieldSanitization.checked);

  jsonKeysList = settings.jsonKeysList || [];
  statisticsFieldsList = settings.statisticsFieldsList || [];
  customKeywordsList = settings.customKeywordsList || [];
  customRegexRules = settings.customRegexRules || [];
  heuristicFieldExclusions = settings.heuristicFieldExclusions || [];
  const hs = settings.heuristicSettings || {};
  document.getElementById('heuristic-min-length').value = hs.min_length || 10;
  document.getElementById('heuristic-lowercase-min-length').value = hs.lowercase_min_length || 14;
  document.getElementById('heuristic-entropy').value = hs.entropy_threshold || 3.5;
  document.getElementById('heuristic-lowercase-entropy').value = hs.lowercase_entropy_threshold || 3.15;
  customCidrsList = settings.customCidrsList || [];
  customDomainsList = settings.customDomainsList || [];
  customPrompts = settings.customPrompts || [];

  // Migrate prompts saved before stable IDs existed, so the default-prompt
  // setting and the popup's selector have something durable to reference.
  let migrated = false;
  customPrompts.forEach((p) => {
    if (!p.id) { p.id = generatePromptId(); migrated = true; }
  });
  if (migrated) {
    await browser.storage.local.set({ customPrompts });
  }

  defaultPromptId = settings.defaultPromptId || 'default';

  // A new installation starts with no connections. Connections in a format from
  // before 1.0.0 are kept in storage but not used (VeiluxConnectors.usable).
  const usable = VeiluxConnectors.usable(settings.connectorProfiles);
  connectorProfiles = usable.profiles;
  setAsideConnections = usable.setAside;
  if (settings.connectorProfiles === undefined) await browser.storage.local.set({ connectorProfiles });

  customAiProviders = settings.customAiProviders || [];

  renderJsonKeysList();
  renderStatisticsFieldsList();
  renderCustomKeywordsList();
  renderCustomRules();
  renderCustomCidrsList();
  renderCustomDomainsList();
  renderPromptList();
  renderDefaultPromptSelect();
  renderConnectorList();
  renderCustomModelList();
  window.VeiluxSettingsUI.saved();
}

function renderConnectorList() {
  const asideCount = setAsideConnections.length;
  document.getElementById('connector-set-aside').hidden = !asideCount;
  document.getElementById('connector-set-aside-text').textContent = asideCount === 1
    ? '1 connection was saved by a development build before VEILUX 1.0.0 and cannot be used. It is kept unchanged; create it again here (a platform template makes this quick), then remove the old one.'
    : asideCount + ' connections were saved by a development build before VEILUX 1.0.0 and cannot be used. They are kept unchanged; create them again here (a platform template makes this quick), then remove the old ones.';
  if (connectorProfiles.length === 0) {
    setHTML(connectorList, '<div class="empty-list">No connections yet. Choose “Add a connection” to set one up.</div>');
    return;
  }

  setHTML(connectorList, '');
  connectorProfiles.forEach((p, index) => {
    const item = document.createElement('div');
    item.className = 'prompt-item';

    const header = document.createElement('div');
    header.className = 'prompt-item-header';

    const titleSpan = document.createElement('span');
    titleSpan.className = 'prompt-title';
    titleSpan.textContent = p.name || '(unnamed)';

    const actionsDiv = document.createElement('div');
    actionsDiv.className = 'prompt-actions';

    const editBtn = document.createElement('button');
    editBtn.className = 'btn btn-secondary btn-small';
    editBtn.textContent = '✏️ Edit';
    editBtn.addEventListener('click', () => openConnectorForm(index));

    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'btn btn-danger btn-small';
    deleteBtn.textContent = '🗑️';
    deleteBtn.addEventListener('click', () => deleteConnector(index));

    actionsDiv.appendChild(editBtn);
    actionsDiv.appendChild(deleteBtn);
    header.appendChild(titleSpan);
    header.appendChild(actionsDiv);

    const detail = document.createElement('div');
    detail.className = 'prompt-content';
    detail.textContent = globalThis.ConnectorEditor ? ConnectorEditor.describe(p) : (p.siemHost || '');

    item.appendChild(header);
    item.appendChild(detail);
    connectorList.appendChild(item);
  });
}

function generateConnectorId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

/**
 * Parse the "cookie names to echo as headers" field. Accepts either a
 * comma-separated list of cookie names ("XSRF-TOKEN, csrf" — each echoed as
 * a same-named header) or an advanced JSON mapping {"HeaderName":"cookieName"}.
 * Returns: object mapping, null (empty field), or undefined (invalid JSON).
 */
function parseCookieEchoConfig(raw) {
  raw = (raw || '').trim();
  if (!raw) return null;
  if (raw[0] === '{') {
    try {
      const parsed = JSON.parse(raw);
      return (parsed && typeof parsed === 'object') ? parsed : undefined;
    } catch (e) { return undefined; }
  }
  const mapping = {};
  raw.split(',').map((s) => s.trim()).filter(Boolean).forEach((name) => { mapping[name] = name; });
  return Object.keys(mapping).length ? mapping : null;
}

// Cookie *values* are long random blobs (UUIDs, tokens); cookie *names* are
// short identifiers. Used to catch the easy mistake of pasting values into
// the echo field — the mapping must reference names.
function looksLikeCookieValue(s) {
  return typeof s === 'string' && (s.length > 30 || /^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(s));
}

// Render a stored echo mapping back into the form: the common all-same-name
// case shows as a friendly CSV ("XSRF-TOKEN, csrf"), anything else as JSON.
function renderCookieEchoConfig(mapping) {
  if (!mapping || typeof mapping !== 'object') return '';
  const keys = Object.keys(mapping);
  if (keys.length && keys.every((k) => mapping[k] === k)) return keys.join(', ');
  return keys.length ? JSON.stringify(mapping) : '';
}

function openConnectorForm(index) { ConnectorEditor.open(index); }
function closeConnectorForm() { ConnectorEditor.close(); }

function readConnectorForm() { return ConnectorEditor.read(); }


/**
 * Change the connection list against a fresh read of storage, by id rather
 * than position, so two open Settings tabs cannot overwrite each other's
 * saved connections.
 */
async function persistConnectorChange(mutator) {
  const stored = await browser.storage.local.get(['connectorProfiles']);
  const current = VeiluxConnectors.usable(stored.connectorProfiles);
  setAsideConnections = current.setAside;
  connectorProfiles = mutator(current.profiles);
  // Connections that cannot be used stay stored until the analyst removes them.
  await browser.storage.local.set({ connectorProfiles: connectorProfiles.concat(setAsideConnections) });
  renderConnectorList();
}

document.getElementById('connector-set-aside-remove').addEventListener('click', async () => {
  if (!confirm('Remove the connections saved by a development build? This cannot be undone.')) return;
  const stored = await browser.storage.local.get(['connectorProfiles']);
  connectorProfiles = VeiluxConnectors.usable(stored.connectorProfiles).profiles;
  setAsideConnections = [];
  await browser.storage.local.set({ connectorProfiles });
  renderConnectorList();
  showSuccess('Removed');
});

async function saveConnector() {
  const profile = readConnectorForm();
  if (!profile) return;

  await persistConnectorChange(function(current) {
    const i = current.findIndex(function(c) { return c && c.id === profile.id; });
    if (i >= 0) current[i] = profile; else current.push(profile);
    return current;
  });
  closeConnectorForm();
  showSuccess('Connection saved');
}

async function deleteConnector(index) {
  const removed = connectorProfiles[index];
  if (!removed) return;
  if (!confirm('Delete connection "' + (removed.name || '') + '"?')) return;
  await persistConnectorChange(function(current) {
    return current.filter(function(c) { return !c || c.id !== removed.id; });
  });
  showSuccess('Connection deleted');
}

function renderJsonKeysList() {
  if (jsonKeysList.length === 0) {
    setHTML(jsonKeysList_el, '<div class="empty-list">No keys added yet</div>');
    return;
  }
  
  setHTML(jsonKeysList_el, jsonKeysList.map((item, index) => `
    <div class="list-item">
      <input type="checkbox" data-index="${index}" class="toggle-item" ${item.enabled ? 'checked' : ''}>
      <div class="list-item-content">
        <span class="list-item-key">${escapeHtml(item.key)}</span>
      </div>
      <div class="list-item-actions">
        <button class="btn btn-danger btn-icon remove-item" data-index="${index}" title="Remove">🗑️</button>
      </div>
    </div>
  `).join(''));
}

function normalizeStatisticsFieldName(value) {
  return (value || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

function renderStatisticsFieldsList() {
  if (!statisticsFieldsList.length) {
    setHTML(statisticsFieldsListEl, '<div class="empty-list">No statistics fields added yet</div>');
    return;
  }
  setHTML(statisticsFieldsListEl, statisticsFieldsList.map((item, index) => `
    <div class="list-item">
      <input type="checkbox" data-index="${index}" class="toggle-item" ${item.enabled ? 'checked' : ''}>
      <div class="list-item-content"><span class="list-item-key">${escapeHtml(item.field)}</span></div>
      <div class="list-item-actions"><button class="btn btn-danger btn-icon remove-item" data-index="${index}" title="Remove">🗑️</button></div>
    </div>`).join(''));
}

function renderCustomKeywordsList() {
  if (customKeywordsList.length === 0) {
    setHTML(customKeywordsList_el, '<div class="empty-list">No keywords added yet</div>');
    return;
  }
  
  setHTML(customKeywordsList_el, customKeywordsList.map((item, index) => `
    <div class="list-item">
      <input type="checkbox" data-index="${index}" class="toggle-item" ${item.enabled ? 'checked' : ''}>
      <div class="list-item-content">
        <span class="list-item-key">${escapeHtml(item.keyword)}</span>
        <span class="list-item-arrow">→</span>
        <span class="list-item-value">${escapeHtml(item.replacement)}</span>
      </div>
      <div class="list-item-actions">
        <button class="btn btn-danger btn-icon remove-item" data-index="${index}" title="Remove">🗑️</button>
      </div>
    </div>
  `).join(''));
}

function renderCustomCidrsList() {
  if (customCidrsList.length === 0) {
    setHTML(customCidrsList_el, '<div class="empty-list">No custom ranges added yet</div>');
    return;
  }

  setHTML(customCidrsList_el, customCidrsList.map((item, index) => `
    <div class="list-item">
      <input type="checkbox" data-index="${index}" class="toggle-item" ${item.enabled ? 'checked' : ''}>
      <div class="list-item-content">
        <span class="list-item-key">${escapeHtml(item.cidr)}</span>
      </div>
      <div class="list-item-actions">
        <button class="btn btn-danger btn-icon remove-item" data-index="${index}" title="Remove">🗑️</button>
      </div>
    </div>
  `).join(''));
}

function addCustomCidr() {
  const cidr = newCidrInput.value.trim();
  if (!cidr) {
    fieldError(newCidrInput, 'Please enter a CIDR range (e.g., 172.20.0.0/16)');
    return;
  }

  if (customCidrsList.some(item => item.cidr.toLowerCase() === cidr.toLowerCase())) {
    fieldError(newCidrInput, 'This range already exists');
    return;
  }

  customCidrsList.push({ cidr, enabled: true });
  renderCustomCidrsList();
  newCidrInput.value = '';
  newCidrInput.focus();
}

function toggleCustomCidr(index) {
  customCidrsList[index].enabled = !customCidrsList[index].enabled;
  renderCustomCidrsList();
}

function removeCustomCidr(index) {
  customCidrsList.splice(index, 1);
  renderCustomCidrsList();
}

function renderCustomDomainsList() {
  if (customDomainsList.length === 0) {
    setHTML(customDomainsList_el, '<div class="empty-list">No custom domains added yet</div>');
    return;
  }

  setHTML(customDomainsList_el, customDomainsList.map((item, index) => `
    <div class="list-item">
      <input type="checkbox" data-index="${index}" class="toggle-item" ${item.enabled ? 'checked' : ''}>
      <div class="list-item-content">
        <span class="list-item-key">${escapeHtml(item.domain)}</span>
      </div>
      <div class="list-item-actions">
        <button class="btn btn-danger btn-icon remove-item" data-index="${index}" title="Remove">🗑️</button>
      </div>
    </div>
  `).join(''));
}

/**
 * Add a custom internal domain suffix (e.g. "corp.example.org" — matches that
 * domain and anything under it, like "lb01.corp.example.org")
 */
function addCustomDomain() {
  const domain = newDomainInput.value.trim().toLowerCase().replace(/^\*?\.*/, '');
  if (!domain) {
    fieldError(newDomainInput, 'Please enter a domain or suffix (e.g., corp.example.org)');
    return;
  }

  if (customDomainsList.some(item => item.domain.toLowerCase() === domain)) {
    fieldError(newDomainInput, 'This domain already exists');
    return;
  }

  customDomainsList.push({ domain, enabled: true });
  renderCustomDomainsList();
  newDomainInput.value = '';
  newDomainInput.focus();
}

function toggleCustomDomain(index) {
  customDomainsList[index].enabled = !customDomainsList[index].enabled;
  renderCustomDomainsList();
}

function removeCustomDomain(index) {
  customDomainsList.splice(index, 1);
  renderCustomDomainsList();
}

function addJsonKey() {
  const key = newJsonKeyInput.value.trim();
  if (!key) {
    fieldError(newJsonKeyInput, 'Please enter a key name');
    return;
  }
  
  if (jsonKeysList.some(item => item.key.toLowerCase() === key.toLowerCase())) {
    fieldError(newJsonKeyInput, 'This key already exists');
    return;
  }
  
  jsonKeysList.push({ key, enabled: true });
  renderJsonKeysList();
  newJsonKeyInput.value = '';
  newJsonKeyInput.focus();
}

function toggleJsonKey(index) {
  jsonKeysList[index].enabled = !jsonKeysList[index].enabled;
  renderJsonKeysList();
}

function removeJsonKey(index) {
  jsonKeysList.splice(index, 1);
  renderJsonKeysList();
}

function addStatisticsField() {
  const field = newStatisticsFieldInput.value.trim();
  if (!field) return fieldError(newStatisticsFieldInput, 'Please enter a statistics field name');
  const normalized = normalizeStatisticsFieldName(field);
  if (!normalized) return fieldError(newStatisticsFieldInput, 'The field name must contain a letter or number');
  if (statisticsFieldsList.some(item => normalizeStatisticsFieldName(item.field) === normalized)) {
    return fieldError(newStatisticsFieldInput, 'An equivalent field already exists (case and punctuation are ignored)');
  }
  statisticsFieldsList.push({ field, enabled: true });
  renderStatisticsFieldsList();
  newStatisticsFieldInput.value = '';
  newStatisticsFieldInput.focus();
}

function toggleStatisticsField(index) {
  statisticsFieldsList[index].enabled = !statisticsFieldsList[index].enabled;
  renderStatisticsFieldsList();
}

function removeStatisticsField(index) {
  statisticsFieldsList.splice(index, 1);
  renderStatisticsFieldsList();
}

function addCustomKeyword() {
  const keyword = newKeywordInput.value.trim();
  const replacement = newReplacementInput.value.trim();
  
  if (!keyword) {
    fieldError(newKeywordInput, 'Please enter a keyword');
    newKeywordInput.focus();
    return;
  }
  
  if (!replacement) {
    fieldError(newReplacementInput, 'Please enter a replacement');
    newReplacementInput.focus();
    return;
  }
  
  if (customKeywordsList.some(item => item.keyword === keyword)) {
    fieldError(newKeywordInput, 'This keyword already exists');
    return;
  }
  
  customKeywordsList.push({ keyword, replacement, enabled: true });
  renderCustomKeywordsList();
  renderCustomRules();
  newKeywordInput.value = '';
  newReplacementInput.value = '';
  newKeywordInput.focus();
}

function toggleCustomKeyword(index) {
  customKeywordsList[index].enabled = !customKeywordsList[index].enabled;
  renderCustomKeywordsList();
}

function removeCustomKeyword(index) {
  customKeywordsList.splice(index, 1);
  renderCustomKeywordsList();
}

function renderPromptList() {
  if (customPrompts.length === 0) {
    setHTML(promptList, '<div class="empty-list">No custom prompts. Click "Add New Custom Prompt" to create one.</div>');
    return;
  }
  
  setHTML(promptList, '');
  customPrompts.forEach((prompt, index) => {
    const item = document.createElement('div');
    item.className = 'prompt-item';
    item.dataset.index = index;
    
    const header = document.createElement('div');
    header.className = 'prompt-item-header';
    
    const titleSpan = document.createElement('span');
    titleSpan.className = 'prompt-title';
    setHTML(titleSpan, `${escapeHtml(prompt.title)}<span class="badge badge-custom">Custom</span>`);
    
    const actionsDiv = document.createElement('div');
    actionsDiv.className = 'prompt-actions';
    
    const editBtn = document.createElement('button');
    editBtn.className = 'btn btn-secondary btn-small';
    editBtn.textContent = '✏️ Edit';
    editBtn.addEventListener('click', () => editPrompt(index));
    
    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'btn btn-danger btn-small';
    deleteBtn.textContent = '🗑️';
    deleteBtn.addEventListener('click', () => deletePrompt(index));
    
    actionsDiv.appendChild(editBtn);
    actionsDiv.appendChild(deleteBtn);
    header.appendChild(titleSpan);
    header.appendChild(actionsDiv);
    
    const contentDiv = document.createElement('div');
    contentDiv.className = 'prompt-content';
    contentDiv.textContent = prompt.content.substring(0, 150) + (prompt.content.length > 150 ? '...' : '');
    
    item.appendChild(header);
    item.appendChild(contentDiv);
    promptList.appendChild(item);
  });
}

/**
 * Render the "Default Prompt" select — built-in prompt plus every custom
 * prompt, keyed by stable id. Falls back to 'default' if the currently
 * configured default no longer exists (e.g. its prompt was deleted).
 */
function renderDefaultPromptSelect() {
  const options = [{ id: 'default', title: 'Default Security Analysis' }]
    .concat(customPrompts.map((p) => ({ id: p.id, title: p.title })));

  if (!options.some((o) => o.id === defaultPromptId)) {
    defaultPromptId = 'default';
  }

  setHTML(defaultPromptSelect, options.map((o) =>
    `<option value="${escapeHtml(o.id)}"${o.id === defaultPromptId ? ' selected' : ''}>${escapeHtml(o.title)}</option>`
  ).join(''));
}

defaultPromptSelect.addEventListener('change', async () => {
  defaultPromptId = defaultPromptSelect.value;
  await browser.storage.local.set({ defaultPromptId });
  showSuccess('Default prompt updated');
});

async function saveNewPrompt() {
  const title = newPromptTitle.value.trim();
  const content = newPromptContent.value.trim();
  
  if (!title || !content) {
    fieldError(!title ? newPromptTitle : newPromptContent, 'Please fill in both title and content');
    return;
  }
  
  customPrompts.push({ id: generatePromptId(), title, content });
  await browser.storage.local.set({ customPrompts });
  renderPromptList();
  renderDefaultPromptSelect();

  addPromptForm.classList.remove('visible');
  addPromptTrigger.style.display = 'block';
  newPromptTitle.value = '';
  newPromptContent.value = '';

  showSuccess('Prompt saved!');
}

function editPrompt(index) {
  const prompt = customPrompts[index];
  const item = document.querySelector(`.prompt-item[data-index="${index}"]`);
  
  if (!item) return;
  
  item.classList.add('editing');
  setHTML(item, `
    <div class="form-group">
      <label>Prompt Title</label>
      <input type="text" id="edit-title-${index}" value="${escapeHtml(prompt.title)}">
    </div>
    <div class="form-group">
      <label>Prompt Content</label>
      <textarea id="edit-content-${index}" rows="4">${escapeHtml(prompt.content)}</textarea>
    </div>
    <div class="btn-group">
      <button class="btn btn-success btn-small" id="save-edit-${index}">💾 Save</button>
      <button class="btn btn-secondary btn-small" id="cancel-edit-${index}">Cancel</button>
    </div>
  `);
  
  document.getElementById(`save-edit-${index}`).addEventListener('click', () => saveEditedPrompt(index));
  document.getElementById(`cancel-edit-${index}`).addEventListener('click', () => renderPromptList());
}

async function saveEditedPrompt(index) {
  const title = document.getElementById(`edit-title-${index}`).value.trim();
  const content = document.getElementById(`edit-content-${index}`).value.trim();
  
  if (!title || !content) {
    fieldError(document.getElementById(!title ? `edit-title-${index}` : `edit-content-${index}`), 'Please fill in both fields');
    return;
  }
  
  // Preserve the stable id — replacing the whole object would silently
  // orphan the default-prompt setting and the popup's saved selection.
  customPrompts[index] = { id: customPrompts[index].id, title, content };
  await browser.storage.local.set({ customPrompts });
  renderPromptList();
  renderDefaultPromptSelect();
  showSuccess('Prompt updated!');
}

async function deletePrompt(index) {
  const removed = customPrompts[index];
  if (!confirm(`Delete "${removed.title}"?`)) return;
  customPrompts.splice(index, 1);

  // If the deleted prompt was set as the default, fall back rather than
  // leaving the setting pointing at a prompt that no longer exists.
  if (removed.id && removed.id === defaultPromptId) {
    defaultPromptId = 'default';
    await browser.storage.local.set({ customPrompts, defaultPromptId });
  } else {
    await browser.storage.local.set({ customPrompts });
  }

  renderPromptList();
  renderDefaultPromptSelect();
  showSuccess('Prompt deleted');
}

function collectMainSettings() {
  return {
    groqApiKey: groqApiKeyInput.value.trim(),
    deepseekApiKey: deepseekApiKeyInput.value.trim(),
    togetherApiKey: togetherApiKeyInput.value.trim(),
    openrouterApiKey: openrouterApiKeyInput.value.trim(),
    geminiApiKey: geminiApiKeyInput.value.trim(),
    claudeApiKey: claudeApiKeyInput.value.trim(),
    virustotalApiKey: virustotalApiKeyInput.value.trim(),
    abuseipdbApiKey: abuseipdbApiKeyInput.value.trim(),
    enableThreatIntel: enableThreatIntel.checked,
    enablePatternSanitization: enablePatternSanitization.checked,
    enableJsonKeySanitization: enableJsonKeySanitization.checked,
    enableCustomKeywords: enableCustomKeywords.checked,
    enableStatisticsFieldSanitization: enableStatisticsFieldSanitization.checked,
    jsonKeysList: jsonKeysList,
    statisticsFieldsList: statisticsFieldsList,
    customKeywordsList: customKeywordsList,
    customRegexRules: customRegexRules,
    heuristicFieldExclusions,
    heuristicSettings: { min_length: Number(document.getElementById('heuristic-min-length').value), lowercase_min_length: Number(document.getElementById('heuristic-lowercase-min-length').value), entropy_threshold: Number(document.getElementById('heuristic-entropy').value), lowercase_entropy_threshold: Number(document.getElementById('heuristic-lowercase-entropy').value) },
    customCidrsList: customCidrsList,
    customDomainsList: customDomainsList,
    customPrompts: customPrompts,
    defaultPromptId: defaultPromptId,
    // connectorProfiles deliberately NOT written here: connectors persist
    // immediately in saveConnector/deleteConnector. Bulk-writing this page's
    // in-memory copy would silently clobber connectors saved from another
    // Settings tab/window opened after this one (stale-array overwrite).
    extractionOutputMode: extractionModeRaw.checked ? 'raw_request' : 'separate_logs',
    backendUrl: VeiluxBackend.normalize(backendUrlInput.value),
    backendToken: backendTokenInput.value.trim(),
    caseSlots: boundedInteger('case-slots', 2, 5, 2),
    maxRunningAnalyses: boundedInteger('max-running-analyses', 1, 5, 3)
  };

}

async function saveAllSettings() {
  if (backendUrlInput.value.trim() && !VeiluxBackend.normalize(backendUrlInput.value)) {
    fieldError(backendUrlInput, 'Enter an HTTP or HTTPS address, such as http://localhost:8000.');
    return;
  }
  const settings = collectMainSettings();
  const snapshot = window.VeiluxSettingsUI.snapshot(settings);
  try {
    await browser.storage.local.set(settings);
    clearFieldError(saveSettingsBtn);
    window.VeiluxSettingsUI.saved(snapshot);
    showSuccess('Settings saved. Open editors still use their own Save buttons.');
  } catch (_) {
    fieldError(saveSettingsBtn, 'Could not save settings. Your edits are still here; try again.');
  }
}

async function resetAllSettings() {
  if (!confirm('Reset ALL settings? This cannot be undone.')) return;

  await browser.storage.local.clear();

  backendUrlInput.value = '';
  backendTokenInput.value = '';
  openRouterPicker.refresh();
  openRouterAdvanced.refresh();
  providerModelPickers.forEach(picker => picker.refresh());
  groqApiKeyInput.value = '';
  deepseekApiKeyInput.value = '';
  togetherApiKeyInput.value = '';
  openrouterApiKeyInput.value = '';
  geminiApiKeyInput.value = '';
  claudeApiKeyInput.value = '';
  showProviderStates();
  virustotalApiKeyInput.value = '';
  abuseipdbApiKeyInput.value = '';
  enableThreatIntel.checked = false;
  extractionModeSeparate.checked = true;
  extractionModeRaw.checked = false;
  enablePatternSanitization.checked = true;
  enableJsonKeySanitization.checked = true;
  enableCustomKeywords.checked = true;
  enableStatisticsFieldSanitization.checked = true;
  jsonKeysSubsection.classList.remove('disabled');
  customKeywordsSubsection.classList.remove('disabled');
  statisticsFieldsSubsection.classList.remove('disabled');
  jsonKeysList = [];
  statisticsFieldsList = [];
  customKeywordsList = [];
  customRegexRules = [];
  heuristicFieldExclusions = [];
  customCidrsList = [];
  customDomainsList = [];
  customPrompts = [];
  defaultPromptId = 'default';
  connectorProfiles = [];
  customAiProviders = [];
  closeConnectorForm();
  closeCustomModelForm();

  renderJsonKeysList();
  renderStatisticsFieldsList();
  renderCustomKeywordsList();
  renderCustomRules();
  renderCustomDomainsList();
  renderCustomCidrsList();
  renderPromptList();
  renderDefaultPromptSelect();
  renderConnectorList();
  renderCustomModelList();

  showSuccess('All settings reset');
  window.VeiluxSettingsUI.saved();
}

/**
 * Custom AI models — analyst-defined endpoints that show up in the popup's
 * provider list next to the built-ins.
 */
function renderCustomModelList() {
  if (!customModelList) return;
  if (customAiProviders.length === 0) {
    setHTML(customModelList, '<div class="empty-list">No custom models yet. The built-in providers still work as usual.</div>');
    return;
  }
  setHTML(customModelList, '');
  customAiProviders.forEach((p, index) => {
    const item = document.createElement('div');
    item.className = 'prompt-item';

    const header = document.createElement('div');
    header.className = 'prompt-item-header';
    const title = document.createElement('span');
    title.className = 'prompt-title';
    title.textContent = p.name || '(unnamed model)';

    const actions = document.createElement('div');
    actions.className = 'prompt-actions';
    const editBtn = document.createElement('button');
    editBtn.className = 'btn btn-secondary btn-small';
    editBtn.textContent = '\u270F\uFE0F Edit';
    editBtn.addEventListener('click', () => openCustomModelForm(index));
    const delBtn = document.createElement('button');
    delBtn.className = 'btn btn-danger btn-small';
    delBtn.textContent = '\uD83D\uDDD1\uFE0F';
    delBtn.addEventListener('click', () => deleteCustomModel(index));
    actions.appendChild(editBtn);
    actions.appendChild(delBtn);
    header.appendChild(title);
    header.appendChild(actions);

    const detail = document.createElement('div');
    detail.className = 'prompt-content';
    detail.textContent = (p.model || '?') + '  •  ' + ({openai:'OpenAI compatible',anthropic:'Claude connection',gemini:'Gemini connection'}[p.apiFormat || 'openai']) + '  •  ' +
      (p.endpoint || '') + (p.apiKey ? '' : '  •  no key (local)');

    item.appendChild(header);
    item.appendChild(detail);
    customModelList.appendChild(item);
  });
}

function openCustomModelForm(index) {
  editingCustomModelIndex = (typeof index === 'number') ? index : null;
  const p = editingCustomModelIndex !== null ? customAiProviders[editingCustomModelIndex] : {};
  cmPreset.value = p.preset || Object.keys(CUSTOM_MODEL_PRESETS).find(key => CUSTOM_MODEL_PRESETS[key].endpoint === p.endpoint) || '';
  cmName.value = p.name || '';
  cmFormat.value = p.apiFormat || 'openai';
  cmEndpoint.value = p.endpoint || '';
  cmModel.value = p.model || '';
  cmKey.value = p.apiKey || '';
  cmTemperature.value = (p.temperature !== undefined && p.temperature !== null) ? p.temperature : '';
  cmMaxTokens.value = p.maxTokens || '';
  cmExtraHeaders.value = p.extraHeaders ? JSON.stringify(p.extraHeaders) : '';
  customModelTestResult.textContent = '';
  customModelForm.classList.add('visible');
  addCustomModelTrigger.style.display = 'none';
  document.getElementById('cm-connection-details').open = !cmPreset.value || cmPreset.value === 'azure';
  document.getElementById('cm-advanced').open = false;
  customModelForm.querySelectorAll('[aria-invalid]').forEach(clearFieldError);
  cmName.focus();
}

function closeCustomModelForm() {
  customModelForm.classList.remove('visible');
  addCustomModelTrigger.style.display = 'block';
  customModelTestResult.textContent = '';
  editingCustomModelIndex = null;
}

function applyCustomModelPreset(key) {
  const preset = CUSTOM_MODEL_PRESETS[key];
  if (!preset) { document.getElementById('cm-connection-details').open = true; return; }
  cmFormat.value = preset.format;
  cmEndpoint.value = preset.endpoint;
  cmModel.value = preset.model;
  if (!cmName.value.trim()) cmName.value = preset.name;
  document.getElementById('cm-connection-details').open = key === 'azure';
  customModelForm.querySelectorAll('[aria-invalid]').forEach(clearFieldError);
  cmModel.focus();
}

function readCustomModelForm() {
  const name = cmName.value.trim();
  const endpoint = cmEndpoint.value.trim();
  const model = cmModel.value.trim();
  if (!name || !endpoint || !model) {
    fieldError(!name ? cmName : !endpoint ? cmEndpoint : cmModel, 'Enter a name, service URL and model ID.');
    return null;
  }
  try {
    const address = new URL(endpoint);
    if (!['http:', 'https:'].includes(address.protocol) || !address.hostname || /[<>]/.test(endpoint)) throw new Error();
  } catch (_) {
    fieldError(cmEndpoint, 'Enter the full service URL, starting with http:// or https://. Replace any example placeholders.');
    return null;
  }
  const temperature = cmTemperature.value === '' ? null : Number(cmTemperature.value);
  if (cmTemperature.validity.badInput || (temperature !== null && (!Number.isFinite(temperature) || temperature < 0 || temperature > 2))) {
    fieldError(cmTemperature, 'Use a number from 0 to 2, or leave blank for the model default.'); return null;
  }
  const maxTokens = cmMaxTokens.value === '' ? 4000 : Number(cmMaxTokens.value);
  if (cmMaxTokens.validity.badInput || !Number.isInteger(maxTokens) || maxTokens < 1) {
    fieldError(cmMaxTokens, 'Use a positive whole number, or leave blank for 4,000.'); return null;
  }

  let extraHeaders = null;
  const raw = cmExtraHeaders.value.trim();
  if (raw) {
    try { extraHeaders = JSON.parse(raw); }
    catch (e) { fieldError(cmExtraHeaders, 'Enter valid JSON, for example {"X-Team":"SOC"}.'); return null; }
    if (!extraHeaders || Array.isArray(extraHeaders) || typeof extraHeaders !== 'object' ||
        Object.values(extraHeaders).some(value => typeof value !== 'string')) {
      fieldError(cmExtraHeaders, 'Use a JSON object with text values, for example {"X-Team":"SOC"}.'); return null;
    }
  }

  const existing = (editingCustomModelIndex !== null && customAiProviders[editingCustomModelIndex]) || {};
  return {
    id: existing.id || generateConnectorId(),
    name: name,
    preset: cmPreset.value,
    apiFormat: cmFormat.value,
    endpoint: endpoint,
    model: model,
    apiKey: cmKey.value.trim(),
    temperature,
    maxTokens,
    extraHeaders: extraHeaders
  };
}

/** Merge against a fresh read of storage, keyed by id — same stale-write
 *  protection the connector list uses. */
async function persistCustomModelChange(mutator) {
  const stored = await browser.storage.local.get(['customAiProviders']);
  const current = Array.isArray(stored.customAiProviders) ? stored.customAiProviders : [];
  customAiProviders = mutator(current);
  await browser.storage.local.set({ customAiProviders });
  renderCustomModelList();
}

async function saveCustomModel() {
  const model = readCustomModelForm();
  if (!model) return;
  await persistCustomModelChange((current) => {
    const i = current.findIndex((m) => m && m.id === model.id);
    if (i >= 0) current[i] = model; else current.push(model);
    return current;
  });
  closeCustomModelForm();
  showSuccess('Model saved! Pick it in the extension popup under AI Provider.');
}

async function deleteCustomModel(index) {
  const removed = customAiProviders[index];
  if (!removed) return;
  if (!confirm('Delete the model "' + (removed.name || '') + '"?')) return;
  await persistCustomModelChange((current) => current.filter((m) => !m || m.id !== removed.id));
  showSuccess('Model deleted');
}

/** Send a trivial prompt through the real analysis path so a green result
 *  means the model will actually work when the analyst clicks Analyze. */
async function testCustomModel() {
  const model = readCustomModelForm();
  if (!model) return;

  testCustomModelBtn.disabled = true;
  customModelTestResult.textContent = 'Checking the model…';
  customModelTestResult.style.color = '';
  try {
    const response = await VeiluxBackend.fetch('/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        logs: ['VEILUX connectivity test. Reply with the single word: OK'],
        mode: 'custom',
        sanitize: false,
        api_key: model.apiKey || null,
        custom_provider: VeiluxCustomModels.requestConfig(model)
      })
    });
    let data;
    try { data = await response.json(); }
    catch (_) {
      customModelTestResult.textContent = 'Your local backend returned an unreadable response (HTTP ' + response.status + '). Check that the VEILUX backend is running.';
      customModelTestResult.style.color = 'var(--danger)';
      return;
    }
    if (response.ok && typeof data.analysis === 'string' && data.analysis.trim()) {
      const reply = (data.analysis || '').trim().slice(0, 120);
      customModelTestResult.textContent = '\u2705 The model answered: "' + reply + '"';
      customModelTestResult.style.color = 'var(--success)';
    } else {
      customModelTestResult.textContent = '\u26A0\uFE0F ' + (response.ok
        ? 'The test returned no answer text. Check the model settings and response length limit.'
        : VeiluxCustomModels.errorMessage(data, response.status));
      customModelTestResult.style.color = 'var(--warning)';
    }
  } catch (e) {
    customModelTestResult.textContent = '\u274C Could not reach your local backend at ' + await VeiluxBackend.base() + '. Start it with "python server.py" and try again.';
    customModelTestResult.style.color = 'var(--danger)';
  } finally {
    testCustomModelBtn.disabled = false;
  }
}

if (addCustomModelTrigger) addCustomModelTrigger.addEventListener('click', () => openCustomModelForm(null));
if (cancelCustomModelBtn) cancelCustomModelBtn.addEventListener('click', closeCustomModelForm);
if (saveCustomModelBtn) saveCustomModelBtn.addEventListener('click', saveCustomModel);
if (testCustomModelBtn) testCustomModelBtn.addEventListener('click', testCustomModel);

// Lists the custom service's models into the Model ID suggestions. Only the
// key (and any extra headers) is sent; the analyst still chooses the ID.
const cmLoadModels = document.getElementById('cm-load-models');
const cmLoadStatus = document.getElementById('cm-load-models-status');
if (cmLoadModels) cmLoadModels.addEventListener('click', async () => {
  let extraHeaders = null;
  try { extraHeaders = cmExtraHeaders.value.trim() ? JSON.parse(cmExtraHeaders.value) : null; }
  catch (_) { cmLoadStatus.textContent = 'Fix Extra request headers first (JSON).'; return; }
  if (!cmEndpoint.value.trim()) { cmLoadStatus.textContent = 'Enter the service URL first.'; cmEndpoint.focus(); return; }
  cmLoadModels.disabled = true; cmLoadStatus.textContent = 'Asking the service for its models…';
  try {
    const models = await VeiluxProviderModels.list('custom', cmKey.value.trim(), { custom_provider: {
      name: cmName.value.trim() || 'Custom model', api_format: cmFormat.value, endpoint: cmEndpoint.value.trim(),
      model: cmModel.value.trim() || 'unset', extra_headers: extraHeaders } });
    document.getElementById('cm-model-options').replaceChildren(...models.map(m => new Option(m.name && m.name !== m.id ? m.name : '', m.id)));
    cmLoadStatus.textContent = models.length ? models.length + ' models found. Pick one in Model ID (start typing to filter).'
      : 'The service listed no chat models. Enter the model ID yourself.';
  } catch (e) {
    cmLoadStatus.textContent = VeiluxProviderModels.failureText(e);
  } finally { cmLoadModels.disabled = false; }
});
if (cmPreset) cmPreset.addEventListener('change', () => applyCustomModelPreset(cmPreset.value));

/**
 * Export current settings to a downloadable JSON file. API keys are
 * excluded unless the user explicitly opts in (they're secrets, and this
 * file is meant to be portable/shareable).
 */
async function exportSettings() {
  const keysToRead = exportIncludeKeys.checked ? [...SETTINGS_KEYS, ...API_KEY_SETTINGS] : SETTINGS_KEYS;
  const settings = await browser.storage.local.get(keysToRead);

  // Connector header-auth tokens are credentials,
  // same as API keys — strip them unless "include keys" is checked.
  if (!exportIncludeKeys.checked && Array.isArray(settings.customAiProviders)) {
    settings.customAiProviders = settings.customAiProviders.map((m) =>
      (m && m.apiKey) ? { ...m, apiKey: '' } : m);
  }

  if (!exportIncludeKeys.checked && Array.isArray(settings.connectorProfiles)) {
    settings.connectorProfiles = settings.connectorProfiles.map((p) => {
      if (p && p.auth && (p.auth.headerValue || p.auth.password || p.auth.clientSecret)) {
        return { ...p, auth: { ...p.auth, headerValue: '', password: '', clientSecret: '' } };
      }
      return p;
    });
  }

  const blob = new Blob([JSON.stringify(settings, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'veilux-settings.json';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  showSuccess(exportIncludeKeys.checked ? 'Settings exported (including API keys)' : 'Settings exported');
}

/**
 * Import settings from a JSON file, replacing current settings with
 * whatever fields are present in it. Unrecognized fields are ignored;
 * missing fields simply keep falling back to their existing/default value.
 */
// Names of imported connections that carry page-script code, wherever an
// older or newer connection format keeps it.
function connectionsWithPageScripts(profiles) {
  if (!Array.isArray(profiles)) return [];
  const hasScript = value => {
    if (!value || typeof value !== 'object') return false;
    return Object.entries(value).some(([key, item]) =>
      (key === 'customScript' && typeof item === 'string' && item.trim()) || hasScript(item));
  };
  return profiles.filter(hasScript).map(p => '"' + String((p && p.name) || 'Unnamed') + '"');
}

async function importSettingsFromFile(file) {
  let imported;
  try {
    const text = await file.text();
    imported = JSON.parse(text);
  } catch (e) {
    fieldError(importSettingsBtn, 'Import failed: not a valid JSON file (' + e.message + ')');
    return;
  }

  if (!imported || typeof imported !== 'object' || Array.isArray(imported)) {
    fieldError(importSettingsBtn, 'Import failed: file does not contain a settings object.');
    return;
  }

  const allowedKeys = new Set([...SETTINGS_KEYS, ...API_KEY_SETTINGS]);
  const toApply = {};
  for (const key of Object.keys(imported)) {
    if (allowedKeys.has(key)) toApply[key] = imported[key];
  }

  if (Object.keys(toApply).length === 0) {
    fieldError(importSettingsBtn, 'Import failed: no recognized settings fields found in this file.');
    return;
  }

  // A connection with its own page script runs that code inside the SIEM page,
  // signed in as you. Nothing in a settings file is trusted for that silently.
  const scripted = connectionsWithPageScripts(toApply.connectorProfiles);
  if (scripted.length && !confirm('This file contains ' + scripted.length + ' connection' + (scripted.length === 1 ? '' : 's') +
      ' with a custom page script: ' + scripted.join(', ') + '.\n\nA page script runs inside your SIEM page with your sign-in, ' +
      'so it can read or change anything you can. Import only files from people you trust, and review each script in ' +
      'Settings → Connections afterwards.\n\nImport this file?')) {
    clearFieldError(importSettingsBtn);
    showSuccess('Import cancelled. Nothing was changed.');
    return;
  }

  await browser.storage.local.set(toApply);
  await loadSettings();
  clearFieldError(importSettingsBtn);
  showSuccess('Settings imported from ' + file.name);
}

// Each provider's key is checked by reading its model list through the local
// backend, and the chosen model must be in that list. No prompt or log is sent,
// and no model is chosen here.
async function testAllApis() {
  testApisBtn.disabled = true;
  testApisBtn.textContent = '⏳ Testing...';
  const rows = [];
  for (const [provider, name] of Object.entries(VeiluxProviderModels.PROVIDERS)) {
    const result = await VeiluxProviderModels.check(provider, providerKeyInputs[provider].value.trim());
    rows.push(formatApiResult(name, result.message, result.state));
  }
  const openRouter = await checkOpenRouter(openrouterApiKeyInput.value.trim());
  rows.splice(3, 0, formatApiResult('OpenRouter', openRouter.message, openRouter.state));
  setHTML(apiTestResults, '<div style="display: flex; flex-direction: column; gap: 8px; margin-top: 12px;">' + rows.join('') + '</div>');
  testApisBtn.disabled = false;
  testApisBtn.textContent = '🧪 Test All APIs';
}

// OpenRouter: its key endpoint, so no model has to be chosen first.
async function checkOpenRouter(key) {
  if (!key) return { state: 'skip', message: 'No key' };
  try {
    const response = await fetch('https://openrouter.ai/api/v1/key', { headers: { 'Authorization': 'Bearer ' + key } });
    return response.ok ? { state: 'success', message: '✓ OK' } : { state: 'error', message: '✗ ' + response.status };
  } catch (e) {
    return { state: 'error', message: '✗ Failed' };
  }
}

function formatApiResult(name, msg, status) {
  const colors = { success: 'var(--success)', error: 'var(--danger)', skip: 'var(--muted)' };
  // The message can contain a provider's own error text.
  return `<div style="display:flex;justify-content:space-between;gap:12px;padding:8px 12px;background:var(--inset);border-radius:4px;border-left:3px solid ${colors[status]}"><strong>${escapeHtml(name)}</strong><span>${escapeHtml(msg)}</span></div>`;
}

async function testSanitization() {
  const testLog = `{"_source":{"TargetUserName":"john.doe","SourceIP":"192.168.1.100","Hostname":"DC1.company.local","email":"admin@example.com","ProcessName":"C:\\\\Windows\\\\System32\\\\test.exe"}}`;

  testSanitizationBtn.disabled = true;
  testSanitizationBtn.textContent = '⏳ Testing...';

  try {
    const enabledKeys = enableJsonKeySanitization.checked 
      ? jsonKeysList.filter(k => k.enabled).map(k => k.key)
      : null;
    
    const enabledKeywords = enableCustomKeywords.checked
      ? Object.fromEntries(customKeywordsList.filter(k => k.enabled).map(k => [k.keyword, k.replacement]))
      : null;

    const enabledCidrs = customCidrsList.filter(c => c.enabled).map(c => c.cidr);
    const enabledStatisticsFields = enableStatisticsFieldSanitization.checked
      ? statisticsFieldsList.filter(field => field.enabled).map(field => field.field)
      : null;

    const response = await VeiluxBackend.fetch('/sanitize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        logs: [testLog],
        custom_keywords: enabledKeywords,
        json_keys_to_hide: enabledKeys,
        internal_cidrs: enabledCidrs,
        statistics_fields_to_hide: enabledStatisticsFields,
        custom_regex_rules: customRegexRules,
        heuristic_field_exclusions: heuristicFieldExclusions,
        heuristic_settings: { min_length: Number(document.getElementById('heuristic-min-length').value), lowercase_min_length: Number(document.getElementById('heuristic-lowercase-min-length').value), entropy_threshold: Number(document.getElementById('heuristic-entropy').value), lowercase_entropy_threshold: Number(document.getElementById('heuristic-lowercase-entropy').value) },
        enable_pattern_sanitization: enablePatternSanitization.checked,
        output_mode: extractionModeRaw.checked ? 'raw_request' : 'separate_logs'
      })
    });

    if (!response.ok) throw new Error('Backend error');

    const result = await response.json();
    
    let html = `<div style="background:#e8f5ec;border:1px solid var(--success);padding:12px;border-radius:6px;margin-top:12px;">`;
    html += `<strong style="color:var(--success);">✓ Test Successful</strong>`;
    html += `<pre style="font-size:11px;background:var(--inset);padding:8px;border-radius:4px;margin-top:8px;overflow-x:auto;white-space:pre-wrap;">${escapeHtml(result.sanitized_logs[0])}</pre>`;
    
    if (result.mapping_table && Object.keys(result.mapping_table).length > 0) {
      html += `<div style="margin-top:8px;font-size:12px;"><strong>Replacements:</strong> ${Object.keys(result.mapping_table).length} values sanitized</div>`;
    }
    html += `</div>`;
    
    setHTML(sanitizationTestResult, html);
  } catch (error) {
    setHTML(sanitizationTestResult, `<div style="background:var(--danger-soft);border:1px solid var(--danger);padding:12px;border-radius:6px;margin-top:12px;"><strong style="color:var(--danger);">✗ Failed:</strong> ${escapeHtml(error.message)}</div>`);
  } finally {
    testSanitizationBtn.disabled = false;
    testSanitizationBtn.textContent = '🧪 Test Sanitization';
  }
}

/**
 * Test threat intel keys against a known-benign public IP (Google DNS),
 * so a successful test never looks alarming regardless of verdict logic.
 */
async function testThreatIntel() {
  const vtKey = virustotalApiKeyInput.value.trim();
  const abuseKey = abuseipdbApiKeyInput.value.trim();

  if (!vtKey && !abuseKey) {
    setHTML(threatIntelTestResult, `<div style="background:var(--danger-soft);border:1px solid var(--danger);padding:12px;border-radius:6px;margin-top:12px;"><strong style="color:var(--danger);">✗ Failed:</strong> Enter at least one API key first.</div>`);
    return;
  }

  testThreatIntelBtn.disabled = true;
  testThreatIntelBtn.textContent = '⏳ Testing...';

  try {
    const response = await VeiluxBackend.fetch('/threat-intel/lookup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ioc: '8.8.8.8',
        virustotal_api_key: vtKey || null,
        abuseipdb_api_key: abuseKey || null,
        enable_virustotal: Boolean(vtKey),
        enable_abuseipdb: Boolean(abuseKey),
        enable_whois: false,
        use_cache: false
      })
    });

    const result = await response.json();
    if (!response.ok) throw new Error(result.detail || 'Backend error');

    const sourceLines = Object.entries(result.sources || {}).map(([name, src]) => {
      const ok = src.status === 'ok';
      return `<div>${ok ? '✓' : '✗'} <strong>${escapeHtml(name)}</strong>: ${escapeHtml(src.status)}${ok ? '' : ' — ' + escapeHtml(src.detail || '')}</div>`;
    }).join('');

    const requested = [vtKey && 'virustotal', abuseKey && 'abuseipdb'].filter(Boolean);
    const allOk = requested.every(name => result.sources?.[name]?.status === 'ok');
    const color = allOk ? 'var(--success)' : 'var(--danger)';
    setHTML(threatIntelTestResult, `<div style="background:var(--inset);border:1px solid ${color};padding:12px;border-radius:6px;margin-top:12px;">
      <strong style="color:${color};">${allOk ? '✓ Lookup completed — keys accepted' : '✗ Lookup completed — some keys could not be verified'}</strong> (8.8.8.8)
      <div style="margin-top:8px;font-size:12px;">${sourceLines || 'No sources responded.'}</div>
    </div>`);
  } catch (error) {
    setHTML(threatIntelTestResult, `<div style="background:var(--danger-soft);border:1px solid var(--danger);padding:12px;border-radius:6px;margin-top:12px;"><strong style="color:var(--danger);">✗ Failed:</strong> ${escapeHtml(error.message)}</div>`);
  } finally {
    testThreatIntelBtn.disabled = false;
    testThreatIntelBtn.textContent = '🧪 Test Threat Intel Keys';
  }
}

function showSuccess(message) {
  successMsg.textContent = `✓ ${message}`;
  successMsg.style.display = 'block';
  setTimeout(() => { successMsg.style.display = 'none'; }, 3000);
}

// Escapes text for HTML, including quotes, so it is safe in element content
// and in attribute values alike.
function escapeHtml(text) {
  return (text === null || text === undefined ? '' : String(text))
    .replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}
