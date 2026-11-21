/**
 * VEILUX popup.
 *
 * Extract finds the connection for the open tab (Settings -> Connections) and
 * reads its records: from the page, through the signed-in tab, or through the
 * local backend. The popup then sends logs for protection, threat-intel
 * enrichment and AI analysis, and shows the results.
 */


document.documentElement.classList.toggle('standalone-popup', new URLSearchParams(location.search).has('tabId'));

// The case this popup shows (see cases.js). Every read and write of case data
// goes through caseStorage and caseSession, so it stays inside this case;
// shared settings such as API keys and connections pass through unchanged.
const caseReady = VeiluxCases.open();
const caseStorage = VeiluxCases.storage(caseReady);
const caseSession = VeiluxCases.storage(caseReady, { area: 'session' });
let currentCase = null;

async function markCaseSeen() {
  try { await VeiluxCases.markSeen(await caseStorage.caseId()); } catch (_) {}
}

// Saved connections, loaded fresh at the start of every Extract so Settings
// changes take effect immediately. Only connections in the current format are
// used (VeiluxConnectors.usable).
let connectorProfiles = [];
let setAsideConnections = 0;

async function loadConnectorProfiles() {
  const result = await caseStorage.get(['connectorProfiles']);
  const usable = VeiluxConnectors.usable(result.connectorProfiles);
  connectorProfiles = usable.profiles;
  setAsideConnections = usable.setAside.length;
  return connectorProfiles;
}

// Added to "no connection" messages when connections from a development build
// before 1.0.0 are stored: they are kept, but cannot be used.
function setAsideNote() {
  if (!setAsideConnections) return '';
  return ' ' + (setAsideConnections === 1 ? '1 saved connection is' : setAsideConnections + ' saved connections are') +
    ' from a development build before VEILUX 1.0.0 and cannot be used: Settings → Connections lists them; create them again there.';
}

// State
let capturedLogs = [];
// Source metadata stays local and is never included in analysis payloads.
let capturedLogPages = [];
let fieldStatisticsPages = [];
let editedPagePending = Promise.resolve();
let pageReview = null;
let lastAnalysis = '';
let lastSanitizedLog = '';
let lastMappingTable = null;
let lastSanitizedAnalystData = '';
let lastSanitizedStatistics = '';
let analystData = '';
let fieldStatistics = [];
let customPrompts = [];
let allPromptOptions = [];

// DOM elements
const extractBtn = document.getElementById('extract-btn');
const extractStatsBtn = document.getElementById('extract-stats-btn');
const analyzeBtn = document.getElementById('analyze-btn');
const hideSelectionBtn = document.getElementById('hide-selection-btn');
const secretReview = document.getElementById('secret-review');
const secretReviewList = document.getElementById('secret-review-list');
const secretReviewContinue = document.getElementById('secret-review-continue');
const secretReviewCancel = document.getElementById('secret-review-cancel');
let requestForceHideValues = [];
const clearBtn = document.getElementById('clear-btn');
const settingsBtn = document.getElementById('settings-btn');
const analystDataTextarea = document.getElementById('analyst-data-textarea');
const logsTextarea = document.getElementById('logs-textarea');
const sanitizedTextarea = document.getElementById('sanitized-textarea');
const sanitizedAnalystTextarea = document.getElementById('sanitized-analyst-textarea');
const mappingTable = document.getElementById('mapping-table');
const analysisOutput = document.getElementById('analysis-output');
const statusText = document.getElementById('status-text');
const logCount = document.getElementById('log-count');
const LOG_SEPARATOR_TOKEN = '---LOG SEPARATOR---';
const loadingOverlay = document.getElementById('loading-overlay');
const loadingText = document.getElementById('loading-text');
const feedbackSection = document.getElementById('feedback-section');
const correctionTextarea = document.getElementById('correction-textarea');
const submitFeedbackBtn = document.getElementById('submit-feedback-btn');
const sanitizedSection = document.getElementById('sanitized-section');
const sanitizedAnalystSection = document.getElementById('sanitized-analyst-section');
const mappingSection = document.getElementById('mapping-section');
const sanitizationToggle = document.getElementById('sanitization-toggle');
const sanitizeCheckbox = document.getElementById('sanitize-checkbox');
const promptSelector = document.getElementById('prompt-selector');
const promptSearch = document.getElementById('prompt-search');
const promptSelectorSection = document.getElementById('prompt-selector-section');
const threatIntelSection = document.getElementById('threat-intel-section');
const threatIntelFindingsEl = document.getElementById('threat-intel-findings');
const iocLookupToggle = document.getElementById('ioc-lookup-toggle');
const iocLookupContent = document.getElementById('ioc-lookup-content');
const iocLookupInput = document.getElementById('ioc-lookup-input');
const iocLookupBtn = document.getElementById('ioc-lookup-btn');
const iocLookupResult = document.getElementById('ioc-lookup-result');
const statisticsSection = document.getElementById('statistics-section');
const statisticsToggle = document.getElementById('statistics-toggle');
const statisticsPreview = document.getElementById('statistics-preview');
const statisticsList = document.getElementById('statistics-list');
const copyStatisticsBtn = document.getElementById('copy-statistics-btn');
const clearStatisticsBtn = document.getElementById('clear-statistics-btn');

// Copy buttons
const copyAnalystDataBtn = document.getElementById('copy-analyst-data-btn');
const copyLogsBtn = document.getElementById('copy-logs-btn');
const copySanitizedBtn = document.getElementById('copy-sanitized-btn');
const copySanitizedAnalystBtn = document.getElementById('copy-sanitized-analyst-btn');
const copyMappingBtn = document.getElementById('copy-mapping-btn');
const copyAnalysisBtn = document.getElementById('copy-analysis-btn');

// Defang/Refang
const defangToggle = document.getElementById('defang-toggle');
const defangContent = document.getElementById('defang-content');
const defangInput = document.getElementById('defang-input');
const defangOutput = document.getElementById('defang-output');
const defangBtn = document.getElementById('defang-btn');
const refangBtn = document.getElementById('refang-btn');
const copyDefangBtn = document.getElementById('copy-defang-btn');

// Collapsible toggles
const analystDataToggle = document.getElementById('analyst-data-toggle');
const analystDataPreview = document.getElementById('analyst-data-preview');
const logsToggle = document.getElementById('logs-toggle');
const logsPreview = document.getElementById('logs-preview');
const sanitizedToggle = document.getElementById('sanitized-toggle');
const sanitizedPreview = document.getElementById('sanitized-preview');
const sanitizedAnalystToggle = document.getElementById('sanitized-analyst-toggle');
const sanitizedAnalystPreview = document.getElementById('sanitized-analyst-preview');
const mappingToggle = document.getElementById('mapping-toggle');
const mappingPreview = document.getElementById('mapping-preview');

// Workflow controls; provider IDs and request modes retain their stored values.
const analysisMode = document.getElementsByName('workflow-mode');
const providerSelect = document.getElementById('ai-provider');
let configuredProviderLabels = new Map();
function selectedAnalysisMode() {
  return document.querySelector('input[name="workflow-mode"]:checked').value === 'sanitize_only'
    ? 'sanitize_only' : providerSelect.value;
}

// Sanitization checkboxes
const popupEnablePattern = document.getElementById('enable-pattern');
const enableTiCheckbox = document.getElementById('enable-ti');
const enableTiVt = document.getElementById('enable-ti-vt');
const enableTiAbuse = document.getElementById('enable-ti-abuseipdb');
const enableTiWhois = document.getElementById('enable-ti-whois');
const tiSourcesBox = document.getElementById('ti-sources');
const popupEnableKeywords = document.getElementById('enable-keywords');
const popupEnableJsonkeys = document.getElementById('enable-jsonkeys');

// Initialize
document.addEventListener('DOMContentLoaded', async function() {
  currentCase = await caseReady;
  await VeiluxCaseUI.init(currentCase);
  checkBackendHealth();
  // Order matters: the provider list and prompt dropdown must be populated
  // before preferences are applied, or the remembered selection has nothing
  // to select.
  await loadPrompts();
  await renderCustomProviders();
  await syncSanitizationToggles();
  await restorePopupPreferences();
  const result = await caseStorage.get([
    'capturedLogs',
    'capturedLogPages',
    'fieldStatisticsPages',
    'analystData',
    'fieldStatistics',
    'lastAnalysis',
    'lastSanitizedLog',
    'lastSanitizedAnalystData',
    'lastSanitizedStatistics',
    'lastMappingTable',
    'lastThreatIntelFindings',
    'lastThreatIntelStatus',
    'lastAnalysisMode',
    'lastShouldSanitize',
    'analysisInProgress',
    'analysisStartedAt',
    'analysisHeartbeat',
    'analysisError'
  ]);
  if (result.capturedLogs) {
    capturedLogs = result.capturedLogs;
  }
  capturedLogPages = Array.isArray(result.capturedLogPages) ? result.capturedLogPages : [];
  fieldStatisticsPages = Array.isArray(result.fieldStatisticsPages) ? result.fieldStatisticsPages : [];
  analystData = result.analystData || '';
  fieldStatistics = Array.isArray(result.fieldStatistics) ? result.fieldStatistics : [];
  if (analystDataTextarea) analystDataTextarea.value = analystData;
  renderPersistedStatistics();
  updateUI();

  if (result.analysisInProgress && isAnalysisStale(result.analysisStartedAt, result.analysisHeartbeat)) {
    // The flag says "running" but it started longer ago than any provider
    // is allowed to take — the background worker was killed mid-analysis
    // (Chrome reaps MV3 service workers aggressively) and its cleanup never
    // ran. Clear the stuck flag instead of trapping the popup in a spinner.
    await clearStuckAnalysis();
    applyAnalysisState(result);
    updateStatus('The previous analysis was interrupted — run it again.', 'error');
  } else if (result.analysisInProgress) {
    // A previous popup instance kicked this off and got closed before it
    // finished — the background service worker kept running it regardless.
    // Pick up watching for the same completion signal.
    showLoading(true, 'Analyzing... (running in background)');
    analyzeBtn.disabled = true;
    waitAndApplyAnalysis().finally(updateAnalyzeButtonState);
  } else {
    applyAnalysisState(result);
    if (result.analysisError) {
      updateStatus('Error: ' + result.analysisError, 'error');
      caseStorage.remove('analysisError').catch(function() {});
    }
  }
  await restoreSecretSession();
  resumeBackgroundExtraction();
  await showInterruptedReview();
  await window.VeiluxCaseNotes.init();
  await window.VeiluxReportPanel.init();
  await window.VeiluxChatPanel.init();
  await window.VeiluxSentPanel.init();
  await window.VeiluxIndicators.init();
  // A report or answer that finished while the popup was closed.
  if (!result.analysisInProgress) await applyPendingAnswer((await caseStorage.get('pendingAnswer')).pendingAnswer);
  await window.VeiluxUI.initialize();
  await markCaseSeen();
  // Start-up is complete: inputs, preferences and the chosen stage are in
  // place. Only a marker for automated tests; nothing reads it.
  document.body.dataset.ready = 'true';
});

// ---- A credential review the analyst walked away from ----
// Clicking the page to look at a value closes the popup. Its highlights stay on
// the page and the review is saved with the case (reviewDraft), so on opening
// the popup says so and offers to continue or drop it.
const REVIEW_RESUME = {
  analysis: { label: 'Analyze', run: () => analyzeBtn.click() },
  chat: { label: 'Ask', run: () => { window.VeiluxChatPanel.open(); const send = document.getElementById('chat-send'); if (document.getElementById('chat-question').value.trim()) send.click(); } },
  report: { label: 'Report', run: () => { window.VeiluxReportPanel.open(); document.getElementById('report-generate').click(); } }
};
async function showInterruptedReview() {
  const banner = document.getElementById('review-interrupted');
  const draft = caseSession.available() ? (await caseSession.get('reviewDraft')).reviewDraft : null;
  banner.hidden = !draft;
  if (!draft) return;
  const count = (draft.values || []).length;
  const resume = REVIEW_RESUME[draft.kind] || REVIEW_RESUME.analysis;
  document.getElementById('review-interrupted-text').textContent = 'Credential review interrupted: ' + count + (count === 1 ? ' value' : ' values')
    + ' still to check. The highlights stay on the page (Esc there removes them), and your choices are kept.';
  const go = document.getElementById('review-interrupted-resume');
  go.textContent = 'Continue review';
  go.onclick = () => { banner.hidden = true; resume.run(); };
  document.getElementById('review-interrupted-drop').onclick = async () => {
    await discardInterruptedReview();
    updateStatus('Review dropped. Nothing was sent.', 'info');
  };
}
async function discardInterruptedReview() {
  const banner = document.getElementById('review-interrupted');
  const draft = caseSession.available() ? (await caseSession.get('reviewDraft')).reviewDraft : null;
  banner.hidden = true;
  if (!draft) return;
  await caseSession.remove('reviewDraft').catch(() => {});
  await SecretPageReview.releaseAll(draft.pages);
}

async function syncSanitizationToggles() {
  const settings = await caseStorage.get([
    'enablePatternSanitization', 'enableJsonKeySanitization', 'enableCustomKeywords'
  ]);
  popupEnablePattern.checked = settings.enablePatternSanitization !== false;
  popupEnableKeywords.checked = settings.enableCustomKeywords !== false;
  popupEnableJsonkeys.checked = settings.enableJsonKeySanitization !== false;
}

// ---------------------------------------------------------------------------
// Popup preferences
//
// Everything the analyst picks in the popup — AI provider, sanitization
// switches, threat-intel switches, chosen prompt — is remembered, because
// the popup's DOM is destroyed every time it closes and re-choosing the
// same options on each open is pure friction. One storage key holds the
// whole panel state, written on any change and applied on open.
// ---------------------------------------------------------------------------
const PREFS_KEY = 'popupPreferences';

function collectPopupPreferences() {
  return {
    mode: selectedAnalysisMode(),
    aiProvider: providerSelect.value,
    sanitize: sanitizeCheckbox ? sanitizeCheckbox.checked : true,
    secretProtectionEnabled: secretProtectionToggle.checked,
    secretProtection: collectSecretProtection(),
    enablePattern: popupEnablePattern ? popupEnablePattern.checked : true,
    enableKeywords: popupEnableKeywords ? popupEnableKeywords.checked : true,
    enableJsonKeys: popupEnableJsonkeys ? popupEnableJsonkeys.checked : true,
    ti: enableTiCheckbox ? enableTiCheckbox.checked : false,
    tiVt: enableTiVt ? enableTiVt.checked : true,
    tiAbuse: enableTiAbuse ? enableTiAbuse.checked : true,
    tiWhois: enableTiWhois ? enableTiWhois.checked : true,
    promptId: promptSelector ? promptSelector.value : null,
    statisticsSampleSize: statisticsSampleSize(),
    statisticsTopValues: statisticsTopValues()
  };
}

// How many records Extract statistics summarizes (1 to 100,000; default 5,000).
const STATISTICS_SAMPLE_DEFAULT = 5000, STATISTICS_SAMPLE_MAX = 100000;
function statisticsSampleSize() {
  const input = document.getElementById('statistics-sample-size');
  const value = Math.round(Number(input && input.value));
  return Number.isFinite(value) && value >= 1 ? Math.min(value, STATISTICS_SAMPLE_MAX) : STATISTICS_SAMPLE_DEFAULT;
}

// How many of the most frequent values statistics keep per field (1 to 10; default 5).
const STATISTICS_TOP_DEFAULT = 5, STATISTICS_TOP_MAX = 10;
function statisticsTopValues() {
  const value = Math.round(Number(document.getElementById('statistics-top-values').value));
  return Number.isFinite(value) && value >= 1 ? Math.min(value, STATISTICS_TOP_MAX) : STATISTICS_TOP_DEFAULT;
}

async function savePopupPreferences() {
  try {
    await caseStorage.set({ [PREFS_KEY]: collectPopupPreferences() });
  } catch (e) { /* preferences are a convenience — never block on them */ }
}

function applyBoolPref(el, value) {
  if (el && typeof value === 'boolean') el.checked = value;
}

async function restorePopupPreferences() {
  const stored = await caseStorage.get([PREFS_KEY, 'enableThreatIntel']);
  const prefs = stored[PREFS_KEY];
  if (!prefs) {
    // First run: start from the threat-intel setting saved in Settings, then
    // the popup's own switches take over.
    applyBoolPref(enableTiCheckbox, stored.enableThreatIntel === true);
    updateTiSourcesState();
    applyModeUiFromSelection();
    return;
  }

  if (prefs.mode) {
    // A remembered custom model may have been deleted since; fall back to
    // whatever is selected rather than leaving nothing chosen.
    document.querySelector('input[name="workflow-mode"][value="' + (prefs.mode === 'sanitize_only' ? 'sanitize_only' : 'ai') + '"]').checked = true;
    const provider = prefs.mode === 'sanitize_only' ? prefs.aiProvider : prefs.mode;
    if (Array.from(providerSelect.options).some(option => option.value === provider)) providerSelect.value = provider;
  }
  applySecretProtection(prefs.secretProtection, prefs.secretProtectionEnabled);
  applyBoolPref(sanitizeCheckbox, prefs.sanitize);
  applyBoolPref(popupEnablePattern, prefs.enablePattern);
  applyBoolPref(popupEnableKeywords, prefs.enableKeywords);
  applyBoolPref(popupEnableJsonkeys, prefs.enableJsonKeys);
  applyBoolPref(enableTiCheckbox, prefs.ti);
  applyBoolPref(enableTiVt, prefs.tiVt);
  applyBoolPref(enableTiAbuse, prefs.tiAbuse);
  applyBoolPref(enableTiWhois, prefs.tiWhois);
  if (prefs.promptId && promptSelector) {
    const exists = Array.prototype.some.call(promptSelector.options,
      function(o) { return o.value === prefs.promptId; });
    if (exists) promptSelector.value = prefs.promptId;
  }
  if (Number.isInteger(prefs.statisticsSampleSize)) document.getElementById('statistics-sample-size').value = prefs.statisticsSampleSize;
  if (Number.isInteger(prefs.statisticsTopValues)) document.getElementById('statistics-top-values').value = prefs.statisticsTopValues;
  updateTiSourcesState();
  applyModeUiFromSelection();
}

// Grey out the per-source rows when enrichment is off, so the panel shows
// at a glance that they do nothing right now.
function updateTiSourcesState() {
  if (!enableTiCheckbox || !tiSourcesBox) return;
  const on = enableTiCheckbox.checked;
  tiSourcesBox.style.opacity = on ? '1' : '0.45';
  [enableTiVt, enableTiAbuse, enableTiWhois].forEach(function(el) {
    if (el) el.disabled = !on;
  });
  [['manual-ti-vt', enableTiVt], ['manual-ti-abuse', enableTiAbuse], ['manual-ti-whois', enableTiWhois]].forEach(([id, el]) => {
    document.getElementById(id).checked = el.checked;
  });
}

[['manual-ti-vt', enableTiVt], ['manual-ti-abuse', enableTiAbuse], ['manual-ti-whois', enableTiWhois]].forEach(([id, el]) => {
  const manual = document.getElementById(id);
  manual.addEventListener('change', () => { el.checked = manual.checked; savePopupPreferences(); });
  el.addEventListener('change', () => { manual.checked = el.checked; });
});

// Any control in the popup persists itself on change.
[sanitizeCheckbox, popupEnablePattern, popupEnableKeywords, popupEnableJsonkeys,
 enableTiVt, enableTiAbuse, enableTiWhois, promptSelector, document.getElementById('statistics-sample-size'), document.getElementById('statistics-top-values')].forEach(function(el) {
  if (el) el.addEventListener('change', savePopupPreferences);
});
if (enableTiCheckbox) {
  enableTiCheckbox.addEventListener('change', function() {
    updateTiSourcesState();
    savePopupPreferences();
  });
}
Array.prototype.forEach.call(analysisMode, function(radio) {
  radio.addEventListener('change', savePopupPreferences);
});

// Renders the provider selector and each provider's setup hint (key and model).
async function renderCustomProviders() {
  const stored = await caseStorage.get(['customAiProviders', 'groqApiKey', 'deepseekApiKey', 'togetherApiKey', 'openrouterApiKey', 'geminiApiKey', 'claudeApiKey']);
  const chosenModels = await VeiluxProviderModels.all(caseStorage);
  const providers = stored.customAiProviders || [];
  providerSelect.querySelectorAll('[data-custom-provider]').forEach(option => option.remove());
  configuredProviderLabels.clear();
  const names = { groq: 'Groq', deepseek: 'DeepSeek', together: 'Together AI', openrouter: 'OpenRouter', gemini: 'Gemini', claude: 'Claude' };
  Array.from(providerSelect.options).forEach(option => {
    const configured = !!stored[option.value + 'ApiKey'];
    option.textContent = names[option.value] + (configured ? ' · key saved' : ' · setup needed');
    const model = VeiluxProviderModels.PROVIDERS[option.value] ? chosenModels[option.value] : null;
    const modelNote = !VeiluxProviderModels.PROVIDERS[option.value] ? ''
      : model && model.id ? ' Model: ' + model.id + '.' : ' No model chosen yet: choose one in Settings → Providers and API keys.';
    configuredProviderLabels.set(option.value, (configured ? 'API key saved. Use Settings to test the connection.' : 'Add an API key in Settings before using this provider.') + modelNote);
  });
  providers.forEach(function(p) {
    const option = document.createElement('option');
    option.value = 'custom:' + p.id;
    option.dataset.customProvider = 'true';
    option.textContent = (p.name || 'Custom model') + ' · custom';
    configuredProviderLabels.set(option.value, 'Saved custom model. Use Settings to test or edit the connection.');
    providerSelect.appendChild(option);
  });
}

// Secret preferences contain booleans only. Analysis rules live in memory or
// session storage (cleared on browser restart), never in permanent preferences.
// Every built-in mechanism is sent explicitly, so the backend never has to
// guess. Browser tests check this list against MECHANISMS in secret_detection.py.
const SECRET_MECHANISMS = ['known_tokens', 'private_keys', 'authorization', 'cookies',
  'urls', 'assignments', 'commands', 'context', 'heuristics', 'decoding'];
const secretProtectionToggle = document.getElementById('enable-secret-protection');
const undoHideBtn = document.getElementById('undo-hide-btn');
let recentSecretField = null;
let manualHistory = [];
let requestAllowedValues = [];
let sanitizedLogsEdited = false;
let sanitizedAnalystEdited = false;
let preflightController = null;
let cancelRequested = false;
let reviewReject = null;
let reviewMilliseconds = 0;
const supportedSecretFields = [logsTextarea, analystDataTextarea, sanitizedTextarea, sanitizedAnalystTextarea].filter(Boolean);

function collectSecretProtection() {
  return Object.fromEntries(SECRET_MECHANISMS.map(name => [name, secretProtectionToggle.checked]));
}
function applySecretProtection(config, enabled) {
  if (typeof enabled === 'boolean') {
    secretProtectionToggle.checked = enabled;
  } else {
    // Migrate the old eight-checkbox UI. Preserve a completely disabled
    // checklist; mixed or absent settings become fully on, never hidden partial
    // protection behind an enabled master switch. Also honor explicit values
    // for the two backend-only mechanisms if an older config contains them.
    const previousControls = SECRET_MECHANISMS.slice(0, 8);
    const allDisabled = config && previousControls.every(name => config[name] === false)
      && config.heuristics !== true && config.decoding !== true;
    secretProtectionToggle.checked = !allDisabled;
  }
  updateSecretNotice();
}
function updateSecretNotice() {
  document.getElementById('secret-protection-notice').hidden = secretProtectionToggle.checked;
  secretProtectionToggle.setAttribute('aria-describedby', secretProtectionToggle.checked
    ? 'secret-protection-help' : 'secret-protection-help secret-protection-notice');
}
secretProtectionToggle.addEventListener('change', () => {
  updateSecretNotice(); savePopupPreferences();
});

function selectedSecretText() {
  if (!recentSecretField || recentSecretField.selectionStart === recentSecretField.selectionEnd) return '';
  const value = recentSecretField.value.slice(recentSecretField.selectionStart, recentSecretField.selectionEnd);
  return value.trim() && !/[⟦⟧]/.test(value) ? value : '';
}
function updateHideSelection() { hideSelectionBtn.disabled = !selectedSecretText(); }
supportedSecretFields.forEach(field => {
  ['focus', 'select', 'keyup', 'mouseup', 'input'].forEach(name => field.addEventListener(name, () => {
    recentSecretField = field; updateHideSelection();
  }));
});
document.addEventListener('selectionchange', updateHideSelection);
hideSelectionBtn.addEventListener('mousedown', event => event.preventDefault());

async function saveSecretSession() {
  if (caseSession.available()) await caseSession.set({ analysisSecretRules: {
    forced: requestForceHideValues, allowed: requestAllowedValues, history: manualHistory,
    logsEdited: sanitizedLogsEdited, analystEdited: sanitizedAnalystEdited
  }});
}
async function restoreSecretSession() {
  if (!caseSession.available()) return;
  const saved = (await caseSession.get('analysisSecretRules')).analysisSecretRules;
  if (!saved) return;
  requestForceHideValues = saved.forced || [];
  requestAllowedValues = saved.allowed || [];
  manualHistory = saved.history || [];
  sanitizedLogsEdited = !!saved.logsEdited;
  sanitizedAnalystEdited = !!saved.analystEdited;
  undoHideBtn.disabled = !manualHistory.length;
}
function resetSecretAnalysis() {
  requestForceHideValues = []; requestAllowedValues = []; manualHistory = [];
  recentSecretField = null; sanitizedLogsEdited = false; sanitizedAnalystEdited = false;
  undoHideBtn.disabled = true; hideSelectionBtn.disabled = true;
  document.getElementById('manual-hide-status').textContent = '';
  saveSecretSession();
}
// Pasted or edited logs: "---LOG SEPARATOR---" divides them, exactly as the
// analysis request divides them, so the count, statistics and indicators see
// the same logs the AI receives. Text without a separator is kept as it is.
function splitLogInput(text) {
  const value = typeof text === 'string' ? text : '';
  if (!value.trim()) return [];
  if (!value.includes(LOG_SEPARATOR_TOKEN)) return [value];
  return value.split(LOG_SEPARATOR_TOKEN).map(log => log.trim()).filter(Boolean);
}
function updateLogCount() {
  logCount.textContent = capturedLogs.length + ' log' + (capturedLogs.length !== 1 ? 's' : '');
  window.VeiluxUI?.sourceSummary();
}
function syncManualFields() {
  capturedLogs = splitLogInput(logsTextarea.value);
  lastSanitizedLog = sanitizedTextarea.value;
  lastSanitizedAnalystData = sanitizedAnalystTextarea.value;
  saveLogs(); saveAnalystData(); saveSecretSession();
  caseStorage.set({ lastSanitizedLog, lastSanitizedAnalystData, lastAnalysis });
}
function hideSelectedText() {
  const value = selectedSecretText();
  if (!value) return;
  // Create the first preview before replacement, so the effect is immediate.
  if (!sanitizedTextarea.value) sanitizedTextarea.value = logsTextarea.value;
  if (!sanitizedAnalystTextarea.value) sanitizedAnalystTextarea.value = analystDataTextarea.value;
  const placeholder = '⟦MANUAL#' + crypto.randomUUID() + '⟧';
  let count = 0;
  supportedSecretFields.forEach(field => {
    field.value = field.value.split(/(⟦[^⟧]*⟧)/g).map(part => {
      if (part.startsWith('⟦')) return part;
      const pieces = part.split(value); count += pieces.length - 1;
      return pieces.join(placeholder);
    }).join('');
  });
  if (lastAnalysis) {
    const pieces = lastAnalysis.split(value); count += pieces.length - 1;
    lastAnalysis = pieces.join(placeholder); displayAnalysis(lastAnalysis);
  }
  const wasAllowed = requestAllowedValues.includes(value);
  requestAllowedValues = requestAllowedValues.filter(v => v !== value);
  if (!requestForceHideValues.includes(value)) requestForceHideValues.push(value);
  manualHistory.push({ value, placeholder, wasAllowed });
  sanitizedLogsEdited = true; sanitizedAnalystEdited = true;
  sanitizedSection.style.display = 'block';
  sanitizedPreview.classList.remove('collapsed');
  if (sanitizedAnalystTextarea.value) {
    sanitizedAnalystSection.style.display = 'block';
    sanitizedAnalystPreview.classList.remove('collapsed');
  }
  undoHideBtn.disabled = false;
  recentSecretField = null; updateHideSelection();
  document.getElementById('manual-hide-status').textContent = count + ' replacements across logs, context and previews.';
  syncManualFields();
}
hideSelectionBtn.addEventListener('click', hideSelectedText);
undoHideBtn.addEventListener('click', () => {
  const action = manualHistory.pop();
  if (!action) return;
  supportedSecretFields.forEach(field => { field.value = field.value.split(action.placeholder).join(action.value); });
  if (lastAnalysis) { lastAnalysis = lastAnalysis.split(action.placeholder).join(action.value); displayAnalysis(lastAnalysis); }
  requestForceHideValues = requestForceHideValues.filter(v => v !== action.value);
  if (action.wasAllowed) requestAllowedValues.push(action.value);
  undoHideBtn.disabled = !manualHistory.length;
  document.getElementById('manual-hide-status').textContent = 'Manual hide undone. Enabled detectors may still mask this value.';
  syncManualFields();
});
logsTextarea.addEventListener('input', () => {
  sanitizedLogsEdited = false;
  capturedLogs = splitLogInput(logsTextarea.value);
  updateLogCount();
  if (pageReview) pageReview.close();
  // A pasted/edited log is associated with the page open at the time of the
  // edit, never with whichever tab happens to be active on a later click.
  const pending = SecretPageReview.activeTab().catch(() => null).then(tab => {
    if (editedPagePending !== pending) return;
    capturedLogPages = capturedLogs.map(() => SecretPageReview.page(tab));
    return saveLogs();
  });
  editedPagePending = pending;
  updateAnalyzeButtonState(); saveSecretSession();
});
analystDataTextarea.addEventListener('input', () => { sanitizedAnalystEdited = false; saveSecretSession(); });
sanitizedTextarea.addEventListener('input', () => { sanitizedLogsEdited = true; syncManualFields(); });
sanitizedAnalystTextarea.addEventListener('input', () => { sanitizedAnalystEdited = true; syncManualFields(); });

const loadingDismissBtn = document.getElementById('loading-dismiss-btn');
loadingDismissBtn.addEventListener('click', async () => {
  cancelRequested = true;
  if (preflightController) preflightController.abort();
  if (reviewReject) reviewReject(new Error('Analysis cancelled during review; nothing was sent.'));
  // Cancels only this case's work; other cases keep running.
  const caseId = await caseStorage.caseId();
  await browser.runtime.sendMessage({ type: 'CANCEL_ANALYSIS', caseId });
  await browser.runtime.sendMessage({ type: 'CANCEL_EXTRACTION', caseId });
  VeiluxExtractionJobs.cancel(caseId); // when this popup runs the job itself
  showLoading(false);
  updateStatus('Cancelled. No further requests will be sent.', 'info');
});
extractBtn.addEventListener('click', smartExtract);
if (extractStatsBtn) extractStatsBtn.addEventListener('click', extractStatsFromDiscover);
analyzeBtn.addEventListener('click', () => analyzeWithAI());

// `trusted` is text VEILUX wrote itself, such as a report's answer format.
// Words from it ("recommendations") can look random to the heuristics but are
// never credentials, so they are kept without asking.
async function reviewAmbiguousSecrets(texts, config, customRegexRules, fieldExclusions, heuristicSettings, trusted = '', kind = 'analysis') {
  await editedPagePending;
  preflightController = new AbortController();
  const controller = preflightController;
  const body = JSON.stringify({ texts, secret_protection: config, force_hide_values: requestForceHideValues, custom_regex_rules: customRegexRules || [], heuristic_field_exclusions: fieldExclusions || [], heuristic_settings: heuristicSettings || {} });
  // Large batches take longer to scan; the backend's own limit grows the same way.
  const timeout = setTimeout(() => controller.abort(), Math.min(15 * 60000, 15000 + 20000 * body.length / 1e6));
  let result;
  try {
    const response = await VeiluxBackend.fetch('/secrets/scan', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, signal: preflightController.signal, body
    });
    if (!response.ok) throw new Error('Secret scan could not complete; nothing was sent.');
    result = await response.json();
  } finally { clearTimeout(timeout); preflightController = null; }
  (result.findings || []).forEach(f => {
    if (trusted && f.confidence === 'ambiguous' && trusted.includes(f.value)
        && !requestForceHideValues.includes(f.value) && !requestAllowedValues.includes(f.value)) requestAllowedValues.push(f.value);
  });
  // Decisions already made for this case stand: only values not reviewed yet
  // (from new logs, context, a report note or a chat message) are shown.
  const ambiguous = Array.from(new Map((result.findings || [])
    .filter(f => f.confidence === 'ambiguous' && !requestForceHideValues.includes(f.value) && !requestAllowedValues.includes(f.value))
    .map(f => [f.value, f])).values());
  if (!ambiguous.length) return requestAllowedValues.slice();
  setHTML(secretReviewList, ambiguous.map((f, i) =>
    '<div class="secret-review-item" data-decision="keep"><label><input type="checkbox" data-secret-index="' + i + '" aria-label="Keep candidate ' + (i + 1) + '" checked><span class="secret-decision">Keep</span></label>' +
    '<button type="button" class="secret-review-value" data-find-secret="' + i + '" title="Find next match on the source page"><code>' +
    escapeHtml(f.value) + '</code></button><div class="secret-review-detail"><details><summary>Why this was flagged</summary><span>' + escapeHtml(f.reason) +
    (f.occurrence_count > 1 ? ' · ' + f.occurrence_count + ' occurrences in analysis inputs' : '') +
    '</span></details><button type="button" class="secret-review-prev" data-previous-secret="' + i + '">Previous page match</button></div></div>').join(''));
  // A review that was interrupted (the popup closed while the analyst looked
  // at the page) comes back with the choices already made.
  const draft = caseSession.available() ? (await caseSession.get('reviewDraft')).reviewDraft : null;
  if (draft && Array.isArray(draft.unchecked)) {
    Array.from(secretReviewList.querySelectorAll('input[data-secret-index]')).forEach(input => {
      if (draft.unchecked.includes(ambiguous[Number(input.dataset.secretIndex)].value)) input.checked = false;
    });
  }
  window.VeiluxUI.updateDecisions();
  const pageStatus = document.getElementById('secret-review-page-status');
  const filter = document.getElementById('secret-review-filter');
  const count = document.getElementById('secret-review-count');
  filter.value = '';
  count.textContent = ambiguous.length + ' values';
  filter.oninput = () => {
    const query = filter.value.toLocaleLowerCase();
    let visible = 0;
    Array.from(secretReviewList.children).forEach((row, index) => {
      row.hidden = !(ambiguous[index].value + ' ' + ambiguous[index].reason).toLocaleLowerCase().includes(query);
      if (!row.hidden) visible++;
    });
    count.textContent = visible + ' of ' + ambiguous.length + ' values';
  };
  // Retain all batches' linked destinations, even for the same source tab.
  const pages = capturedLogPages.concat(fieldStatisticsPages).filter(Boolean);
  if (pageReview) pageReview.close();
  const inspector = new SecretPageReview(pages, ambiguous.map(f => f.value), message => { pageStatus.textContent = message; });
  pageReview = inspector;
  // Saved with the case for this browser session, so closing the popup does not
  // lose the review: its choices, and the pages that carry highlights.
  const saveDraft = () => {
    if (!caseSession.available()) return;
    const inputs = Array.from(secretReviewList.querySelectorAll('input[data-secret-index]'));
    caseSession.set({ reviewDraft: { kind, savedAt: Date.now(), values: ambiguous.map(f => f.value),
      unchecked: inputs.filter(input => !input.checked).map(input => ambiguous[Number(input.dataset.secretIndex)].value),
      pages: pages.filter(page => Number.isInteger(page.id)).map(page => ({ id: page.id, url: page.url, title: page.title })) } }).catch(() => {});
  };
  saveDraft();
  document.getElementById('review-interrupted').hidden = true;
  secretReviewList.addEventListener('change', saveDraft);
  pageStatus.textContent = 'Finding matches on the source page…';
  secretReviewList.onclick = event => {
    const next = event.target.closest('[data-find-secret]');
    const previous = event.target.closest('[data-previous-secret]');
    if (next || previous) inspector.inspect(Number(next ? next.dataset.findSecret : previous.dataset.previousSecret), next ? 1 : -1);
  };
  document.getElementById('secret-review-refresh').onclick = () => inspector.inspect(null, 1, true);
  inspector.inspect();
  showLoading(false);
  updateStatus('Waiting for your review', 'info');
  secretReview.style.display = 'block';
  window.VeiluxUI.setReview(true);
  secretReview.scrollIntoView({ block: 'nearest' });
  const started = performance.now();
  return new Promise((resolve, reject) => {
    const finish = () => {
      // Answered or cancelled: the highlights come off the page and the draft goes.
      inspector.close();
      secretReviewList.removeEventListener('change', saveDraft);
      if (caseSession.available()) caseSession.remove('reviewDraft').catch(() => {});
      if (pageReview === inspector) pageReview = null;
      secretReview.style.display = 'none'; reviewReject = null; reviewMilliseconds += performance.now()-started;
      window.VeiluxUI.setReview(false);
    };
    reviewReject = error => { finish(); reject(error); };
    secretReviewContinue.onclick = () => {
      const inputs = Array.from(secretReviewList.querySelectorAll('input'));
      requestAllowedValues = requestAllowedValues.concat(inputs.filter(input => input.checked)
        .map(input => ambiguous[Number(input.dataset.secretIndex)].value)
        .filter(value => !requestForceHideValues.includes(value) && !requestAllowedValues.includes(value)));
      inputs.filter(input => !input.checked).forEach(input => {
        const value = ambiguous[Number(input.dataset.secretIndex)].value;
        if (!requestForceHideValues.includes(value)) requestForceHideValues.push(value);
      });
      finish(); saveSecretSession(); resolve(requestAllowedValues.slice());
    };
    secretReviewCancel.onclick = () => reviewReject(new Error('Analysis cancelled during credential review; nothing was sent.'));
  });
}
clearBtn.addEventListener('click', clearAllLogs);
submitFeedbackBtn.addEventListener('click', submitFeedback);
settingsBtn.addEventListener('click', function() {
  browser.tabs.create({ url: browser.runtime.getURL('settings.html') });
});

if (copyAnalystDataBtn) copyAnalystDataBtn.addEventListener('click', function() { copyToClipboard(analystDataTextarea ? analystDataTextarea.value : '', 'Case notes'); });
copyLogsBtn.addEventListener('click', function() { copyToClipboard(logsTextarea.value, 'Logs'); });
// Puts a separator at the cursor (or at the end), on its own line, so the next
// pasted log is counted and analysed as a separate log.
const insertSeparatorBtn = document.getElementById('insert-separator-btn');
insertSeparatorBtn.addEventListener('click', function() {
  if (logsTextarea.readOnly) return;
  const value = logsTextarea.value;
  const focused = document.activeElement === logsTextarea;
  const start = focused ? logsTextarea.selectionStart : value.length;
  const end = focused ? logsTextarea.selectionEnd : value.length;
  const before = value.slice(0, start).replace(/[ \t]*$/, ''), after = value.slice(end).replace(/^[ \t]*/, '');
  const insert = (before ? (before.endsWith('\n\n') ? '' : before.endsWith('\n') ? '\n' : '\n\n') : '')
    + LOG_SEPARATOR_TOKEN + '\n\n';
  logsTextarea.value = before + insert + after;
  const cursor = (before + insert).length;
  logsTextarea.focus();
  logsTextarea.setSelectionRange(cursor, cursor);
  logsTextarea.dispatchEvent(new Event('input', { bubbles: true }));
  updateStatus('Separator inserted. Paste the next log below it.', 'success');
});
copySanitizedBtn.addEventListener('click', function() { copyToClipboard(sanitizedTextarea.value, 'Sanitized'); });
if (copySanitizedAnalystBtn) copySanitizedAnalystBtn.addEventListener('click', function() { copyToClipboard(sanitizedAnalystTextarea ? sanitizedAnalystTextarea.value : '', 'Sanitized case notes'); });
copyMappingBtn.addEventListener('click', function() { copyToClipboard(formatMappingForCopy(), 'Mapping'); });
copyAnalysisBtn.addEventListener('click', function() { copyToClipboard(lastAnalysis, 'Analysis'); });

// The Case and Tools tabs (logs, statistics, case notes, indicator check,
// defang) are handled in popup_ui.js; these are the collapsible result sections.
sanitizedToggle.addEventListener('click', function() { toggleSection(sanitizedPreview, sanitizedToggle); });
if (sanitizedAnalystToggle && sanitizedAnalystPreview) sanitizedAnalystToggle.addEventListener('click', function() { toggleSection(sanitizedAnalystPreview, sanitizedAnalystToggle); });
mappingToggle.addEventListener('click', function() { toggleSection(mappingPreview, mappingToggle); });
if (copyStatisticsBtn) copyStatisticsBtn.addEventListener('click', function() {
  copyToClipboard(formatFieldStatisticsForPrompt(fieldStatistics), 'Search statistics');
});
document.getElementById('copy-sanitized-statistics-btn').addEventListener('click', () => {
  copyToClipboard(lastSanitizedStatistics, 'Sanitized statistics');
});
if (clearStatisticsBtn) clearStatisticsBtn.addEventListener('click', async function() {
  fieldStatistics = [];
  fieldStatisticsPages = [];
  openStatistics = new Set();
  await caseStorage.set({ fieldStatistics: fieldStatistics, fieldStatisticsPages });
  renderPersistedStatistics();
  updateStatus('All search statistics cleared', 'info');
});
if (statisticsList) statisticsList.addEventListener('click', function(event) {
  const fieldButton = event.target.closest('[data-remove-stat-field]');
  if (fieldButton) {
    const parts = fieldButton.dataset.removeStatField.split(':').map(Number);
    const statistic = fieldStatistics[parts[0]];
    if (statistic && Array.isArray(statistic.fields)) statistic.fields.splice(parts[1], 1);
    caseStorage.set({ fieldStatistics: fieldStatistics });
    renderPersistedStatistics();
    return;
  }
  const button = event.target.closest('[data-remove-stat]');
  if (!button) return;
  const removed = Number(button.dataset.removeStat);
  fieldStatistics.splice(removed, 1);
  fieldStatisticsPages.splice(removed, 1);
  // Queries after the removed one move up; their open state moves with them.
  openStatistics = new Set(Array.from(openStatistics || []).filter(function(index) { return index !== removed; })
    .map(function(index) { return index > removed ? index - 1 : index; }));
  caseStorage.set({ fieldStatistics: fieldStatistics, fieldStatisticsPages });
  renderPersistedStatistics();
});

function statisticTitle(stat) {
  const summary = stat.summary || {};
  const filters = (summary.filters || []).join(', ') || 'none';
  return (stat.indexPattern || 'index') + ' | Query: ' + (summary.query || '*') +
    ' | Filters: ' + filters + ' | Time: ' + (summary.timeFrame || 'All time');
}


function formatFieldStatisticsForPrompt(items) {
  return (items || []).map(function(stat) {
    const lines = ['### ' + statisticTitle(stat), 'Sample: ' + stat.sampled + ' records; total matches: ' + (stat.total ?? 'unknown') + '. ' + (stat.sourceDescription || '') + (stat.limited ? ' (limit reached)' : '')];
    (stat.fields || []).forEach(function(field) {
      lines.push('- ' + field.field + ': present ' + field.count + '/' + stat.sampled + ' (' + field.percentage.toFixed(1) + '%)');
      (field.topValues || []).forEach(function(value) {
        lines.push('  - ' + value.value + ': ' + value.count + ' (' + value.percentage.toFixed(1) + '%)');
      });
    });
    return lines.join('\n');
  }).join('\n\n');
}

// Each statistics query is a block that opens and closes, so a second or
// third query is one click away instead of a long scroll. A new query opens
// and the older ones close; the analyst's own choices are kept after that.
let openStatistics = null; // indexes of the open queries
function renderPersistedStatistics() {
  if (!statisticsSection || !statisticsList) return;
  statisticsSection.style.display = fieldStatistics.length ? 'block' : 'none';
  if (openStatistics === null) openStatistics = new Set(fieldStatistics.length ? [fieldStatistics.length - 1] : []);
  setHTML(statisticsList, fieldStatistics.map(function(stat, index) {
    const fields = stat.fields || [];
    return '<article class="statistics-entry"><details data-stat-index="' + index + '"' + (openStatistics.has(index) ? ' open' : '') + '>' +
      '<summary><span class="statistics-title">' + escapeHtml(statisticTitle(stat)) + '</span>' +
      '<span class="statistics-brief">' + escapeHtml(stat.sampled) + ' record' + (stat.sampled === 1 ? '' : 's') + ' · ' + fields.length + ' field' + (fields.length === 1 ? '' : 's') +
      (stat.failed ? ' · ' + escapeHtml(stat.failed) + ' not read' : '') + '</span></summary>' +
      '<div class="field-stat-meta">Sample: ' + escapeHtml(stat.sampled) + ' records; total matches: ' + escapeHtml(stat.total ?? 'unknown') + '. ' + escapeHtml(stat.sourceDescription || '') + (stat.limited ? ' (limit reached)' : '') + '</div>' +
      fields.map(function(field, fieldIndex) {
        return '<div class="field-stat"><div class="field-stat-heading"><div class="field-stat-name">' + escapeHtml(field.field) + '</div>' +
          '<button class="field-stat-delete" data-remove-stat-field="' + index + ':' + fieldIndex + '" title="Remove this field" aria-label="Remove ' + escapeHtml(field.field) + '">×</button></div>' +
          '<div class="field-stat-meta">Present: ' + escapeHtml(field.count) + ' (' + Number(field.percentage).toFixed(1) + '%)</div>' +
          (field.topValues || []).map(function(value) { return '<div class="field-stat-value"><code>' + escapeHtml(value.value) +
            '</code><span>' + escapeHtml(value.count) + ' (' + Number(value.percentage).toFixed(1) + '%)</span></div>'; }).join('') + '</div>';
      }).join('') + '<button class="btn btn-danger btn-small" data-remove-stat="' + index + '">Remove this query</button></details></article>';
  }).join(''));
  const toggleAll = document.getElementById('statistics-toggle-all');
  toggleAll.hidden = fieldStatistics.length < 2;
  toggleAll.textContent = openStatistics.size ? 'Collapse all' : 'Expand all';
  updateAnalyzeButtonState();
  window.VeiluxUI?.sourceSummary();
}
// "toggle" does not bubble, so it is caught on the way down.
if (statisticsList) statisticsList.addEventListener('toggle', function(event) {
  const index = Number(event.target.dataset && event.target.dataset.statIndex);
  if (!Number.isInteger(index) || !openStatistics) return;
  if (event.target.open) openStatistics.add(index); else openStatistics.delete(index);
  document.getElementById('statistics-toggle-all').textContent = openStatistics.size ? 'Collapse all' : 'Expand all';
}, true);
document.getElementById('statistics-toggle-all').addEventListener('click', function() {
  openStatistics = new Set(openStatistics && openStatistics.size ? [] : fieldStatistics.map(function(_, index) { return index; }));
  renderPersistedStatistics();
});

function updateAnalyzeButtonState() {
  const hasLogs = capturedLogs.some(function(log) { return typeof log === 'string' && log.trim(); });
  analyzeBtn.disabled = (!hasLogs && fieldStatistics.length === 0) || !!(currentCase && currentCase.archived);
}

async function appendFieldStatistics(stat, page = null) {
  while (fieldStatisticsPages.length < fieldStatistics.length) fieldStatisticsPages.push(null);
  fieldStatistics.push(stat);
  fieldStatisticsPages.push(page);
  await caseStorage.set({ fieldStatistics: fieldStatistics, fieldStatisticsPages });
  openStatistics = new Set([fieldStatistics.length - 1]);
  renderPersistedStatistics();
  window.VeiluxUI?.reveal(statisticsList);
  updateStatus('Statistics appended (' + fieldStatistics.length + ' queries)'
    + (stat.failed ? '. ' + stat.failed + ' record' + (stat.failed === 1 ? '' : 's') + ' could not be read and ' + (stat.failed === 1 ? 'was' : 'were') + ' left out.' : ''),
    stat.failed ? 'info' : 'success');
}

async function extractStatsFromDiscover() {
  extractStatsBtn.disabled = true;
  showLoading(true, 'Reading records and calculating statistics…');
  try {
    await loadConnectorProfiles();
    const tab = await getTargetTab();
    if (!tab || !tab.id) throw new Error('Open the source page first.');
    const host = new URL(tab.url).hostname;
    const chosen=await choosePortableConnection(tab);
    const source = chosen?.profile || connectorProfiles.find(profile => VeiluxConnectorClient.matchesPage(profile, tab.url));
    if (!source) throw new Error('The active tab does not match a configured SIEM connector.' + setAsideNote());
    const configuredMode=VeiluxConnectors.statsMode(source);
    const mode=chosen?.prepared&&configuredMode==='opensearch'?'records':configuredMode;
    if(mode==='disabled')throw new Error('Statistics are disabled for this connection. Change its statistics option in Settings.');
    const sampleSize=statisticsSampleSize(), topValues=statisticsTopValues();
    if(mode==='captured') {
      const rows=capturedLogs.slice(0,sampleSize).map(log=>typeof log==='string'?JSON.parse(log):log);
      if(!rows.length)throw new Error('No records available to summarize.');
      await appendFieldStatistics({indexPattern:source.name,sampled:rows.length,total:null,
        fields:VeiluxConnectors.statistics(rows,topValues),summary:{query:'',filters:[],timeFrame:[]},
        sourceDescription:'logs currently captured in VEILUX',limited:capturedLogs.length>sampleSize},null);
      return;
    }
    // Reading records (or the Inspector panel search) runs in the background worker.
    await startBackgroundJob({kind:'statistics',mode,profile:source,prepared:chosen?.prepared||null,tab,sampleSize,topValues},
      'Reading up to '+sampleSize.toLocaleString()+' records and calculating statistics…');
    return;
  } catch (error) {
    updateStatus('Statistics: ' + error.message, 'error');
  } finally {
    extractStatsBtn.disabled = false;
    showLoading(false);
  }
}

if (defangBtn) defangBtn.addEventListener('click', defangText);
if (refangBtn) refangBtn.addEventListener('click', refangText);
if (copyDefangBtn) copyDefangBtn.addEventListener('click', function() { copyToClipboard(defangOutput ? defangOutput.value : '', 'Result'); });
if (iocLookupBtn) iocLookupBtn.addEventListener('click', checkIocManually);
if (iocLookupInput) iocLookupInput.addEventListener('keypress', function(e) { if (e.key === 'Enter') checkIocManually(); });
if (analystDataTextarea) analystDataTextarea.addEventListener('input', debounce(saveAnalystData, 250));

promptSearch.addEventListener('input', filterPrompts);
promptSearch.addEventListener('focus', function() {
  promptSelector.size = Math.min(allPromptOptions.length + 1, 6);
});
promptSearch.addEventListener('blur', function() {
  setTimeout(function() { promptSelector.size = 1; }, 200);
});

// Sanitize-only hides the AI-specific controls. Extracted so the same rule
// applies however the mode was chosen — clicked now, restored from saved
// preferences on open, or selected on a dynamically added custom model.
function applyModeUi(mode) {
  const sanitizeOnly = mode === 'sanitize_only';
  document.getElementById('openrouter-model-panel').hidden = sanitizeOnly || providerSelect.value !== 'openrouter';
  document.getElementById('sanitization-controls').style.display = 'block';
  sanitizeCheckbox.closest('label').style.display = sanitizeOnly ? 'none' : 'flex';
  promptSelectorSection.style.display = sanitizeOnly ? 'none' : 'block';
  document.getElementById('provider-controls').hidden = sanitizeOnly;
  document.getElementById('local-mode-help').hidden = !sanitizeOnly;
  document.getElementById('ti-toggle-container').hidden = sanitizeOnly;
  document.getElementById('provider-status').textContent = configuredProviderLabels.get(providerSelect.value) || '';
  analyzeBtn.textContent = sanitizeOnly ? 'Sanitize Logs' : 'Analyze with AI';
}

function applyModeUiFromSelection() {
  applyModeUi(selectedAnalysisMode());
}

analysisMode.forEach(function(radio) {
  radio.addEventListener('change', applyModeUiFromSelection);
});
providerSelect.addEventListener('change', () => { applyModeUiFromSelection(); savePopupPreferences(); });

// OpenRouter model picker, shown under the provider when OpenRouter is selected.
async function showOpenRouterModel() {
  const { id, info } = await VeiluxOpenRouter.current(caseStorage);
  document.getElementById('openrouter-model-name').textContent = id ? (info?.name || id) : 'not chosen';
}
VeiluxOpenRouter.mount(document.getElementById('popup-openrouter-picker'), { prefix: 'popup-openrouter', onChange: showOpenRouterModel, storage: caseStorage });
showOpenRouterModel();
document.getElementById('provider-settings').addEventListener('click', () => browser.tabs.create({ url: browser.runtime.getURL('settings.html#ai') }));

async function loadPrompts() {
  const settings = await caseStorage.get(['customPrompts', 'defaultPromptId']);
  customPrompts = settings.customPrompts || [];
  // Prompts saved before stable IDs existed fall back to a positional key
  // for this session only — Settings assigns them a real id on its own
  // next load, at which point this fallback stops being needed.
  allPromptOptions = [{ value: 'default', title: 'Default Security Analysis' }];
  customPrompts.forEach(function(p, i) {
    allPromptOptions.push({ value: 'custom_' + (p.id || ('idx' + i)), title: p.title });
  });
  renderPromptOptions(allPromptOptions);

  const defaultId = settings.defaultPromptId;
  const wantedValue = (!defaultId || defaultId === 'default') ? 'default' : 'custom_' + defaultId;
  if (allPromptOptions.some(function(o) { return o.value === wantedValue; })) {
    promptSelector.value = wantedValue;
  }
}

function renderPromptOptions(options) {
  setHTML(promptSelector, options.map(function(o) {
    return '<option value="' + escapeHtml(o.value) + '">' + escapeHtml(o.title) + '</option>';
  }).join(''));
}

function filterPrompts() {
  const term = promptSearch.value.toLowerCase().trim();
  const filtered = term
    ? allPromptOptions.filter(function(o) { return o.title.toLowerCase().includes(term); })
    : allPromptOptions;
  renderPromptOptions(filtered.length ? filtered : allPromptOptions);
}

function getSelectedPrompt() {
  const val = promptSelector.value;
  if (val === 'default') return null;
  const id = val.replace('custom_', '');
  const found = customPrompts.find(function(p, i) { return (p.id || ('idx' + i)) === id; });
  return (found && found.content) || null;
}

async function defangText() {
  const text = defangInput ? defangInput.value.trim() : '';
  if (!text) return updateStatus('Enter text', 'error');
  try {
    const res = await VeiluxBackend.fetch('/defang', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: text })
    });
    const data = await res.json();
    defangOutput.value = data.defanged;
    updateStatus('Defanged', 'success');
  } catch (e) {
    // Offline: the same scheme form as the backend (http -> hxxp, keeping the
    // letter case); without the backend's public-suffix list every dot is bracketed.
    defangOutput.value = text
      .replace(/\b(h)(tt)(ps?):\/\//gi, (m, h, tt, rest) => h + (tt === 'TT' ? 'XX' : 'xx') + rest + '://')
      .replace(/(?<!\[)\.(?!\])/g, '[.]')
      .replace(/(?<!\[)@(?!\])/g, '[@]');
    updateStatus('Defanged (offline)', 'success');
  }
}

async function refangText() {
  const text = defangInput ? defangInput.value.trim() : '';
  if (!text) return updateStatus('Enter text', 'error');
  try {
    const res = await VeiluxBackend.fetch('/refang', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: text })
    });
    const data = await res.json();
    defangOutput.value = data.refanged;
    updateStatus('Refanged', 'success');
  } catch (e) {
    defangOutput.value = text
      .replace(/\b(h)(xx)(ps?):\/\//gi, (m, h, xx, rest) => h + (h === 'H' && xx === 'XX' ? 'TT' : 'tt') + rest + '://')
      .replace(/\[\.\]/g, '.')
      .replace(/\[@\]/g, '@')
      .replace(/\[:\]/g, ':');
    updateStatus('Refanged (offline)', 'success');
  }
}

// =============================================================================
// THREAT INTELLIGENCE
// =============================================================================

function formatThreatIntelSources(sources) {
  return VeiluxThreatIntel.renderSources(sources);
}

function verdictBadge(verdict) {
  return VeiluxThreatIntel.verdictBadge(verdict);
}

// One threat-intelligence lookup through the backend, with the same
// credential protection as an analysis, using the lookup sources chosen in
// the popup. It is added to the case's record of what was sent. `fresh`
// skips the backend's 24-hour cache (the manual check); the Indicators list
// uses the cache so that checking many values does not spend the quota twice.
async function lookupIndicator(ioc, { fresh = false } = {}) {
  const settings = await caseStorage.get(['virustotalApiKey', 'abuseipdbApiKey', 'customRegexRules', 'heuristicFieldExclusions', 'heuristicSettings']);
  const response = await VeiluxBackend.fetch('/threat-intel/lookup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      ioc: ioc,
      secret_protection: collectSecretProtection(),
      force_hide_values: requestForceHideValues.slice(),
      allowed_ambiguous_secrets: requestAllowedValues.slice(),
      custom_regex_rules: settings.customRegexRules || [],
      heuristic_field_exclusions: settings.heuristicFieldExclusions || [],
      heuristic_settings: settings.heuristicSettings || {},
      virustotal_api_key: settings.virustotalApiKey || null,
      abuseipdb_api_key: settings.abuseipdbApiKey || null,
      enable_virustotal: enableTiVt.checked,
      enable_abuseipdb: enableTiAbuse.checked,
      enable_whois: enableTiWhois.checked,
      use_cache: !fresh
    })
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.detail || 'Lookup failed');
  if (result.outbound && result.outbound.lookups && result.outbound.lookups.length)
    await VeiluxCases.recordSend(await caseStorage.caseId(), { purpose: 'ioc-check', outcome: 'completed', localOnly: false,
      ai: null, lookups: result.outbound.lookups }).catch(() => {});
  return result;
}

// Lookup sources usable right now: WHOIS needs no key.
async function lookupSourcesReady() {
  const keys = await caseStorage.get(['virustotalApiKey', 'abuseipdbApiKey']);
  return enableTiWhois.checked || (enableTiVt.checked && !!keys.virustotalApiKey) || (enableTiAbuse.checked && !!keys.abuseipdbApiKey);
}

// Adds lookups made outside an analysis to the case's threat intelligence, so
// the Threat intel tab, Ask and the report see them too.
async function mergeThreatIntelFindings(findings) {
  const saved = await caseStorage.get(['lastThreatIntelFindings', 'lastThreatIntelStatus']);
  const merged = new Map((Array.isArray(saved.lastThreatIntelFindings) ? saved.lastThreatIntelFindings : []).map(f => [f.ioc, f]));
  findings.forEach(f => { const { outbound, ...finding } = f; merged.set(finding.ioc, finding); });
  const list = Array.from(merged.values());
  const status = saved.lastThreatIntelStatus || { state: 'ok', message: 'Indicators checked from the Indicators list.' };
  await caseStorage.set({ lastThreatIntelFindings: list, lastThreatIntelStatus: status });
  displayThreatIntelFindings(list, status);
}

async function checkIocManually() {
  const ioc = iocLookupInput.value.trim();
  if (!ioc) return updateStatus('Enter an IOC to check', 'error');

  const settings = await caseStorage.get(['virustotalApiKey', 'abuseipdbApiKey', 'customRegexRules', 'heuristicFieldExclusions', 'heuristicSettings']);
  if (!(enableTiWhois.checked || (enableTiVt.checked && settings.virustotalApiKey) || (enableTiAbuse.checked && settings.abuseipdbApiKey))) {
    setHTML(iocLookupResult, '<div class="placeholder">Enable WHOIS for free IP/domain registration checks, or enable a reputation source and add its key in Settings.</div>');
    return;
  }

  iocLookupBtn.disabled = true;
  iocLookupBtn.textContent = '⏳ Checking...';
  setHTML(iocLookupResult, '');

  try {
    const result = await lookupIndicator(ioc, { fresh: true });
    setHTML(iocLookupResult, VeiluxThreatIntel.renderFinding(result));
    updateStatus(result.lookup_status === 'unavailable' ? 'Lookup sources unavailable' : result.lookup_status === 'partial' ? 'Lookup complete — some sources unavailable' : 'Lookup complete',
      result.lookup_status === 'unavailable' ? 'error' : result.lookup_status === 'partial' ? 'info' : 'success');
  } catch (e) {
    setHTML(iocLookupResult, '<div class="placeholder" style="color:var(--danger);">Error: ' + escapeHtml(e.message) + '</div>');
    updateStatus('Lookup failed', 'error');
  } finally {
    iocLookupBtn.disabled = false;
    iocLookupBtn.textContent = '🔍 Check';
  }
}

function displayThreatIntelFindings(findings, status = null) {
  if ((!findings || findings.length === 0) && !status?.message) {
    threatIntelSection.style.display = 'none';
    setHTML(threatIntelFindingsEl, '');
    return;
  }

  const summary = status?.message ? '<p class="ti-analysis-status field-hint">' + escapeHtml(status.message) + '</p>' : '';
  setHTML(threatIntelFindingsEl, summary + (findings || []).map(VeiluxThreatIntel.renderFinding).join(''));
  threatIntelSection.style.display = 'block';
}

// =============================================================================
// SMART EXTRACT
// Every connection is read by VeiluxConnectorClient (connector_client.js): it
// finds the connections that match the open tab and what each one can read
// there (a table, page JSON, the Inspector panel, a page script, or API
// requests built from values on the page).
// =============================================================================

// The tab Extract operates on. Normally the active tab of the current
// window; when the popup was opened from the right-click context menu
// (see background.js) it carries ?tabId=<id> and is pinned to that exact
// tab instead — that's how extraction reaches pages living in toolbar-less
// popup windows where the extension icon isn't clickable.
async function getTargetTab() {
  const forcedId = parseInt(new URLSearchParams(window.location.search).get('tabId'), 10);
  if (!isNaN(forcedId)) {
    try { return await browser.tabs.get(forcedId); } catch (e) { /* tab closed — fall back */ }
  }
  const tabs = await browser.tabs.query({ active: true, currentWindow: true });
  return tabs[0];
}

async function choosePortableConnection(tab) {
  const found=await VeiluxConnectorClient.candidates(connectorProfiles,tab);
  if(!found.matched)return null;
  if(!found.candidates.length)throw Error(found.errors.join('\n')||'No connection can read this page. Preview its parameter rules in Settings.');
  if(found.candidates.length===1)return found.candidates[0];
  showLoading(false);
  return new Promise((resolve,reject)=>{
    const dialog=document.createElement('dialog');dialog.id='connector-choice';dialog.className='connector-choice';
    const label=document.createElement('label');label.htmlFor='connector-choice-select';label.textContent='Several connections match this page. Choose which records to read.';
    const select=document.createElement('select');select.id='connector-choice-select';
    found.candidates.forEach((c,i)=>select.add(new Option(c.profile.name+' — '+c.label,String(i))));
    const use=document.createElement('button');use.type='button';use.className='btn btn-primary';use.textContent='Use connection';
    const cancel=document.createElement('button');cancel.type='button';cancel.className='btn btn-secondary';cancel.textContent='Cancel';
    const finish=value=>{dialog.close();dialog.remove();if(value){showLoading(true,'Reading selected connection…');resolve(value);}else reject(Error('Connection selection cancelled.'));};
    use.addEventListener('click',()=>finish(found.candidates[Number(select.value)]));cancel.addEventListener('click',()=>finish(null));
    dialog.addEventListener('cancel',event=>{event.preventDefault();finish(null);});
    dialog.append(label,select,use,cancel);document.body.append(dialog);dialog.showModal();select.focus();
  });
}

async function smartExtract() {
  updateStatus('Detecting page...', 'info');
  showLoading(true, 'Detecting context...');

  try {
    await loadConnectorProfiles();
    if (connectorProfiles.length === 0) {
      throw new Error('No connections yet. Add one in Settings → Connections.' + setAsideNote());
    }

    const tab = await getTargetTab();
    if (!tab || !tab.id) throw new Error('No active tab found.');
    if (/^(chrome|chrome-extension|edge|about|moz-extension|safari-extension|safari-web-extension):/i.test(tab.url)) {
      throw new Error('Cannot extract from this page.');
    }

    const chosen=await choosePortableConnection(tab);
    if (chosen) {
      return await startBackgroundJob({ kind: 'extract', call: 'read', profile: chosen.profile, prepared: chosen.prepared,
        tab, label: chosen.prepared ? 'page' : 'search' }, 'Extracting from ' + chosen.profile.name + '…');
    }
    const known = [...new Set(connectorProfiles.flatMap(p => [p.siemHost, ...(p.pageSources || []).map(s => s.website)]).filter(Boolean))];
    throw new Error('No connection reads this page (' + new URL(tab.url).hostname + '). Connections cover: ' + known.join(', ') + '. ' +
      'Add or change one in Settings → Connections. Connections are stored in this browser\'s extension storage, so loading ' +
      'the extension from a different folder starts with an empty list.' + setAsideNote());

  } catch (e) {
    updateStatus('Extract: ' + e.message, 'error');
  } finally {
    showLoading(false);
  }
}

// Pushes fetched logs into state, updates UI, shows status
async function storeResults(fetchData, source, label, sourceTab = null, linkedUrls = []) {
  const logs = Array.isArray(fetchData && fetchData.logs) ? fetchData.logs : [];
  const failed = Number(fetchData && fetchData.failed) || 0;
  const total = (fetchData && typeof fetchData.total === 'number') ? fetchData.total : logs.length;

  if (logs.length > 0) {
    while (capturedLogPages.length < capturedLogs.length) capturedLogPages.push(null);
    const page = SecretPageReview.page(sourceTab, linkedUrls);
    logs.forEach(function(log) { capturedLogs.push(log); capturedLogPages.push(page); });
    await saveLogs();
    updateUI();
    window.VeiluxUI.reveal(logsTextarea);
    let msg = 'Extracted ' + logs.length + ' log(s) from ' + source.name + ' ' + label;
    if (fetchData.limited) msg += ' (sample limit reached)';
    if (typeof total === 'number' && total > logs.length) {
      msg += ' (' + total + ' total hits)';
    }
    if (failed > 0) {
      const reasons = Array.isArray(fetchData.errors) ? fetchData.errors.filter(Boolean) : [];
      msg += ' (' + failed + ' failed' + (reasons.length ? ': ' + reasons[0] + (reasons.length > 1 ? ' (+' + (reasons.length - 1) + ' more)' : '')
        : ' - check ' + source.name + ' SIEM session') + ')';
    }
    if (fetchData.note) {
      msg += ' [' + fetchData.note + ']';
    } else if (fetchData.info) {
      msg += ' [' + fetchData.info + ']';
    }
    updateStatus(msg, failed > 0 ? 'info' : 'success');
    return;
  }

  if (failed === 0) {
    let msg = 'Current ' + source.name + ' ' + label + ' search returned 0 logs';
    if (typeof total === 'number' && total >= 0) {
      msg += ' (0 hits)';
    }
    if (fetchData.note) {
      msg += ' [' + fetchData.note + ']';
    } else if (fetchData.info) {
      msg += ' [' + fetchData.info + ']';
    }
    updateStatus(msg + '.', 'info');
    return;
  }

  const loginTarget = source.ssoHint || source.siemBaseUrl;
  throw new Error(
    'No logs returned from ' + source.name + ' SIEM - ' +
    failed + ' request(s) failed. ' +
    'Session may have expired - re-authenticate at ' + loginTarget + '.'
  );
}

// =============================================================================
// BACKGROUND EXTRACTION
// Extract logs and Extract statistics read their records in
// the background worker (background.js), so closing the popup does not stop
// them. The result belongs to the case that started the job and is applied
// when a popup shows that case.
// =============================================================================
const EXTRACTION_STALE_MS = 90 * 1000; // more than four missed 20-second heartbeats
// A job run by a popup stops when that popup closes, so it is judged sooner.
const POPUP_EXTRACTION_STALE_MS = 30 * 1000;
// A job the background accepted writes extractionJob at once; this long without it means it never started.
const EXTRACTION_START_MS = 15 * 1000;
const POPUP_RUNNER_HINT = 'The background worker did not take this extraction, so it runs in this popup: keep the popup open. ' +
  'To let extractions continue in the background, reload the extension (chrome://extensions, or about:debugging in Firefox).';

function extractionStale(job) {
  const limit = job.runner === 'popup' ? POPUP_EXTRACTION_STALE_MS : EXTRACTION_STALE_MS;
  return Date.now() - (job.heartbeat || 0) > limit;
}

function tabSummary(tab) {
  return tab ? { id: tab.id, url: tab.url, windowId: tab.windowId, title: tab.title,
    incognito: tab.incognito, cookieStoreId: tab.cookieStoreId } : null;
}

async function startBackgroundJob(job, loadingText) {
  const { extractionJob } = await caseStorage.get('extractionJob');
  if (extractionJob && !extractionStale(extractionJob)) {
    throw new Error('Another extraction is still running. Wait for it to finish, or cancel it.');
  }
  job = Object.assign({}, job, { id: crypto.randomUUID(), tab: tabSummary(job.tab), caseId: await caseStorage.caseId() });
  await caseStorage.set({ extractionResult: null, extractionError: null });
  showLoading(true, loadingText, true);
  // The background worker replies when it takes the job. No reply means it is
  // missing the handler, usually because it still runs the previous version of
  // the extension; the popup then runs the same job itself.
  let reply = null;
  try { reply = await browser.runtime.sendMessage({ type: 'START_EXTRACTION', job }); } catch (_) {}
  if (reply && reply.reason === 'busy') throw new Error('Another extraction is still running. Wait for it to finish, or cancel it.');
  if (!reply || !reply.accepted) {
    showLoading(true, loadingText, POPUP_RUNNER_HINT);
    VeiluxExtractionJobs.start(job, 'popup');
  }
  return waitForExtraction(job.id);
}

// Resolves when the job's result has been applied; rejects with its error.
function waitForExtraction(id) {
  return new Promise((resolve, reject) => {
    let done = false, seen = false;
    const waitingSince = Date.now();
    const finish = (error, result) => {
      if (done) return;
      done = true;
      caseStorage.onChanged.removeListener(listener);
      clearInterval(watchdog);
      if (error) { caseStorage.set({ extractionError: null }).catch(() => {}); reject(error); }
      else applyExtractionResult(result).then(resolve, reject);
    };
    const check = async () => {
      const stored = await caseStorage.get(['extractionResult', 'extractionError', 'extractionJob']);
      if (stored.extractionResult && stored.extractionResult.id === id) return finish(null, stored.extractionResult);
      if (stored.extractionError && stored.extractionError.id === id) return finish(new Error(stored.extractionError.message));
      const job = stored.extractionJob;
      if (job && job.id === id && extractionStale(job)) {
        await caseStorage.set({ extractionJob: null });
        finish(new Error(job.runner === 'popup'
          ? 'The extraction ran in the popup and stopped when the popup closed. Run it again; reload the extension so it can continue in the background.'
          : 'The background extraction stopped unexpectedly. Run it again.'));
      } else if (job && job.id === id) {
        seen = true;
      } else if (!seen && Date.now() - waitingSince > EXTRACTION_START_MS) {
        finish(new Error('The extraction did not start. Reload the extension, then try again.'));
      }
    };
    const listener = (changes, area) => {
      if (area === 'local' && (changes.extractionResult || changes.extractionError)) check();
    };
    caseStorage.onChanged.addListener(listener);
    const watchdog = setInterval(check, 5000);
    check();
  });
}

// Applies a finished job once: it is removed from storage before being added.
async function applyExtractionResult(result) {
  const stored = await caseStorage.get('extractionResult');
  if (!stored.extractionResult || stored.extractionResult.id !== result.id) return;
  await caseStorage.set({ extractionResult: null });
  if (result.kind === 'statistics') {
    const page = result.mode === 'opensearch' ? SecretPageReview.page(result.tab) : SecretPageReview.page(result.tab, result.linkedUrls || []);
    await appendFieldStatistics(result.statistic, page);
    return;
  }
  await loadConnectorProfiles();
  const source = connectorProfiles.find(p => p.id === result.profileId) || { name: result.profileName || 'connection' };
  await storeResults(result.data, source, result.label, result.tab, result.data.linkedUrls || []);
}

// On opening: apply a result that finished while the popup was closed, or keep
// waiting for a job that is still running.
async function resumeBackgroundExtraction() {
  const stored = await caseStorage.get(['extractionResult', 'extractionError', 'extractionJob']);
  if (stored.extractionResult) {
    await applyExtractionResult(stored.extractionResult);
  } else if (stored.extractionError) {
    updateStatus('Extract: ' + stored.extractionError.message, 'error');
    await caseStorage.set({ extractionError: null });
  } else if (stored.extractionJob) {
    showLoading(true, 'Extraction is still running in the background…', stored.extractionJob.runner === 'popup' ? POPUP_RUNNER_HINT : true);
    try { await waitForExtraction(stored.extractionJob.id); }
    catch (e) { updateStatus('Extract: ' + e.message, 'error'); }
    finally { showLoading(false); }
  }
}

// =============================================================================
// AI ANALYSIS
// =============================================================================

// Is a running analysis dead, or just slow? Judged by LIVENESS, not by
// elapsed time: the background worker writes analysisHeartbeat every 20s
// while it works, so a missing heartbeat means the worker died, while a
// fresh one means the work is fine no matter how long it has taken. This
// matters because a legitimate analysis can run for many minutes — threat
// intel enriches IOCs sequentially before the AI call even starts.
const ANALYSIS_HEARTBEAT_STALE_MS = 90 * 1000;     // 4+ missed 20s beats
const ANALYSIS_ABSOLUTE_MAX_MS = 30 * 60 * 1000;   // backstop for a wedged flag

function isAnalysisStale(startedAt, heartbeat) {
  const now = Date.now();
  if (startedAt && (now - startedAt) > ANALYSIS_ABSOLUTE_MAX_MS) return true;
  if (heartbeat) return (now - heartbeat) > ANALYSIS_HEARTBEAT_STALE_MS;
  // No heartbeat recorded: either a flag left by an older build or one whose
  // worker died before its first beat — both are stuck.
  return !startedAt || (now - startedAt) > ANALYSIS_HEARTBEAT_STALE_MS;
}

async function clearStuckAnalysis() {
  try { await caseStorage.set({ analysisInProgress: false }); } catch (e) {}
  await markCaseSeen();
}

function waitForAnalysisResult() {
  return new Promise(function(resolve, reject) {
    // Watchdog alongside the event listener: if the background worker dies
    // mid-analysis, no completion event will ever fire — poll the started
    // timestamp and bail out (clearing the stuck flag) once it goes stale.
    const watchdog = setInterval(function() {
      caseStorage.get(['analysisInProgress', 'analysisStartedAt', 'analysisHeartbeat']).then(function(s) {
        if (!s.analysisInProgress) return;  // completion event will handle it
        if (isAnalysisStale(s.analysisStartedAt, s.analysisHeartbeat)) {
          cleanup();
          clearStuckAnalysis();
          reject(new Error('The analysis was interrupted (background task stopped). Run it again.'));
        }
      }).catch(function() {});
    }, 10000);

    function cleanup() {
      clearInterval(watchdog);
      caseStorage.onChanged.removeListener(listener);
    }

    function listener(changes, area) {
      if (area !== 'local') return;
      if (changes.analysisPhase && changes.analysisPhase.newValue && changes.analysisPhase.newValue !== changes.analysisPhase.oldValue) showLoading(true, changes.analysisPhase.newValue);
      if (!changes.analysisInProgress) return;
      if (changes.analysisInProgress.newValue === false) {
        cleanup();
        caseStorage.get([
          'lastAnalysis', 'lastSanitizedLog', 'lastSanitizedAnalystData', 'lastSanitizedStatistics',
          'lastMappingTable', 'lastThreatIntelFindings', 'lastThreatIntelStatus', 'lastAnalysisMode',
          'lastShouldSanitize', 'analysisError', 'analysisTimings', 'analysisPurpose', 'pendingAnswer'
        ]).then(function(saved) {
          if (saved.analysisError) {
            reject(new Error(saved.analysisError));
          } else {
            resolve(saved);
          }
        });
      }
    }
    caseStorage.onChanged.addListener(listener);
  });
}

function secretReviewSnapshot(text, analystContext, statistics, customPrompt, secretConfig, _reviewDecisions) {
  // Normalize missing values the same way before and after the preflight
  // scan. Otherwise an unchanged request looks edited and triggers another
  // scan, endlessly.
  return JSON.stringify([
    text || '',
    analystContext || '',
    statistics || [],
    customPrompt || null,
    secretConfig || {}
  ]);
}

// A report or an answer that finished while the popup was closed, or showed
// another case, waits in "pendingAnswer" until this case is opened.
async function applyPendingAnswer(pending) {
  if (!pending || !pending.raw && pending.raw !== '') return;
  try {
    if (pending.purpose === 'report') {
      await window.VeiluxReportPanel.applyAnswer(pending.raw, pending.mapping);
      updateStatus('Report ready. Review it, then copy it into your email.', 'success');
    } else if (pending.purpose === 'chat') {
      await window.VeiluxChatPanel.applyAnswer(pending.raw);
      updateStatus('Answer ready.', 'success');
    }
  } catch (error) {
    updateStatus('Error: ' + error.message, 'error');
    if (pending.purpose === 'report') window.VeiluxReportPanel.showError(error.message);
    else window.VeiluxChatPanel.showError(error.message);
  } finally {
    await caseStorage.remove('pendingAnswer').catch(() => {});
  }
}

// Resolves when the background worker (background.js) marks the analysis as
// finished, with the saved result, or rejects with its error. The request runs
// in the background worker, so it survives the popup closing or switching to
// another case; the result is saved in this case and shown when it is opened.
async function waitAndApplyAnalysis() {
  let completed = false;
  try {
    const saved = await waitForAnalysisResult();
    if (saved.analysisPurpose === 'report' || saved.analysisPurpose === 'chat') {
      // Reports and answers never replace the case's analysis results.
      await applyPendingAnswer(saved.pendingAnswer);
      return;
    }
    applyAnalysisState(saved);
    completed = true;
    const timing = saved.analysisTimings || {};
    // One short line (total, AI, protection); the full breakdown opens with "More".
    const seconds = ms => (ms / 1000).toFixed(1) + 's';
    const wait = Object.entries(timing).filter(([stage]) => stage !== 'review').reduce((sum, [, ms]) => sum + ms, 0);
    const protection = ['detection', 'privacy_masking', 'replacement'].reduce((sum, stage) => sum + (timing[stage] || 0), 0);
    const brief = [seconds(wait), timing.ai > 0 && 'AI ' + seconds(timing.ai), protection > 0 && 'protection ' + seconds(protection),
      timing.threat_intelligence > 0 && 'threat intel ' + seconds(timing.threat_intelligence)].filter(Boolean).join(' · ');
    const details = Object.entries(timing).map(([stage, ms]) => stage.replaceAll('_', ' ') + ': ' + (ms/1000).toFixed(2) + 's').join(' · ');
    updateStatus((saved.lastAnalysisMode === 'sanitize_only' ? 'Sanitized!' : 'Done!') + (wait ? ' ' + brief : ''), 'success',
      details ? 'Timing: ' + details + (timing.review ? ' (review is time you spent deciding, not counted in the total)' : '') : '');
  } catch (e) {
    updateStatus('Error: ' + e.message, 'error');
    const purpose = (await caseStorage.get('analysisPurpose').catch(() => ({}))).analysisPurpose;
    if (purpose === 'report') window.VeiluxReportPanel.showError(e.message);
    else if (purpose === 'chat') window.VeiluxChatPanel.showError(e.message);
    else showAnalysisError(e.message);
  } finally {
    showLoading(false);
    if (completed) window.VeiluxUI.revealResults();
    await markCaseSeen();
  }
}

// `task` turns the same protected request into something other than an
// analysis: {purpose: 'report' | 'chat', instructions, context, provider}.
// report_panel.js and chat_panel.js build it. The instructions replace the
// analysis prompt, the context joins the analyst context (so it is protected
// like it), and provider, when set, overrides the popup's model for this one
// request.
async function analyzeWithAI(task = null) {
  if (!capturedLogs.length && !fieldStatistics.length) return;

  cancelRequested = false; reviewMilliseconds = 0;
  const contextNow = () => {
    const base = (sanitizedAnalystEdited ? sanitizedAnalystTextarea : analystDataTextarea).value.trim();
    // Case notes kept from Ask travel with the analyst's own notes in every
    // analysis, question and report (case_notes.js).
    const notes = window.VeiluxCaseNotes.withNotes(base);
    return task && task.context ? [notes, task.context].filter(Boolean).join('\n\n') : notes;
  };
  const promptNow = () => task ? task.instructions : getSelectedPrompt();
  let text = (sanitizedLogsEdited ? sanitizedTextarea : logsTextarea).value.trim();
  let logsToAnalyze = splitLogInput(text);

  let analystContext = contextNow();

  // Reports and answers always need an AI provider, even when this case sanitizes only.
  const selected = task ? (task.provider || providerSelect.value) : selectedAnalysisMode();
  // Analyst-defined models use selector values of the form "custom:<id>"; the
  // backend sees mode "custom" plus the model's configuration.
  const isCustom = selected.indexOf('custom:') === 0;
  const customId = isCustom ? selected.slice('custom:'.length) : null;
  const mode = isCustom ? 'custom' : selected;
  let shouldSanitize = mode === 'sanitize_only' || sanitizeCheckbox.checked;

  const modeNames = {
    groq: 'Groq', deepseek: 'DeepSeek', together: 'Together',
    openrouter: 'OpenRouter', gemini: 'Gemini', claude: 'Claude', sanitize_only: 'Sanitize'
  };

  let customProvider = null;
  if (isCustom) {
    const stored = await caseStorage.get(['customAiProviders']);
    const found = (stored.customAiProviders || []).find(function(p) { return p.id === customId; });
    if (!found) throw new Error('That custom model no longer exists — pick another in Settings.');
    customProvider = found;
  }

  const label = isCustom ? customProvider.name : modeNames[mode];
  analyzeBtn.disabled = true;
  showLoading(true, 'Sanitizing logs');

  try {
    let apiKey = null;
    if (isCustom) {
      // Local runners (Ollama, LM Studio, vLLM) have no key — absence is legal.
      apiKey = customProvider.apiKey || null;
    } else if (mode !== 'sanitize_only') {
      const keyMap = {
        groq: 'groqApiKey', deepseek: 'deepseekApiKey', together: 'togetherApiKey',
        openrouter: 'openrouterApiKey', gemini: 'geminiApiKey', claude: 'claudeApiKey'
      };
      const settings = await caseStorage.get([keyMap[mode]]);
      apiKey = settings[keyMap[mode]];
      if (!apiKey) throw new Error(modeNames[mode] + ' API key not set. Go to Settings.');
    }
    const openrouterModel = mode === 'openrouter' ? (await VeiluxOpenRouter.current(caseStorage)).id : null;
    // Built-in providers use the model chosen in Settings; none is picked for the analyst.
    const providerModel = VeiluxProviderModels.PROVIDERS[mode] ? await VeiluxProviderModels.current(mode, caseStorage) : null;
    if (VeiluxProviderModels.PROVIDERS[mode] && !providerModel) throw new Error(VeiluxProviderModels.missingMessage(mode));
    if (mode === 'openrouter' && !openrouterModel) {
      document.getElementById('openrouter-model-panel').open = true;
      window.VeiluxUI.reveal(document.getElementById('openrouter-model-panel'));
      throw new Error('Choose an OpenRouter model first: open “OpenRouter model” under the provider and find a free model.');
    }

    const sanitizationSettings = await caseStorage.get([
      'jsonKeysList', 'customKeywordsList', 'customRegexRules', 'heuristicFieldExclusions', 'heuristicSettings', 'customCidrsList', 'customDomainsList',
      'statisticsFieldsList',
      'enableStatisticsFieldSanitization',
      'enableThreatIntel', 'virustotalApiKey', 'abuseipdbApiKey'
    ]);

    let enablePattern = true;
    let jsonKeysToHide = null;
    let customKeywords = null;
    let internalCidrs = null;
    let internalDomains = null;
    let statisticsFieldsToHide = null;


    let customPrompt, allowedAmbiguous, secretConfig;
    // Re-read after review: edits or checkbox changes invalidate the preflight.
    let preflightAttempts = 0;
    while (true) {
      preflightAttempts += 1;
      if (preflightAttempts > 5) {
        throw new Error('Inputs kept changing during credential review. Stop editing and try again.');
      }
      text = (sanitizedLogsEdited ? sanitizedTextarea : logsTextarea).value.trim();
      logsToAnalyze = splitLogInput(text);
      analystContext = contextNow();
      customPrompt = promptNow(); secretConfig = collectSecretProtection();
      const livePolicy = await caseStorage.get(['customRegexRules', 'heuristicFieldExclusions', 'heuristicSettings']);
      Object.assign(sanitizationSettings, livePolicy);
      const statisticsJson = fieldStatistics.length ? JSON.stringify(fieldStatistics) : '';
      const effectivePolicy = {secretConfig, customRegexRules: sanitizationSettings.customRegexRules || [], heuristicFieldExclusions: sanitizationSettings.heuristicFieldExclusions || [], heuristicSettings: sanitizationSettings.heuristicSettings || {}};
      const snapshot = secretReviewSnapshot(
        text, analystContext, fieldStatistics, customPrompt, effectivePolicy, requestForceHideValues
      );
      allowedAmbiguous = await reviewAmbiguousSecrets(logsToAnalyze.concat([analystContext, statisticsJson, customPrompt || '']), secretConfig, sanitizationSettings.customRegexRules, sanitizationSettings.heuristicFieldExclusions, sanitizationSettings.heuristicSettings, task && task.trusted, task ? task.purpose : 'analysis');
      if (cancelRequested) throw new Error('Analysis cancelled; nothing was sent.');
      const currentPolicySettings = await caseStorage.get(['customRegexRules', 'heuristicFieldExclusions', 'heuristicSettings']);
      Object.assign(sanitizationSettings, currentPolicySettings);
      const currentPolicy = {secretConfig: collectSecretProtection(), customRegexRules: sanitizationSettings.customRegexRules || [], heuristicFieldExclusions: sanitizationSettings.heuristicFieldExclusions || [], heuristicSettings: sanitizationSettings.heuristicSettings || {}};
      const current = secretReviewSnapshot(
        (sanitizedLogsEdited ? sanitizedTextarea : logsTextarea).value.trim(),
        contextNow(), fieldStatistics, promptNow(), currentPolicy, requestForceHideValues
      );
      if (current === snapshot) break;
      showLoading(true, 'Sanitizing logs');
    }
    showLoading(true, 'Sanitizing logs');

    shouldSanitize = mode === 'sanitize_only' || sanitizeCheckbox.checked;
    if (shouldSanitize) {
      enablePattern = popupEnablePattern.checked;

      if (popupEnableJsonkeys.checked && sanitizationSettings.jsonKeysList) {
        const enabledKeys = sanitizationSettings.jsonKeysList
          .filter(function(k) { return k.enabled; })
          .map(function(k) { return k.key; });
        if (enabledKeys.length > 0) jsonKeysToHide = enabledKeys;
      }

      if (popupEnableKeywords.checked && sanitizationSettings.customKeywordsList) {
        const enabledKw = sanitizationSettings.customKeywordsList.filter(function(k) { return k.enabled; });
        if (enabledKw.length > 0) {
          customKeywords = {};
          enabledKw.forEach(function(k) { customKeywords[k.keyword] = k.replacement; });
        }
      }

      if (sanitizationSettings.enableStatisticsFieldSanitization !== false && sanitizationSettings.statisticsFieldsList) {
        const enabledStatisticFields = sanitizationSettings.statisticsFieldsList
          .filter(function(field) { return field.enabled; })
          .map(function(field) { return field.field; });
        if (enabledStatisticFields.length) statisticsFieldsToHide = enabledStatisticFields;
      }
    }

    // Internal infrastructure is never a public TI target, even when the
    // analyst disables optional privacy masking of the AI prompt.
    if (sanitizationSettings.customCidrsList) {
      internalCidrs = sanitizationSettings.customCidrsList.filter(c => c.enabled).map(c => c.cidr);
    }
    if (sanitizationSettings.customDomainsList) {
      internalDomains = sanitizationSettings.customDomainsList.filter(d => d.enabled).map(d => d.domain);
    }

    const payload = {
      logs: logsToAnalyze,
      secret_protection: secretConfig,
      request_id: crypto.randomUUID(),
      mode: mode,
      sanitize: shouldSanitize,
      api_key: apiKey,
      enable_pattern_sanitization: enablePattern,
      custom_keywords: customKeywords,
      json_keys_to_hide: jsonKeysToHide,
      internal_cidrs: internalCidrs,
      internal_domains: internalDomains,
      custom_prompt: customPrompt,
      analyst_data: analystContext || null,
      field_statistics: fieldStatistics.length ? fieldStatistics : null,
      statistics_fields_to_hide: statisticsFieldsToHide,
      // Threat intel follows the popup's switches, so it can change per analysis.
      // Reports and answers reuse the results already in the case instead of
      // looking indicators up again.
      enable_threat_intel: !task && mode !== 'sanitize_only' && enableTiCheckbox.checked,
      enable_virustotal: enableTiVt.checked,
      enable_abuseipdb: enableTiAbuse.checked,
      enable_whois: enableTiWhois.checked,
      virustotal_api_key: sanitizationSettings.virustotalApiKey || null,
      abuseipdb_api_key: sanitizationSettings.abuseipdbApiKey || null,
      allowed_ambiguous_secrets: allowedAmbiguous,
      force_hide_values: requestForceHideValues.slice(),
      custom_regex_rules: sanitizationSettings.customRegexRules || []
      ,heuristic_field_exclusions: sanitizationSettings.heuristicFieldExclusions || []
      ,heuristic_settings: sanitizationSettings.heuristicSettings || {}
    };

    if (customProvider) {
      payload.custom_provider = VeiluxCustomModels.requestConfig(customProvider);
    }
    if (openrouterModel) payload.openrouter_model = openrouterModel;
    if (providerModel) payload.model = providerModel.id;

    // The request runs in the background worker (background.js), so closing
    // the popup does not cancel it. waitAndApplyAnalysis picks up the result.
    analyzeBtn.disabled = true;
    const waiting = waitAndApplyAnalysis();
    const reply = await browser.runtime.sendMessage({ type: 'START_ANALYSIS', caseId: await caseStorage.caseId(), payload, reviewMilliseconds,
      purpose: task ? task.purpose : 'analysis',
      // What the analysis was based on, to notice later that the case changed.
      basis: task ? null : window.VeiluxCaseNotes.basisNow() });
    if (reply && reply.reason === 'busy') throw new Error('This case is already being analyzed. Wait for it to finish, or cancel it.');
    await waiting;

  } catch (e) {
    updateStatus('Error: ' + e.message, 'error');
    if (task && task.purpose === 'report') window.VeiluxReportPanel.showError(e.message);
    else if (task && task.purpose === 'chat') window.VeiluxChatPanel.showError(e.message);
    else showAnalysisError(e.message);
    showLoading(false);
  } finally {
    updateAnalyzeButtonState();
  }
}

async function submitFeedback() {
  const correction = correctionTextarea.value.trim();
  if (!correction) return updateStatus('Enter a correction first.', 'error');
  try {
    const policy = await caseStorage.get(['customRegexRules', 'heuristicFieldExclusions', 'heuristicSettings']);
    const response = await VeiluxBackend.fetch('/feedback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        secret_protection: collectSecretProtection(),
        force_hide_values: requestForceHideValues.slice(),
        custom_regex_rules: policy.customRegexRules || [],
        heuristic_field_exclusions: policy.heuristicFieldExclusions || [],
        heuristic_settings: policy.heuristicSettings || {},
        original_log: capturedLogs.join('\n---\n'),
        analyst_data: analystDataTextarea ? analystDataTextarea.value.trim() : '',
        ai_response: lastAnalysis,
        user_correction: correction
      })
    });
    if (!response.ok) throw new Error('not saved');
    updateStatus('Saved as a pending lesson. Approve it in Settings → Lessons to use it in future analyses.', 'success');
    correctionTextarea.value = '';
  } catch (e) {
    updateStatus('Failed to save', 'error');
  }
}

async function clearAllLogs() {
  resetSecretAnalysis();
  await window.VeiluxCaseUI.clearDetails();
  sanitizedTextarea.value = '';
  capturedLogs = [];
  capturedLogPages = [];
  fieldStatistics = [];
  fieldStatisticsPages = [];
  if (pageReview) pageReview.close();
  await discardInterruptedReview();
  analystData = '';
  lastAnalysis = '';
  lastSanitizedLog = '';
  lastSanitizedAnalystData = '';
  lastSanitizedStatistics = '';
  document.getElementById('sanitized-statistics-textarea').value = '';
  document.getElementById('sanitized-statistics-section').style.display = 'none';
  lastMappingTable = null;
  if (analystDataTextarea) analystDataTextarea.value = '';
  if (sanitizedAnalystTextarea) sanitizedAnalystTextarea.value = '';
  await saveLogs();
  await caseStorage.set({ fieldStatistics, fieldStatisticsPages });
  renderPersistedStatistics();
  await saveAnalystData();
  await clearSavedAnalysisState();
  updateUI();
  setHTML(analysisOutput, '<p class="placeholder">Analysis will appear here</p>');
  feedbackSection.style.display = 'none';
  sanitizedSection.style.display = 'none';
  if (sanitizedAnalystSection) sanitizedAnalystSection.style.display = 'none';
  mappingSection.style.display = 'none';
  setHTML(mappingTable, '');
  displayThreatIntelFindings(null);
  copyAnalysisBtn.style.display = 'none';
  correctionTextarea.value = '';
  await window.VeiluxReportPanel.reset();
  await window.VeiluxChatPanel.reset();
  await window.VeiluxCaseNotes.reset();
  await window.VeiluxSentPanel.render();
  await window.VeiluxIndicators.reset();
  await markCaseSeen();
  updateStatus('Cleared', 'info');
  window.VeiluxUI.syncResults();
}

async function clearSavedAnalysisState() {
  try {
    await caseStorage.remove([
      'lastAnalysis',
      'lastSanitizedLog',
      'lastSanitizedAnalystData',
      'lastSanitizedStatistics',
      'lastMappingTable',
      'lastThreatIntelFindings',
      'lastThreatIntelStatus',
      'lastAnalysisMode',
      'lastShouldSanitize',
      'analysisInProgress',
      'analysisError',
      'analysisCompletedAt',
      'pendingAnswer',
      'sendRecord',
      'analysisBasis'
    ]);
  } catch (e) {
    console.warn('[VEILUX] Could not clear saved analysis state:', e.message);
  }
}

function applyAnalysisState(saved) {
  if (!saved || !saved.lastAnalysis) {
    return;
  }

  lastAnalysis = saved.lastAnalysis || '';
  lastSanitizedLog = saved.lastSanitizedLog || '';
  lastSanitizedAnalystData = saved.lastSanitizedAnalystData || '';
  lastSanitizedStatistics = saved.lastSanitizedStatistics || '';
  document.getElementById('sanitized-statistics-textarea').value = lastSanitizedStatistics;
  document.getElementById('sanitized-statistics-section').style.display = lastSanitizedStatistics ? 'block' : 'none';
  lastMappingTable = saved.lastMappingTable || null;

  displayAnalysis(lastAnalysis);
  displayThreatIntelFindings(saved.lastThreatIntelFindings || null, saved.lastThreatIntelStatus || null);
  const isSanitizeOnly = saved.lastAnalysisMode === 'sanitize_only';
  copyAnalysisBtn.style.display = isSanitizeOnly ? 'none' : 'block';
  feedbackSection.style.display = isSanitizeOnly ? 'none' : 'block';

  if (lastSanitizedLog) {
    sanitizedTextarea.value = lastSanitizedLog;
    sanitizedSection.style.display = 'block';
  } else {
    sanitizedTextarea.value = '';
    sanitizedSection.style.display = 'none';
  }

  if (sanitizedAnalystTextarea) {
    if (lastSanitizedAnalystData) {
      sanitizedAnalystTextarea.value = lastSanitizedAnalystData;
      if (sanitizedAnalystSection) sanitizedAnalystSection.style.display = 'block';
    } else {
      sanitizedAnalystTextarea.value = '';
      if (sanitizedAnalystSection) sanitizedAnalystSection.style.display = 'none';
    }
  }

  if (lastMappingTable && Object.keys(lastMappingTable).length) {
    displayMappingTable(lastMappingTable);
    mappingSection.style.display = 'block';
  } else {
    setHTML(mappingTable, '');
    mappingSection.style.display = 'none';
  }
  window.VeiluxUI.syncResults(isSanitizeOnly ? 'sanitized' : 'analysis');
}

async function saveAnalystData() {
  analystData = analystDataTextarea ? analystDataTextarea.value : '';
  try {
    await caseStorage.set({ analystData: analystData });
  } catch (e) {
    console.warn('[VEILUX] Could not persist analyst context:', e.message);
  }
}

function debounce(fn, wait) {
  let timeout = null;
  return function() {
    const args = arguments;
    clearTimeout(timeout);
    timeout = setTimeout(function() { fn.apply(null, args); }, wait);
  };
}

function toggleSection(content, header) {
  content.classList.toggle('collapsed');
  header.classList.toggle('collapsed');
  header.setAttribute('aria-expanded', String(!content.classList.contains('collapsed')));
}

function updateUI() {
  updateAnalyzeButtonState();
  logsTextarea.value = capturedLogs.length ? capturedLogs.join('\n\n' + LOG_SEPARATOR_TOKEN + '\n\n') : '';
  if (analystDataTextarea && analystDataTextarea.value !== analystData) analystDataTextarea.value = analystData;
  updateLogCount();
}

// The AI's answer is text: it is escaped first, so an answer can never add
// markup to the popup, then the few Markdown forms the prompts ask for are
// turned into HTML.
function displayAnalysis(md) {
  let html = escapeHtml(String(md || ''))
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/`(.+?)`/g, '<code>$1</code>')
    .replace(/^- (.+)$/gm, '<li>$1</li>')
    .replace(/\n\n/g, '</p><p>')
    .replace(/^### (.+)$/gm, '<h3>$1</h3>');
  html = html.replace(/(<li>[\s\S]*?<\/li>)/g, '<ul>$1</ul>');
  if (!html.startsWith('<')) html = '<p>' + html + '</p>';
  setHTML(analysisOutput, html);
}

function showAnalysisError(message) {
  setHTML(analysisOutput, '<div class="placeholder" style="color:var(--danger);">Error: ' + escapeHtml(message) + '</div>');
}

// Sanitize placeholders look like ⟦CATEGORY#N⟧ — strip the wrapping
// brackets for display, leaving just the category label.
const PLACEHOLDER_BRACKETS = /[⟦⟧]/g;

function displayMappingTable(mapping) {
  let html = '<table class="mapping-table"><tr><th>Placeholder</th><th>Original / handling</th></tr>';
  Object.keys(mapping).forEach(function(p) {
    html += '<tr><td><code>' + escapeHtml(p.replace(PLACEHOLDER_BRACKETS, '')) + '</code></td><td>' + escapeHtml(mapping[p]) + '</td></tr>';
  });
  setHTML(mappingTable, html + '</table>');
}

function formatMappingForCopy() {
  if (!lastMappingTable) return '';
  return Object.keys(lastMappingTable).map(function(p) {
    return p.replace(PLACEHOLDER_BRACKETS, '') + ' = ' + lastMappingTable[p];
  }).join('\n');
}

// Escapes text for HTML, including quotes, so it is safe in element content
// and in attribute values alike.
function escapeHtml(text) {
  return (text === null || text === undefined ? '' : String(text))
    .replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}

async function copyToClipboard(text, label) {
  if (!text) return updateStatus('Nothing to copy', 'error');
  try {
    await navigator.clipboard.writeText(text);
    updateStatus(label + ' copied', 'success');
  } catch (e) {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.cssText = 'position:fixed;left:-9999px;top:-9999px;opacity:0;';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      updateStatus(label + ' copied', 'success');
    } catch (e2) {
      updateStatus('Copy failed', 'error');
    }
  }
}

let statusVersion = 0;
// The status line keeps two lines. Anything longer (an error with its reason,
// the timing breakdown) opens in full with "More", on its own row above the
// buttons.
// `details` is extra text that only the expanded line and the tooltip carry.
const statusMore = document.getElementById('status-more');
let statusFull = '';
function showStatusLine(expanded) {
  statusText.classList.toggle('expanded', expanded);
  document.querySelector('.workflow-dock').classList.toggle('status-expanded', expanded);
  statusText.textContent = expanded ? statusFull : statusShort;
  statusMore.textContent = expanded ? 'Less' : 'More';
}
let statusShort = '';
function updateStatus(msg, type, details = '') {
  statusVersion++;
  statusShort = msg;
  statusFull = details ? msg + '\n' + details : msg;
  statusText.classList.remove('expanded');
  document.querySelector('.workflow-dock').classList.remove('status-expanded');
  statusText.textContent = msg;
  const colors = { success: 'var(--success)', error: 'var(--danger)', info: 'var(--muted)' };
  statusText.style.color = colors[type] || 'var(--text)';
  // Offer "More" when the text does not fit its two lines, or has details.
  statusMore.hidden = true;
  requestAnimationFrame(() => {
    statusMore.hidden = !(details || statusText.scrollHeight > statusText.clientHeight + 1);
    statusMore.textContent = 'More';
  });
}
statusMore.addEventListener('click', () => showStatusLine(!statusText.classList.contains('expanded')));

let _loadingTimer = null;
let _loadingStartedAt = 0;
let _loadingBaseText = '';

// Long-running operations (async SIEM search jobs can poll for a minute)
// show an elapsed-seconds counter, so a slow search reads as "working"
// rather than frozen.
// `hint`: true for the usual "continues if you close the popup" note, or other text to show instead.
const BACKGROUND_HINT = document.getElementById('loading-hint').textContent;
function showLoading(show, text, hint = false) {
  loadingOverlay.style.display = show ? 'flex' : 'none';
  // The overlay starts below the header, so other cases stay one click away
  // while this one works in the background.
  if (show) loadingOverlay.style.top = Math.round(document.querySelector('.header').getBoundingClientRect().bottom) + 'px';
  const hintLine = document.getElementById('loading-hint');
  hintLine.hidden = !(show && hint);
  hintLine.textContent = typeof hint === 'string' ? hint : BACKGROUND_HINT;
  window.VeiluxUI?.loading(show);
  if (_loadingTimer) { clearInterval(_loadingTimer); _loadingTimer = null; }
  if (show && text) {
    _loadingBaseText = text;
    _loadingStartedAt = Date.now();
    loadingText.textContent = text;
    _loadingTimer = setInterval(function() {
      const secs = Math.round((Date.now() - _loadingStartedAt) / 1000);
      if (secs >= 3) loadingText.textContent = _loadingBaseText + ' (' + secs + 's)';
    }, 1000);
  }
}

async function saveLogs() {
  window.VeiluxUI?.sourceSummary();
  // Every captured log is kept (the extension has unlimitedStorage), so an
  // extraction that finished in the background is still there after reopening.
  try {
    return await caseStorage.set({ capturedLogs: capturedLogs, capturedLogPages: capturedLogPages.slice(-capturedLogs.length) });
  } catch (e) {
    console.warn('[VEILUX] Could not persist logs to storage (quota?):', e.message);
  }
}

// Reports the backend state, unless something else (such as a background
// result found on opening) set the status while the check was running.
async function checkBackendHealth() {
  const before = statusVersion;
  const report = (msg, type) => { if (statusVersion === before) updateStatus(msg, type); };
  try {
    const res = await VeiluxBackend.fetch('/health');
    const data = await res.json();
    if (data.status === 'healthy') {
      const paired = await VeiluxBackend.fetch('/auth/check');
      if (paired.ok) report('Backend v' + (data.version || '?') + ' connected', 'success');
      else report('Backend v' + (data.version || '?') + ' is running, but VEILUX is not paired with it: Settings → Backend → Pair.', 'error');
    }
  } catch (e) {
    report('Backend offline', 'error');
  }
}
