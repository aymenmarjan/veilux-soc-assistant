/**
 * VEILUX - Background service worker
 *
 * The /analyze call runs here instead of in popup.js because the popup's
 * whole JS context (and any in-flight fetch it started) is destroyed the
 * moment the popup closes — click outside it, or close it manually, and a
 * fetch running there is aborted mid-request. A background service worker
 * survives that; it keeps running the fetch and writes the result to the
 * storage of the case that started it (see cases.js), which the popup reads
 * when it shows that case, or live through storage.onChanged.
 */

if (typeof browser === 'undefined' && typeof importScripts === 'function') {
  importScripts('browser-polyfill.js');
}
// Connection readers for extraction jobs. Chrome loads them here; Firefox lists
// them under "background.scripts" in manifest.json.
if (typeof VeiluxConnectorClient === 'undefined' && typeof importScripts === 'function') {
  importScripts('backend_address.js', 'cases.js', 'connector_config.js', 'connector_parameters.js', 'connector_sources.js',
    'connector_client.js', 'connector_browser.js', 'extraction_jobs.js');
}


// Right-click menu: "Extract from this page". Exists because some SIEM
// screens open in toolbar-less popup windows (window.open with features),
// where the browser hides all
// extension icons so the action popup can't be reached. The context menu is
// available in ANY window; it opens the VEILUX popup as its own small
// window, pinned to the exact tab that was right-clicked (?tabId=...).
browser.runtime.onInstalled.addListener(function() {
  try {
    browser.contextMenus.create({
      id: 'veilux-extract-page',
      title: 'VEILUX: Extract logs from this page',
      contexts: ['page']
    });
  } catch (e) {
    // menu may already exist after an extension reload — non-fatal
  }
});

browser.contextMenus.onClicked.addListener(function(info, tab) {
  if (info.menuItemId !== 'veilux-extract-page' || !tab || !tab.id) return;
  browser.windows.create({
    url: browser.runtime.getURL('popup.html') + '?tabId=' + tab.id,
    type: 'popup',
    width: 780,
    height: 800
  });
});

browser.runtime.onMessage.addListener(function(message) {
  if (!message) return false;
  const caseId = typeof message.caseId === 'string' ? message.caseId : VeiluxCases.FIRST_CASE;
  // Replies tell the popup the job was taken; results arrive through storage.
  if (message.type === 'START_ANALYSIS') return Promise.resolve(queueAnalysis(caseId, message.payload, message.reviewMilliseconds || 0,
    ['report', 'chat'].includes(message.purpose) ? message.purpose : 'analysis', message.basis || null));
  if (message.type === 'CANCEL_ANALYSIS') return cancelAnalysis(caseId);
  if (message.type === 'START_EXTRACTION') return Promise.resolve(VeiluxExtractionJobs.start(message.job, 'background'));
  if (message.type === 'CANCEL_EXTRACTION') VeiluxExtractionJobs.cancel(caseId);
  return false;
});

// =============================================================================
// Analyses, one per case
//
// Each case can run one analysis. Analyses of different cases run side by side
// up to the limit set in Settings ("Analyses running at once"); the rest wait
// in a queue and start in order. Every analysis writes only to the case that
// started it, whichever case the popup shows when it finishes.
// =============================================================================

// Chrome stops an idle service worker after about 30 seconds, and a pending
// fetch does not count as activity. Calling an extension API every 20 seconds
// keeps the worker alive, and the heartbeat it writes lets the popup tell a
// slow analysis from one whose worker was stopped.
const HEARTBEAT_INTERVAL_MS = 20000;
const running = new Map();   // caseId -> { id, controller, cancelled }
const waiting = [];          // [{ caseId, payload, reviewMilliseconds, purpose, basis }]
let keepAlive = null;

function updateKeepAlive() {
  const busy = running.size || waiting.length;
  if (busy && !keepAlive) {
    keepAlive = setInterval(() => {
      try { browser.runtime.getPlatformInfo().catch(() => {}); } catch (_) {}
      const ids = [...running.keys(), ...waiting.map(job => job.caseId)];
      ids.forEach(id => VeiluxCases.storage(id).set({ analysisHeartbeat: Date.now() }).catch(() => {}));
    }, HEARTBEAT_INTERVAL_MS);
  } else if (!busy && keepAlive) {
    clearInterval(keepAlive);
    keepAlive = null;
  }
}

// purpose "report" writes an email report (report_panel.js) and "chat" answers a
// follow-up question (chat_panel.js); both leave the case's analysis untouched.
// basis: a fingerprint of the inputs an analysis was started with (case_notes.js),
// saved with its result so the popup can tell when the case has changed since.
async function queueAnalysis(caseId, payload, reviewMilliseconds, purpose = 'analysis', basis = null) {
  if (running.has(caseId) || waiting.some(job => job.caseId === caseId)) return { accepted: false, reason: 'busy' };
  const { running: limit } = await VeiluxCases.limits();
  const store = VeiluxCases.storage(caseId);
  if (running.size >= limit) {
    waiting.push({ caseId, payload, reviewMilliseconds, purpose, basis });
    await store.set({ analysisInProgress: true, analysisQueued: true, analysisPurpose: purpose, analysisPhase: 'Queued: another case is being analyzed',
      analysisStartedAt: Date.now(), analysisHeartbeat: Date.now(), analysisError: null });
    updateKeepAlive();
    await VeiluxCases.updateBadge();
    return { accepted: true, queued: true };
  }
  runAnalysis(caseId, payload, reviewMilliseconds, purpose, basis);
  return { accepted: true, queued: false };
}

async function startNextQueued() {
  const { running: limit } = await VeiluxCases.limits();
  while (waiting.length && running.size < limit) {
    const next = waiting.shift();
    runAnalysis(next.caseId, next.payload, next.reviewMilliseconds, next.purpose, next.basis);
  }
  updateKeepAlive();
}

async function cancelAnalysis(caseId) {
  const queued = waiting.findIndex(job => job.caseId === caseId);
  if (queued >= 0) {
    waiting.splice(queued, 1);
    await VeiluxCases.storage(caseId).set({ analysisError: 'Analysis cancelled before it started; nothing was sent.',
      analysisQueued: false, analysisInProgress: false });
    updateKeepAlive();
    await VeiluxCases.updateBadge();
    return;
  }
  const active = running.get(caseId);
  if (!active) return;
  active.cancelled = true;
  // Wait for the backend to acknowledge cancellation before aborting the fetch.
  try {
    await VeiluxBackend.fetch('/analysis/' + encodeURIComponent(active.id) + '/cancel', {
      method: 'POST', signal: AbortSignal.timeout(3000)
    });
  } finally { active.controller.abort(); }
}

// Adds the backend's account of what it sent (see _record_ai_request in
// server.py) to the case's record. Never fails the analysis itself.
function recordSend(caseId, payload, purpose, outbound, outcome, error) {
  const sent = outbound || { ai: null, lookups: [] };
  return VeiluxCases.recordSend(caseId, { purpose, outcome, error: error || null,
    localOnly: payload.mode === 'sanitize_only', ai: sent.ai || null, lookups: Array.isArray(sent.lookups) ? sent.lookups : [] })
    .catch(() => {});
}

async function runAnalysis(caseId, payload, reviewMilliseconds = 0, purpose = 'analysis', basis = null) {
  const store = VeiluxCases.storage(caseId);
  const controller = new AbortController();
  payload.request_id = payload.request_id || crypto.randomUUID();
  const active = { controller, id: payload.request_id, cancelled: false };
  running.set(caseId, active);
  updateKeepAlive();
  // Protection runs several stages over the whole batch, each allowed more time
  // for larger requests (see local_work_timeout in server.py), so the overall
  // limit grows with the request size too, up to 30 minutes.
  const megabytes = JSON.stringify(payload).length / 1e6;
  const limit = Math.min(30 * 60000, (payload.mode === 'sanitize_only' ? 30000 : 240000) + 60000 * megabytes);
  const timeout = setTimeout(() => { cancelAnalysis(caseId).catch(() => {}); }, limit);
  let polling = false;
  const progress = setInterval(async () => {
    if (polling || active.cancelled) return;
    polling = true;
    try {
      const response = await VeiluxBackend.fetch('/analysis/' + encodeURIComponent(active.id) + '/status', { signal: AbortSignal.timeout(2500) });
      if (response.ok) {
        const state = await response.json();
        if (running.get(caseId) === active && !active.cancelled && !['Complete', 'Cancelled', 'Failed'].includes(state.phase))
          await store.set({ analysisPhase: state.phase });
      }
    } catch (e) { /* progress is advisory; the request itself still fails closed */ }
    finally { polling = false; }
  }, 750);
  await store.set({
    analysisInProgress: true,
    analysisQueued: false,
    analysisPurpose: purpose,
    analysisPhase: 'Sanitizing logs',
    analysisStartedAt: Date.now(),
    analysisHeartbeat: Date.now(),
    analysisError: null
  });
  await VeiluxCases.updateBadge();

  try {
    if (active.cancelled) throw new Error('Analysis cancelled');
    const response = await VeiluxBackend.fetch('/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal
    });

    if (!response.ok) {
      const err = await response.json().catch(function() { return {}; });
      // A failure after something was sent still belongs in the record.
      if (err.outbound) await recordSend(caseId, payload, purpose, err.outbound, 'failed', err.detail);
      throw new Error(err.detail || 'Analysis failed');
    }

    const result = await response.json();
    await recordSend(caseId, payload, purpose, result.outbound, 'completed');
    if (active.cancelled) throw new Error('Analysis cancelled');

    if (purpose !== 'analysis') {
      // The AI's answer (real values restored by the backend) and the restore
      // map, kept until the popup shows this case and files the answer under
      // its report or conversation, even if the popup was closed meanwhile.
      await store.set({ pendingAnswer: { purpose, raw: result.analysis || '', mapping: result.mapping_table || null, completedAt: Date.now() },
        analysisError: null, analysisCompletedAt: Date.now() });
      return;
    }

    // The backend appends statistics to sanitize-only logs for older clients.
    // The popup shows statistics separately, so keep them out of the editable
    // event text, where a second run would treat them as events.
    const statistics = result.sanitized_field_statistics || '';
    let sanitizedLog = result.sanitized_log || '';
    if (payload.mode === 'sanitize_only' && statistics && sanitizedLog.endsWith(statistics)) {
      sanitizedLog = sanitizedLog.slice(0, -statistics.length);
      const separator = payload.output_mode === 'raw_request' ? '\n\n' : '\n\n---LOG SEPARATOR---\n\n';
      if (sanitizedLog.endsWith(separator)) sanitizedLog = sanitizedLog.slice(0, -separator.length);
    }

    await store.set({
      analysisTimings: Object.assign({ review: reviewMilliseconds }, result.timings_ms || {}),
      lastAnalysis: result.analysis || '',
      lastSanitizedLog: sanitizedLog,
      lastSanitizedStatistics: statistics,
      lastSanitizedAnalystData: result.sanitized_analyst_data || '',
      lastMappingTable: result.mapping_table || null,
      lastThreatIntelFindings: result.threat_intel_findings || null,
      lastThreatIntelStatus: result.threat_intel_status || null,
      lastAnalysisMode: payload.mode || null,
      lastShouldSanitize: !!payload.sanitize,
      analysisBasis: basis,
      analysisError: null,
      analysisCompletedAt: Date.now()
    });
  } catch (e) {
    await store.set({ analysisError: active.cancelled ? 'Analysis cancelled or timed out; no further requests will be sent.' : (e.message || 'Analysis failed') });
  } finally {
    clearInterval(progress);
    clearTimeout(timeout);
    running.delete(caseId);
    // Cleared last, so a popup waiting for this change reads the results above.
    await store.set({ analysisInProgress: false, caseUnseen: true });
    await VeiluxCases.updateBadge();
    startNextQueued();
  }
}
