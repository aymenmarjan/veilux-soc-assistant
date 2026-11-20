/* Extraction and statistics jobs, shared by the background worker and the popup.

   The popup finds the connection and reads values from the page (quick, and it
   needs a Worker the background cannot create). The slow part, reading the
   records, normally runs in the background worker so it continues when the
   popup closes. If the worker does not take the job (for example, it still runs
   an older version of the extension until the extension is reloaded), the popup
   runs the same job itself.

   Each case runs at most one job at a time; jobs of different cases run side
   by side. A job writes only to the case that started it (job.caseId), in
   that case's storage, whichever side runs it:
   - extractionJob {id, kind, label, runner, startedAt, heartbeat} while it runs;
   - then extractionResult or extractionError, carrying the same id;
   - extractionJob is cleared last. */
globalThis.VeiluxExtractionJobs = (() => {
  const HEARTBEAT_MS = 20000;
  const active = new Map(); // caseId -> { id, controller }

  async function discoverBridge(tabId, payload) {
    let result;
    try { result = await browser.tabs.sendMessage(tabId, payload); }
    catch (e) { result = { success: false, error: e && e.message ? e.message : String(e) }; }
    if (!result || /Receiving end does not exist|Could not establish connection/i.test(result.error || '')) {
      await browser.scripting.executeScript({ target: { tabId }, files: ['browser-polyfill.js', 'content.js'] });
      result = await browser.tabs.sendMessage(tabId, payload);
    }
    return result;
  }

  async function records(job, signal) {
    const options = Object.assign({}, job.options || {}, { tab: job.tab, signal });
    if (job.call === 'fetchAPI') return VeiluxConnectorClient.fetchAPI(job.profile, options);
    return VeiluxConnectorClient.read(job.profile, job.tab, Object.assign(options, { prepared: job.prepared || null, resolved: true }));
  }

  async function statistics(job, signal) {
    if (job.mode === 'opensearch') {
      const api = VeiluxConnectors.api(job.profile);
      const result = await discoverBridge(job.tab.id, { action: 'veiluxExtractDiscoverFieldStats',
        config: (job.profile.dom && job.profile.dom.discover) || {},
        api: { path: api.pathTemplate, headers: api.headers, sampleSize: job.sampleSize, topValues: job.topValues } });
      if (!result || result.success === false) throw new Error((result && result.error) || 'Statistics extraction failed.');
      return { statistic: { indexPattern: result.indexPattern, sampled: result.sampled, total: result.total,
        fields: result.fields || [], summary: result.summary || {}, request: result.request || {} }, linkedUrls: [] };
    }
    const data = await VeiluxConnectorClient.read(job.profile, job.tab, { statistics: true, prepared: job.prepared || null,
      resolved: true, limit: job.sampleSize, signal });
    const logs = data.logs || [];
    const rows = logs.slice(0, job.sampleSize).map(log => typeof log === 'string' ? JSON.parse(log) : log);
    // Records that could not be read (a deleted event answers 404, for
    // example) are left out and counted, instead of stopping the statistics.
    const failed = Number(data.failed) || 0;
    const reason = (Array.isArray(data.errors) ? data.errors.filter(Boolean)[0] : '') || '';
    if (!rows.length) throw new Error(failed
      ? 'None of the ' + failed + ' record' + (failed === 1 ? '' : 's') + ' could be read' + (reason ? ' (' + reason + ')' : '') + '. Check the connection and your SIEM session.'
      : 'No records available to summarize.');
    const skipped = failed ? failed + ' record' + (failed === 1 ? '' : 's') + ' could not be read and ' + (failed === 1 ? 'is' : 'are') + ' not counted'
      + (reason ? ' (' + reason + ')' : '') : '';
    return { statistic: { indexPattern: job.profile.name, sampled: rows.length, total: data.total ?? null,
      fields: VeiluxConnectors.statistics(rows, job.topValues), summary: { query: data.query || '', filters: [], timeFrame: [] },
      sourceDescription: (data.info || 'source records') + (skipped ? '; ' + skipped : ''), failed,
      limited: !!data.limited || logs.length > job.sampleSize },
      linkedUrls: data.linkedUrls || [] };
  }

  async function run(job, runner) {
    const caseId = job.caseId || VeiluxCases.FIRST_CASE;
    const store = VeiluxCases.storage(caseId);
    const controller = new AbortController();
    const mine = { id: job.id, controller };
    active.set(caseId, mine);
    const state = { id: job.id, kind: job.kind, label: job.label || '', runner, startedAt: Date.now(), heartbeat: Date.now() };
    // The heartbeat also counts as activity, which keeps Chrome's service worker alive during a slow request.
    const keepAlive = setInterval(() => {
      try { browser.runtime.getPlatformInfo().catch(() => {}); } catch (_) {}
      state.heartbeat = Date.now();
      store.set({ extractionJob: state }).catch(() => {});
    }, HEARTBEAT_MS);
    try {
      await store.set({ extractionJob: state, extractionError: null });
      await VeiluxCases.updateBadge();
      const outcome = job.kind === 'statistics' ? await statistics(job, controller.signal) : { data: await records(job, controller.signal) };
      if (controller.signal.aborted) throw new Error('cancelled');
      await store.set({ extractionResult: Object.assign({ id: job.id, kind: job.kind, label: job.label || '',
        mode: job.mode || '', profileId: job.profile.id, profileName: job.profile.name, tab: job.tab, finishedAt: Date.now() }, outcome) });
    } catch (e) {
      await store.set({ extractionError: { id: job.id, kind: job.kind,
        message: controller.signal.aborted ? 'Extraction cancelled. No further requests will be sent.' : (e && e.message) || 'Extraction failed.' } });
    } finally {
      clearInterval(keepAlive);
      if (active.get(caseId) === mine) active.delete(caseId);
      // Cleared last, so a popup watching it reads the result written above.
      await store.set({ extractionJob: null, caseUnseen: true });
      await VeiluxCases.updateBadge();
    }
  }

  // Starts a job unless its case already runs one here. The reply is what the
  // background worker sends back to the popup.
  function start(job, runner) {
    if (!job || !job.id || !job.profile) return { accepted: false, reason: 'invalid' };
    if (active.has(job.caseId || VeiluxCases.FIRST_CASE)) return { accepted: false, reason: 'busy' };
    run(job, runner);
    return { accepted: true, id: job.id };
  }

  function cancel(caseId = VeiluxCases.FIRST_CASE) { active.get(caseId)?.controller.abort(); }

  return { start, cancel, running: caseId => active.has(caseId ?? VeiluxCases.FIRST_CASE) };
})();
