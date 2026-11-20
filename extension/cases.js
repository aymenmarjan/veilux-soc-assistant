/* Cases: each numbered slot in the popup is an independent investigation with
   its own logs, statistics, context, choices, review decisions and results.

   Storage layout
   - Case data lives under keys of its own: "case.<id>.<name>". Saving one case
     never touches another, and a background job writes only to the case that
     started it.
   - The first case keeps the plain key names used before cases existed
     ("capturedLogs", "lastAnalysis", ...), so existing data needs no migration.
   - "casesIndex" lists the slots, the archive and the case being viewed.

   Settings (API keys, connections, keyword lists, prompts) stay shared by all
   cases; each case only chooses which of them it uses. */
globalThis.VeiluxCases = (() => {
  const INDEX_KEY = 'casesIndex';
  const FIRST_CASE = '';
  const SLOTS_DEFAULT = 2, SLOTS_MAX = 5;
  const RUNNING_DEFAULT = 3, RUNNING_MAX = 5;

  // Everything below belongs to one case.
  const CASE_KEYS = new Set([
    'capturedLogs', 'capturedLogPages', 'fieldStatistics', 'fieldStatisticsPages', 'analystData',
    'lastAnalysis', 'lastSanitizedLog', 'lastSanitizedAnalystData', 'lastSanitizedStatistics', 'lastMappingTable',
    'lastThreatIntelFindings', 'lastThreatIntelStatus', 'lastAnalysisMode', 'lastShouldSanitize',
    'analysisInProgress', 'analysisQueued', 'analysisStartedAt', 'analysisHeartbeat', 'analysisError',
    'analysisPhase', 'analysisTimings', 'analysisCompletedAt',
    'extractionJob', 'extractionResult', 'extractionError',
    'analysisPurpose', 'pendingAnswer', 'reportState', 'chatState', 'sendRecord', 'caseNotes', 'analysisBasis', 'caseIndicators',
    'popupPreferences', 'popupResultView', 'popupStage', 'openrouterModel', 'openrouterModelInfo',
    'caseUnseen', 'caseMeta'
  ]);
  const SESSION_KEYS = new Set(['analysisSecretRules', 'reviewDraft']);
  // A case without its own value uses the default chosen in Settings.
  const SHARED_DEFAULTS = new Set(['openrouterModel', 'openrouterModelInfo']);
  // A new case starts empty but keeps the choices of the case it was made from.
  const CARRIED_OVER = ['popupPreferences', 'openrouterModel', 'openrouterModelInfo'];
  const CONTENT_KEYS = ['capturedLogs', 'fieldStatistics', 'analystData', 'lastAnalysis', 'lastSanitizedLog', 'reportState', 'chatState', 'caseNotes'];

  const prefix = caseId => caseId ? 'case.' + caseId + '.' : '';
  const keyFor = (caseId, name, keys) => keys.has(name) ? prefix(caseId) + name : name;
  const asList = keys => typeof keys === 'string' ? [keys] : Array.isArray(keys) ? keys : Object.keys(keys || {});
  const otherCaseKey = (key, caseId) => key.startsWith('case.') && !key.startsWith(prefix(caseId) || '\u0000');

  // The case a storage key belongs to, or null for a shared key.
  function caseOfKey(key) {
    const match = /^case\.([^.]+)\.(.+)$/.exec(key);
    if (match) return CASE_KEYS.has(match[2]) || SESSION_KEYS.has(match[2]) ? { caseId: match[1], name: match[2] } : null;
    return CASE_KEYS.has(key) || SESSION_KEYS.has(key) ? { caseId: FIRST_CASE, name: key } : null;
  }

  // Same interface as browser.storage.local (get/set/remove/onChanged), with
  // case keys mapped to the given case. `ready` is a case id, or a promise of
  // one or of {caseId, archived} (archived cases are read-only).
  function storage(ready, { area = 'local', readOnly = false } = {}) {
    const keys = area === 'session' ? SESSION_KEYS : CASE_KEYS;
    const backing = () => browser.storage[area];
    let resolved = typeof ready === 'string' ? ready : null;
    const settle = info => {
      if (info && typeof info === 'object') { readOnly = readOnly || !!info.archived; info = info.caseId; }
      return (resolved = info);
    };
    const pending = resolved === null ? Promise.resolve(ready).then(settle) : null;
    const caseId = async () => resolved !== null ? resolved : pending;
    const listeners = new Map();
    return {
      available: () => !!backing(),
      caseId,
      async get(names) {
        const id = await caseId();
        const list = asList(names);
        const mapped = list.map(name => keyFor(id, name, keys));
        const defaults = list.filter(name => SHARED_DEFAULTS.has(name) && id);
        const raw = await backing().get(mapped.concat(defaults));
        const out = {};
        list.forEach((name, i) => {
          out[name] = raw[mapped[i]];
          if (out[name] === undefined && defaults.includes(name)) out[name] = raw[name];
          if (out[name] === undefined && !Array.isArray(names) && typeof names === 'object' && names) out[name] = names[name];
        });
        return out;
      },
      async set(values) {
        const id = await caseId();
        const out = {};
        for (const [name, value] of Object.entries(values)) {
          if (readOnly && keys.has(name)) continue; // archived cases are read-only
          out[keyFor(id, name, keys)] = value;
        }
        if (Object.keys(out).length) await backing().set(out);
      },
      async remove(names) {
        const id = await caseId();
        const list = asList(names).filter(name => !(readOnly && keys.has(name)));
        if (list.length) await backing().remove(list.map(name => keyFor(id, name, keys)));
      },
      onChanged: {
        // Reports changes to this case's keys under their plain names, and
        // changes to shared keys as they are. Other cases' changes are dropped.
        addListener(fn) {
          const wrapped = (changes, changedArea) => {
            if (changedArea !== area || resolved === null) return;
            const out = {};
            for (const [key, change] of Object.entries(changes)) {
              const owner = caseOfKey(key);
              if (owner) { if (owner.caseId === resolved && keys.has(owner.name)) out[owner.name] = change; }
              else if (!otherCaseKey(key, resolved)) out[key] = change;
            }
            if (Object.keys(out).length) fn(out, changedArea);
          };
          listeners.set(fn, wrapped);
          browser.storage.onChanged.addListener(wrapped);
        },
        removeListener(fn) {
          const wrapped = listeners.get(fn);
          if (wrapped) { browser.storage.onChanged.removeListener(wrapped); listeners.delete(fn); }
        }
      }
    };
  }

  // ---- Settings shared by all cases ----
  async function limits() {
    const stored = await browser.storage.local.get(['caseSlots', 'maxRunningAnalyses']);
    const clamp = (value, fallback, max) => Number.isInteger(value) && value >= 1 ? Math.min(value, max) : fallback;
    return { slots: Math.max(2, clamp(stored.caseSlots, SLOTS_DEFAULT, SLOTS_MAX)),
             running: clamp(stored.maxRunningAnalyses, RUNNING_DEFAULT, RUNNING_MAX) };
  }

  // ---- Index of slots and archive ----
  async function readIndex() {
    const stored = (await browser.storage.local.get(INDEX_KEY))[INDEX_KEY];
    return stored && Array.isArray(stored.slots) ? { archive: [], active: { slot: 0 }, ...stored } : null;
  }
  async function writeIndex(index) { await browser.storage.local.set({ [INDEX_KEY]: index }); }

  async function createCase(copyFrom) {
    const id = crypto.randomUUID().replace(/-/g, '').slice(0, 16);
    const carried = copyFrom === undefined ? {} : await storage(copyFrom).get(CARRIED_OVER);
    const values = { caseMeta: { createdAt: Date.now() } };
    CARRIED_OVER.forEach(name => {
      // A model chosen in Settings stays a default; only a case's own choice is copied.
      if (carried[name] !== undefined && !(SHARED_DEFAULTS.has(name) && copyFrom === FIRST_CASE)) values[name] = carried[name];
    });
    await storage(id).set(values);
    return id;
  }

  async function isEmpty(caseId) {
    const stored = await storage(caseId).get(CONTENT_KEYS.concat(['analysisInProgress', 'extractionJob']));
    return !stored.analysisInProgress && !stored.extractionJob && CONTENT_KEYS.every(name => {
      const value = stored[name];
      return value === undefined || value === null || value === '' || (Array.isArray(value) && !value.some(v => v && String(v).trim()));
    });
  }

  async function removeCase(caseId) {
    await browser.storage.local.remove([...CASE_KEYS].map(name => keyFor(caseId, name, CASE_KEYS)));
    if (browser.storage.session) await browser.storage.session.remove([...SESSION_KEYS].map(name => keyFor(caseId, name, SESSION_KEYS)));
  }

  async function busy(caseId) {
    const stored = await storage(caseId).get(['analysisInProgress', 'extractionJob']);
    return !!(stored.analysisInProgress || stored.extractionJob);
  }

  // Opens the index, creating it on first use and matching the slot count set
  // in Settings. Extra slots that hold work are archived, never deleted.
  async function load() {
    let index = await readIndex();
    if (!index) {
      index = { slots: [FIRST_CASE], archive: [], active: { slot: 0 } };
      await storage(FIRST_CASE).set({ caseMeta: { createdAt: Date.now() } });
    }
    const { slots } = await limits();
    const source = index.slots[index.active.slot ?? 0] ?? FIRST_CASE;
    let changed = false;
    while (index.slots.length < slots) { index.slots.push(await createCase(source)); changed = true; }
    while (index.slots.length > slots) {
      const caseId = index.slots.pop();
      if (await isEmpty(caseId)) await removeCase(caseId);
      else { index.archive.push(caseId); await stamp(caseId); }
      changed = true;
    }
    if (index.active.slot !== undefined && index.active.slot >= index.slots.length) { index.active = { slot: 0 }; changed = true; }
    if (index.active.archive !== undefined && !index.archive.includes(index.active.archive)) { index.active = { slot: 0 }; changed = true; }
    if (changed || !(await readIndex())) await writeIndex(index);
    return index;
  }

  // Records when a case was archived and a one-line summary for the archive list.
  async function stamp(caseId) {
    const stored = await storage(caseId).get(['caseMeta', 'capturedLogs', 'fieldStatistics', 'capturedLogPages', 'lastAnalysis']);
    const count = (n, word) => n + ' ' + word + (n === 1 ? '' : 's');
    const titles = (stored.capturedLogPages || []).map(page => page && page.title).filter(Boolean);
    const parts = [count((stored.capturedLogs || []).filter(Boolean).length, 'log')];
    if ((stored.fieldStatistics || []).length) parts.push(count(stored.fieldStatistics.length, 'statistics query').replace('querys', 'queries'));
    if (stored.lastAnalysis) parts.push('analyzed');
    if (titles.length) parts.push(titles[0].slice(0, 60));
    await storage(caseId).set({ caseMeta: { ...(stored.caseMeta || {}), archivedAt: Date.now(), summary: parts.join(', ') } });
  }

  // What the popup shows: the active slot's case, or an archived case.
  function describe(index) {
    if (index.active.archive !== undefined) {
      const position = index.archive.indexOf(index.active.archive);
      return { caseId: index.active.archive, archived: true, slot: null, label: 'A' + (position + 1), index };
    }
    const slot = index.active.slot ?? 0;
    return { caseId: index.slots[slot], archived: false, slot, label: 'Case ' + (slot + 1), index };
  }

  async function open() { return describe(await load()); }

  async function select(target) {
    const index = await load();
    index.active = target.archive !== undefined ? { archive: target.archive } : { slot: target.slot };
    await writeIndex(index);
    return describe(index);
  }

  // Moves a slot's case to the archive; the slot starts a fresh case that keeps
  // the archived case's choices, just like "Clear all inputs & results".
  async function archive(slot) {
    const index = await load();
    const caseId = index.slots[slot];
    if (await busy(caseId)) throw new Error('This case is still extracting or analyzing. Wait for it to finish, or cancel it, before archiving.');
    if (await isEmpty(caseId)) throw new Error('This case is empty, so there is nothing to archive.');
    await stamp(caseId);
    index.archive.push(caseId);
    index.slots[slot] = await createCase(caseId);
    index.active = { slot };
    await writeIndex(index);
    return describe(index);
  }

  // Puts an archived case back into the first empty slot.
  async function restore(caseId) {
    const index = await load();
    let free = -1;
    for (let slot = 0; slot < index.slots.length && free < 0; slot++) if (await isEmpty(index.slots[slot])) free = slot;
    if (free < 0) throw new Error('Every case slot holds work. Archive one, or clear its inputs and results, then restore again.');
    await removeCase(index.slots[free]);
    index.slots[free] = caseId;
    index.archive = index.archive.filter(id => id !== caseId);
    const { caseMeta } = await storage(caseId).get('caseMeta');
    await storage(caseId).set({ caseMeta: { ...(caseMeta || {}), archivedAt: null } });
    index.active = { slot: free };
    await writeIndex(index);
    return describe(index);
  }

  async function deleteArchived(caseIds) {
    const index = await load();
    const doomed = caseIds === 'all' ? index.archive.slice() : caseIds.filter(id => index.archive.includes(id));
    for (const caseId of doomed) await removeCase(caseId);
    index.archive = index.archive.filter(id => !doomed.includes(id));
    if (index.active.archive !== undefined && doomed.includes(index.active.archive)) index.active = { slot: 0 };
    await writeIndex(index);
    return describe(index);
  }

  // Running, queued, finished-but-unseen or failed, for the status dots and the badge.
  async function statuses(index) {
    const ids = index.slots.concat(index.archive);
    const out = {};
    for (const caseId of ids) {
      const s = await storage(caseId).get(['analysisInProgress', 'analysisQueued', 'extractionJob', 'caseUnseen', 'analysisError', 'extractionError']);
      out[caseId] = s.analysisQueued ? 'queued' : (s.analysisInProgress || s.extractionJob) ? 'running'
        : s.caseUnseen ? ((s.analysisError || s.extractionError) ? 'error' : 'done') : 'idle';
    }
    return out;
  }

  // Toolbar badge: how many cases have results you have not opened yet, or "…"
  // while work is running.
  async function updateBadge() {
    try {
      const index = await readIndex();
      const states = Object.values(index ? await statuses(index) : {});
      const unseen = states.filter(s => s === 'done' || s === 'error').length;
      const running = states.some(s => s === 'running' || s === 'queued');
      const text = unseen ? String(unseen) : running ? '…' : '';
      await browser.action.setBadgeText({ text });
      await browser.action.setBadgeBackgroundColor({ color: states.includes('error') ? '#b91c1c' : unseen ? '#176445' : '#854d0e' });
    } catch (_) { /* no badge on this browser build */ }
  }

  // Record of what left this computer for the case: one entry per request
  // that reached outside services (or ran locally only), newest last.
  const SEND_RECORD_LIMIT = 50;
  async function recordSend(caseId, entry) {
    const store = storage(caseId);
    const { sendRecord } = await store.get('sendRecord');
    const list = (Array.isArray(sendRecord) ? sendRecord : []).concat([{ id: crypto.randomUUID(), at: new Date().toISOString(), ...entry }]);
    await store.set({ sendRecord: list.slice(-SEND_RECORD_LIMIT) });
  }

  async function markUnseen(caseId) { await storage(caseId).set({ caseUnseen: true }); await updateBadge(); }
  async function markSeen(caseId) { await storage(caseId).set({ caseUnseen: false }); await updateBadge(); }

  return { FIRST_CASE, SLOTS_MAX, RUNNING_MAX, CASE_KEYS, storage, limits, open, select, archive, restore,
    deleteArchived, statuses, updateBadge, markSeen, markUnseen, isEmpty, readIndex, recordSend };
})();
