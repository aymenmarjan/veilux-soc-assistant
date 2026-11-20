/* Popup case switcher. ‹ › moves between the numbered case slots, the dots show
   what each case is doing, and the ⋯ menu names the case, holds its private
   notes, archives it or opens an archived one. A name is optional and shows
   next to the case number; private notes are the analyst's own and are never
   sent anywhere (unlike Case notes, which every AI request receives). Switching saves the open case and reloads the popup on the
   chosen case, so nothing held in memory can carry over from one case to another. */
window.VeiluxCaseUI = (() => {
  const byId = id => document.getElementById(id);
  const STATE_TEXT = { idle: 'no new results', running: 'working', queued: 'queued', done: 'new results', error: 'finished with an error' };
  let info = null; // { caseId, archived, slot, label, index }
  let meta = {};    // the open case's caseMeta: createdAt, name, privateNotes, archive details
  const MAX_NAME = 40;

  const named = (label, details) => details && details.name ? label + ' · ' + details.name : label;
  function showLabel() {
    const label = byId('case-label');
    label.textContent = info.archived ? 'Archived ' + named(info.label, meta) : meta.name ? named(info.label, meta) : info.label + ' of ' + info.index.slots.length;
    label.title = meta.name ? info.label + ' of ' + info.index.slots.length + ': ' + meta.name : '';
  }
  let saveTimer = null;
  function saveDetails(changes) {
    meta = { ...meta, ...changes };
    showLabel();
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => VeiluxCases.storage(info.caseId).set({ caseMeta: meta }).then(renderDots).catch(() => {}), 300);
  }

  // Name and private notes, at the top of the ⋯ menu.
  function detailsSection() {
    const section = document.createElement('div');
    section.className = 'case-details';
    const nameLabel = Object.assign(document.createElement('label'), { htmlFor: 'case-name', textContent: 'Case name · optional' });
    const name = Object.assign(document.createElement('input'), { type: 'text', id: 'case-name', maxLength: MAX_NAME,
      value: meta.name || '', placeholder: 'e.g. Phishing, finance team', readOnly: !!info.archived });
    name.addEventListener('input', () => saveDetails({ name: name.value.trim() }));
    const notesLabel = Object.assign(document.createElement('label'), { htmlFor: 'case-private-notes', textContent: 'Private notes' });
    const notes = Object.assign(document.createElement('textarea'), { id: 'case-private-notes', rows: 4, value: meta.privateNotes || '',
      placeholder: 'Ticket links, to-dos, who you contacted…', readOnly: !!info.archived });
    notes.addEventListener('input', () => saveDetails({ privateNotes: notes.value }));
    const hint = Object.assign(document.createElement('p'), { className: 'field-hint',
      textContent: 'Kept on this computer and never sent. Facts the AI should use go in Case notes.' });
    section.append(nameLabel, name, notesLabel, notes, hint);
    return section;
  }

  // "Clear all inputs & results" starts the slot over, name and notes included.
  async function clearDetails() {
    clearTimeout(saveTimer);
    meta = { createdAt: meta.createdAt || Date.now() };
    await VeiluxCases.storage(info.caseId).set({ caseMeta: meta });
    showLabel();
    renderDots();
  }

  // Work that lives in this popup page and would be lost by reloading it.
  function localWorkInProgress() {
    return !!(reviewReject || preflightController || byId('connector-choice') || VeiluxExtractionJobs.running(info.caseId));
  }

  async function saveOpenCase() {
    await editedPagePending;
    await Promise.all([saveAnalystData(), savePopupPreferences(), saveSecretSession()]);
  }

  async function go(target) {
    if (localWorkInProgress()) {
      updateStatus('Finish or cancel the credential review or connection choice in this case before switching.', 'error');
      return;
    }
    if (!info.archived) await saveOpenCase();
    await VeiluxCases.select(target);
    location.reload();
  }

  function step(direction) {
    const count = info.index.slots.length;
    const from = info.archived ? 0 : info.slot;
    go({ slot: ((from + direction) % count + count) % count });
  }

  // A button that only acts on a second click, for actions that delete data.
  function confirmTwice(button, label, action) {
    let armed = false, timer = null;
    button.addEventListener('click', async () => {
      if (!armed) {
        armed = true;
        button.textContent = 'Click again to ' + label.toLowerCase();
        timer = setTimeout(() => { armed = false; button.textContent = label; }, 4000);
        return;
      }
      clearTimeout(timer);
      await action();
    });
  }

  function describeArchived(meta, position) {
    const when = meta && meta.archivedAt ? new Date(meta.archivedAt).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : 'date unknown';
    const summary = meta && meta.summary ? meta.summary : '';
    return named('A' + (position + 1), meta) + ' · ' + when + (summary ? ' · ' + summary : '');
  }

  async function renderMenu() {
    const panel = byId('case-menu-panel');
    panel.replaceChildren(detailsSection());
    if (!info.archived) {
      const archive = document.createElement('button');
      archive.type = 'button'; archive.className = 'btn btn-secondary btn-small'; archive.id = 'case-archive';
      archive.textContent = 'Archive ' + info.label;
      archive.title = 'Keep this case read-only in the archive and start a fresh ' + info.label + ' with the same choices';
      archive.addEventListener('click', async () => {
        try {
          if (localWorkInProgress()) throw new Error('Finish or cancel the work running in this popup first.');
          await saveOpenCase();
          await VeiluxCases.archive(info.slot);
          location.reload();
        } catch (error) { updateStatus('Archive: ' + error.message, 'error'); byId('case-menu').open = false; }
      });
      panel.append(archive);
    }
    const heading = document.createElement('p');
    heading.className = 'case-menu-heading';
    heading.textContent = 'Archived cases (' + info.index.archive.length + ')';
    panel.append(heading);
    if (!info.index.archive.length) {
      const empty = document.createElement('p');
      empty.className = 'field-hint'; empty.textContent = 'Archived cases are kept here, read-only, until you delete them.';
      panel.append(empty);
      return;
    }
    const list = document.createElement('div');
    list.className = 'case-archive-list';
    for (const [position, caseId] of info.index.archive.entries()) {
      const { caseMeta } = await VeiluxCases.storage(caseId).get('caseMeta');
      const open = document.createElement('button');
      open.type = 'button'; open.className = 'case-archive-item'; open.dataset.archivedCase = caseId;
      open.textContent = describeArchived(caseMeta, position);
      if (info.archived && info.caseId === caseId) open.setAttribute('aria-current', 'page');
      open.addEventListener('click', () => go({ archive: caseId }));
      list.append(open);
    }
    const clear = document.createElement('button');
    clear.type = 'button'; clear.className = 'btn btn-danger btn-small'; clear.id = 'case-clear-archive';
    clear.textContent = 'Clear archive';
    confirmTwice(clear, 'Clear archive', async () => { await VeiluxCases.deleteArchived('all'); location.reload(); });
    panel.append(list, clear);
  }

  async function renderDots() {
    const index = await VeiluxCases.readIndex();
    if (index) info.index = index;
    const states = await VeiluxCases.statuses(info.index);
    const names = await Promise.all(info.index.slots.map(caseId =>
      VeiluxCases.storage(caseId).get('caseMeta').then(({ caseMeta }) => (caseMeta && caseMeta.name) || '').catch(() => '')));
    // The buttons are updated in place rather than rebuilt: status updates arrive
    // while the analyst may be clicking, and a click whose press and release land
    // on different elements is lost.
    const dots = byId('case-dots');
    const slots = info.index.slots;
    while (dots.children.length > slots.length) dots.lastElementChild.remove();
    while (dots.children.length < slots.length) {
      const dot = document.createElement('button');
      dot.type = 'button'; dot.className = 'case-dot'; dot.dataset.slot = String(dots.children.length);
      dot.addEventListener('click', () => {
        const slot = Number(dot.dataset.slot);
        if (info.archived || slot !== info.slot) go({ slot });
      });
      dots.append(dot);
    }
    slots.forEach((caseId, slot) => {
      const dot = dots.children[slot];
      const state = states[caseId] || 'idle';
      const label = named('Case ' + (slot + 1), { name: names[slot] });
      dot.dataset.state = state;
      dot.setAttribute('aria-label', label + ': ' + STATE_TEXT[state]);
      dot.title = label + ' · ' + STATE_TEXT[state];
      if (!info.archived && slot === info.slot) dot.setAttribute('aria-current', 'true');
      else dot.removeAttribute('aria-current');
    });
  }

  // Archived cases are shown read-only: results and inputs can be read and
  // copied, but nothing can be extracted, edited or sent.
  function showArchived() {
    document.body.classList.add('case-archived');
    ['analysis-setup', 'protection-section'].forEach(id => { const node = byId(id); if (node) node.inert = true; });
    document.querySelectorAll('#main-workflow textarea, #feedback-section textarea').forEach(field => { field.readOnly = true; });
    const banner = byId('archived-banner');
    banner.hidden = false;
    byId('archived-banner-text').textContent = 'Archived case ' + named(info.label, meta) + ' · ' +
      describeArchived({ ...meta, name: '' }, info.index.archive.indexOf(info.caseId)).split(' · ').slice(1).join(' · ') +
      '. Read-only: copy what you need, or restore it to an empty slot to keep working.';
    byId('archived-back').addEventListener('click', () => go({ slot: 0 }));
    byId('archived-restore').addEventListener('click', async () => {
      try { await VeiluxCases.restore(info.caseId); location.reload(); }
      catch (error) { updateStatus('Restore: ' + error.message, 'error'); }
    });
    confirmTwice(byId('archived-delete'), 'Delete', async () => { await VeiluxCases.deleteArchived([info.caseId]); location.reload(); });
  }

  async function init(current) {
    info = current;
    meta = (await VeiluxCases.storage(info.caseId).get('caseMeta')).caseMeta || {};
    showLabel();
    byId('case-prev').addEventListener('click', () => step(-1));
    byId('case-next').addEventListener('click', () => step(1));
    byId('case-menu').addEventListener('toggle', () => { if (byId('case-menu').open) renderMenu(); });
    document.addEventListener('click', event => {
      if (byId('case-menu').open && !byId('case-menu').contains(event.target)) byId('case-menu').open = false;
    });
    if (info.archived) showArchived();
    await renderDots();
    // Keep the dots current while other cases work in the background, and
    // treat a result that arrives for the open case as seen.
    let pending = null;
    browser.storage.onChanged.addListener((changes, area) => {
      if (area !== 'local') return;
      const relevant = Object.keys(changes).some(key => /(^|\.)(analysisInProgress|analysisQueued|extractionJob|caseUnseen)$/.test(key) || key === 'casesIndex');
      if (!relevant) return;
      const own = (info.caseId ? 'case.' + info.caseId + '.' : '') + 'caseUnseen';
      if (changes[own] && changes[own].newValue === true && document.visibilityState === 'visible') VeiluxCases.markSeen(info.caseId);
      clearTimeout(pending);
      pending = setTimeout(renderDots, 150);
    });
  }

  return { init, go, localWorkInProgress, clearDetails, name: () => meta.name || '' };
})();
