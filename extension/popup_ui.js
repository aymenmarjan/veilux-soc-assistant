/* Popup layout: stages, tabs, panels and loading. Buttons call the handlers
   in popup.js; this file sends no requests.

   The popup shows one stage at a time, chosen in the rail under the header:
     Case     what the case holds: logs, statistics, case notes
     Options  what to run and what is sent
     Results  the analysis, Ask and Report, plus details of what happened
     Tools    indicator check and defang
   A credential review takes over as its own stage until it is answered. */
window.VeiluxUI = (() => {
  const byId = id => document.getElementById(id);
  let view = null, reviewing = false, loading = false, returnFocus = null;
  // The Sent record arrives just before results; it is shown only when chosen
  // or when nothing else is available.
  let sentChosen = false;
  const dock = document.querySelector('.workflow-dock');

  // The decision count sits in the dock next to Continue; the list stays in the stage.
  byId('secret-review-decisions').hidden = true;
  dock.insertBefore(byId('secret-review-decisions'), dock.querySelector('.dock-main'));

  // ---- Stages ----
  const main = byId('main-workflow');
  const stageTabs = Array.from(document.querySelectorAll('.stage-tab'));
  let stage = 'case', stageBeforeReview = 'case';
  function selectStage(name, remember = true) {
    if (name === 'review' && !reviewing) return;
    stage = name;
    stageTabs.forEach(tab => {
      const selected = tab.dataset.stage === name;
      tab.setAttribute('aria-selected', String(selected));
      tab.tabIndex = selected ? 0 : -1;
      byId('stage-' + tab.dataset.stage).hidden = !selected;
    });
    main.scrollTop = 0;
    if (remember && name !== 'review') caseStorage.set({ popupStage: name }).catch(() => {});
    syncResults();
  }
  stageTabs.forEach(tab => tab.addEventListener('click', () => selectStage(tab.dataset.stage)));
  byId('stage-rail').addEventListener('keydown', event => {
    if (!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return;
    event.preventDefault();
    const shown = stageTabs.filter(tab => !tab.hidden);
    const index = shown.indexOf(document.activeElement);
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? shown.length - 1
      : (index + (event.key === 'ArrowRight' ? 1 : -1) + shown.length) % shown.length;
    shown[next].focus(); shown[next].click();
  });

  // ---- Tabs inside a stage (Logs / Statistics / Case notes, and the tools) ----
  const subtabs = Array.from(document.querySelectorAll('.subtab'));
  function selectSubtab(button) {
    Array.from(button.parentElement.querySelectorAll('.subtab')).forEach(other => {
      const selected = other === button, content = byId(other.getAttribute('aria-controls'));
      other.setAttribute('aria-selected', String(selected));
      other.setAttribute('aria-expanded', String(selected));
      other.tabIndex = selected ? 0 : -1;
      other.classList.toggle('collapsed', !selected);
      content.classList.toggle('collapsed', !selected);
      content.closest('.sub-panel').hidden = !selected;
    });
  }
  subtabs.forEach(button => button.addEventListener('click', () => selectSubtab(button)));
  document.querySelectorAll('.subtabs').forEach(list => selectSubtab(list.querySelector('.subtab')));

  // Brings a control into view: its stage, its tab inside the stage and, for
  // results, its result view. Used by links between stages.
  function reveal(element) {
    if (!element || !element.closest) return;
    const home = element.closest('.stage');
    if (home && home.dataset.stage !== stage) selectStage(home.dataset.stage);
    const panel = element.closest('.sub-panel');
    if (panel && panel.hidden) {
      const button = subtabs.find(tab => panel.contains(byId(tab.getAttribute('aria-controls'))));
      if (button) selectSubtab(button);
    }
    const result = element.closest('[role="tabpanel"][id^="result-"]');
    if (result && result.hidden) selectView(result.id.slice('result-'.length));
  }

  // One line under each stage name says what it holds, so nothing has to be
  // opened just to check.
  function summaries() {
    const logs = capturedLogs.filter(log => typeof log === 'string' && log.trim()).length;
    const notes = byId('analyst-data-textarea').value.trim() || (window.VeiluxCaseNotes && window.VeiluxCaseNotes.count());
    byId('case-count-logs').textContent = logs ? String(logs) : '';
    byId('case-count-statistics').textContent = fieldStatistics.length ? String(fieldStatistics.length) : '';
    byId('stage-sum-case').textContent = [logs && logs + (logs === 1 ? ' log' : ' logs'), fieldStatistics.length && fieldStatistics.length + ' statistics',
      notes && 'notes'].filter(Boolean).join(' · ') || 'No inputs yet';
    const local = document.querySelector('input[name="workflow-mode"]:checked').value === 'sanitize_only';
    const provider = byId('ai-provider').selectedOptions[0];
    byId('stage-sum-options').textContent = (local ? 'Sanitize locally' : provider ? provider.textContent.split(' · ')[0] : 'AI')
      + (!byId('enable-secret-protection').checked ? ' · secrets not protected' : !local && byId('enable-ti').checked ? ' · threat intel' : '');
    const state = available(), answers = window.VeiluxChatPanel ? window.VeiluxChatPanel.count() : 0;
    const indicators = window.VeiluxIndicators ? window.VeiluxIndicators.count() : 0;
    byId('stage-sum-tools').textContent = indicators ? indicators + (indicators === 1 ? ' indicator' : ' indicators') : 'Indicators';
    byId('stage-sum-results').textContent = [state.analysis && (byId('analysis-stale').hidden ? 'Analysis' : 'Analysis out of date'),
      !state.analysis && state.sanitized && 'Sanitized', answers && answers + (answers === 1 ? ' answer' : ' answers'),
      state.report && !byId('report-output').hidden && 'report'].filter(Boolean).join(' · ') || 'None yet';
    byId('statistics-empty').hidden = byId('statistics-section').style.display !== 'none';
  }
  const tabs = Array.from(document.querySelectorAll('[data-result-view]'));
  // Result views that open on demand, with the button that opens each.
  const OPENABLE = { chat: 'ask-btn', report: 'report-btn' };
  const shown = id => byId(id).style.display !== 'none';
  const available = () => ({
    analysis: !!lastAnalysis && shown('copy-analysis-btn'),
    sanitized: shown('sanitized-section') || shown('sanitized-analyst-section') || shown('sanitized-statistics-section'),
    changes: shown('mapping-section'), ti: shown('threat-intel-section'),
    report: !!window.VeiluxReportPanel?.isOpen(),
    chat: !!window.VeiluxChatPanel?.isOpen(),
    sent: !!window.VeiluxSentPanel?.count()
  });
  const copyTargets = () => ({ analysis: 'copy-analysis-btn',
    sanitized: shown('sanitized-section') ? 'copy-sanitized-btn' : shown('sanitized-analyst-section') ? 'copy-sanitized-analyst-btn' : 'copy-sanitized-statistics-btn',
    changes: 'copy-mapping-btn', ti: 'copy-ti-btn', report: 'report-copy-email', chat: 'chat-copy-last', sent: 'sent-copy' });

  function syncResults(preferred) {
    const state = available();
    const any = Object.values(state).some(Boolean);
    byId('results-workspace').hidden = !any;
    byId('results-empty').hidden = any;
    const others = Object.keys(state).filter(key => state[key] && key !== 'sent');
    if (!state[view] || (view === 'sent' && !sentChosen && others.length))
      view = state[preferred] ? preferred : others[0] || (state.sent ? 'sent' : undefined);
    const counts = { changes: Object.keys(lastMappingTable || {}).length,
      ti: byId('threat-intel-findings').querySelectorAll('.ti-finding').length,
      chat: window.VeiluxChatPanel ? window.VeiluxChatPanel.count() : 0,
      sent: window.VeiluxSentPanel ? window.VeiluxSentPanel.count() : 0 };
    tabs.forEach(tab => {
      const name = tab.dataset.resultView;
      // Ask and Report need no analysis, so their tabs are always usable.
      tab.disabled = !state[name] && !OPENABLE[name];
      tab.setAttribute('aria-selected', String(name === view));
      tab.tabIndex = name === view ? 0 : -1;
      byId('result-' + name).hidden = name !== view;
      const label = { analysis:'Analysis', sanitized:'Sanitized inputs', changes:'Changes', ti:'Threat intel', report:'Report', chat:'Ask', sent:'Sent' }[name];
      tab.textContent = label + (counts[name] ? ' (' + counts[name] + ')' : '');
    });
    // Details that do not exist yet are left out instead of shown greyed.
    byId('result-tabs-more').hidden = !['sanitized', 'changes', 'ti', 'sent'].some(name => state[name]);
    const copy = byId('copy-result-action');
    // Copy belongs to the result on screen. The report and Ask have their own
    // copy buttons, which need content.
    copy.hidden = !any || stage !== 'results' || (view === 'report' && byId('report-output').hidden) || (view === 'chat' && byId('chat-copy-last').hidden);
    if (!copy.hidden) copy.textContent = byId(copyTargets()[view]).textContent;
    document.querySelector('.workflow-dock').classList.toggle('results-ready', any && !reviewing && stage === 'results');
    summaries();
  }
  function selectView(name) {
    if (!available()[name]) return;
    view = name;
    sentChosen = name === 'sent';
    syncResults();
    caseStorage.set({ popupResultView: name }).catch(() => {});
  }
  tabs.forEach(tab => tab.addEventListener('click', () => {
    const name = tab.dataset.resultView;
    if (!available()[name] && OPENABLE[name]) byId(OPENABLE[name]).click();
    else selectView(name);
  }));
  document.querySelector('.result-tabs').addEventListener('keydown', event => {
    if (!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return;
    event.preventDefault();
    const enabled = tabs.filter(tab => !tab.disabled);
    if (!enabled.length) return;
    const index = enabled.indexOf(document.activeElement);
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? enabled.length - 1
      : (index + (event.key === 'ArrowRight' ? 1 : -1) + enabled.length) % enabled.length;
    enabled[next].focus();
    // Arrowing over Ask or Report does not open them; Enter or a click does.
    if (available()[enabled[next].dataset.resultView]) enabled[next].click();
  });
  const copyTi = document.createElement('button');
  copyTi.id = 'copy-ti-btn'; copyTi.type = 'button'; copyTi.className = 'btn-copy';
  copyTi.textContent = 'Copy threat intelligence';
  byId('result-ti').appendChild(copyTi);
  copyTi.addEventListener('click', () => {
    // Copy every fact even when the user leaves provider cards collapsed.
    // Expand an offscreen clone so the live layout/focus stays unchanged.
    const copy = byId('threat-intel-findings').cloneNode(true);
    copy.removeAttribute('id');
    copy.setAttribute('aria-hidden', 'true');
    copy.style.cssText = 'position:fixed;left:-10000px;top:0;width:720px;';
    copy.querySelectorAll('details').forEach(details => { details.open = true; });
    document.body.appendChild(copy);
    let text;
    try { text = copy.innerText; } finally { copy.remove(); }
    copyToClipboard(text, 'Threat intelligence findings');
  });
  byId('copy-result-action').addEventListener('click', () => {
    if (view && available()[view]) byId(copyTargets()[view]).click();
  });
  byId('compare-source').addEventListener('click', () => {
    reveal(byId('logs-textarea'));
    byId('logs-textarea').focus();
  });
  byId('results-empty-ask').addEventListener('click', () => byId('ask-btn').click());
  byId('results-empty-report').addEventListener('click', () => byId('report-btn').click());
  // The review is one question to answer, so it gets the whole stage: its tab
  // appears in the rail and is selected, and the stage the analyst came from
  // returns afterwards. Case and Options stay reachable while it waits.
  function setReview(open) {
    if (open && !reviewing) stageBeforeReview = stage;
    reviewing = open;
    byId('stage-tab-review').hidden = !open;
    byId('review-actions').hidden = !open;
    byId('main-actions').hidden = open;
    byId('secret-review-decisions').hidden = !open;
    document.body.classList.toggle('reviewing', open);
    if (open) {
      updateDecisions();
      selectStage('review', false);
      byId('secret-review-filter').focus();
    } else selectStage(stage === 'review' ? stageBeforeReview : stage, false);
  }
  function updateDecisions() {
    const inputs = Array.from(byId('secret-review-list').querySelectorAll('input[data-secret-index]'));
    const keep = inputs.filter(input => input.checked).length;
    inputs.forEach(input => {
      const row = input.closest('.secret-review-item');
      row.dataset.decision = input.checked ? 'keep' : 'hide';
      row.querySelector('.secret-decision').textContent = input.checked ? 'Keep' : 'Hide';
    });
    byId('secret-review-decisions').textContent = keep + ' kept · ' + (inputs.length - keep) + ' to hide';
    byId('stage-sum-review').textContent = inputs.length + (inputs.length === 1 ? ' value' : ' values');
  }
  byId('secret-review-list').addEventListener('change', updateDecisions);
  function sourceSummary() {
    const pages = capturedLogPages.concat(fieldStatisticsPages).filter(Boolean);
    const titles = Array.from(new Set(pages.map(page => page.title).filter(Boolean)));
    const latest = Math.max(0, ...pages.map(page => Number(page.capturedAt) || 0));
    const text = !capturedLogs.length && !fieldStatistics.length ? 'Paste logs or extract from a source page.'
      : (titles.length ? titles.slice(0, 2).join(' · ') + (titles.length > 2 ? ' +' + (titles.length - 2) + ' sources' : '') : 'Pasted or edited input')
      + (latest ? ' · Captured ' + new Date(latest).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}) : ' · Saved capture')
      + (fieldStatistics.length ? ' · ' + fieldStatistics.length + ' statistics queries' : '');
    byId('source-summary').textContent = text;
    summaries();
  }
  // Manual hiding can reveal previews before analysis runs. Observe only those
  // visibility changes, not text or policy, and leave the chosen view intact.
  const observer = new MutationObserver(() => syncResults());
  ['sanitized-section','sanitized-analyst-section','sanitized-statistics-section','mapping-section','threat-intel-section','copy-analysis-btn','statistics-section']
    .forEach(id => observer.observe(byId(id), { attributes:true, attributeFilter:['style'] }));
  observer.observe(byId('analysis-stale'), { attributes:true, attributeFilter:['hidden'] });
  observer.observe(byId('report-output'), { attributes:true, attributeFilter:['hidden'] });
  // "Hide selected text" appears only when there is a selection to hide or a
  // hide to undo, instead of taking a row of the dock all the time.
  const manual = document.querySelector('.manual-actions');
  const syncManual = () => {
    manual.hidden = byId('hide-selection-btn').disabled && byId('undo-hide-btn').disabled && !byId('manual-hide-status').textContent;
  };
  const manualObserver = new MutationObserver(syncManual);
  ['hide-selection-btn', 'undo-hide-btn'].forEach(id => manualObserver.observe(byId(id), { attributes:true, attributeFilter:['disabled'] }));
  manualObserver.observe(byId('manual-hide-status'), { childList:true, characterData:true, subtree:true });
  syncManual();
  let summaryTimer = null;
  ['input', 'change'].forEach(type => document.addEventListener(type, () => {
    clearTimeout(summaryTimer); summaryTimer = setTimeout(summaries, 100);
  }));
  window.addEventListener('pagehide', () => { observer.disconnect(); manualObserver.disconnect(); }, { once:true });
  // While work is running, Tab moves between Cancel and the case switcher only.
  byId('loading-overlay').addEventListener('keydown', event => {
    if (event.key === 'Escape') byId('loading-dismiss-btn').click();
  });
  document.addEventListener('keydown', event => {
    if (event.key !== 'Tab' || !loading) return;
    const stops = [byId('loading-dismiss-btn'), byId('case-prev'), byId('case-next')].filter(node => node && !node.disabled && node.offsetParent);
    event.preventDefault();
    const at = stops.indexOf(document.activeElement);
    stops[(at + (event.shiftKey ? -1 : 1) + stops.length) % stops.length].focus();
  });
  return { setReview, syncResults, sourceSummary, updateDecisions, selectView, selectStage, selectSubtab, reveal, summaries,
    stage: () => stage,
    revealResults() {
      if (byId('results-workspace').hidden) return;
      if (!reviewing) selectStage('results');
      else stageBeforeReview = 'results';
      tabs.find(tab => tab.getAttribute('aria-selected') === 'true')?.focus({ preventScroll:true });
    },
    loading(show) {
      if (show && !loading) { returnFocus = document.activeElement; byId('loading-dismiss-btn').focus(); }
      if (!show && loading && document.activeElement === byId('loading-dismiss-btn') && returnFocus?.isConnected) returnFocus.focus();
      loading = show;
    },
    async initialize() {
      const stored = await caseStorage.get(['popupResultView', 'popupStage']);
      if (available()[stored.popupResultView]) { view = stored.popupResultView; sentChosen = view === 'sent'; }
      sourceSummary(); syncResults();
      // Open where the analyst left this case; a case with results opens on them.
      const any = Object.entries(available()).some(([name, present]) => present && name !== 'sent');
      const wanted = ['case', 'options', 'results', 'tools'].includes(stored.popupStage) ? stored.popupStage : any ? 'results' : 'case';
      if (!reviewing) selectStage(wanted, false);
    }
  };
})();
