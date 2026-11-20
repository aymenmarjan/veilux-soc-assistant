/* Page inspection is local to a pending review. It never changes Keep/Hide.

   Highlights outlive the popup: closing it (which happens whenever the analyst
   clicks the page to look at a value) leaves them painted. Every other end of a
   review (answered, cancelled, another tab, edited logs) removes them, as does
   releaseAll()
   when the analyst discards an interrupted review, by Esc on the page, or when
   the page navigates (see secret_highlights.js). */
class SecretPageReview {
  constructor(pages, values, report) {
    this.pages = pages;
    this.linkedUrls = new Set(pages.flatMap(page => page.linkedUrls || []).map(SecretPageReview.url).filter(Boolean));
    this.values = values;
    this.report = report;
    this.frames = [];
    this.cursor = new Map();
    this.closed = false;
    this.busy = false;
    this.sequence = 0;
    this.focusSequence = 0;
    this.lastNormalFocus = 0;
    this.onLeave = () => this.close(false);
    window.addEventListener('pagehide', this.onLeave, { once: true });
    // Follow the analyst's browser window, never activate a tab ourselves.
    // In a separate review window currentWindow refers to the extension UI.
    this.onActivated = info => {
      if (info.windowId === this.sourceWindowId) this.scheduleRefresh();
    };
    this.onUpdated = (id, change, tab) => {
      if ((change.url || change.status === 'complete') && tab.windowId === this.sourceWindowId)
        this.scheduleRefresh();
    };
    this.onFocus = async id => {
      if (id < 0 || this.closed) return;
      const sequence = ++this.focusSequence;
      try {
        const focused = await browser.windows.get(id);
        if (this.closed || focused.type !== 'normal' || sequence < this.lastNormalFocus) return;
        this.lastNormalFocus = sequence;
        this.sourceWindowId = id;
        this.scheduleRefresh();
      } catch (_) { /* A window can close while focus changes. */ }
    };
    this.onWindowRemoved = id => {
      if (id !== this.sourceWindowId) return;
      // Closing a SIEM window can focus the review window itself. There need
      // not be a new normal-window focus event to replace the closed ID.
      this.sourceWindowId = undefined;
      this.scheduleRefresh();
    };
    this.events = [[browser.tabs.onActivated, this.onActivated], [browser.tabs.onUpdated, this.onUpdated],
      [browser.windows?.onFocusChanged, this.onFocus], [browser.windows?.onRemoved, this.onWindowRemoved]];
    this.events.forEach(([event, listener]) => event?.addListener(listener));
  }

  static url(value) {
    try { const url = new URL(value); return /^https?:$/.test(url.protocol) ? url.href : null; }
    catch (_) { return null; }
  }

  static page(tab, linkedUrls = []) {
    const links = Array.from(new Set(linkedUrls.map(SecretPageReview.url).filter(Boolean)));
    const url = SecretPageReview.url(tab?.url) || links[0];
    if (!url) return null;
    return { id: Number.isInteger(tab?.id) ? tab.id : null, url,
      capturedAt: Date.now(),
      windowId: tab?.windowId, title: tab?.title || new URL(url).hostname,
      ...(links.length ? { linkedUrls: links } : {}) };
  }

  static async activeTab(sourceWindowId) {
    const tabs = await browser.tabs.query({ active: true, currentWindow: true });
    let tab = tabs[0];
    // The pinned tab identifies a browser WINDOW. Its active tab may now be
    // a linked record opened after extracting from the page that links to it.
    const pinned = Number(new URLSearchParams(location.search).get('tabId'));
    if (new URLSearchParams(location.search).has('tabId') &&
        (!tab || (tab.url || '').startsWith(browser.runtime.getURL('popup.html')))) {
      if (!Number.isInteger(sourceWindowId)) {
        try { tab = await browser.tabs.get(pinned); } catch (_) { return null; }
        sourceWindowId = tab.windowId;
      }
      if (Number.isInteger(sourceWindowId))
        tab = (await browser.tabs.query({ active: true, windowId: sourceWindowId }))[0];
      else if (!tab?.active) return null;
    }
    return tab;
  }

  async checkPage() {
    const tab = await SecretPageReview.activeTab(this.sourceWindowId);
    if (Number.isInteger(tab?.windowId)) this.sourceWindowId = tab.windowId;
    const url = SecretPageReview.url(tab?.url);
    const page = this.pages.find(page => tab && page.id === tab.id && page.url === url);
    const linked = url && this.linkedUrls.has(url);
    if (tab?.pendingUrl && SecretPageReview.url(tab.pendingUrl) !== url)
      throw new Error('The source tab has navigated to another page. Wait for the linked log to load or return to the captured page.');
    if (!page && !linked && this.pages.some(page => tab && page.id === tab.id))
      throw new Error('The source tab has navigated to another page. Return to the captured page or open its linked SIEM log.');
    if (!page && !linked) {
      const titles = Array.from(new Set(this.pages.map(page => '“' + page.title + '”'))).join(' or ');
      const destinations = titles + (this.linkedUrls.size ? ' or the linked SIEM log' : '');
      throw new Error(destinations ? 'This secret is not on this tab. Switch to ' + destinations + ' and click the value again.'
        : 'No source page is available. Open the page containing these logs and extract them again.');
    }
    return SecretPageReview.page(tab);
  }

  scheduleRefresh() {
    if (this.closed) return;
    clearTimeout(this.refreshTimer);
    this.refreshTimer = setTimeout(() => {
      if (this.busy) this.refreshPending = true;
      else this.inspect(null, 1, true);
    }, 75);
  }

  request(frame, payload) {
    return new Promise((resolve, reject) => {
      const id = ++this.sequence;
      const timer = setTimeout(() => { frame.pending.delete(id); reject(new Error('Page highlighting timed out. Try refreshing the highlights.')); }, 6000);
      frame.pending.set(id, { resolve, reject, timer });
      try { frame.port.postMessage({ ...payload, id, nonce: frame.identity.nonce, url: frame.identity.url }); }
      catch (error) { clearTimeout(timer); frame.pending.delete(id); reject(error); }
    });
  }

  // release (the default): take the highlights off the page. Only a popup that
  // is closing passes false, so the analyst can keep checking the values.
  disconnectFrames(release = true) {
    this.frames.forEach(frame => {
      frame.pending.forEach(pending => { clearTimeout(pending.timer); pending.reject(new Error('Page review closed.')); });
      frame.pending.clear();
      if (release) { try { frame.port.postMessage({ action: 'release', nonce: frame.identity.nonce, url: frame.identity.url }); } catch (_) {} }
      frame.port.disconnect();
    });
    this.frames = [];
    this.cursor.clear();
  }

  async connect(page) {
    if (this.frames.length && this.tabId === page.id && this.tabUrl === page.url && this.frames.every(frame => !frame.disconnected)) return;
    this.disconnectFrames();
    let injected, restricted = false;
    try {
      injected = await browser.scripting.executeScript({ target: { tabId: page.id, allFrames: true }, files: ['secret_highlights.js'] });
    } catch (_) {
      restricted = true;
      injected = await browser.scripting.executeScript({ target: { tabId: page.id }, files: ['secret_highlights.js'] });
    }
    if (this.closed) return;
    const current = await this.checkPage();
    if (this.closed) return;
    if (current.id !== page.id || current.url !== page.url) throw new Error('The active tab changed. Switch back to the source tab and try again.');
    this.tabId = page.id;
    this.tabUrl = page.url;
    this.restricted = restricted;
    const results = await Promise.allSettled(injected.filter(item => item.result && item.result.nonce).map(async item => {
      const port = browser.tabs.connect(page.id, { frameId: item.frameId, name: 'veilux-secret-review' });
      const frame = { port, identity: item.result, frameId: item.frameId, pending: new Map(), counts: [] };
      this.frames.push(frame);
      port.onMessage.addListener(message => {
        const pending = frame.pending.get(message.id);
        if (!pending) return;
        frame.pending.delete(message.id); clearTimeout(pending.timer);
        if (message.error) pending.reject(new Error(message.error));
        else { frame.counts = message.counts; frame.limited = message.limited; pending.resolve(message); }
      });
      port.onDisconnect.addListener(() => {
        frame.disconnected = true;
        frame.pending.forEach(pending => { clearTimeout(pending.timer); pending.reject(new Error('The page changed or closed. Open the captured page or linked SIEM log to locate this value.')); });
        frame.pending.clear();
      });
      await this.request(frame, { action: 'init', values: this.values });
    }));
    results.forEach(result => { if (result.status === 'rejected') this.restricted = true; });
    this.frames = this.frames.filter(frame => {
      if (frame.counts.length === this.values.length && !frame.disconnected) return true;
      frame.port.disconnect(); return false;
    }).sort((a, b) => a.frameId - b.frameId);
    if (!this.frames.length) {
      const failed = results.find(result => result.status === 'rejected');
      throw new Error(failed ? failed.reason.message : 'This page does not allow highlighting. Open the logs in a regular browser tab and try again.');
    }
  }

  note() {
    return (this.restricted ? ' Some frames could not be inspected.' : '') +
      (this.frames.some(frame => frame.limited) ? ' Page highlighting reached its display limit; review smaller batches for the remaining matches.' : '');
  }

  async inspect(index = null, direction = 1, refresh = false) {
    if (this.closed) return;
    if (index !== null) {
      // A user click must survive an automatic refresh already in flight.
      clearTimeout(this.refreshTimer);
      this.refreshPending = false;
    }
    if (this.busy) {
      if (index !== null) this.pendingNavigation = { index, direction };
      return;
    }
    this.busy = true;
    try {
      const page = await this.checkPage();
      await this.connect(page);
      if (this.closed) return;
      // Refresh counts at navigation time as virtualized SIEM tables may have
      // changed since review opened. Only source pages receive candidate text.
      if (refresh || index !== null) {
        await Promise.all(this.frames.map(frame => this.request(frame, { action: 'refresh' })));
      }
      if (this.closed) return;
      const current = await this.checkPage(); // The analyst may switch tabs during a scan.
      if (current.id !== page.id || current.url !== page.url) throw new Error('The active tab changed. Switch back to the source tab and try again.');
      if (index === null) {
        const total = this.frames.reduce((n, frame) => n + frame.counts.reduce((a, b) => a + b, 0), 0);
        this.report(total ? total + ' page matches highlighted in red. Click a value to jump to it.' + this.note()
          : 'No matching text is currently displayed on the source page. Expand the log or load its row, then refresh highlights.' + this.note());
        return;
      }
      const total = this.frames.reduce((n, frame) => n + (frame.counts[index] || 0), 0);
      if (!total) {
        this.report('This value is not currently displayed on this page. Expand the log or load its row, then click again.' +
          (this.pages.length > 1 ? ' It may be on another captured source tab.' : '') + this.note());
        return;
      }
      const previous = this.cursor.has(index) ? this.cursor.get(index) : (direction > 0 ? -1 : 0);
      const position = (previous + direction + total) % total;
      let offset = position, frame;
      for (const candidate of this.frames) {
        const count = candidate.counts[index] || 0;
        if (offset < count) { frame = candidate; break; }
        offset -= count;
      }
      const result = await this.request(frame, { action: 'find', valueIndex: index, index: offset });
      if (result.index < 0) { this.report('The page content changed. Click again to find the remaining matches.'); return; }
      this.cursor.set(index, position);
      this.report('Showing page match ' + (position + 1) + ' of ' + total + '. Orange marks the selected match; click the value again for the next.' + this.note());
    } catch (error) {
      this.disconnectFrames();
      if (!this.closed) this.report(error.message || 'Could not highlight this page.');
    } finally {
      this.busy = false;
      if (this.pendingNavigation) {
        const next = this.pendingNavigation;
        this.pendingNavigation = null;
        this.inspect(next.index, next.direction);
      } else if (this.refreshPending) { this.refreshPending = false; this.scheduleRefresh(); }
    }
  }

  // close(): the review is over, take the highlights off. close(false): the popup
  // is going away, so leave them on the page.
  close(release = true) {
    this.closed = true;
    clearTimeout(this.refreshTimer);
    this.events.forEach(([event, listener]) => event?.removeListener(listener));
    this.disconnectFrames(release);
    window.removeEventListener('pagehide', this.onLeave);
  }

  // Removes highlights an interrupted review left on its pages.
  static async releaseAll(pages) {
    const seen = new Set();
    for (const page of pages || []) {
      if (!Number.isInteger(page && page.id) || seen.has(page.id)) continue;
      seen.add(page.id);
      try {
        const injected = await browser.scripting.executeScript({ target: { tabId: page.id, allFrames: true }, files: ['secret_highlights.js'] });
        for (const item of injected.filter(entry => entry.result && entry.result.nonce)) {
          const port = browser.tabs.connect(page.id, { frameId: item.frameId, name: 'veilux-secret-review' });
          port.postMessage({ action: 'release', nonce: item.result.nonce, url: item.result.url });
          setTimeout(() => { try { port.disconnect(); } catch (_) {} }, 200);
        }
      } catch (_) { /* the tab is gone or cannot be inspected: nothing to clear */ }
    }
  }
}
