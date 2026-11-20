/* Request-local, isolated-world page highlighting. No page text is rewritten.

   Highlights belong to the credential review, not to the popup window: a popup
   closes whenever the analyst clicks the page to look at a value, so the
   highlights stay painted when the popup goes away ("kept"). They end when the
   popup releases them (the review was answered or cancelled), when a new review
   takes over, when the analyst presses Esc on the page, when the page
   navigates, or after an hour. */
(() => {
  if (globalThis.__veiluxSecretHighlights) return { ...globalThis.__veiluxSecretHighlights, url: location.href };
  const api = typeof browser !== 'undefined' ? browser : chrome;
  const identity = { url: location.href, nonce: crypto.randomUUID() };
  globalThis.__veiluxSecretHighlights = identity;
  const name = 'veilux-secrets-' + identity.nonce;
  const activeName = name + '-active';
  const MAX_CHARS = 2000000, MAX_NODES = 100000, MAX_MATCHES = 10000;
  const KEEP_MS = 60 * 60 * 1000;
  let owner = null, kept = false, keepTimer = null;
  let values = [], matches = [], selected = null, observer = null;
  let styles = [], canvas = null, dirty = true, limited = false, timer = null;
  let paintFrame = null, revision = 0;
  // Browsers without the CSS Custom Highlight API get the canvas painter below.
  // It is also used when the highlight styles cannot be attached to the page:
  // in Firefox, a content script sees the page's adoptedStyleSheets through a
  // security wrapper that cannot be read or extended as a normal array.
  // eslint-disable-next-line compat/compat -- this line is the feature check
  let cssHighlights = !!(globalThis.CSS && CSS.highlights && globalThis.Highlight);

  function clearPaint() {
    if (cssHighlights) { try { CSS.highlights.delete(name); CSS.highlights.delete(activeName); } catch (_) {} }
    styles.forEach(({ root, sheet }) => {
      try { root.adoptedStyleSheets = Array.prototype.filter.call(root.adoptedStyleSheets, item => item !== sheet); } catch (_) {}
    });
    styles = [];
    if (canvas) canvas.remove();
    canvas = null;
  }
  function clear() {
    kept = false;
    clearTimeout(keepTimer); keepTimer = null;
    removeEventListener('keydown', onEscape, true);
    revision++;
    clearTimeout(timer); timer = null;
    if (observer) observer.disconnect();
    observer = null;
    if (paintFrame) cancelAnimationFrame(paintFrame);
    paintFrame = null;
    removeEventListener('scroll', schedulePaint, true);
    removeEventListener('resize', schedulePaint);
    clearPaint(); values = []; matches = []; selected = null; dirty = true;
  }

  // Esc on the page ends kept highlights. The key is not consumed, so the
  // SIEM page still receives it.
  function onEscape(event) { if (event.key === 'Escape' && kept) clear(); }

  // The popup went away without releasing: keep painting, and keep them
  // current when the page changes.
  function keep() {
    if (!values.length) { clear(); return; }
    kept = true;
    addEventListener('keydown', onEscape, true);
    clearTimeout(keepTimer);
    keepTimer = setTimeout(clear, KEEP_MS);
  }

  // Literal multi-pattern search: shared prefixes and repeated occurrences are
  // visited once, without a regex made from untrusted candidate strings.
  function matcher(patterns) {
    const nodes = [{ next: new Map(), fail: 0, output: [], suffix: 0 }];
    patterns.forEach((value, id) => {
      let state = 0;
      for (let i = 0; i < value.length; i++) {
        const c = value[i];
        if (!nodes[state].next.has(c)) {
          nodes[state].next.set(c, nodes.length);
          nodes.push({ next: new Map(), fail: 0, output: [], suffix: 0 });
        }
        state = nodes[state].next.get(c);
      }
      if (value.length) nodes[state].output.push(id);
    });
    const queue = Array.from(nodes[0].next.values());
    for (let head = 0; head < queue.length; head++) {
      const state = queue[head];
      for (const [c, child] of nodes[state].next) {
        let fail = nodes[state].fail;
        while (fail && !nodes[fail].next.has(c)) fail = nodes[fail].fail;
        fail = nodes[fail].next.get(c) || 0;
        nodes[child].fail = fail;
        nodes[child].suffix = nodes[fail].output.length ? fail : nodes[fail].suffix;
        queue.push(child);
      }
    }
    return nodes;
  }

  async function scan() {
    if (observer) observer.disconnect();
    const generation = ++revision;
    const found = values.map(() => []), roots = [document];
    const machine = matcher(values);
    const blocks = new WeakMap(), excluded = new WeakMap();
    let count = 0, chars = 0, visited = 0, partial = false, slice = performance.now();
    function blockFor(element) {
      if (!element) return null;
      if (blocks.has(element)) return blocks.get(element);
      const display = getComputedStyle(element).display;
      const block = display === 'contents' || display.startsWith('inline')
        ? blockFor(element.parentElement) : element;
      blocks.set(element, block); return block;
    }
    function isExcluded(element) {
      if (!element) return false;
      if (excluded.has(element)) return excluded.get(element);
      const skip = /^(SCRIPT|STYLE|NOSCRIPT|TEXTAREA|INPUT|SELECT|OPTION|CANVAS|SVG)$/.test(element.tagName)
        || element.hidden || element.isContentEditable
        || element.getAttribute('aria-hidden') === 'true' || element === canvas
        || getComputedStyle(element).display === 'none' || isExcluded(element.parentElement);
      excluded.set(element, skip); return skip;
    }
    function addRun(text, segments) {
      let state = 0;
      function point(offset, end) {
        let lo = 0, hi = segments.length;
        while (lo < hi) {
          const mid = (lo + hi) >> 1;
          if (segments[mid].offset < offset || (!end && segments[mid].offset === offset)) lo = mid + 1;
          else hi = mid;
        }
        const segment = segments[Math.max(0, lo - 1)];
        return [segment.node, offset - segment.offset];
      }
      for (let i = 0; i < text.length; i++) {
        const c = text[i];
        while (state && !machine[state].next.has(c)) state = machine[state].fail;
        state = machine[state].next.get(c) || 0;
        for (let output = state; output; output = machine[output].suffix) {
          for (const id of machine[output].output) {
            const [startNode, start] = point(i + 1 - values[id].length, false);
            const [endNode, end] = point(i + 1, true);
            const range = document.createRange();
            range.setStart(startNode, start); range.setEnd(endNode, end);
            if (!range.getClientRects().length) continue;
            found[id].push(range);
            if (++count >= MAX_MATCHES) { partial = true; return; }
          }
        }
      }
    }
    for (let rootIndex = 0; rootIndex < roots.length && !partial; rootIndex++) {
      const walker = document.createTreeWalker(roots[rootIndex], NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
      let node, text = '', segments = [], block = null;
      const flush = () => { if (text && !partial) addRun(text, segments); text = ''; segments = []; };
      while ((node = walker.nextNode()) && !partial) {
        if (++visited > MAX_NODES || chars >= MAX_CHARS) { flush(); partial = true; break; }
        if (node.nodeType === Node.ELEMENT_NODE) {
          if (node.tagName === 'BR') flush();
          if (node.shadowRoot && !isExcluded(node)) roots.push(node.shadowRoot);
          continue;
        }
        const parent = node.parentElement;
        if (!parent || isExcluded(parent) || getComputedStyle(parent).visibility !== 'visible') { flush(); continue; }
        const nextBlock = blockFor(parent);
        if (nextBlock !== block) { flush(); block = nextBlock; }
        segments.push({ node, offset: text.length });
        const part = node.data.slice(0, MAX_CHARS - chars);
        text += part; chars += part.length;
        if (part.length < node.data.length) { flush(); partial = true; }
        // Yield on large DOMs; cancellation/disconnection invalidates this scan.
        if (performance.now() - slice > 8) {
          await new Promise(resolve => setTimeout(resolve, 0));
          if (generation !== revision || (!owner && !kept)) return false;
          slice = performance.now();
        }
      }
      flush();
    }
    if (generation !== revision || (!owner && !kept)) return false;
    matches = found; limited = partial; dirty = false; selected = null;
    clearPaint();
    if (cssHighlights) {
      try {
        const highlight = new Highlight();
        found.forEach(ranges => ranges.forEach(range => highlight.add(range)));
        CSS.highlights.set(name, highlight);
        roots.forEach(root => {
          // Constructed sheets work under a SIEM's restrictive inline-style CSP
          // and don't add style text to subsequent DOM log extraction.
          const sheet = new CSSStyleSheet();
          sheet.replaceSync(`::highlight(${name}) { background-color: #fecaca; color: #7f1d1d; }
            ::highlight(${activeName}) { background-color: #b91c1c; color: #ffffff; text-decoration: underline; }`);
          root.adoptedStyleSheets = Array.prototype.concat.call(Array.prototype.slice.call(root.adoptedStyleSheets), [sheet]);
          styles.push({ root, sheet });
          // A wrapper can accept the assignment and drop the sheet: check it took.
          if (!Array.prototype.includes.call(root.adoptedStyleSheets, sheet)) throw new Error('style not attached');
        });
      } catch (_) {
        // From now on this page uses the canvas painter.
        clearPaint();
        cssHighlights = false;
      }
    }
    if (!cssHighlights) {
      // Older browsers: paint rectangles, without inserting wrappers into SIEM
      // text or changing selections, event handlers, or copied log content.
      canvas = document.createElement('canvas');
      canvas.setAttribute('aria-hidden', 'true');
      canvas.style.cssText = 'position:fixed!important;inset:0!important;width:100vw!important;height:100vh!important;pointer-events:none!important;z-index:2147483647!important;';
      document.documentElement.appendChild(canvas);
      schedulePaint();
    }
    if (observer) observer.disconnect();
    observer = new MutationObserver(records => {
      if (records.every(record => record.target === canvas ||
          (record.type === 'childList' && [...record.addedNodes, ...record.removedNodes].every(n => n === canvas)))) return;
      dirty = true;
      clearTimeout(timer);
      timer = setTimeout(() => { if (owner || kept) scan().catch(() => {}); }, 250);
    });
    roots.forEach(root => observer.observe(root, { childList: true, subtree: true, characterData: true }));
    return true;
  }

  function schedulePaint() {
    if (!canvas || paintFrame) return;
    paintFrame = requestAnimationFrame(() => {
      paintFrame = null;
      if (!canvas) return;
      canvas.width = innerWidth; canvas.height = innerHeight;
      const ctx = canvas.getContext('2d');
      function paint(range, active) {
        ctx.fillStyle = active ? '#dc262666' : '#ef444433';
        for (const rect of range.getClientRects()) {
          if (rect.bottom >= 0 && rect.top <= innerHeight && rect.right >= 0 && rect.left <= innerWidth) {
            ctx.fillRect(rect.x, rect.y, rect.width, rect.height);
            if (active) {
              ctx.strokeStyle = '#b91c1c'; ctx.lineWidth = 2;
              ctx.strokeRect(rect.x, rect.y, rect.width, rect.height);
            }
          }
        }
      }
      matches.forEach(ranges => ranges.forEach(range => paint(range, false)));
      if (selected) paint(selected, true);
    });
  }
  function focusRange(range) {
    const element = range.startContainer.parentElement;
    element.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' });
    // A log may be a single tall/wide <pre>; scroll to the text, not its box.
    for (let parent = element; parent; parent = parent.parentElement) {
      const rect = range.getClientRects()[0], box = parent.getBoundingClientRect();
      if (!rect) return;
      if (parent.scrollHeight > parent.clientHeight && /(auto|scroll)/.test(getComputedStyle(parent).overflowY))
        parent.scrollTop += rect.top - box.top - parent.clientHeight / 2;
      if (parent.scrollWidth > parent.clientWidth && /(auto|scroll)/.test(getComputedStyle(parent).overflowX))
        parent.scrollLeft += rect.left - box.left - parent.clientWidth / 2;
    }
    const rect = range.getClientRects()[0];
    if (rect) window.scrollBy({ top: rect.top - innerHeight / 2, left: rect.left - innerWidth / 2, behavior: 'instant' });
    selected = range;
    if (cssHighlights) {
      const highlight = new Highlight(range); highlight.priority = 1;
      CSS.highlights.set(activeName, highlight);
    }
    schedulePaint();
  }

  api.runtime.onConnect.addListener(port => {
    if (port.name !== 'veilux-secret-review') return;
    const previous = owner;
    clear(); owner = port;
    if (previous) previous.disconnect();
    let chain = Promise.resolve();
    port.onMessage.addListener(message => {
      // Release is handled at once: the popup disconnects right after sending it,
      // and a disconnect alone means "keep the highlights".
      if (message && message.action === 'release') {
        if (owner === port && message.nonce === identity.nonce) { clear(); owner = null; }
        return;
      }
      chain = chain.then(async () => {
        if (owner !== port) return;
        if (message.nonce !== identity.nonce || message.url !== location.href) throw new Error('The page changed. Extract again to review this page.');
        if (message.action === 'init') {
          values = message.values.filter(value => typeof value === 'string' && value.length);
          if (values.length > 5000 || values.reduce((n, value) => n + value.length, 0) > 1000000)
            throw new Error('Too many values to highlight on this page. Review smaller batches.');
          addEventListener('scroll', schedulePaint, true);
          addEventListener('resize', schedulePaint);
          if (!await scan()) return;
        } else if (message.action === 'find' || message.action === 'refresh') {
          if (dirty || message.action === 'refresh') { if (!await scan()) return; }
          if (message.action === 'find') {
            const ranges = (matches[message.valueIndex] || []).filter(range => range.startContainer.isConnected && range.toString() === values[message.valueIndex]);
            matches[message.valueIndex] = ranges;
            const index = ranges.length ? ((message.index % ranges.length) + ranges.length) % ranges.length : -1;
            if (index >= 0) focusRange(ranges[index]);
            port.postMessage({ id: message.id, counts: matches.map(items => items.length), index, limited });
            return;
          }
        }
        port.postMessage({ id: message.id, counts: matches.map(items => items.length), limited });
      }).catch(error => { try { port.postMessage({ id: message.id, error: error.message }); } catch (_) {} });
    });
    port.onDisconnect.addListener(() => { if (owner === port) { owner = null; keep(); } });
  });
  return identity;
})();
