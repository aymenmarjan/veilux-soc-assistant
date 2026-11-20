/* Connection editor.
   One form, five questions: basics, where the logs are, the API request, where its
   values come from, and how to sign in. It reads and writes the existing saved
   connection format, so the popup, backend and older connections are unchanged. */
globalThis.ConnectorEditor = (() => {
  const $ = id => document.getElementById('conn-' + id);
  const value = id => $(id).value.trim();
  const set = (id, v) => { $(id).value = v ?? ''; };
  const form = document.getElementById('connector-form');
  const trigger = document.getElementById('add-connector-trigger');
  const cardsList = $('values');
  const READERS = { table: 'table_scrape', json: 'json_dom', inspector: 'inspector_panel', script: 'custom_script' };
  const READER_OF = Object.fromEntries(Object.entries(READERS).map(([k, v]) => [v, k]));
  const READER_LABEL = { table: 'a table on the page', json: 'JSON shown on the page', inspector: 'the search Inspector panel', script: 'a custom page script', api: 'an API request' };
  const NEVER = '(?!)';
  const AUTH_HELP = {
    browser_session: 'Sign in to the platform in this browser and keep a tab open. VEILUX reuses that login.',
    cookie: 'Sends only the named cookie. If records open in your browser but VEILUX gets HTTP 401, choose “Use my current browser login”.',
    header: 'Use a current key or token that is allowed to read the records.',
    basic: 'Use an account the API accepts. A single sign-on password may not work here.',
    oauth_client_credentials: 'For APIs that issue tokens to a registered app, such as Microsoft Entra ID app registrations. Requests run through the local backend.',
    none: 'Only for APIs that answer without signing in.'
  };
  const TYPES = {
    url: { title: 'The page address', help: 'Captures values from the address (URL) of the page you are viewing.' },
    links: { title: 'Links on a page', help: 'Finds record links on a page, for example in a case description. One request is made for each matching link.' },
    text: { title: 'Text on a page', help: 'Captures values from text shown on the page, such as “Alert 42”.' },
    attribute: { title: 'An element attribute', help: 'Reads an attribute such as href or data-event-id from an element on the page.' },
    fixed: { title: 'A fixed value', help: 'Always uses the same value, such as a workspace ID.' }
  };
  let editingIndex = null, existing = {}, sequence = 0, copyable = [];

  const fail = (target, message) => { throw { target, message }; };
  const safeName = name => /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) && !['__proto__', 'constructor', 'prototype'].includes(name);
  const regexGroups = re => [...(re || '').replace(/\(\?P</g, '(?<').matchAll(/\(\?<([A-Za-z_][A-Za-z0-9_]*)>/g)].map(m => m[1]);
  const templateNames = t => [...(t || '').matchAll(/\{([A-Za-z_][A-Za-z0-9_]*)\}/g)].map(m => m[1]);
  const source = () => form.querySelector('input[name="conn-source"]:checked')?.value || '';
  const reader = () => source() === 'api' ? value('api-fallback') : source();
  const uniqueFlags = flags => [...new Set(flags)].join('');

  function websiteURL(raw = value('siem-address')) {
    if (!raw) return null;
    try {
      const url = new URL(raw.includes('://') ? raw : 'https://' + raw);
      return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password ? url : null;
    } catch (_) { return null; }
  }
  function context() {
    const url = websiteURL();
    return { origin: url?.origin || '', siemHost: url?.hostname || '' };
  }
  function tabFor(match) {
    return browser.tabs.query({}).then(tabs => tabs.find(t => t.active && match(t.url)) || tabs.find(t => match(t.url)));
  }

  /* ---------- Value sources ---------- */

  function field(card, key, label, opts = {}) {
    const wrap = document.createElement('div'); wrap.className = opts.type === 'checkbox' ? 'toggle-label' : 'form-group';
    wrap.dataset.group = key;
    const id = 'value-' + (++sequence) + '-' + key;
    const caption = document.createElement('label'); caption.htmlFor = id; caption.textContent = label;
    let input;
    if (opts.choices) {
      input = document.createElement('select');
      opts.choices.forEach(([v, text]) => input.add(new Option(text, v)));
    } else {
      input = document.createElement('input'); input.type = opts.type || 'text';
      if (opts.placeholder) input.placeholder = opts.placeholder;
    }
    input.id = id; input.dataset.key = key;
    if (opts.type === 'checkbox') { input.checked = !!opts.value; wrap.append(input, caption); }
    else { input.value = opts.value ?? ''; wrap.append(caption, input); }
    if (opts.hint) { const p = document.createElement('p'); p.className = 'field-hint'; p.textContent = opts.hint; wrap.append(p); }
    (opts.parent || card).append(wrap);
    return input;
  }
  const cardInput = (card, key) => card.querySelector('[data-key="' + key + '"]');
  const cardGroup = (card, key) => card.querySelector('[data-group="' + key + '"]');

  function addCard(type, data = {}) {
    const d = { site: type === 'links' ? 'other' : 'main', patternType: 'template', decode: type === 'url' || type === 'attribute', required: true, read: 'text', attribute: 'href', ...data };
    const card = document.createElement('fieldset');
    card.className = 'value-card'; card.dataset.type = type; card.dataset.sourceName = d.sourceName || ''; card.dataset.extraFlags = d.extraFlags || '';
    const legend = document.createElement('legend'); legend.textContent = TYPES[type].title; card.append(legend);
    const help = document.createElement('p'); help.className = 'field-hint'; help.textContent = TYPES[type].help; card.append(help);
    if (type !== 'fixed') {
      field(card, 'site', 'Read it on', { value: d.site, choices: [['main', 'This connection’s website'], ['other', 'Another website, such as a case platform']] });
      field(card, 'website', 'Website address', { value: d.website, placeholder: 'https://tickets.example.com',
        hint: 'Enter only the hostname, such as cases.example.com, to match it on any port.' });
      field(card, 'urlIncludes', 'Only when the page address contains (optional)', { value: d.urlIncludes, placeholder: '/ticket/' });
    }
    if (type === 'url' || type === 'links') {
      if (type === 'links') field(card, 'selector', 'Part of the page to search (optional)', { value: d.selector, placeholder: '.record-links',
        hint: 'A CSS selector. Leave blank to check every link on the page. If addresses are written as plain text, enter the element that contains them.' });
      field(card, 'patternType', type === 'url' ? 'Describe the address with' : 'Describe the links with', { value: d.patternType,
        choices: [['template', 'An example address with {names}'], ['regex', 'A regular expression']] });
      field(card, 'template', type === 'url' ? 'Address pattern' : 'Link pattern', { value: d.template, placeholder: 'https://siem.example.com/events/{event_id}',
        hint: 'Paste a real address and replace each changing part with a name in braces. {event_id} fills ${event_id} in the request.' });
      field(card, 'regex', 'Regular expression', { value: d.regex, placeholder: '/events/(?<event_id>[^/?#]+)',
        hint: 'Name each value with a group such as (?<event_id>...). Each name fills the matching ${name} in the request.' });
      if (type === 'links') {
        field(card, 'linkHost', 'Accept links to', { value: d.linkHost || '', choices: [['', 'This connection’s website'], ['*', 'Any website (the expression decides)'], ['host', 'Another host']] });
        field(card, 'host', 'Host', { value: d.host, placeholder: 'files.example.com' });
      }
      const row = document.createElement('div'); row.className = 'value-example';
      field(card, 'example', type === 'url' ? 'Example address to test' : 'Example link to test', { value: '', placeholder: 'https://…', parent: row });
      const check = document.createElement('button'); check.type = 'button'; check.className = 'btn btn-secondary btn-small'; check.textContent = 'Check example';
      check.addEventListener('click', () => checkExample(card)); row.append(check); card.append(row);
    }
    if (type === 'text' || type === 'attribute') {
      field(card, 'selector', type === 'text' ? 'Element (optional)' : 'Element', { value: d.selector, placeholder: type === 'text' ? '#description, .case-title' : 'a.event-link, [data-event-id]',
        hint: type === 'text' ? 'A CSS selector. Leave blank to search the whole page.' : 'A CSS selector, such as #event or a.event-link.' });
      if (type === 'attribute') field(card, 'attribute', 'Attribute', { value: d.attribute, placeholder: 'href or data-event-id' });
      field(card, 'pattern', 'Value pattern (optional regular expression)', { value: d.pattern, placeholder: type === 'text' ? 'Alert (?<alert_id>\\d+)' : 'id=(?<event_id>\\d+)',
        hint: 'Name each value with a group such as (?<name>...). Leave blank to use the whole ' + (type === 'text' ? 'text' : 'attribute') + ' as one value.' });
      field(card, 'name', 'Value name', { value: d.name, placeholder: 'event_id', hint: 'Used as ${name} in the request.' });
    }
    if (type === 'fixed') {
      field(card, 'name', 'Value name', { value: d.name, placeholder: 'workspace', hint: 'Used as ${name} in the request.' });
      field(card, 'value', 'Value', { value: d.value });
    }
    if (type !== 'fixed') {
      const options = document.createElement('details'); options.className = 'value-options';
      const summary = document.createElement('summary'); summary.textContent = 'Options'; options.append(summary);
      if (type === 'text') field(card, 'read', 'Read', { value: d.read, choices: [['text', 'The visible text'], ['html', 'The HTML source']], parent: options });
      if (type === 'text' || type === 'attribute') {
        field(card, 'ignoreCase', 'Ignore letter case in the pattern', { type: 'checkbox', value: d.ignoreCase, parent: options });
        field(card, 'repeat', 'Make one request for each value found', { type: 'checkbox', value: d.repeat, parent: options });
      }
      if (type !== 'links') field(card, 'decode', 'Decode URL-encoded values (%20 becomes a space)', { type: 'checkbox', value: d.decode, parent: options });
      if (type !== 'links') field(card, 'required', 'Required: stop with an error when no value is found', { type: 'checkbox', value: d.required, parent: options });
      const note = document.createElement('p'); note.className = 'field-hint'; note.dataset.group = 'mainNote';
      note.textContent = 'On this connection’s website, values are optional: when none is found, VEILUX uses the choice under “When the current page provides none of these values”.';
      options.append(note); card.append(options);
    }
    const actions = document.createElement('div'); actions.className = 'value-actions';
    if (type !== 'fixed') {
      const test = document.createElement('button'); test.type = 'button'; test.className = 'btn btn-secondary btn-small'; test.textContent = 'Test on the open page';
      test.addEventListener('click', () => testCard(card, test)); actions.append(test);
    }
    const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'btn btn-danger btn-small'; remove.textContent = 'Remove';
    remove.setAttribute('aria-label', 'Remove value source: ' + TYPES[type].title);
    remove.addEventListener('click', () => { card.remove(); show(); }); actions.append(remove);
    card.append(actions);
    const result = document.createElement('pre'); result.className = 'value-result'; result.setAttribute('role', 'status'); card.append(result);
    card.addEventListener('input', () => updateCard(card));
    card.addEventListener('change', () => updateCard(card));
    cardsList.append(card); updateCard(card);
    return card;
  }

  function updateCard(card) {
    const type = card.dataset.type, other = cardInput(card, 'site')?.value === 'other';
    const hide = (key, hidden) => { const g = cardGroup(card, key); if (g) g.hidden = hidden; };
    hide('website', !other);
    const template = cardInput(card, 'patternType')?.value !== 'regex';
    hide('template', !template); hide('regex', template);
    hide('linkHost', template); hide('host', template || cardInput(card, 'linkHost')?.value !== 'host');
    if (type === 'text' || type === 'attribute') hide('name', !!cardInput(card, 'pattern').value.trim());
    hide('required', !other); hide('mainNote', other || type === 'links');
    card.querySelectorAll('[data-group][hidden] [aria-invalid]').forEach(clearFieldError);
    updatePlaceholders();
  }

  function readCard(card) {
    const d = { type: card.dataset.type, sourceName: card.dataset.sourceName, extraFlags: card.dataset.extraFlags, card };
    card.querySelectorAll('[data-key]').forEach(input => { d[input.dataset.key] = input.type === 'checkbox' ? input.checked : input.value.trim(); });
    if (d.site === 'other') d.website = d.website.replace(/\/+$/, '');
    return d;
  }

  function cardNames(d) {
    if (d.type === 'url' || d.type === 'links') return d.patternType === 'regex' ? regexGroups(d.regex) : templateNames(d.template);
    if (d.type === 'text' || d.type === 'attribute') return d.pattern ? regexGroups(d.pattern) : (d.name ? [d.name] : []);
    return d.name ? [d.name] : [];
  }

  // Checks a card's own fields and returns its regular expression for links/addresses.
  function checkCard(d) {
    const el = key => cardInput(d.card, key);
    if (d.type !== 'fixed' && d.site === 'other' && !d.website) fail(el('website'), 'Enter the website address where this value is found.');
    if (d.type === 'url' || d.type === 'links') {
      if (d.patternType === 'regex') {
        if (!d.regex) fail(el('regex'), 'Enter a regular expression.');
        try { new RegExp(d.regex.replace(/\(\?P</g, '(?<')); } catch (_) { fail(el('regex'), 'This regular expression is invalid. Check its brackets and escapes.'); }
        if (!regexGroups(d.regex).length) fail(el('regex'), 'Name the captured values with groups such as (?<event_id>...).');
        if (d.type === 'links' && d.linkHost === 'host' && !d.host) fail(el('host'), 'Enter the host the links point to.');
        return d.regex.replace(/\(\?P</g, '(?<');
      }
      if (!d.template) fail(el('template'), 'Paste an example address and replace each changing part with {name}.');
      if (!/^https?:\/\//i.test(d.template)) fail(el('template'), 'Use a complete address starting with https:// or http://.');
      try { return VeiluxConnectors.linkPattern({ schemaVersion: 2, api: { linkTemplate: d.template } }); }
      catch (e) { fail(el('template'), e.message); }
    }
    if (d.type === 'attribute' && !d.selector) fail(el('selector'), 'Enter the element that carries the attribute.');
    if (d.type === 'attribute' && !d.attribute) fail(el('attribute'), 'Enter an attribute name, such as href or data-event-id.');
    if (d.type === 'text' || d.type === 'attribute') {
      if (d.pattern) {
        try { new RegExp(d.pattern.replace(/\(\?P</g, '(?<')); } catch (_) { fail(el('pattern'), 'This regular expression is invalid. Check its brackets and escapes.'); }
        if (!regexGroups(d.pattern).length) fail(el('pattern'), 'Name the captured values with groups such as (?<event_id>\\d+), or clear the pattern and enter a value name.');
      } else if (!safeName(d.name || '')) fail(el('name'), 'Enter a value name using letters, digits and _, such as event_id.');
    }
    if (d.type === 'fixed' && !safeName(d.name || '')) fail(el('name'), 'Enter a value name using letters, digits and _, such as workspace.');
    cardNames(d).forEach(name => { if (!safeName(name)) fail(el(d.pattern ? 'pattern' : d.regex ? 'regex' : 'template'), 'Use letters, digits and _ in value names. ' + name + ' is not allowed.'); });
    return null;
  }

  function ruleFromCard(d, main) {
    const required = main ? false : d.required !== false;
    if (d.type === 'url') return { source: 'page_url', pattern: checkCard(d), template: d.patternType === 'regex' ? undefined : d.template, flags: '', decode: !!d.decode, required, repeat: false };
    const flags = uniqueFlags((d.ignoreCase ? 'i' : '') + (d.extraFlags || ''));
    if (d.type === 'text') return { source: d.read === 'html' ? 'html' : 'text', selector: d.selector || 'body', pattern: d.pattern, name: d.pattern ? '' : d.name, flags, decode: !!d.decode, required, repeat: !!d.repeat };
    return { source: 'attribute', selector: d.selector, attribute: d.attribute, pattern: d.pattern, name: d.pattern ? '' : d.name, flags, decode: !!d.decode, required, repeat: !!d.repeat };
  }

  function linksSource(d, src) {
    checkCard(d);
    src.mode = 'links'; src.selector = d.selector || 'a[href]';
    if (d.patternType === 'regex') { src.pattern = d.regex; src.linkHost = d.linkHost === 'host' ? normalizeHostInput(d.host) : d.linkHost || ''; }
    else { src.linkTemplate = d.template; src.linkHost = new URL(d.template).hostname; }
    return src;
  }

  // A single-card page source, used by "Test on the open page".
  function cardSource(d, ctx) {
    const src = { name: d.sourceName || '', website: d.site === 'other' ? d.website : ctx.origin, urlIncludes: d.urlIncludes || '', mode: 'parameters', rules: [] };
    if (d.type === 'links') return linksSource(d, src);
    src.rules = [{ ...ruleFromCard(d, false), required: true }];
    return src;
  }

  // Turns the cards into the saved format: fixed values become request parameters,
  // the address and text of the connection's own website keep their dedicated
  // fields, and everything else becomes page sources grouped by page.
  function compile(cards, ctx) {
    const out = { linkTemplate: '', linkRegex: '', contentRegex: '', contentSelector: '', contentFlags: '', parameters: {}, pageSources: [] };
    const groups = new Map();
    let haveUrl = false, haveText = false;
    for (const d of cards) {
      checkCard(d);
      if (d.type === 'fixed') {
        if (Object.hasOwn(out.parameters, d.name)) fail(cardInput(d.card, 'name'), 'Another fixed value already uses the name ' + d.name + '.');
        out.parameters[d.name] = d.value; continue;
      }
      const main = d.site === 'main';
      if (main && !d.urlIncludes && d.type === 'url' && !haveUrl && d.decode) {
        haveUrl = true;
        if (d.patternType === 'regex') out.linkRegex = d.regex; else out.linkTemplate = d.template;
        continue;
      }
      if (main && !d.urlIncludes && d.type === 'text' && !haveText && d.pattern && d.read !== 'html' && !d.repeat && !d.decode) {
        haveText = true;
        out.contentRegex = d.pattern; out.contentSelector = d.selector; out.contentFlags = uniqueFlags((d.ignoreCase ? 'i' : '') + (d.extraFlags || ''));
        continue;
      }
      const key = (main ? '' : d.website.toLowerCase()) + '\n' + d.urlIncludes;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(d);
    }
    for (const group of groups.values()) {
      const links = group.filter(d => d.type === 'links');
      if (links.length > 1) fail(cardInput(links[1].card, 'patternType'), 'Use one “Links on a page” source per page. To accept several link formats, combine them in one regular expression.');
      const first = group[0], main = first.site === 'main';
      let host = ''; try { host = main ? new URL(ctx.origin).hostname : new URL(ConnectorSources.hostOnly(first.website) ? 'https://' + first.website : first.website).hostname; } catch (_) {}
      let src = { name: first.sourceName || ((host || 'Page') + (first.urlIncludes ? ' ' + first.urlIncludes : '')), website: main ? ctx.origin : first.website,
        urlIncludes: first.urlIncludes, mode: 'parameters', rules: [] };
      if (links.length) src = linksSource(links[0], src);
      const others = group.filter(d => d.type !== 'links');
      src.rules = others.map(d => ruleFromCard(d, main));
      try { ConnectorSources.validate(src); }
      catch (e) {
        const card = Number.isInteger(e.ruleIndex) ? others[e.ruleIndex]?.card : (e.field === 'website' ? first.card : (links[0] || others.find(d => d.repeat) || first).card);
        fail(e.field && card ? cardInput(card, e.field) || card.querySelector('[data-key]') : card?.querySelector('[data-key]'), e.message.replace(/^Parameter rule \d+: /, ''));
      }
      out.pageSources.push(src);
    }
    if (out.pageSources.length > 20) fail(cardsList, 'Use value sources on at most 20 different pages.');
    return out;
  }

  // Turns a saved connection back into cards.
  function decompile(p) {
    const a = p.api || {}, cards = [];
    let origin = '';
    try { origin = new URL(p.websiteUrl || p.siemBaseUrl || 'https://' + p.siemHost).origin; } catch (_) {}
    for (const [name, v] of Object.entries(a.parameters || {})) cards.push({ type: 'fixed', name, value: String(v) });
    const usable = a.linkRegex && a.linkRegex !== NEVER ? a.linkRegex : '';
    const inherited = a.linkTemplate ? { patternType: 'template', template: a.linkTemplate } : { patternType: 'regex', regex: usable };
    if (a.linkTemplate) cards.push({ type: 'url', site: 'main', patternType: 'template', template: a.linkTemplate, decode: true });
    else if (usable) cards.push({ type: 'url', site: 'main', patternType: 'regex', regex: usable, decode: true });
    if (a.contentRegex) {
      const flags = a.contentFlags || '';
      cards.push({ type: 'text', site: 'main', selector: a.contentSelector || '', pattern: a.contentRegex, ignoreCase: flags.includes('i'), extraFlags: flags.replace(/i/g, ''), decode: false });
    }
    for (const s of p.pageSources || []) {
      let main = false;
      try { main = !ConnectorSources.hostOnly(s.website) && new URL(s.website).origin === origin; } catch (_) {}
      const base = { site: main ? 'main' : 'other', website: main ? '' : s.website, urlIncludes: s.urlIncludes || '', sourceName: s.name || '' };
      if (s.mode === 'links') {
        const pattern = s.linkTemplate ? { patternType: 'template', template: s.linkTemplate } : s.pattern ? { patternType: 'regex', regex: s.pattern } : inherited;
        const host = s.linkHost || '';
        cards.push({ type: 'links', ...base, selector: s.selector === 'a[href]' ? '' : s.selector || '', ...pattern,
          linkHost: host === '' || host === '*' ? host : 'host', host: host === '*' ? '' : host });
      }
      for (const r of s.rules || []) {
        const flags = r.flags || '', common = { ...base, required: r.required !== false, repeat: !!r.repeat, decode: !!r.decode, ignoreCase: flags.includes('i'), extraFlags: flags.replace(/i/g, '') };
        if (r.source === 'page_url') cards.push({ type: 'url', ...common, ...(r.template ? { patternType: 'template', template: r.template } : { patternType: 'regex', regex: r.pattern }) });
        else if (r.source === 'text' || r.source === 'html') cards.push({ type: 'text', ...common, read: r.source, selector: r.selector === 'body' ? '' : r.selector, pattern: r.pattern || '', name: r.name || '' });
        else if (r.source === 'attribute') cards.push({ type: 'attribute', ...common, selector: r.selector, attribute: r.attribute, pattern: r.pattern || '', name: r.name || '' });
        else if (r.source === 'constant') {
          if (!r.pattern) { if (r.name) cards.push({ type: 'fixed', name: r.name, value: r.value || '' }); }
          else {
            try {
              const groups = new RegExp(r.pattern.replace(/\(\?P</g, '(?<'), flags).exec(r.value || '')?.groups || {};
              Object.entries(groups).forEach(([name, v]) => v !== undefined && cards.push({ type: 'fixed', name, value: v }));
            } catch (_) { /* An invalid constant rule could never produce a value. */ }
          }
        }
      }
    }
    return cards;
  }

  async function checkExample(card) {
    const d = readCard(card), result = card.querySelector('.value-result');
    try {
      if (!d.example) fail(cardInput(card, 'example'), 'Paste an example address first.');
      const pattern = checkCard(d);
      const match = new RegExp(pattern).exec(d.example);
      if (!match?.groups) { result.textContent = 'No match. Adjust the pattern so it matches this example.'; return; }
      const values = Object.fromEntries(Object.entries(match.groups).filter(([, v]) => v !== undefined).map(([k, v]) => {
        try { return [k, d.type === 'links' || d.decode ? decodeURIComponent(v) : v]; } catch (_) { return [k, v]; }
      }));
      result.textContent = 'Match. Values:\n' + JSON.stringify(values, null, 2);
    } catch (e) { result.textContent = e.message; if (e.target) fieldError(e.target, e.message); }
  }

  async function testCard(card, button) {
    const d = readCard(card), result = card.querySelector('.value-result');
    button.disabled = true; result.textContent = 'Reading the open page…';
    try {
      const ctx = context();
      if (d.site === 'main' && !ctx.origin) fail($('siem-address'), 'Enter the website address first.');
      const src = cardSource(d, ctx);
      try { ConnectorSources.validate(src); } catch (e) { fail(cardInput(card, e.field) || card.querySelector('[data-key]'), e.message.replace(/^Parameter rule \d+: /, '')); }
      const tab = await tabFor(url => ConnectorSources.matches(src, url));
      if (!tab) fail(null, 'Open a page on ' + src.website + (src.urlIncludes ? ' whose address contains ' + src.urlIncludes : '') + ' in another tab, then try again.');
      const prepared = await ConnectorSources.prepare({ schemaVersion: 2, siemHost: ctx.siemHost, api: {} }, src, tab);
      const values = prepared.records.map(r => r.params);
      result.textContent = values.length + (values.length === 1 ? ' request' : ' requests') + ' would be made. Nothing was sent.\n' + JSON.stringify(values.slice(0, 10), null, 2);
    } catch (e) { result.textContent = e.message; if (e.target) fieldError(e.target, e.message); }
    finally { button.disabled = false; }
  }

  /* ---------- Placeholder check ---------- */

  function requestTexts() {
    const ids = value('fetch-mode') === 'search_job'
      ? ['job-create-path', 'job-create-query', 'job-create-body', 'job-status-path', 'job-results-path']
      : ['api-path', 'api-query', 'api-body'];
    return ids.concat(['context-path', 'api-headers']).map(value);
  }
  function updatePlaceholders() {
    const box = $('placeholders'); box.replaceChildren();
    if (source() !== 'api') return;
    const used = new Set();
    requestTexts().forEach(t => { for (const m of t.matchAll(/\$\{\s*([A-Za-z_][A-Za-z0-9_]*)/g)) used.add(m[1]); });
    ['job_id', 'context'].forEach(n => used.delete(n));
    if (value('fetch-mode') === 'search_job' && value('job-query-parameter')) used.add('query');
    const provided = new Map();
    [...cardsList.children].forEach(card => cardNames(readCard(card)).forEach(name => {
      if (!provided.has(name)) provided.set(name, []);
      provided.get(name).push(TYPES[card.dataset.type].title.toLowerCase());
    }));
    const heading = document.createElement('p'); heading.className = 'placeholder-heading';
    if (!used.size) { heading.textContent = 'This request has no ${name} placeholders, so it needs no values from the page.'; box.append(heading); }
    else {
      heading.textContent = 'Values this request uses:'; box.append(heading);
      const list = document.createElement('ul');
      for (const name of used) {
        const li = document.createElement('li'), code = document.createElement('code'); code.textContent = '${' + name + '}';
        let text, ok = true;
        if (name === 'query') text = value('default-query') ? ' from the default search, or a search typed in the popup' : ' from a search typed in the popup (no default search set)';
        else if (provided.has(name)) text = ' from ' + [...new Set(provided.get(name))].join(' or ');
        else { text = ' has no value source yet. Add one below.'; ok = false; }
        li.className = ok ? 'placeholder-ok' : 'placeholder-missing';
        li.append(ok ? '✓ ' : '⚠ ', code, text); list.append(li);
      }
      box.append(list);
    }
    const unused = [...provided.keys()].filter(name => !used.has(name));
    if (unused.length && used.size) {
      const note = document.createElement('p'); note.className = 'field-hint';
      note.textContent = 'Captured but not used in the request: ' + unused.map(n => '${' + n + '}').join(', ') + '. Check the spelling, or add them to the request.';
      box.append(note);
    }
  }

  /* ---------- Form state ---------- */

  const INSPECTOR_FIELDS = [['open-btn', 'openButtonSelector'], ['response-tab', 'responseTabSelector'], ['response-body', 'responseBodySelector'],
    ['close-btn', 'closeButtonSelector'], ['hits-path', 'hitsPath'], ['total-path', 'totalPath'], ['request-tab', 'requestTabSelector'],
    ['request-body', 'requestBodySelector'], ['request-url', 'requestUrlSelector'], ['statistics-tab', 'statisticsTabSelector']];
  let usedInspector = false;
  const needsInspector = () => reader() === 'inspector' || value('statistics-mode') === 'opensearch';
  // When the Inspector panel starts being used, its blank selector fields are
  // filled with the standard Inspector selectors, visibly and only once, so they
  // stay editable.
  function fillInspectorFields() {
    const now = needsInspector();
    if (now && !usedInspector) for (const [id, key] of INSPECTOR_FIELDS) if (!value(id)) set(id, VeiluxConnectors.opensearch.inspector[key]);
    usedInspector = now;
  }

  function show() {
    fillInspectorFields();
    const src = source(), api = src === 'api', current = reader();
    for (const key of Object.keys(READERS)) {
      const panel = $(key + '-panel');
      panel.hidden = current !== key || !src;
      panel.classList.toggle('as-fallback', api);
    }
    ['api-step', 'values-step', 'signin-step', 'more-api'].forEach(id => { $(id).hidden = !api; });
    const records = $('records-panel');
    // Move the records mapping only when needed: re-inserting it would cancel a click in progress.
    if (current === 'json' && !api) { if (records.parentElement !== $('json-panel')) $('json-panel').append(records); }
    else if (records.previousElementSibling !== $('records-home')) $('records-home').after(records);
    $('table-specific-fields').hidden = !$('table-specific').checked;
    const job = value('fetch-mode') === 'search_job';
    $('job-fields').hidden = !job; $('single-fields').hidden = job;
    $('api-body-group').hidden = value('api-method') === 'GET' && !value('api-body');
    $('columns-fields').hidden = value('record-format') !== 'columns';
    $('pagination-fields').hidden = value('pagination-mode') === 'none';
    $('cursor-group').hidden = value('pagination-mode') !== 'cursor';
    const auth = value('auth-type');
    $('auth-help').textContent = AUTH_HELP[auth] || '';
    $('cookie-name-group').hidden = auth !== 'cookie';
    $('header-auth-group').hidden = auth !== 'header';
    $('basic-auth-group').hidden = auth !== 'basic';
    $('oauth-group').hidden = auth !== 'oauth_client_credentials';
    $('session-headers-group').hidden = auth !== 'browser_session';
    $('copy-values-group').hidden = !copyable.length;
    form.querySelectorAll('[hidden] [aria-invalid]').forEach(clearFieldError);
    let summary;
    if (!src) summary = 'Choose where the logs are in step 2.';
    else if (api) {
      const count = cardsList.children.length;
      summary = 'Reads an API request' + (count ? ' using ' + count + ' value source' + (count === 1 ? '' : 's') : '') + '. '
        + (current === 'request' ? 'Without page values, it sends the request with fixed values and the default search.' : 'Without page values, it reads ' + READER_LABEL[current] + '.');
    } else summary = 'Reads ' + READER_LABEL[src] + '. No API is used.';
    $('summary').textContent = summary + ' Statistics: ' + $('statistics-mode').selectedOptions[0].textContent.toLowerCase() + '.';
    updatePlaceholders();
  }

  function fill(p) {
    const a = p.api || {}, d = p.dom?.discover || {}, j = a.job || {}, auth = p.auth || {}, pg = a.pagination || {}, ctx = a.context || {};
    const effective = VeiluxConnectors.api(p), isNew = !p.id;
    set('preset', CONNECTOR_PRESETS[p.platform] ? p.platform : '');
    $('preset-note').textContent = CONNECTOR_PRESET_NOTES[p.platform] || '';
    set('name', p.name);
    const address = p.websiteUrl || p.siemBaseUrl || (p.siemHost ? 'https://' + p.siemHost : '');
    set('siem-address', address);
    set('siem-base-url', p.siemBaseUrl || websiteURL(address)?.origin || '');
    $('siem-base-url').dataset.manual = p.siemBaseUrl && p.siemBaseUrl !== websiteURL(address)?.origin ? 'true' : '';
    // Where the logs are
    const strategy = d.strategy || 'table_scrape';
    const enabled = a.enabled ?? !!(a.pathTemplate || a.linkRegex || j.createPathTemplate);
    let src = '', fallback = 'request';
    if (strategy === 'api_request') src = 'api';
    else if (enabled) { src = 'api'; fallback = READER_OF[strategy] || 'table'; }
    else src = READER_OF[strategy] || 'table';
    if (isNew && !p.platform && !p.dom) src = '';
    form.querySelectorAll('input[name="conn-source"]').forEach(r => { r.checked = r.value === src; });
    set('api-fallback', fallback);
    $('table-auto').checked = !d.tableSelector; $('table-specific').checked = !!d.tableSelector;
    set('table-selector', d.tableSelector); $('table-list').replaceChildren();
    set('json-selector', d.jsonSelector || 'pre'); set('custom-script', d.customScript);
    INSPECTOR_FIELDS.forEach(([id, key]) => set(id, d[key]));
    // API request
    set('fetch-mode', a.fetchMode || 'single_request');
    set('api-method', effective.method || 'GET'); set('api-path', effective.pathTemplate);
    set('api-query', a.queryTemplate && Object.keys(a.queryTemplate).length ? JSON.stringify(a.queryTemplate) : '');
    set('api-body', effective.bodyTemplate);
    set('api-headers', effective.headers && Object.keys(effective.headers).length ? JSON.stringify(effective.headers) : '');
    set('job-create-method', j.createMethod || 'POST'); set('job-create-path', j.createPathTemplate);
    set('job-create-query', j.createQueryTemplate && Object.keys(j.createQueryTemplate).length ? JSON.stringify(j.createQueryTemplate) : '');
    set('job-create-body', j.createBodyTemplate); set('job-parameters-as', j.createParametersAs === 'form' ? 'form' : 'query');
    set('job-error-message', j.errorMessagePath);
    set('job-query-parameter', j.queryParameter ?? '');
    set('job-id-path', j.jobIdPath); set('job-status-path', j.statusPathTemplate); set('job-status-field', j.statusField);
    set('job-complete-values', j.completeValues); set('job-error-values', j.errorValues); set('job-results-path', j.resultsPathTemplate);
    set('job-poll-interval', j.pollIntervalSeconds); set('job-timeout', j.timeoutSeconds);
    set('default-query', a.defaultQuery);
    set('response-path', effective.responsePath); set('record-format', a.recordFormat || 'objects'); set('columns-path', a.columnsPath); set('total-records-path', a.totalPath);
    set('sample-response', ''); $('sample-path').replaceChildren(new Option('Whole response', '')); $('sample-result').textContent = '';
    set('pagination-mode', pg.mode || 'none'); set('pagination-parameter', pg.parameter || 'offset'); set('pagination-size-parameter', pg.sizeParameter);
    set('page-size', pg.pageSize || 100); set('max-pages', pg.maxPages || 10); set('cursor-path', pg.cursorPath);
    $('pagination-details').open = !!pg.mode && pg.mode !== 'none';
    set('context-path', ctx.pathTemplate); set('context-response-path', ctx.responsePath); $('context-details').open = !!ctx.pathTemplate;
    // Values
    cardsList.replaceChildren(); decompile(p).forEach(card => addCard(card.type, card));
    copyable = connectorProfiles.filter(other => other.id !== existing.id).map(other => ({ name: other.name,
      cards: decompile(other).filter(c => c.site === 'other') })).filter(c => c.cards.length);
    $('copy-values').replaceChildren(new Option('Choose a connection', ''), ...copyable.map((c, i) => new Option(c.name + ' (' + c.cards.length + ')', String(i))));
    // Sign-in
    set('auth-type', auth.type || 'browser_session'); set('cookie-name', auth.cookieName); set('header-name', auth.headerName);
    set('header-value', auth.headerValue); set('basic-username', auth.username); set('basic-password', auth.password);
    set('oauth-token-url', auth.tokenUrl); set('oauth-client-id', auth.clientId); set('oauth-client-secret', auth.clientSecret); set('oauth-scope', auth.scope);
    set('headers-from-cookies', renderCookieEchoConfig(auth.headersFromCookies));
    $('session-headers-group').open = !!value('headers-from-cookies');
    // More options
    set('page-match', p.pageMatch); set('discover-hint', p.discoverPathHint); set('sso-hint', p.ssoHint);
    set('max-records', p.maxRecords || 5000);
    set('statistics-mode', VeiluxConnectors.statsMode(p));
    set('test-path', a.testPath); set('execute-via', a.executeVia === 'backend' ? 'backend' : 'auto');
    $('verify-ssl').checked = p.verifySsl !== false; set('tls-trust', p.tlsTrust || 'system'); set('ca-pem', p.caBundlePem); $('ca-status').textContent = '';
    document.getElementById('connector-test-result').textContent = '';
    document.getElementById('connector-preview-result').textContent = '';
    form.querySelectorAll('[aria-invalid]').forEach(clearFieldError);
    usedInspector = needsInspector();
    show();
  }

  function open(index) {
    editingIndex = typeof index === 'number' ? index : null;
    existing = editingIndex !== null ? structuredClone(connectorProfiles[editingIndex] || {}) : {};
    fill(existing);
    $('more').open = false;
    form.classList.add('visible'); trigger.style.display = 'none';
    $('name').focus();
  }
  function close() {
    form.classList.remove('visible'); trigger.style.display = 'block';
    editingIndex = null; existing = {};
  }

  // Applying a template keeps the name and website, and replaces the technical settings.
  function applyTemplate(key) {
    const keep = { name: value('name'), address: value('siem-address') };
    const template = key ? structuredClone(CONNECTOR_PRESETS[key]) : {};
    fill({ ...template, platform: key, schemaVersion: 2, dom: template.dom || {}, id: undefined, maxRecords: undefined });
    set('name', keep.name); set('siem-address', keep.address);
    if (template.siemBaseUrl) { set('siem-base-url', template.siemBaseUrl); $('siem-base-url').dataset.manual = 'true'; }
    else syncAddress();
    if (!key) form.querySelectorAll('input[name="conn-source"]').forEach(r => { r.checked = false; });
    show();
  }

  function syncAddress() {
    const url = websiteURL();
    if (url && $('siem-base-url').dataset.manual !== 'true') set('siem-base-url', url.origin);
  }

  /* ---------- Reading the form ---------- */

  function object(id, strings = false) {
    if (!value(id)) return {};
    let data; try { data = JSON.parse(value(id)); } catch (_) { fail($(id), 'Enter valid JSON, for example {"name":"value"}.'); }
    if (!data || typeof data !== 'object' || Array.isArray(data) || (strings && Object.values(data).some(v => typeof v !== 'string')))
      fail($(id), strings ? 'Use a JSON object with text values, for example {"name":"value"}.' : 'Use a JSON object.');
    return data;
  }
  function integer(id, fallback, max) {
    const n = value(id) ? Number(value(id)) : fallback;
    if (!Number.isInteger(n) || n < 1 || n > max) fail($(id), 'Use a whole number between 1 and ' + max + '.');
    return n;
  }
  function jsonBody(id) {
    const raw = value(id); if (!raw) return '';
    try { JSON.parse(raw); return raw; } catch (_) {}
    // A placeholder outside JSON quotes may stand for a number.
    try { JSON.parse(raw.replace(/\$\{[^}]+\}/g, '0')); return raw; }
    catch (_) { fail($(id), 'Enter valid JSON. Put text placeholders inside quotes, for example {"query":"${query}"}.'); }
  }
  function apiPath(id, required, message) {
    const path = value(id);
    if (required && !path) fail($(id), message);
    if (path && (!path.startsWith('/') || path.startsWith('//'))) fail($(id), 'Use a path starting with /, relative to the API address.');
    return path;
  }

  function build() {
    if (!value('name')) fail($('name'), 'Enter a name for this connection.');
    const website = websiteURL();
    if (!website) fail($('siem-address'), 'Enter the website address, such as https://siem.example.com.');
    const src = source();
    if (!src) fail($('source-table'), 'Choose where the logs are.');
    const api = src === 'api', current = reader();
    let base = website;
    if (api) {
      try { base = new URL(value('siem-base-url') || website.origin); if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password) throw Error(); }
      catch (_) { fail($('siem-base-url'), 'Enter a complete HTTP or HTTPS API address.'); }
    }
    if (current === 'table' && $('table-specific').checked && !value('table-selector')) fail($('table-selector'), 'Enter the table selector, or choose “The largest visible table”.');
    if (current === 'table' && value('table-selector')) {
      try { document.createDocumentFragment().querySelector(value('table-selector')); } catch (_) { fail($('table-selector'), 'This is not a valid CSS selector.'); }
    }
    if (current === 'script' && !$('custom-script').value.trim()) fail($('custom-script'), 'Enter the page extraction script.');
    const inspectorRequired = [...(current === 'inspector' ? [['open-btn', 'Open Inspector button'], ['response-tab', 'Response tab'],
      ['response-body', 'Response JSON'], ['hits-path', 'Records location inside the response']] : []),
      ...(value('statistics-mode') === 'opensearch' ? [['open-btn', 'Open Inspector button'], ['request-tab', 'Request tab'], ['request-body', 'Request JSON']] : [])];
    for (const [id, label] of inspectorRequired) if (!value(id)) fail($(id), 'Enter the Inspector setting “' + label + '”.');
    if (value('statistics-mode') === 'opensearch' && !value('api-path'))
      fail($('statistics-mode'), 'Inspector statistics re-run the search through the API. Choose “An API request” and enter its path, or pick another statistics option.');
    const job = value('fetch-mode') === 'search_job';
    let headers = {}, query = {}, jobQuery = {}, body = '', jobBody = '';
    let compiled = { linkTemplate: existing.api?.linkTemplate || '', linkRegex: existing.api?.linkRegex || '', contentRegex: existing.api?.contentRegex || '',
      contentSelector: existing.api?.contentSelector || '', contentFlags: existing.api?.contentFlags || '', parameters: existing.api?.parameters || {}, pageSources: [] };
    if (api) {
      headers = object('api-headers', true);
      if (job) {
        apiPath('job-create-path', true, 'Enter the path that starts a search.');
        apiPath('job-status-path', true, 'Enter the path that checks the search status.');
        apiPath('job-results-path', true, 'Enter the path that returns the results.');
        jobQuery = object('job-create-query', true); jobBody = jsonBody('job-create-body');
        if (value('job-parameters-as') === 'form' && jobBody) fail($('job-create-body'), 'A form body and a JSON body cannot be sent together. Clear the JSON body, or send the start parameters as URL query parameters.');
        if (!value('job-id-path')) fail($('job-id-path'), 'Enter where the search ID is in the response, such as id.');
        if (!value('job-status-field')) fail($('job-status-field'), 'Enter where the status is in the response, such as status.');
        if (!value('job-complete-values')) fail($('job-complete-values'), 'Enter the status value that means the search finished.');
      } else {
        apiPath('api-path', true, 'Enter the API path, starting with /.');
        query = object('api-query', true); body = jsonBody('api-body');
        if (value('api-method') === 'GET' && body) fail($('api-body'), 'GET requests have no body. Put values in the URL query parameters, or choose POST.');
      }
      apiPath('context-path', false); apiPath('test-path', false);
      compiled = compile([...cardsList.children].map(readCard), { origin: website.origin, siemHost: website.hostname });
      if (value('record-format') === 'columns' && !value('columns-path')) fail($('columns-path'), 'Enter where the column names are.');
      if (job && value('pagination-mode') === 'cursor') fail($('pagination-mode'), 'Search-job results are read by offset. Choose “Offset in a URL parameter” or “One response only”.');
      if (value('pagination-mode') === 'cursor' && !value('cursor-path')) fail($('cursor-path'), 'Enter where the next-page token is in the response.');
      if (value('pagination-mode') !== 'none' && !value('pagination-parameter')) fail($('pagination-parameter'), 'Enter the URL parameter that carries the offset or token.');
      const auth = value('auth-type');
      if (auth === 'header' && !value('header-value')) fail($('header-value'), 'Enter the API key or token.');
      if (auth === 'header' && !value('header-name')) fail($('header-name'), 'Enter the header name, usually Authorization.');
      if (auth === 'basic' && (!value('basic-username') || !$('basic-password').value)) fail($(value('basic-username') ? 'basic-password' : 'basic-username'), 'Enter the username and password.');
      if (auth === 'cookie' && !value('cookie-name')) fail($('cookie-name'), 'Enter the cookie name.');
      if (auth === 'oauth_client_credentials') {
        let tokenUrl = null; try { tokenUrl = new URL(value('oauth-token-url')); } catch (_) {}
        const local = tokenUrl && tokenUrl.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(tokenUrl.hostname);
        if (!tokenUrl || !(tokenUrl.protocol === 'https:' || local) || tokenUrl.username || tokenUrl.password) fail($('oauth-token-url'), 'Enter the https:// token address of the identity provider.');
        if (!value('oauth-client-id')) fail($('oauth-client-id'), 'Enter the client (application) ID.');
        if (!$('oauth-client-secret').value) fail($('oauth-client-secret'), 'Enter the client secret.');
      }
    } else if (current === 'json') {
      // Validates the records mapping fields even without an API.
      if (value('record-format') === 'columns' && !value('columns-path')) fail($('columns-path'), 'Enter where the column names are.');
    }
    const mapping = parseCookieEchoConfig(value('headers-from-cookies'));
    if (mapping === undefined || (mapping && (Array.isArray(mapping) || Object.values(mapping).some(v => typeof v !== 'string' || looksLikeCookieValue(v)))))
      fail($('headers-from-cookies'), 'Use cookie names, for example XSRF-TOKEN. Do not paste cookie values.');
    const caPem = value('ca-pem');
    if (caPem && (caPem.length > 200000 || caPem.includes('PRIVATE KEY') || !caPem.includes('-----BEGIN CERTIFICATE-----')))
      fail($('ca-pem'), 'Load a public CA certificate in PEM format (at most 200,000 characters), not a private key.');
    const strategy = api ? (current === 'request' ? 'api_request' : READERS[current]) : READERS[src];
    const a = existing.api || {};
    const profile = {
      ...existing, id: existing.id || generateConnectorId(), schemaVersion: 2, platform: value('preset'),
      name: value('name'), websiteUrl: website.href, siemHost: website.hostname, siemBaseUrl: base.href.replace(/\/$/, ''),
      // Linked case websites are now "Links on a page" value sources.
      pageSources: api ? compiled.pageSources : [],
      pageMatch: value('page-match'), ssoHint: value('sso-hint'), discoverPathHint: value('discover-hint'),
      tlsTrust: value('tls-trust'), caBundlePem: caPem, verifySsl: $('verify-ssl').checked,
      maxRecords: integer('max-records', 5000, 5000), statistics: { ...existing.statistics, mode: value('statistics-mode') },
      auth: { ...existing.auth, type: value('auth-type'), cookieName: value('cookie-name'), headerName: value('header-name'), headerValue: value('header-value'),
        username: value('basic-username'), password: $('basic-password').value, headersFromCookies: mapping,
        tokenUrl: value('oauth-token-url'), clientId: value('oauth-client-id'), clientSecret: $('oauth-client-secret').value, scope: value('oauth-scope') },
      api: { ...a, enabled: api, executeVia: value('execute-via'), fetchMode: value('fetch-mode'),
        method: value('api-method'), pathTemplate: value('api-path'), queryTemplate: query, bodyTemplate: body,
        headersTemplate: headers,
        responsePath: value('response-path'), totalPath: value('total-records-path'), recordFormat: value('record-format'), columnsPath: value('columns-path'),
        linkTemplate: compiled.linkTemplate, linkRegex: compiled.linkRegex, contentRegex: compiled.contentRegex,
        contentSelector: compiled.contentSelector, contentFlags: compiled.contentFlags, parameters: compiled.parameters,
        defaultQuery: value('default-query'), testPath: value('test-path'),
        pagination: { mode: value('pagination-mode'), parameter: value('pagination-parameter'), sizeParameter: value('pagination-size-parameter'),
          cursorPath: value('cursor-path'), pageSize: integer('page-size', 100, 5000), maxPages: integer('max-pages', 10, 50) },
        job: { ...a.job, createMethod: value('job-create-method'), createPathTemplate: value('job-create-path'), createQueryTemplate: jobQuery, createBodyTemplate: jobBody,
          createParametersAs: value('job-parameters-as'), errorMessagePath: value('job-error-message'),
          queryParameter: value('job-query-parameter'), jobIdPath: value('job-id-path'), statusPathTemplate: value('job-status-path'), statusField: value('job-status-field'),
          completeValues: value('job-complete-values'), errorValues: value('job-error-values'), resultsPathTemplate: value('job-results-path'),
          pollIntervalSeconds: integer('job-poll-interval', 2, 60), timeoutSeconds: integer('job-timeout', 90, 180) },
        context: { ...a.context, method: 'GET', pathTemplate: value('context-path'), responsePath: value('context-response-path') } },
      dom: { ...existing.dom, discover: { ...existing.dom?.discover, strategy,
        tableSelector: $('table-specific').checked ? value('table-selector') : '', jsonSelector: value('json-selector') || 'pre', customScript: $('custom-script').value,
        openButtonSelector: value('open-btn'), responseTabSelector: value('response-tab'), responseBodySelector: value('response-body'), closeButtonSelector: value('close-btn'),
        hitsPath: value('hits-path'), totalPath: value('total-path'), requestTabSelector: value('request-tab'), requestBodySelector: value('request-body'),
        requestUrlSelector: value('request-url'), statisticsTabSelector: value('statistics-tab') } }
    };
    try { new RegExp(VeiluxConnectors.linkPattern(profile)); } catch (e) { fail(cardsList, e.message); }
    return profile;
  }

  function read() {
    try { return build(); }
    catch (e) {
      if (!e || !('message' in e)) throw e;
      const target = e.target || $('name');
      fieldError(target, e.message || String(e));
      return null;
    }
  }

  /* ---------- Actions ---------- */

  async function test() {
    const button = document.getElementById('test-connector'), result = document.getElementById('connector-test-result');
    const p = read(); if (!p) return;
    button.disabled = true; result.style.color = ''; result.textContent = 'Checking the connection…';
    try {
      if (!p.api.enabled) { result.textContent = 'This connection reads the page directly, so there is no API to check. Use Preview extraction with a matching page open.'; return; }
      const native = VeiluxBrowserSession.supports(p);
      const payload = await VeiluxConnectorClient.requestPayload(p, { includeAuth: !native });
      let data;
      if (native) data = await VeiluxBrowserSession.check(p, payload);
      else {
        const response = await VeiluxBackend.fetch('/test-siem', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
        data = await response.json();
      }
      result.textContent = data.message || VeiluxConnectorClient.errorMessage(data);
      result.style.color = data.status === 'connected' ? 'var(--success)' : 'var(--danger)';
    } catch (e) { result.textContent = e.message || 'Cannot reach the local backend.'; }
    finally { button.disabled = false; }
  }

  // Preview reads where the values come from. A page used by a value source on another
  // website (a case page, a profile page…) wins over the connection's own website, whose
  // tab may only be open to supply the sign-in. Active tabs win within each group.
  async function previewTab(p) {
    const tabs = await browser.tabs.query({});
    const rank = t => {
      if (!VeiluxConnectorClient.matchesPage(p, t.url)) return Infinity;
      return (VeiluxConnectors.matches(p, t.url) ? 2 : 0) + (t.active ? 0 : 1);
    };
    let best = null;
    for (const t of tabs) if (rank(t) < (best ? rank(best) : Infinity)) best = t;
    return best;
  }

  async function preview(event) {
    const p = read(); if (!p) return;
    const button = event.currentTarget, result = document.getElementById('connector-preview-result');
    button.disabled = true; result.textContent = 'Reading…';
    try {
      const tab = await previewTab(p);
      if (!tab) throw Error('Open a page on ' + p.siemHost + ' (or on a page used by a value source) in another tab, then try again.');
      const data = await VeiluxConnectorClient.read(p, tab);
      const failed = Number(data.failed) || 0, errors = (data.errors || []).filter(Boolean);
      result.textContent = 'Read from: ' + tab.url + '\n' + data.logs.length + ' records read' + (failed ? ', ' + failed + ' failed' : '') + '. ' + (data.info || '')
        + (errors.length ? '\n' + errors.slice(0, 5).join('\n') + (errors.length > 5 ? '\n…and ' + (errors.length - 5) + ' more' : '') : '')
        + '\n' + data.logs.slice(0, 3).join('\n').slice(0, 12000);
    } catch (e) { result.textContent = 'Preview: ' + e.message; }
    finally { button.disabled = false; }
  }

  // Lists the visible tables on the open page, so a specific one can be picked.
  function listTables() {
    const unique = sel => { try { return document.querySelectorAll(sel).length === 1; } catch (_) { return false; } };
    function selectorFor(el) {
      if (el.id && unique('#' + CSS.escape(el.id))) return '#' + CSS.escape(el.id);
      const classes = [...el.classList].map(c => '.' + CSS.escape(c)).join('');
      if (classes && unique('table' + classes)) return 'table' + classes;
      const parts = [];
      for (let n = el; n && n.nodeType === 1 && n !== document.documentElement; n = n.parentElement) {
        if (n !== el && n.id && unique('#' + CSS.escape(n.id))) { parts.unshift('#' + CSS.escape(n.id)); break; }
        let i = 1; for (let s = n.previousElementSibling; s; s = s.previousElementSibling) if (s.tagName === n.tagName) i++;
        parts.unshift(n.tagName.toLowerCase() + ':nth-of-type(' + i + ')');
      }
      return parts.join(' > ');
    }
    return [...document.querySelectorAll('table')].filter(t => (t.offsetWidth || t.offsetHeight) && t.rows && t.rows.length >= 2).slice(0, 30).map(t => {
      const head = t.tHead && t.tHead.rows.length ? t.tHead.rows[t.tHead.rows.length - 1] : t.rows[0];
      return { selector: selectorFor(t), rows: t.tHead ? [...t.tBodies].reduce((n, b) => n + b.rows.length, 0) : t.rows.length - 1,
        columns: [...head.cells].map(c => (c.innerText || '').replace(/\s+/g, ' ').trim()).filter(Boolean).slice(0, 6),
        caption: ((t.caption && t.caption.innerText) || t.getAttribute('aria-label') || '').trim().slice(0, 80), frame: location.href };
    });
  }

  async function findTables() {
    const list = $('table-list'); list.textContent = 'Looking for tables…';
    try {
      const url = websiteURL(); if (!url) fail($('siem-address'), 'Enter the website address first.');
      const tab = await tabFor(u => VeiluxConnectors.matches({ siemHost: url.hostname, pageMatch: value('page-match') }, u));
      if (!tab) throw Error('Open the page with the table on ' + url.hostname + ' in another tab, then try again.');
      let frames;
      try { frames = await browser.scripting.executeScript({ target: { tabId: tab.id, allFrames: true }, func: listTables, args: [] }); }
      catch (_) { frames = await browser.scripting.executeScript({ target: { tabId: tab.id }, func: listTables, args: [] }); }
      const tables = frames.flatMap(f => f.result || []);
      list.replaceChildren();
      if (!tables.length) { list.textContent = 'No visible table with rows was found. Open a page that shows results, then try again.'; return; }
      const heading = document.createElement('p'); heading.className = 'field-hint'; heading.textContent = tables.length + ' table' + (tables.length === 1 ? '' : 's') + ' found. Pick the one with your logs.';
      list.append(heading);
      tables.forEach((t, i) => {
        const row = document.createElement('div'); row.className = 'table-choice';
        const text = document.createElement('div');
        const title = document.createElement('strong'); title.textContent = (t.caption || 'Table ' + (i + 1)) + ' · ' + t.rows + ' row' + (t.rows === 1 ? '' : 's');
        const cols = document.createElement('small'); cols.textContent = t.columns.length ? 'Columns: ' + t.columns.join(', ') : 'No column headings';
        const sel = document.createElement('code'); sel.textContent = t.selector;
        text.append(title, cols, sel);
        const use = document.createElement('button'); use.type = 'button'; use.className = 'btn btn-secondary btn-small'; use.textContent = 'Use this table';
        use.setAttribute('aria-label', 'Use table ' + (i + 1) + ': ' + t.columns.join(', '));
        use.addEventListener('click', () => {
          set('table-selector', t.selector); $('table-specific').checked = true;
          list.querySelectorAll('.table-choice').forEach(r => r.classList.toggle('chosen', r === row));
          clearFieldError($('table-selector')); show();
        });
        row.append(text, use); list.append(row);
      });
    } catch (e) { list.textContent = e.message; if (e.target) fieldError(e.target, e.message); }
  }

  function describe(p) {
    const d = p.dom?.discover?.strategy || 'table_scrape', api = d === 'api_request' || (p.api?.enabled ?? !!p.api?.pathTemplate);
    const how = api ? 'API' + (p.api?.fetchMode === 'search_job' ? ' search job' : '') + (d !== 'api_request' ? ', otherwise ' + READER_LABEL[READER_OF[d]] : '')
      : READER_LABEL[READER_OF[d]] || 'page';
    const pages = (p.pageSources || []).map(s => s.name || s.website).filter(Boolean);
    return (p.siemHost || '—') + ' · reads ' + how + (pages.length ? ' · values from ' + pages.join(', ') : '');
  }

  /* ---------- Wiring ---------- */

  form.addEventListener('change', show);
  form.addEventListener('input', event => { if (event.target.closest('#conn-api-step,#conn-values-step')) updatePlaceholders(); });
  $('preset').addEventListener('change', () => applyTemplate(value('preset')));
  $('auth-type').addEventListener('change', () => { if (value('auth-type') === 'header' && !value('header-name')) set('header-name', 'Authorization'); });
  $('siem-address').addEventListener('input', syncAddress);
  $('siem-base-url').addEventListener('input', () => { $('siem-base-url').dataset.manual = 'true'; });
  $('find-tables').addEventListener('click', findTables);
  $('table-selector').addEventListener('input', () => { if (value('table-selector')) $('table-specific').checked = true; });
  form.querySelectorAll('[data-add-value]').forEach(button => button.addEventListener('click', () => {
    // New sources start on the same page as the previous one, which is usually the case platform.
    const last = [...cardsList.children].reverse().map(readCard).find(d => d.type !== 'fixed');
    const type = button.dataset.addValue;
    const site = type === 'fixed' || !last ? {} : { site: last.site, website: last.website, urlIncludes: last.urlIncludes };
    const card = addCard(type, site); show(); card.querySelector('select,input')?.focus();
  }));
  $('copy-values').addEventListener('change', () => {
    const chosen = copyable[Number(value('copy-values'))];
    if (chosen) chosen.cards.forEach(c => addCard(c.type, c));
    set('copy-values', ''); show();
  });
  $('inspect-sample').addEventListener('click', () => {
    try {
      const data = JSON.parse(value('sample-response'));
      $('sample-path').replaceChildren(...VeiluxConnectors.samplePaths(data).map(path => new Option(path || 'Whole response', path)));
      $('sample-result').textContent = 'Choose the location of the records, then Preview records.';
    } catch (e) { $('sample-result').textContent = 'The sample is not valid JSON: ' + e.message; }
  });
  $('sample-path').addEventListener('change', () => set('response-path', value('sample-path')));
  $('preview-sample').addEventListener('click', () => {
    try {
      const rows = VeiluxConnectors.records(JSON.parse(value('sample-response')), value('response-path'), value('record-format'), value('columns-path'));
      $('sample-result').textContent = rows.length + ' records\n' + JSON.stringify(rows.slice(0, 3), null, 2).slice(0, 12000);
    } catch (e) { $('sample-result').textContent = e.message; }
  });
  $('load-ca').addEventListener('click', () => $('ca-file').click());
  $('ca-file').addEventListener('change', async () => {
    try {
      const file = $('ca-file').files[0]; if (!file) return;
      if (file.size > 200000) throw Error('The CA file is too large. Use a PEM certificate bundle below 200,000 bytes.');
      const pem = await file.text();
      if (pem.includes('PRIVATE KEY') || !pem.includes('-----BEGIN CERTIFICATE-----')) throw Error('Use a public PEM certificate from your IT team, not a private key or binary DER file.');
      set('ca-pem', pem); $('ca-pem').dispatchEvent(new Event('input', { bubbles: true }));
      $('ca-status').textContent = 'Certificate loaded into this draft. Test connection, then Save connection.';
    } catch (e) { $('ca-status').textContent = e.message; }
    finally { $('ca-file').value = ''; }
  });
  document.getElementById('test-connector').addEventListener('click', test);
  document.getElementById('preview-connector').addEventListener('click', preview);

  return { open, close, read, test, show, describe, addCard, compile, decompile, applyTemplate };
})();
// Settings may have rendered the list before this file loaded.
if (typeof renderConnectorList === 'function' && Array.isArray(connectorProfiles) && connectorProfiles.length) renderConnectorList();
