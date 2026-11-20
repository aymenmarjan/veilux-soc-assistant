/**
 * VEILUX content script, injected into SIEM pages on demand.
 * - Search pages: reads the page's own Inspector panel (the request and
 *   response JSON it already shows) instead of intercepting network traffic.
 *   It only reads the page, so it behaves the same in every browser. Selectors
 *   and JSON paths come from the connection.
 * A connection's own page script does not run here: Manifest V3 forbids
 * building code from text in extension scripts, in every browser. It runs in
 * the page itself instead (connector_client.js, customScriptInjected).
 */

browser.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request && request.action === 'veiluxDiscoverExtract') {
    extractDiscoverViaInspector(request.config || {})
      .then((result) => sendResponse(Object.assign({ success: true }, result)))
      .catch((error) => sendResponse({ success: false, error: error && error.message ? error.message : String(error) }));
    return true;
  }


  if (request && request.action === 'veiluxExtractDiscoverFieldStats') {
    extractDiscoverFieldStatistics(request.config || {}, request.api || {})
      .then((result) => sendResponse(Object.assign({ success: true }, result)))
      .catch((error) => sendResponse({ success: false, error: error && error.message ? error.message : String(error) }));
    return true;
  }
});

// Statistics sample size when the popup does not send one (its setting defaults to this).
const FIELD_STATS_DEFAULT_DOCUMENTS = 5000;
// Most frequent values kept per field (the popup lets the analyst choose 1 to 10).
const FIELD_STATS_TOP_VALUES = 5, FIELD_STATS_TOP_VALUES_MAX = 10;
const topValuesLimit = value => Number.isInteger(value) && value >= 1 ? Math.min(value, FIELD_STATS_TOP_VALUES_MAX) : FIELD_STATS_TOP_VALUES;

function normalizeDiscoverRequest(value, indexPattern, size = FIELD_STATS_DEFAULT_DOCUMENTS) {
  let request = typeof value === 'string' ? JSON.parse(value) : value;
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    throw new Error('Discover request must be a JSON object.');
  }
  // The Inspector may show either the search body alone or the complete
  // internal-search payload. Accept both so analysts can paste it unchanged.
  const params = request.params && typeof request.params === 'object'
    ? Object.assign({}, request.params) : {};
  let body = Object.keys(params).length ? params.body : request;
  if (typeof body === 'string') body = JSON.parse(body);
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new Error('Discover request does not contain an object search body.');
  }
  body = Object.assign({}, body, { size: size });
  delete body.aggregations;
  delete body.aggs;
  body._source = true;
  params.index = indexPattern;
  params.body = body;
  return { params: params };
}

function flattenStatisticFields(value, prefix, out) {
  if (value === null || value === undefined) return;
  if (Array.isArray(value)) {
    value.forEach(function(item) { flattenStatisticFields(item, prefix, out); });
    return;
  }
  if (typeof value === 'object') {
    Object.keys(value).forEach(function(key) {
      flattenStatisticFields(value[key], prefix ? prefix + '.' + key : key, out);
    });
    return;
  }
  if (prefix) {
    if (!out[prefix]) out[prefix] = [];
    out[prefix].push(String(value));
  }
}

function calculateFieldStatistics(hits, topCount) {
  const fields = {};
  (hits || []).forEach(function(hit) {
    const values = {};
    flattenStatisticFields((hit && hit._source) || hit, '', values);
    Object.keys(values).forEach(function(name) {
      if (!fields[name]) fields[name] = { documents: 0, values: {} };
      fields[name].documents++;
      // Count a value at most once per document. This makes its percentage
      // comparable to field presence even when a source field is an array.
      Array.from(new Set(values[name])).forEach(function(value) {
        fields[name].values[value] = (fields[name].values[value] || 0) + 1;
      });
    });
  });
  const total = (hits || []).length;
  return Object.keys(fields).sort().map(function(name) {
    const field = fields[name];
    const topValues = Object.keys(field.values).map(function(value) {
      const count = field.values[value];
      return { value: value, count: count, percentage: total ? count * 100 / total : 0 };
    }).sort(function(a, b) { return b.count - a.count || a.value.localeCompare(b.value); })
      .slice(0, topValuesLimit(topCount));
    return {
      field: name,
      count: field.documents,
      percentage: total ? field.documents * 100 / total : 0,
      topValues: topValues
    };
  });
}

async function fetchOpenSearchFieldStatistics(options) {
  const indexPattern = (options.indexPattern || '').trim();
  if (!indexPattern) throw new Error('Enter an index pattern.');
  const size = Number.isInteger(options.sampleSize) && options.sampleSize > 0 ? options.sampleSize : FIELD_STATS_DEFAULT_DOCUMENTS;
  const payload = normalizeDiscoverRequest(options.requestJson, indexPattern, size);
  if (!options.path) throw new Error('This connection has no API path. Set it in the connection\'s API request settings.');
  const response = await fetch(options.path, {
    method: 'POST',
    credentials: 'include',
    headers: Object.assign({ 'Content-Type': 'application/json' }, options.headers || {}),
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    const detail = await response.text();
    if (/max_result_window|Result window is too large/i.test(detail)) {
      throw new Error('OpenSearch refused a sample of ' + size + ' documents: by default it returns at most 10,000 per search ' +
        '(index.max_result_window). Lower the statistics sample, or ask your OpenSearch administrator to raise that limit.');
    }
    throw new Error('OpenSearch returned HTTP ' + response.status + (detail ? ': ' + detail.slice(0, 300) : ''));
  }
  const data = await response.json();
  const raw = data.rawResponse || data;
  const hits = raw && raw.hits && Array.isArray(raw.hits.hits) ? raw.hits.hits : [];
  const reportedTotal = raw && raw.hits && raw.hits.total;
  const total = typeof reportedTotal === 'number' ? reportedTotal
    : (reportedTotal && typeof reportedTotal.value === 'number' ? reportedTotal.value : hits.length);
  return { sampled: hits.length, total: total, fields: calculateFieldStatistics(hits, options.topValues) };
}

function discoverRequestSummary(body) {
  const bool = body && body.query && body.query.bool ? body.query.bool : {};
  const clauses = [].concat(bool.must || [], bool.filter || [], bool.must_not || []);
  let query = '*';
  const filters = [];
  let timeFrame = 'All time';
  clauses.forEach(function(clause) {
    if (clause.query_string && clause.query_string.query) query = clause.query_string.query;
    if (clause.range) {
      const field = Object.keys(clause.range)[0];
      const range = clause.range[field] || {};
      timeFrame = field + ': ' + (range.gte || '*') + ' → ' + (range.lte || '*');
    } else if (clause.match_phrase) {
      const field = Object.keys(clause.match_phrase)[0];
      filters.push(field + '=' + JSON.stringify(clause.match_phrase[field]));
    } else if (!clause.query_string) {
      filters.push(JSON.stringify(clause));
    }
  });
  return { query: query, filters: filters, timeFrame: timeFrame };
}

function indexFromInspectorUrl(text) {
  const raw = (text || '').trim();
  const match = raw.match(/(?:^|\s|\/)([^/?\s]+)\/(?:_search|_msearch)(?:[/?\s]|$)/);
  if (!match) return '';
  try { return decodeURIComponent(match[1]); } catch (_) { return match[1]; }
}

function readIndexPatternFromStatisticsRoot(root) {
  if (!root || !root.querySelectorAll) return '';
  const rows = root.querySelectorAll('tr, [role="row"], dt');
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    const cells = row.querySelectorAll ? row.querySelectorAll('th, td, [role="cell"], [role="rowheader"]') : [];
    if (cells.length >= 2) {
      const label = (cells[0].textContent || '').trim().toLowerCase();
      if (label === 'index pattern') return (cells[cells.length - 1].textContent || '').trim();
    }
    // EUI description lists render the label as <dt> and value as the
    // following <dd>, rather than as a table row.
    if (row.tagName && row.tagName.toLowerCase() === 'dt' &&
        (row.textContent || '').trim().toLowerCase() === 'index pattern') {
      const value = row.nextElementSibling;
      return value ? (value.textContent || '').trim() : '';
    }
  }
  return '';
}

async function readInspectorIndexPattern(config) {
  const tab = (config.statisticsTabSelector && document.querySelector(config.statisticsTabSelector)) ||
    Array.from(document.querySelectorAll('button, [role="tab"]'))
    .find(function(element) { return (element.textContent || '').trim() === 'Statistics'; });
  if (tab) try { tab.click(); } catch (_) {}

  const deadline = Date.now() + 2500;
  while (Date.now() < deadline) {
    const value = readIndexPatternFromStatisticsRoot(document);
    if (value) return value;
    await new Promise(function(resolve) { setTimeout(resolve, 100); });
  }
  return '';
}

async function extractDiscoverFieldStatistics(config, api) {
  const openSel = inspectorSetting(config, 'openButtonSelector', 'Open Inspector button');
  const requestTabSel = inspectorSetting(config, 'requestTabSelector', 'Request tab');
  const requestBodySel = inspectorSetting(config, 'requestBodySelector', 'Request JSON');
  const requestUrlSel = config.requestUrlSelector || '';
  const closeSel = config.closeButtonSelector || '';
  const inspectBtn = document.querySelector(openSel);
  if (!inspectBtn) throw new Error('Inspect button not found. Run a Discover search first.');
  inspectBtn.click();
  // The Statistics tab is the authoritative source for the data-view title
  // (for example "logs-*"). Request URLs often contain only _msearch, while
  // the UUID shown as "Index pattern ID" is not a usable search index.
  const statisticsIndexPattern = await readInspectorIndexPattern(config);
  const requestTab = await waitForElement(requestTabSel, 5000, 'Inspector Request tab did not open.');
  requestTab.click();
  const requestBody = await waitForElement(requestBodySel, 5000, 'Inspector Request JSON did not render.');
  const requestText = readCodeBlockText(requestBody);
  const urlElement = requestUrlSel ? document.querySelector(requestUrlSel) : null;
  const requestUrl = urlElement ? readCodeBlockText(urlElement) : '';
  const closeBtn = closeSel ? document.querySelector(closeSel) : null;
  if (closeBtn) try { closeBtn.click(); } catch (_) {}

  let parsed;
  try { parsed = JSON.parse(requestText); }
  catch (error) { throw new Error('Inspector Request was not valid JSON: ' + error.message); }
  const body = parsed.params && parsed.params.body ? parsed.params.body : parsed;
  const indexPattern = statisticsIndexPattern || (parsed.params && parsed.params.index) || indexFromInspectorUrl(requestUrl);
  if (!indexPattern) {
    throw new Error('Could not read the index pattern from the Inspector panel. Run the search again so the panel shows its Statistics tab, or choose another statistics option for this connection.');
  }
  const result = await fetchOpenSearchFieldStatistics({
    indexPattern: indexPattern,
    requestJson: parsed,
    path: api.path,
    headers: api.headers,
    sampleSize: api.sampleSize,
    topValues: api.topValues
  });
  return Object.assign(result, {
    indexPattern: indexPattern,
    request: body,
    summary: discoverRequestSummary(body)
  });
}

// Inspector selectors come from the connection (a platform template can fill them).
function inspectorSetting(config, key, label) {
  const value = (config[key] || '').trim();
  if (!value) throw new Error('Set the Inspector setting "' + label + '" for this connection in Settings.');
  return value;
}

async function extractDiscoverViaInspector(config) {
  const openSel = inspectorSetting(config, 'openButtonSelector', 'Open Inspector button');
  const responseTabSel = inspectorSetting(config, 'responseTabSelector', 'Response tab');
  const responseBodySel = inspectorSetting(config, 'responseBodySelector', 'Response JSON');
  const closeSel = config.closeButtonSelector || '';
  const hitsPath = inspectorSetting(config, 'hitsPath', 'Records location inside the response');
  const totalPath = config.totalPath || '';

  const inspectBtn = document.querySelector(openSel);
  if (!inspectBtn) {
    throw new Error('Inspect button not found (selector: ' + openSel + '). Make sure you are on the search results page and have run a search, or check this connector\'s DOM selectors in Settings.');
  }
  inspectBtn.click();

  const responseTab = await waitForElement(
    responseTabSel,
    5000,
    'Inspector panel did not open (response tab not found: ' + responseTabSel + ').'
  );

  // The panel opens on the Request tab by default — its body content
  // doesn't render until the Response tab is actually clicked.
  responseTab.click();
  const responseEl = await waitForElement(
    responseBodySel,
    5000,
    'Response tab did not render its content (selector: ' + responseBodySel + ').'
  );

  const responseText = readCodeBlockText(responseEl);
  const closeBtn = closeSel ? document.querySelector(closeSel) : null;
  if (closeBtn) {
    try { closeBtn.click(); } catch (_) {}
  }

  let responseData;
  try {
    responseData = JSON.parse(responseText);
  } catch (e) {
    throw new Error('Inspector response was not valid JSON: ' + e.message);
  }

  const hits = getByPath(responseData, hitsPath);
  const hitsArr = Array.isArray(hits) ? hits : [];
  const total = getTotalHits(responseData, totalPath, hitsArr.length);
  const index = hitsArr.length > 0 ? (hitsArr[0]._index || '') : '';

  return {
    logs: hitsArr.map(function(hit) { return JSON.stringify(hit, null, 2); }),
    failed: 0,
    total: total,
    note: 'inspector_read',
    info: index ? ('index=' + index + ' visible_hits=' + hitsArr.length) : ''
  };
}

function getByPath(obj, path) {
  if (!path) return obj;
  let cur = obj;
  const parts = path.split('.');
  for (let i = 0; i < parts.length; i++) {
    if (cur === null || cur === undefined) return undefined;
    cur = cur[parts[i]];
  }
  return cur;
}

function getTotalHits(responseData, totalPath, fallback) {
  const total = getByPath(responseData, totalPath);
  if (typeof total === 'number') return total;
  if (total && typeof total.value === 'number') return total.value;
  return fallback;
}

function readCodeBlockText(codeElement) {
  const lines = codeElement.querySelectorAll('span.euiCodeBlock__line');
  if (lines.length === 0) return codeElement.textContent.trim();
  let text = '';
  lines.forEach(function(line) { text += line.textContent + '\n'; });
  return text.trim();
}

function waitForElement(selector, timeoutMs, errorMessage) {
  return new Promise(function(resolve, reject) {
    const existing = document.querySelector(selector);
    if (existing) return resolve(existing);

    const start = Date.now();
    const interval = setInterval(function() {
      const el = document.querySelector(selector);
      if (el) {
        clearInterval(interval);
        resolve(el);
      } else if (Date.now() - start > timeoutMs) {
        clearInterval(interval);
        reject(new Error(errorMessage || ('Timed out waiting for: ' + selector)));
      }
    }, 150);
  });
}
