const assert = require('assert');
const fs = require('fs');
const vm = require('vm');

let listener;
const context = {
  console,
  document: {},
  window: {},
  browser: { runtime: { onMessage: { addListener(fn) { listener = fn; } } } },
  fetch: async (_path, options) => {
    const sent = JSON.parse(options.body);
    assert.equal(sent.params.index, 'logs-*');
    assert.equal(sent.params.body.size, 5000);
    assert.equal(sent.params.body._source, true);
    assert.deepEqual(sent.params.body.query, { match_all: {} });
    return {
      ok: true,
      async json() {
        return { rawResponse: { hits: { total: { value: 8 }, hits: [
          { _source: { host: { name: 'alpha' }, tags: ['prod', 'prod'] } },
          { _source: { host: { name: 'beta' }, tags: ['prod'] } },
          { _source: { host: { name: 'alpha' } } }
        ] } } };
      }
    };
  },
  setInterval, clearInterval, setTimeout, Promise
};
vm.createContext(context);
vm.runInContext(fs.readFileSync('extension/content.js', 'utf8'), context);

assert.equal(typeof listener, 'function');
const normalized = context.normalizeDiscoverRequest(
  { params: { body: JSON.stringify({ query: { match_all: {} }, aggs: { old: {} } }) } },
  'logs-*'
);
assert.equal(normalized.params.index, 'logs-*');
assert.equal(normalized.params.body.aggs, undefined);
assert.equal(context.indexFromInspectorUrl('POST /logs-%2A/_search'), 'logs-*');
const statisticsCells = [
  { textContent: 'Index pattern' },
  { textContent: 'soc*' }
];
const statisticsRoot = {
  querySelectorAll(selector) {
    assert.equal(selector, 'tr, [role="row"], dt');
    return [{
      tagName: 'TR', textContent: 'Index pattern soc*',
      querySelectorAll() { return statisticsCells; }
    }];
  }
};
assert.equal(context.readIndexPatternFromStatisticsRoot(statisticsRoot), 'soc*');
const summary = context.discoverRequestSummary({ query: { bool: {
  must: [{ query_string: { query: 'event.action:login' } }],
  filter: [
    { match_phrase: { Category: 'Logon' } },
    { range: { '@timestamp': { gte: 'start', lte: 'end' } } }
  ]
} } });
assert.equal(summary.query, 'event.action:login');
assert.deepEqual(JSON.parse(JSON.stringify(summary.filters)), ['Category="Logon"']);
assert.equal(summary.timeFrame, '@timestamp: start → end');

const stats = context.calculateFieldStatistics([
  { _source: { a: 1, nested: { value: 'x' }, list: ['x', 'x'] } },
  { _source: { a: 1, nested: { value: 'y' }, list: ['x', 'y'] } },
  { _source: { a: 2 } }
]);
const a = stats.find(item => item.field === 'a');
assert.equal(a.count, 3);
assert.equal(a.percentage, 100);
assert.deepEqual(JSON.parse(JSON.stringify(a.topValues)), [
  { value: '1', count: 2, percentage: 200 / 3 },
  { value: '2', count: 1, percentage: 100 / 3 }
]);
const list = stats.find(item => item.field === 'list');
assert.equal(list.count, 2);
assert.equal(list.topValues[0].count, 2, 'duplicate array values count once per document');

context.fetchOpenSearchFieldStatistics({ indexPattern: 'logs-*', requestJson: '{}' })
  .then(() => assert.fail('a blank API path must not fall back to a built-in one'),
        error => assert.match(error.message, /no API path/))
  .then(() => context.fetchOpenSearchFieldStatistics({
    indexPattern: 'logs-*', requestJson: JSON.stringify({ query: { match_all: {} } }),
    path: '/internal/search/opensearch-with-long-numerals', headers: { 'osd-xsrf': 'osd-fetch' }
  })).then(result => {
  assert.equal(result.sampled, 3);
  assert.equal(result.total, 8);
  assert.equal(result.fields.find(item => item.field === 'host.name').count, 3);
  // The page reader keeps the chosen number of top values (1 to 10, default 5).
const twelve = Array.from({ length: 12 }, (_, i) => ({ _source: { user: 'u' + String(i).padStart(2, '0') } }));
assert.strictEqual(context.calculateFieldStatistics(twelve)[0].topValues.length, 5);
assert.strictEqual(context.calculateFieldStatistics(twelve, 10)[0].topValues.length, 10);
assert.strictEqual(context.calculateFieldStatistics(twelve, 99)[0].topValues.length, 10);
console.log('field statistics tests passed');
}).catch(error => { console.error(error); process.exitCode = 1; });
