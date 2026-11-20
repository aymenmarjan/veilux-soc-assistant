const assert = require('assert');
const fs = require('fs');
const vm = require('vm');

// Git's Windows checkout may use CRLF; source extraction is line-ending neutral.
const source = fs.readFileSync('extension/popup.js', 'utf8').replace(/\r\n/g, '\n');
const match = source.match(/function secretReviewSnapshot\([^]*?\n}\n/);
assert(match, 'secretReviewSnapshot helper must remain directly testable');
const context = { JSON };
vm.createContext(context);
vm.runInContext(match[0], context);

const config = { context: true, assignments: true };
const statistics = [{ fields: [{ field: 'user', topValues: [{ value: 'alice' }] }] }];
const before = context.secretReviewSnapshot('event', '', statistics, null, config, []);
const after = context.secretReviewSnapshot('event', '', statistics, null, config, []);
assert.equal(before, after, 'default/null prompt must not retrigger preflight');
assert.equal(
  context.secretReviewSnapshot('event', '', statistics, '', config, []),
  before,
  'empty and absent custom prompts must have the same canonical form'
);
assert.notEqual(
  context.secretReviewSnapshot('edited event', '', statistics, null, config, []),
  before,
  'real edits must still trigger one more safety scan'
);
assert.notEqual(
  context.secretReviewSnapshot('event', '', statistics, null, { context: false }, []),
  before,
  'protection changes must still trigger one more safety scan'
);
assert.equal(
  context.secretReviewSnapshot('event', '', statistics, null, config, ['unchecked-value']),
  before,
  'decisions produced by this review must not reopen it for unchanged input'
);
console.log('popup preflight snapshot tests passed');
