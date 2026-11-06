const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('gui/src/main.js', 'utf8');
function declaration(name) {
  const bareStart = source.indexOf(`function ${name}(`);
  const start = source.slice(bareStart - 6, bareStart) === "async " ? bareStart - 6 : bareStart;
  assert.notEqual(start, -1, name);
  return source.slice(start, source.indexOf('\n}\n', start) + 3);
}
const timingStart = source.indexOf('const SAPLING_ACTIVATION_HEIGHT_JS');
const timingEnd = source.indexOf('function approxDateFromHeight(');
const timing = vm.runInNewContext(source.slice(timingStart, timingEnd) + '\n' +
  declaration('approxDateFromHeight') + '; approxDateFromHeight', {});
test('mainnet and testnet estimates retain 75 second timing before NU7 and use 25 seconds at their activation', () => {
  for (const [network, activation] of [['mainnet', 3543405], ['testnet', 4465026]]) {
    const at = timing(activation, network).getTime();
    assert.equal(at - timing(activation - 1, network).getTime(), 75000);
    assert.equal(timing(activation + 1, network).getTime() - at, 25000);
    assert.equal(timing(activation + 100, network).getTime() - at, 2500000);
  }
});

test('height estimates remain finite for u32 bounds and retain historical 150 second timing', () => {
  assert.equal(timing(500001).getTime() - timing(500000).getTime(), 150000);
  assert.equal(timing(1000001).getTime() - timing(1000000).getTime(), 75000);
  for (const network of ['mainnet', 'testnet']) {
    assert.ok(Number.isFinite(timing(0, network).getTime()));
    assert.ok(Number.isFinite(timing(4294967295, network).getTime()));
    assert.ok(timing(4294967295, network).getTime() > timing(4294967294, network).getTime());
  }
});
