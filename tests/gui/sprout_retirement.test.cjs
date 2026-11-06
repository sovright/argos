const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('gui/src/main.js', 'utf8');
const html = fs.readFileSync('gui/src/index.html', 'utf8');
function loadFunction(name, context) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1);
  const end = source.indexOf('\n}\n', start);
  return vm.runInNewContext(`${source.slice(start, end + 3)}; ${name}`, context);
}
function harness() {
  const elements = new Map();
  const get = (id) => {
    if (!elements.has(id)) elements.set(id, { hidden: false, textContent: '', innerHTML: '', children: [], appendChild(child) { this.children.push(child); } });
    return elements.get(id);
  };
  const render = loadFunction('renderWalletSummary', {
    $: get,
    document: { createElement: () => ({ textContent: '' }) },
  });
  return { render, get };
}
test('a mixed wallet explains retired Sprout funds and lists supported keys', () => {
  const h = harness();
  h.render({ transparent_keys: 2, sapling_keys: 1, sprout_records: 3,
    sprout_notice: 'Sprout funds are unspendable under NU7.', diagnostics: [] });
  assert.equal(h.get('wallet-sprout-warning').hidden, false);
  assert.match(h.get('wallet-sprout-warning').textContent, /unspendable under NU7/);
  assert.match(h.get('wallet-summary-list').children.map(x => x.textContent).join('\n'), /Transparent keys: 2/);
  assert.match(h.get('wallet-summary-list').children.map(x => x.textContent).join('\n'), /Sapling keys: 1/);
});
test('reopening a wallet without Sprout records clears the retirement notice', () => {
  const h = harness();
  h.render({ transparent_keys: 1, sapling_keys: 0, sprout_records: 3, sprout_notice: 'unspendable', diagnostics: [] });
  h.render({ transparent_keys: 1, sapling_keys: 0, sprout_records: 0, sprout_notice: '', diagnostics: [] });
  assert.equal(h.get('wallet-sprout-warning').hidden, true);
  assert.equal(h.get('wallet-sprout-warning').textContent, '');
});
test('the GUI offers no Sprout key entry, scan, sweep, or recovery IPC', () => {
  assert.doesNotMatch(html, /id="sprout-(?:scan|sweep|destination)/);
  assert.doesNotMatch(source, /invoke\("(?:start|retry|pause|get|release)_sprout|invoke\("(?:propose|execute)_(?:wallet_)?sprout/);
  const commands = fs.readFileSync('gui/src-tauri/src/main.rs', 'utf8');
  assert.doesNotMatch(commands, /commands::(?:\w*_sprout|sprout_)/);
});
