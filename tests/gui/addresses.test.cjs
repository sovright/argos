const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

// A small DOM harness for state/async regressions, not a rendering substitute.
function harness(invoke) {
  class Element {
    constructor() { this.value = ''; this.children = []; this.listeners = {}; this.open = false; this.textContent = ''; this.hidden = false; this.classList = {add() {}, toggle() {}}; }
    addEventListener(event, fn) { this.listeners[event] = fn; }
    fire(event) { return this.listeners[event]?.({preventDefault() {}}); }
    replaceChildren(...children) { this.children = children; }
    append(...children) { this.children.push(...children); }
    focus() {}
    showModal() { this.open = true; }
    close() { this.open = false; this.fire('close'); }
  }
  const elements = new Map();
  const el = id => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); };
  const document = {getElementById:el, createElement:() => new Element(), addEventListener:(_, fn) => fn()};
  vm.runInNewContext(fs.readFileSync('gui/src/addresses.js', 'utf8'), {document, window:{__TAURI__:{core:{invoke}}}});
  el('open-addresses').fire('click');
  el('addresses-start').value = '400'; el('addresses-count').value = '20'; el('addresses-network').value = 'mainnet';
  el('addresses-seed').value = 'synthetic seed for state tests only';
  return el;
}
function accounts(start, count) {
  return Array.from({length:count}, (_, n) => {
    const index = start + n;
    return {index, transparent_receive_address:`t1receive-${index}`, transparent_receive_path:`receive/${index}`,
      transparent_change_address:`t1change-${index}`, transparent_change_path:`change/${index}`,
      sapling_address:`zs-${index}`, sapling_path:`sapling/${index}`, unified_address:`u1-${index}`, orchard_path:`orchard/${index}`};
  });
}
test('range results paginate and exact search covers rows on other pages', async () => {
  const el = harness(async (_, {input}) => accounts(input.start_index, input.count));
  await el('addresses-form').fire('submit');
  assert.equal(el('addresses-seed').value, '');
  assert.equal(el('addresses-rows').children.length, 40);
  el('addresses-next').fire('click');
  assert.match(el('addresses-page').textContent, /Page 2 of 2/);
  el('addresses-target').value = 't1change-417'; el('addresses-target').fire('input');
  assert.equal(el('addresses-rows').children.length, 1);
  assert.equal(el('addresses-rows').children[0].children[0].textContent, '417');
  assert.equal(el('addresses-rows').children[0].children[2].children[1].textContent, 'change/417');
  el('addresses-target').value = 't1change-999'; el('addresses-target').fire('input');
  assert.equal(el('addresses-rows').children.length, 0);
  assert.match(el('addresses-match').textContent, /does not rule out/);
});
test('close and reopen discards a delayed response and prevents duplicate jobs', async () => {
  let resolve, calls = 0;
  const el = harness(() => { calls++; return new Promise(r => {resolve = r;}); });
  const pending = el('addresses-form').fire('submit');
  assert.equal(el('addresses-seed').value, '');
  el('close-addresses').fire('click'); el('open-addresses').fire('click');
  await el('addresses-form').fire('submit');
  assert.equal(calls, 1);
  resolve(accounts(400, 20)); await pending;
  assert.equal(el('addresses-results').hidden, true);
  assert.equal(el('addresses-rows').children.length, 0);
  assert.equal(el('derive-addresses').disabled, false);
});
test('errors clear previous results and range overflow never invokes the backend', async () => {
  let calls = 0;
  const el = harness(async () => { calls++; throw new Error('invalid mnemonic'); });
  el('addresses-start').value = '2147483647'; el('addresses-count').value = '2';
  await el('addresses-form').fire('submit'); assert.equal(calls, 0);
  el('addresses-count').value = '1';
  await el('addresses-form').fire('submit');
  assert.equal(el('addresses-seed').value, '');
  assert.equal(el('addresses-results').hidden, true);
  assert.match(el('addresses-status').textContent, /invalid mnemonic/);
  assert.equal(el('derive-addresses').disabled, false);
});
