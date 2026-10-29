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
function load(names, context = {}) {
  return vm.runInNewContext(names.map(declaration).join('\n') + `; ({${names.join(',')}})`, context);
}
const policy = load(['sproutReviewHasLifecycleStatus', 'sproutReviewMayRun']);
test('new Sprout proofs require explicit backend permission; missing or unknown permission fails closed', () => {
  assert.equal(policy.sproutReviewMayRun({ params_present: true }), false);
  assert.equal(policy.sproutReviewMayRun({ params_present: true, allow_new_spends: false }), false);
  assert.equal(policy.sproutReviewMayRun({ params_present: true, allow_new_spends: true }), true);
});
test('read-only saved status remains available with no proof permission or parameters', () => {
  for (const state of ['pending', 'invalid_after_activation', 'mined']) {
    assert.equal(policy.sproutReviewMayRun({ params_present: false, allow_new_spends: false,
      active: [{ state }] }), true);
  }
});
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

function availabilityHarness() {
  const elements = new Map();
  const $ = (id) => { if (!elements.has(id)) elements.set(id, { value: '', textContent: '', disabled: false, hidden: true }); return elements.get(id); };
  $('network-select').value = 'mainnet';
  $('lightwalletd-url').value = 'https://primary.example';
  const pending = [];
  const ctx = vm.createContext({ $, walletFile: { summary: { sprout_keys: 1, sprout_spendable_notes: 2 } },
    confirmationSourcesFromForm: () => ['backup=https://confirm.example'],
    setTimeout: () => 1, clearTimeout() {},
    sproutScanPeerEntries: () => [], sproutScanNu7Warning: '', sproutNu7Warning: '', sproutNu7Broadcast: false, sproutScanNu7Broadcast: false,
    renderSproutScanPanel() {}, renderSproutUncoveredBanners() {}, showSproutNu7Warning() {},
    updateWalletSproutSweepButton() {}, updateSproutScanSweepButton() {},
    invoke: () => new Promise(resolve => pending.push(resolve)),
  });
  const start = source.indexOf('let sproutNu7Status =');
  assert.notEqual(start, -1, 'availability state must be defined');
  const end = source.indexOf('// Only the newest import', start);
  vm.runInContext(source.slice(start, end), ctx);
  vm.runInContext(['walletSproutExecutionConfig', 'sproutNu7StatusConfig', 'sproutNu7StatusCurrent',
    'invalidateSproutNu7Status', 'renderSproutNu7Availability', 'refreshSproutNu7Status']
    .map(declaration).join('\n'), ctx);
  return { $, ctx, pending, run: () => vm.runInContext('refreshSproutNu7Status()', ctx),
    status: () => vm.runInContext('sproutNu7Status.state', ctx) };
}
test('availability starts unknown and validates both activation boundaries from backend height', async () => {
  const h = availabilityHarness();
  assert.equal(h.status(), 'unknown');
  for (const [network, activation] of [['mainnet', 3543405], ['testnet', 4465026]]) {
    h.$('network-select').value = network;
    for (const [height, state] of [[activation - 2, 'before_activation'], [activation - 1, 'before_activation'], [activation, 'activated'], [activation + 1, 'activated']]) {
      const task = h.run();
      h.pending.shift()({ state, activation_height: activation, tip_height: height, allow_new_spends: height < activation - 1, warning: 'NU7 deadline' });
      await task;
      assert.equal(h.status(), state);
      assert.equal(vm.runInContext('sproutNu7StatusCurrent().allow_new_spends', h.ctx), height < activation - 1);
    }
  }
});
test('missing height and contradictory availability fail closed', async () => {
  const h = availabilityHarness();
  for (const result of [
    { state: 'before_activation', activation_height: 3543405, tip_height: null },
    { state: 'before_activation', activation_height: 3543405, tip_height: 3543405 },
    { state: 'before_activation', activation_height: 4465026, tip_height: 3000000 },
  ]) {
    const task = h.run(); h.pending.shift()(result); await task;
    assert.equal(h.status(), 'unknown');
  }
});
test('late availability cannot authorize a changed wallet, endpoint, network, or newer request', async () => {
  const safe = { state: 'before_activation', activation_height: 3543405, tip_height: 3543404, warning: 'deadline' };
  for (const change of [
    h => vm.runInContext('walletFile = {summary:{sprout_keys:1}}', h.ctx),
    h => { h.$('lightwalletd-url').value = 'https://changed.example'; },
    h => { h.$('network-select').value = 'testnet'; },
  ]) {
    const h = availabilityHarness(); const task = h.run(); change(h); h.pending.shift()(safe); await task;
    assert.equal(h.status(), 'unknown');
  }
  const h = availabilityHarness(); const old = h.run(); const latest = h.run();
  h.pending[1]({ state: 'activated', activation_height: 3543405, tip_height: 3543405, warning: 'read only' });
  await latest; h.pending[0](safe); await old;
  assert.equal(h.status(), 'activated');
});


test('a backend permission cannot authorize the next inclusion block at activation, or omit explicit permission', async () => {
  const h = availabilityHarness();
  for (const result of [
    { state: 'before_activation', activation_height: 3543405, tip_height: 3543404, allow_new_spends: true },
    { state: 'before_activation', activation_height: 3543405, tip_height: 3543403 },
  ]) {
    const pending = h.run(); h.pending.shift()(result); await pending;
    assert.equal(vm.runInContext('sproutNu7StatusCurrent().allow_new_spends', h.ctx), false);
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
