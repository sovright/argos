const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("gui/src/main.js", "utf8");
const start = source.indexOf("function donationParamsFromForm()");
const end = source.indexOf("// ─── Step 6: Complete", start);
assert.ok(start >= 0 && end > start);

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function harness(
  propose = async () => review("proposal-current"),
  execute = async () => ({ transactions: [], skipped_accounts: [], total_donation_zatoshis: 0 }),
) {
  const elements = new Map();
  const calls = [];
  const completed = [];
  const chips = ["10", "99", "custom"].map((pct) => element({ pct }));
  function element(dataset = {}) {
    const listeners = new Map();
    return {
      value: "", checked: false, disabled: false, hidden: false,
      textContent: "", title: "", dataset, children: [], style: {},
      classList: { add() {}, remove() {} },
      addEventListener(type, callback) { listeners.set(type, callback); },
      fire(type) { return listeners.get(type)?.({ target: this }); },
      setAttribute() {},
      querySelector() { return element(); },
      appendChild(child) { this.children.push(child); },
      replaceChildren(...children) { this.children = children; },
      closest() { return null; },
    };
  }
  const $ = (id) => {
    if (!elements.has(id)) elements.set(id, element());
    return elements.get(id);
  };
  $("destination-input").value = "zs-reviewed";
  $("sweep-memo").value = "reviewed memo";
  $("max-fee-zec").value = "0.01";
  $("donate-enabled").checked = true;
  $("donate-rate").value = "10";
  const state = {
    scanHandle: { id: "scan-current" }, scanAuthorityGeneration: 0, destination: "zs-reviewed",
    memo: "reviewed memo", maxFeeZec: "0.01", donationEnabled: true,
    scanConfig: { network: "mainnet" }, lastProgress: { phase: "complete" },
    sweepReview: null, proposalGeneration: 0, proposalPending: false,
    sweepExecutionPending: false,
  };
  const context = vm.createContext({
    state, $, fmt: (value) => String(value),
    document: {
      querySelectorAll: () => chips,
      createElement: () => element(),
      createTextNode: (text) => ({ textContent: text }),
    },
    invoke: async (command, args) => {
      calls.push({ command, args });
      if (command === "propose_sweep") return propose(args);
      if (command === "execute_sweep") return execute(args);
      throw new Error(`unexpected command ${command}`);
    },
    setStatus: (id, message) => { $(id).textContent = message; },
    goTo: () => {},
    renderCompleteScreen: (...args) => completed.push(args),
    cleanupListeners: () => {}, eta: { reset() {} },
  });
  vm.runInContext(source.slice(start, end), context);
  return {
    $, state, chips, calls, completed, context,
    refresh: () => vm.runInContext("refreshSweepProposal()", context),
    fire: (id, type) => $(id).fire(type),
    executeArgs: () => calls.filter((call) => call.command === "execute_sweep").map((call) => call.args),
  };
}

function review(id, overrides = {}) {
  const proposal = {
    transactions: [], skipped_accounts: [], net_received_zatoshis: 100000,
    total_fee_zatoshis: 1000, total_donation_zatoshis: 10000,
    ...overrides,
  };
  return { proposal_id: id, proposal };
}

async function accepted(h) {
  await h.refresh();
  h.$("irreversible-check").checked = true;
  h.fire("irreversible-check", "change");
  assert.equal(h.$("execute-sweep").disabled, false);
}

test("reviewed 10 percent donation executes only its proposal id", async () => {
  const h = harness();
  await accepted(h);
  await h.fire("execute-sweep", "click");
  assert.deepEqual(JSON.parse(JSON.stringify(h.executeArgs()[0])), {
    handle: { id: "scan-current" }, proposalId: "proposal-current",
  });
});

test("changing donation to 99 percent disables execution immediately", async () => {
  const pending = deferred();
  const h = harness(async (args) => args.donationRate === 0.99 ? pending.promise : review("proposal-current"));
  await accepted(h);
  h.$("donate-rate").value = "99";
  h.fire("donate-rate", "input");
  assert.equal(h.$("irreversible-check").checked, false);
  assert.equal(h.$("irreversible-check").disabled, true);
  assert.equal(h.$("execute-sweep").disabled, true);
  const next = h.fire("donate-rate", "change");
  assert.equal(h.$("execute-sweep").disabled, true);
  pending.resolve(review("proposal-new"));
  await next;
});

test("older proposal success cannot replace a newer review", async () => {
  const old = deferred();
  const h = harness(async (args) => args.donationRate === 0.1 ? old.promise : review("proposal-new"));
  const first = h.refresh();
  h.$("donate-rate").value = "99";
  await h.refresh();
  old.resolve(review("proposal-old", { net_received_zatoshis: 1 }));
  await first;
  assert.equal(h.state.sweepReview.proposal_id, "proposal-new");
  assert.match(h.$("sweep-summary").textContent, /100000/);
});

test("older proposal failure cannot disable a newer review", async () => {
  const old = deferred();
  const h = harness(async (args) => args.donationRate === 0.1 ? old.promise : review("proposal-new"));
  const first = h.refresh();
  h.$("donate-rate").value = "99";
  await h.refresh();
  old.reject(new Error("old proposal failed"));
  await Promise.allSettled([first]);
  h.$("irreversible-check").checked = true;
  h.fire("irreversible-check", "change");
  assert.equal(h.state.sweepReview.proposal_id, "proposal-new");
  assert.equal(h.$("execute-sweep").disabled, false);
  assert.doesNotMatch(h.$("sweep-execute-status").textContent, /old proposal failed/);
});

test("proposal failure leaves irreversible controls disabled", async () => {
  let fail = false;
  const h = harness(async () => {
    if (fail) throw new Error("proposal unavailable");
    return review("proposal-current");
  });
  await accepted(h);
  fail = true;
  await Promise.allSettled([h.refresh()]);
  assert.equal(h.$("irreversible-check").checked, false);
  assert.equal(h.$("irreversible-check").disabled, true);
  assert.equal(h.$("execute-sweep").disabled, true);
  h.$("irreversible-check").checked = true;
  h.fire("irreversible-check", "change");
  assert.equal(h.$("execute-sweep").disabled, true);
});

test("destination memo fee and donor email edits invalidate review", async () => {
  for (const id of ["destination-input", "sweep-memo", "max-fee-zec", "donate-email"]) {
    const h = harness();
    await accepted(h);
    h.$(id).value = "edited";
    h.fire(id, "input");
    assert.equal(h.state.sweepReview, null, `${id} retained old review`);
    assert.equal(h.$("irreversible-check").disabled, true, `${id} left checkbox enabled`);
    assert.equal(h.$("execute-sweep").disabled, true, `${id} left execution enabled`);
  }
});

test("execute_sweep sends no mutable request fields", async () => {
  const h = harness();
  await accepted(h);
  await h.fire("execute-sweep", "click");
  assert.deepEqual(JSON.parse(JSON.stringify(h.executeArgs())), [{
    handle: { id: "scan-current" }, proposalId: "proposal-current",
  }]);
});

test("donation edits cannot enable another sweep during execution", async () => {
  const inFlight = deferred();
  const h = harness(async () => review("proposal-next"), () => inFlight.promise);
  await accepted(h);
  const first = h.fire("execute-sweep", "click");
  assert.equal(h.executeArgs().length, 1);

  h.$("donate-rate").value = "99";
  h.fire("donate-rate", "input");
  h.fire("donate-rate", "change");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(h.$("irreversible-check").disabled, true);
  assert.equal(h.$("execute-sweep").disabled, true);
  assert.equal(h.calls.filter((call) => call.command === "propose_sweep").length, 1);

  h.$("irreversible-check").checked = true;
  h.fire("irreversible-check", "change");
  await h.fire("execute-sweep", "click");
  assert.equal(h.executeArgs().length, 1);
  inFlight.reject(new Error("first sweep failed"));
  await first;
  assert.equal(h.state.sweepExecutionPending, false);
  assert.equal(h.state.sweepReview, null);
  await h.refresh();
  assert.equal(h.state.sweepReview.proposal_id, "proposal-next");
});

test("source edit during execution clears authority but retains the old broadcast receipt", async () => {
  const inFlight = deferred();
  const h = harness(async () => review("proposal-old"), () => inFlight.promise);
  await accepted(h);
  loadFlow(h, "function invalidateScanAuthority(", "function donationParamsFromForm(");
  const first = h.fire("execute-sweep", "click");
  h.$("network-select").fire("input");
  assert.equal(h.state.scanHandle, null);
  assert.equal(h.state.lastProgress, null);
  assert.equal(h.$("review-sweep").disabled, true);
  inFlight.resolve({ transactions: [{ txid: "old-tx", status: "pending" }],
    skipped_accounts: [], total_donation_zatoshis: 0 });
  await first;
  assert.equal(h.completed.length, 1);
  assert.equal(h.completed[0][0][0].txid, "old-tx");
  assert.equal(h.completed[0].at(-1).handle.id, "scan-current");
  assert.equal(h.state.scanHandle, null);
  assert.equal(h.$("execute-sweep").disabled, true);
});

function flowHarness() {
  const elements = new Map();
  const events = new Map();
  const calls = [];
  const chips = ["10", "99"].map((pct) => ({
    dataset: { pct }, setAttribute(name, value) { this[name] = value; },
  }));
  function element() {
    const handlers = new Map();
    return {
      value: "", checked: false, disabled: false, hidden: false, innerHTML: "old",
      textContent: "old", style: {}, classList: { add() {}, remove() {}, toggle() {} },
      children: [], dataset: {},
      addEventListener(type, handler) {
        if (!handlers.has(type)) handlers.set(type, []);
        handlers.get(type).push(handler);
      },
      fire(type) {
        const results = (handlers.get(type) || []).map((handler) => handler({ target: this }));
        return results.at(-1);
      },
      appendChild(child) { this.children.push(child); },
      setAttribute() {}, focus() {},
    };
  }
  const $ = (id) => {
    if (!elements.has(id)) elements.set(id, element());
    return elements.get(id);
  };
  const state = {
    scanHandle: { id: "scan-old" }, scanAuthorityGeneration: 0,
    lastProgress: { phase: "complete" },
    sweepReview: review("old"), proposalGeneration: 4, proposalPending: false,
    sweepExecutionPending: false, destination: "zs-old", memo: "old memo",
    maxFeeZec: "0.5", donationEnabled: true,
    scanConfig: { network: "mainnet", data_dir: "/old", lightwalletd_url: "old" },
    savedReportPath: "/old/report", retainedAddressSearchId: null, matchedRecovery: null,
  };
  $("destination-input").value = "zs-old";
  $("sweep-memo").value = "old memo";
  $("max-fee-zec").value = "0.5";
  $("donate-enabled").checked = false;
  $("donate-rate").value = "99";
  $("donate-email").value = "old@example.test";
  $("scan-rows").innerHTML = "old rows";
  $("scan-discoveries").innerHTML = "old discovery";
  $("scan-totals").textContent = "old balance";
  $("sweep-rows").innerHTML = "old proposal";
  $("sweep-skipped").innerHTML = "old skipped account";
  $("irreversible-check").checked = true;
  $("execute-sweep").disabled = false;
  $("review-sweep").disabled = false;
  const context = vm.createContext({
    state, $, window: {}, seedInput: element(), seedVisibility: element(), seedNextBtn: element(),
    steps: ["welcome", "seed", "config", "scan"], furthestStep: 3,
    SERVER_PRESETS: { mainnet: "main.example", testnet: "test.example" },
    eta: { reset() {} }, fmt: String,
    document: {
      createElement: () => element(),
      querySelectorAll: () => chips,
      dispatchEvent() {},
    },
    CustomEvent: class { constructor(name, opts) { this.type = name; this.detail = opts?.detail; } },
    invoke: async (command, args) => {
      calls.push({ command, args });
      if (command === "validate_address") return { destination_ok: true };
      if (command === "resume_session") return {
        handle: { id: "scan-new" }, network: "testnet", data_dir: "/resumed",
        lightwalletd_url: "resumed.example",
      };
      throw new Error(`unexpected ${command}`);
    },
    listen: async (name, callback) => { events.set(name, callback); return () => events.delete(name); },
    setStatus: (id, message) => { $(id).textContent = message; },
    cleanupListeners() {}, invalidateSweepReview() {
      state.proposalGeneration++;
      state.sweepReview = null;
      $("irreversible-check").checked = false;
      $("irreversible-check").disabled = true;
      $("execute-sweep").disabled = true;
    },
    forgetWalletCaveats() {},
    // This harness loads only the ordinary-flow slice; Sprout review state is
    // exercised by the dedicated wallet and scan VM suites.
    invalidateWalletSproutReview() {},
    invalidateSproutScanSource() {},
    updateTransparentScanSummary() {}, clearMatchedRecoveryUi() {},
    goTo() {}, updateScanUI(progress) { state.lastProgress = progress; },
    notifyScanComplete() {},
  });
  context.walletOpenGeneration = 0;
  context.sproutPreviewWallet = { path: "/old/wallet.dat" };
  context.walletFile = { path: "/old/wallet.dat" };
  const forgetStart = source.indexOf("function forgetLoadedWalletFile(");
  const forgetEnd = source.indexOf("function renderSproutUncoveredBanners(", forgetStart);
  vm.runInContext(source.slice(forgetStart, forgetEnd), context);
  return { $, state, context, events, calls, chips };
}

function loadFlow(h, start, end) {
  const from = source.indexOf(start);
  const to = source.indexOf(end, from);
  assert.ok(from >= 0 && to > from, `missing production flow ${start}`);
  vm.runInContext(source.slice(from, to), h.context);
}

test("scan discovery from another handle is ignored", async () => {
  const h = flowHarness();
  loadFlow(h, "async function startProgressListeners(", "function scanCompletionSummary(");
  await vm.runInContext('startProgressListeners({ id: "scan-old" })', h.context);
  const staleListener = h.events.get("scan-discovery");
  h.state.scanHandle = { id: "scan-new" };
  await vm.runInContext('startProgressListeners({ id: "scan-new" })', h.context);
  const old = { handle: { id: "scan-old" }, discovery: {
    account_index: 1, pool: "orchard", zatoshis: 5, at_block_height: 10,
  } };
  h.events.get("scan-discovery")({ payload: old });
  assert.equal(h.$("scan-discoveries").children.length, 0);
  staleListener({ payload: { ...old, handle: { id: "scan-new" } } });
  assert.equal(h.$("scan-discoveries").children.length, 0);
  h.events.get("scan-discovery")({ payload: { ...old, handle: { id: "scan-new" } } });
  assert.equal(h.$("scan-discoveries").children.length, 1);
  assert.match(h.$("scan-discoveries").children[0].textContent, /account 1/);
  h.events.get("scan-progress")({ payload: { handle: { id: "scan-old" }, phase: "complete" } });
  assert.equal(h.state.lastProgress.phase, "complete");
});

test("source setting edits invalidate completed scan authority", () => {
  for (const id of [
    "seed-input", "wallet-path", "sapling-scan-keys", "network-select",
    "birthday-height", "accounts-range", "gap-limit", "transparent-index-start",
    "lightwalletd-url", "data-dir", "sprout-scan-peers",
  ]) {
    const h = flowHarness();
    loadFlow(h, "function invalidateScanAuthority(", "function donationParamsFromForm(");
    h.$(id).fire("input");
    assert.equal(h.state.scanHandle, null, `${id} retained the scan handle`);
    assert.equal(h.state.lastProgress, null, `${id} retained progress`);
    assert.equal(h.state.sweepReview, null, `${id} retained sweep review`);
    assert.equal(h.$("review-sweep").disabled, true, `${id} left review available`);
    assert.equal(h.$("scan-rows").innerHTML, "");
    assert.equal(h.$("scan-discoveries").innerHTML, "");
    assert.equal(h.$("sweep-skipped").innerHTML, "", `${id} retained skipped account`);
    assert.doesNotMatch(h.$("scan-totals").textContent, /old balance/);
  }
});

test("editing wallet path drops the prior loaded wallet", () => {
  const h = flowHarness();
  h.$("wallet-path").value = "/new/wallet.dat";
  loadFlow(h, "function invalidateScanAuthority(", "function donationParamsFromForm(");
  h.$("wallet-path").fire("input");
  assert.equal(h.context.walletFile, null);
  assert.equal(h.$("wallet-path").value, "/new/wallet.dat");
});

test("wallet drop invalidates the previous scan before opening the new file", async () => {
  const h = flowHarness();
  loadFlow(h, "function invalidateScanAuthority(", "function donationParamsFromForm(");
  const nativeEvents = new Map();
  let opened = 0;
  h.context.window.__TAURI__ = { event: {
    listen: async (name, callback) => { nativeEvents.set(name, callback); },
  } };
  h.context.document.querySelector = () => ({ classList: { contains: () => true } });
  h.context.openWalletFile = () => { opened++; };
  loadFlow(h, "// Drag-and-drop, using Tauri", '$("sprout-sweep-run").addEventListener');
  await new Promise((resolve) => setImmediate(resolve));
  nativeEvents.get("tauri://drag-drop")({ payload: { paths: ["/new/wallet.dat"] } });
  assert.equal(h.state.scanHandle, null);
  assert.equal(h.state.sweepReview, null);
  assert.equal(h.$("wallet-path").value, "/new/wallet.dat");
  assert.equal(opened, 1);
});

test("a start response after a source edit cannot install its old handle", async () => {
  const h = flowHarness();
  const oldStart = deferred();
  const commands = [];
  let scanViews = 0;
  let listeners = 0;
  h.context.walletFile = null;
  h.context.seedInput.value = "seed A";
  h.$("destination-input").value = "zs-destination";
  h.$("data-dir").value = "/new-data";
  h.$("network-select").value = "mainnet";
  h.$("auto-gap-limit").checked = true;
  h.$("gap-limit").value = "20";
  h.$("birthday-height").value = "419200";
  h.context.hasSaplingScanKeys = () => false;
  h.context.shouldShowTransparentRange = () => false;
  h.context.scanKeySourceConflict = () => null;
  h.context.defaultScanLabel = () => "scan";
  h.context.startProgressListeners = async () => { listeners++; };
  h.context.goTo = () => { scanViews++; };
  h.context.invoke = async (command, args) => {
    commands.push({ command, args });
    if (command === "validate_address") return { destination_ok: true };
    if (command === "start_scan") return oldStart.promise;
    if (command === "cancel_scan") return null;
    throw new Error(`unexpected ${command}`);
  };
  loadFlow(h, "function invalidateScanAuthority(", "function donationParamsFromForm(");
  loadFlow(h, '$("start-scan").addEventListener("click"', "// ─── Step 4: Scan Progress");
  const first = h.$("start-scan").fire("click");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(commands.filter((call) => call.command === "start_scan").length, 1);
  h.$("network-select").fire("input");
  h.context.seedInput.value = "seed B";
  oldStart.resolve({ id: "scan-A" });
  await first;
  assert.equal(h.state.scanHandle, null);
  assert.equal(h.state.scanConfig, null);
  assert.equal(h.context.seedInput.value, "seed B");
  assert.equal(scanViews, 0);
  assert.equal(listeners, 0);
  assert.equal(commands.filter((call) => call.command === "cancel_scan").length, 1);
});

test("a stale matched-start failure releases its address-search lock", async () => {
  const h = flowHarness();
  const oldStart = deferred();
  h.state.matchedRecovery = { searchId: "search-A", matchId: "match-A" };
  h.context.walletFile = null;
  h.$("destination-input").value = "zs-destination";
  h.$("data-dir").value = "/data";
  h.$("network-select").value = "mainnet";
  h.$("auto-gap-limit").checked = true;
  h.$("gap-limit").value = "20";
  h.$("birthday-height").value = "419200";
  h.context.hasSaplingScanKeys = () => false;
  h.context.shouldShowTransparentRange = () => false;
  h.context.scanKeySourceConflict = () => null;
  h.context.defaultScanLabel = () => "scan";
  h.context.configForMatchedRecovery = (config) => config;
  h.context.invoke = async (command) => {
    if (command === "validate_address") return { destination_ok: true };
    if (command === "start_matched_recovery") return oldStart.promise;
    throw new Error(`unexpected ${command}`);
  };
  loadFlow(h, "function invalidateScanAuthority(", "function donationParamsFromForm(");
  loadFlow(h, '$("start-scan").addEventListener("click"', "// ─── Step 4: Scan Progress");
  const first = h.$("start-scan").fire("click");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(h.state.addressMatchRecoveryLocked, true);
  h.$("network-select").fire("input");
  oldStart.reject(new Error("old start failed"));
  await first;
  assert.equal(h.state.addressMatchRecoveryLocked, false);
});

for (const oldOutcome of ["resolved", "rejected"]) {
  test(`an old matched start ${oldOutcome} cannot unlock a newer matched start`, async () => {
    const h = flowHarness();
    const firstStart = deferred();
    const secondStart = deferred();
    const commands = [];
    h.state.matchedRecovery = { searchId: "search-A", matchId: "match-A" };
    h.context.walletFile = null;
    h.$("destination-input").value = "zs-destination";
    h.$("data-dir").value = "/data";
    h.$("network-select").value = "mainnet";
    h.$("auto-gap-limit").checked = true;
    h.$("gap-limit").value = "20";
    h.$("birthday-height").value = "419200";
    h.context.hasSaplingScanKeys = () => false;
    h.context.shouldShowTransparentRange = () => false;
    h.context.scanKeySourceConflict = () => null;
    h.context.defaultScanLabel = () => "scan";
    h.context.configForMatchedRecovery = (config) => config;
    h.context.startProgressListeners = async () => {};
    h.context.invoke = async (command, args) => {
      commands.push({ command, args });
      if (command === "validate_address") return { destination_ok: true };
      if (command === "start_matched_recovery") {
        return commands.filter((call) => call.command === "start_matched_recovery").length === 1
          ? firstStart.promise : secondStart.promise;
      }
      if (command === "cancel_scan") return null;
      throw new Error(`unexpected ${command}`);
    };
    loadFlow(h, "function invalidateScanAuthority(", "function donationParamsFromForm(");
    loadFlow(h, '$("start-scan").addEventListener("click"', "// ─── Step 4: Scan Progress");
    const first = h.$("start-scan").fire("click");
    await new Promise((resolve) => setImmediate(resolve));
    h.$("network-select").fire("input");
    const second = h.$("start-scan").fire("click");
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(commands.filter((call) => call.command === "start_matched_recovery").length, 2);
    assert.equal(h.state.addressMatchRecoveryLocked, true);
    if (oldOutcome === "resolved") firstStart.resolve({ id: "scan-A" });
    else firstStart.reject(new Error("old start failed"));
    await first;
    assert.equal(h.state.addressMatchRecoveryLocked, true);
    secondStart.resolve({ id: "scan-B" });
    await second;
    assert.equal(h.state.scanHandle.id, "scan-B");
    assert.equal(h.state.addressMatchRecoveryLocked, true);
  });
}

test("destination edit preserves completed scan authority", async () => {
  const h = harness();
  await accepted(h);
  h.$("destination-input").value = "zs-new";
  h.fire("destination-input", "input");
  assert.equal(h.state.scanHandle.id, "scan-current");
  assert.equal(h.state.lastProgress.phase, "complete");
  assert.equal(h.state.sweepReview, null);
});

test("resume initializes every reviewed field", async () => {
  const h = flowHarness();
  loadFlow(h, "function invalidateScanAuthority(", "function donationParamsFromForm(");
  loadFlow(h, "function resetRecoveryFlowState(", '$("restart-flow").addEventListener');
  loadFlow(h, "async function startProgressListeners(", "function scanCompletionSummary(");
  vm.runInContext("let pendingResumeRow = null;", h.context);
  loadFlow(h, "function openResumeModal(", "// ─── Init");
  vm.runInContext('openResumeModal({ workspace_path: "/resumed/ws", network: "testnet", match_coordinates: null })', h.context);
  h.$("resume-seed-input").value = "seed words";
  h.$("resume-destination-input").value = "zs-new";
  h.$("resume-memo-input").value = "new memo";
  h.$("resume-max-fee-zec").value = "0.02";
  await h.$("resume-confirm").fire("click");
  assert.equal(h.calls.filter((call) => call.command === "resume_session").length, 1);
  assert.equal(h.state.scanHandle.id, "scan-new");
  assert.equal(h.state.scanConfig.network, "testnet");
  assert.equal(h.state.scanConfig.data_dir, "/resumed");
  assert.equal(h.state.scanConfig.lightwalletd_url, "resumed.example");
  assert.equal(h.state.destination, "zs-new");
  assert.equal(h.state.memo, "new memo");
  assert.equal(h.state.maxFeeZec, "0.02");
  assert.equal(h.$("destination-input").value, "zs-new");
  assert.equal(h.$("sweep-memo").value, "new memo");
  assert.equal(h.$("max-fee-zec").value, "0.02");
  assert.equal(h.$("donate-enabled").checked, true);
  assert.equal(h.$("donate-rate").value, "10");
  assert.equal(h.$("donate-email").value, "");
  assert.equal(h.context.walletFile, null);
  assert.equal(h.state.sweepReview, null);
  assert.equal(h.state.lastProgress, null);
  assert.equal(h.$("scan-rows").innerHTML, "");
  assert.equal(h.$("scan-discoveries").innerHTML, "");
  assert.equal(h.$("sweep-skipped").innerHTML, "");
  assert.equal(h.$("review-sweep").disabled, true);
});

test("start over still drops the loaded wallet", () => {
  const h = flowHarness();
  loadFlow(h, "function invalidateScanAuthority(", "function donationParamsFromForm(");
  loadFlow(h, "function resetRecoveryFlowState(", "// ─── Donate");
  h.$("restart-flow").fire("click");
  assert.equal(h.context.walletFile, null);
  assert.equal(h.$("wallet-path").value, "");
  assert.equal(h.state.scanHandle, null);
  assert.equal(h.$("donate-rate").value, "10");
  assert.equal(h.$("scan-rows").innerHTML, "");
  assert.equal(h.$("sweep-skipped").innerHTML, "");
});
