const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("gui/src/main.js", "utf8");

function loadFunctions(names, context) {
  const declarations = names.map((name) => {
    const asyncStart = source.indexOf(`async function ${name}(`);
    const start = asyncStart >= 0 ? asyncStart : source.indexOf(`function ${name}(`);
    assert.notEqual(start, -1, `${name} must exist`);
    const end = source.indexOf("\n}\n", start);
    assert.notEqual(end, -1, `${name} must have a closing brace`);
    return source.slice(start, end + 3);
  });
  return vm.runInNewContext(`${declarations.join("\n")}; ({ ${names.join(", ")} })`, context);
}

function harness(invoke, confirm = () => true, prompt = () => "tx-1") {
  const elements = new Map();
  function element() {
    const listeners = new Map();
    return {
      value: "", textContent: "", hidden: false, disabled: false,
      className: "", style: {}, dataset: {}, children: [],
      set innerHTML(value) { this.children = []; this._innerHTML = value; },
      get innerHTML() { return this._innerHTML || ""; },
      appendChild(child) { this.children.push(child); },
      replaceChildren(...children) { this.children = children; },
      addEventListener(name, callback) { listeners.set(name, callback); },
      fire(name) { return this[`on${name}`]?.({ target: this }) ?? listeners.get(name)?.({ target: this }); },
    };
  }
  const $ = (id) => {
    if (!elements.has(id)) elements.set(id, element());
    return elements.get(id);
  };
  const state = {
    retainedAddressSearchId: null, scanHandle: { id: "scan-a" },
    completedScanHandle: { id: "scan-a" }, scanAuthorityGeneration: 1,
    scanConfig: null, lastProgress: { phase: "complete" }, reconciliationPending: false,
    reviewInvalidations: 0,
  };
  const functions = loadFunctions([
    "txStatusKind", "txStatusLabel", "sweepStatusCounts", "sweepCompleteSummary",
    "buildReport", "buildDefaultReportPath", "renderCompleteScreen",
    "applyReconciledTransactions", "refreshSweepStatus", "retryStoredSweepTransaction",
    "confirmationSourcesFromForm", "showSavedTransactions",
  ], {
    $, state, invoke, window: { confirm, prompt }, Date,
    document: { createElement: element },
    fmt: (n) => `${(n / 1e8).toFixed(8)} ZEC`,
    setStatus: (id, message) => { $(id).textContent = message; },
    invalidateSweepReview: () => { state.reviewInvalidations += 1; },
    goTo: (step) => { state.step = step; },
  });
  return { $, state, ...functions };
}

function outcome(status) {
  return {
    transactions: [{ source_account: 2, txid: "tx-1", status,
      fee_zatoshis: 10000, detail: "accepted", confirmed_height: null }],
    skipped_accounts: [], total_donation_zatoshis: 0,
    donation_note: null, error: null, follow_up_review_required: true,
  };
}

test("status refresh observes pending journal tx and renders canonical mined evidence", async () => {
  const calls = [];
  const h = harness(async (command, args) => {
    calls.push({ command, args });
    assert.equal(command, "reconcile_sweep");
    return [{ txid: "tx-1", status: "mined", fee_zatoshis: 10000,
      confirmed_height: 120, detail: "two independent matching blocks" }];
  });
  const initial = outcome("pending");
  h.renderCompleteScreen(initial.transactions, [], 0, null, null, null,
    { outcome: initial, handle: { id: "scan-a" } });
  await h.$("complete-check-status").fire("click");
  assert.deepEqual(JSON.parse(JSON.stringify(calls)),
    [{ command: "reconcile_sweep", args: { handle: { id: "scan-a" } } }]);
  assert.match(h.$("complete-txids").children[0].children.map((x) => x.textContent).join(" "),
    /Mined at block 120|two independent matching blocks/);
  assert.equal(h.$("delete-workspace").disabled, true,
    "a partial staged sweep still needs new review after its first tx mined");
  assert.match(h.$("complete-reconciliation-status").textContent, /fresh scan/i);
  assert.equal(h.state.reviewInvalidations, 1);
  assert.equal(h.state.lastProgress, null);
});

test("unknown retry requires explicit confirmation and sends only handle and txid", async () => {
  const calls = [];
  const typed = [];
  const h = harness(async (command, args) => {
    calls.push({ command, args });
    assert.equal(command, "retry_unknown_sweep");
    return { txid: "tx-1", status: "pending", fee_zatoshis: 10000,
      confirmed_height: null, detail: "exact saved transaction accepted" };
  }, () => true, (_message, initial) => { typed.push(initial); return "tx-1"; });
  const initial = outcome("submission_unknown");
  h.renderCompleteScreen(initial.transactions, [], 0, null, null, null,
    { outcome: initial, handle: { id: "scan-a" } });
  const card = h.$("complete-txids").children[0];
  const retry = card.children.find((child) => child.textContent.includes("Retry saved transaction"));
  assert.ok(retry, "Unknown transaction must have an explicit retry control");
  await retry.fire("click");
  assert.deepEqual(typed, [""], "successful retry required a blank full-txid prompt");
  assert.deepEqual(JSON.parse(JSON.stringify(calls)), [{ command: "retry_unknown_sweep",
    args: { handle: { id: "scan-a" }, txid: "tx-1" } }]);
  assert.match(h.$("complete-summary").textContent, /independent confirmation/i);
});

test("declining an Unknown retry performs no network command", async () => {
  const calls = [];
  const h = harness(async (command) => { calls.push(command); }, () => false);
  const initial = outcome("submission_unknown");
  h.renderCompleteScreen(initial.transactions, [], 0, null, null, null,
    { outcome: initial, handle: { id: "scan-a" } });
  const retry = h.$("complete-txids").children[0].children
    .find((child) => child.textContent.includes("Retry saved transaction"));
  await retry.fire("click");
  assert.deepEqual(calls, []);
});

test("retry requires typing the full txid after a cross-wallet journal warning", async () => {
  const calls = [];
  const prompts = [];
  const h = harness(async (command) => { calls.push(command); }, () => true,
    (message, initial) => { prompts.push({ message, initial }); return "tx-2"; });
  h.state.scanConfig = { network: "mainnet", data_dir: "/wallet-data" };
  const initial = outcome("submission_unknown");
  h.renderCompleteScreen(initial.transactions, [], 0, null, null, null,
    { outcome: initial, handle: { id: "scan-a" } });
  const retry = h.$("complete-txids").children[0].children
    .find((child) => child.textContent.includes("Retry saved transaction"));
  await retry.fire("click");
  assert.equal(prompts.length, 1);
  assert.equal(prompts[0].initial, "", "the txid must not be prefilled");
  assert.match(prompts[0].message, /mainnet.*\/wallet-data.*another wallet/i);
  assert.deepEqual(calls, [], "a mismatch must never reach Tauri");
  assert.match(h.$("complete-reconciliation-status").textContent, /txid.*match/i);
});

test("a prepared but not submitted record offers the exact saved transaction retry", async () => {
  const h = harness(async (command, args) => {
    assert.equal(command, "retry_unknown_sweep");
    assert.equal(args.txid, "tx-1");
    return { txid: "tx-1", status: "pending", fee_zatoshis: 10000,
      confirmed_height: null, detail: "accepted" };
  });
  const initial = outcome("not_submitted");
  h.renderCompleteScreen(initial.transactions, [], 0, null, null, null,
    { outcome: initial, handle: { id: "scan-a" } });
  const retry = h.$("complete-txids").children[0].children
    .find((child) => child.textContent.includes("Retry saved transaction"));
  assert.ok(retry, "durable prepared bytes need an explicit crash-recovery control");
  await retry.fire("click");
  assert.match(h.$("complete-summary").textContent, /independent confirmation/i);
});

test("an incomplete journal response cannot enable workspace deletion", async () => {
  const h = harness(async () => []);
  const initial = outcome("mined");
  initial.follow_up_review_required = false;
  h.renderCompleteScreen(initial.transactions, [], 0, null, null, null,
    { outcome: initial, handle: { id: "scan-a" } });
  await h.$("complete-check-status").fire("click");
  assert.equal(h.$("delete-workspace").disabled, true);
  assert.match(h.$("complete-reconciliation-status").textContent, /did not return every displayed transaction/);
});

test("status refresh lists other journal transactions and keeps cleanup blocked", async () => {
  const h = harness(async () => [
    { txid: "tx-1", status: "mined", fee_zatoshis: 10000,
      confirmed_height: 120, detail: "canonical block evidence" },
    { txid: "tx-older", status: "submission_unknown", fee_zatoshis: 10000,
      confirmed_height: null, detail: "older retry unresolved" },
  ]);
  const initial = outcome("pending");
  initial.follow_up_review_required = false;
  h.renderCompleteScreen(initial.transactions, [], 0, null, null, null,
    { outcome: initial, handle: { id: "scan-a" } });
  await h.$("complete-check-status").fire("click");
  assert.equal(h.$("complete-txids").children.length, 2);
  assert.equal(h.$("delete-workspace").disabled, true);
  assert.match(h.$("save-report").dataset.report, /tx-older/);
});

test("newly discovered mined journal receipt invalidates an older review", async () => {
  const h = harness(async () => [
    { txid: "tx-1", status: "pending", fee_zatoshis: 10000,
      confirmed_height: null, detail: "still pending" },
    { txid: "older-mined", status: "mined", fee_zatoshis: 10000,
      confirmed_height: 119, detail: "canonical block evidence" },
  ]);
  const initial = outcome("pending");
  h.renderCompleteScreen(initial.transactions, [], 0, null, null, null,
    { outcome: initial, handle: { id: "scan-a" } });
  await h.$("complete-check-status").fire("click");
  assert.equal(h.state.reviewInvalidations, 1);
  assert.match(h.$("complete-reconciliation-status").textContent, /fresh scan/i);
});

test("confirmation source input keeps explicit operator and URL lines", () => {
  const h = harness(async () => []);
  h.$("confirmation-sources").value =
    " independent=https://other.example:443\n\n second=https://second.example:443 ";
  assert.deepEqual(Array.from(h.confirmationSourcesFromForm()), [
    "independent=https://other.example:443", "second=https://second.example:443",
  ]);
});

test("a new scan can open prior journal records and the saved-byte retry control", async () => {
  const calls = [];
  const h = harness(async (command, args) => {
    calls.push({ command, args });
    assert.equal(command, "reconcile_sweep");
    return [{ txid: "older-unknown", status: "submission_unknown", fee_zatoshis: 10000,
      confirmed_height: null, detail: "unresolved prior send" }];
  });
  await h.showSavedTransactions();
  assert.equal(h.state.step, "complete");
  assert.match(h.$("complete-heading").textContent, /saved transaction status/i);
  assert.equal(h.$("delete-workspace").disabled, true);
  const retry = h.$("complete-txids").children[0].children
    .find((child) => child.textContent.includes("Retry saved transaction"));
  assert.ok(retry);
  assert.deepEqual(JSON.parse(JSON.stringify(calls)),
    [{ command: "reconcile_sweep", args: { handle: { id: "scan-a" } } }]);
  assert.match(source, /\$\("scan-saved-transactions"\)\.addEventListener\("click",\s*showSavedTransactions\)/);
});
