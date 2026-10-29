const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const flush = () => new Promise((resolve) => setImmediate(resolve));
const report = (notes) => ({ blocks_scanned: 100, joinsplits_seen: 3,
  notes_found: notes, spent_notes: 0, total_zatoshis: notes * 100000,
  tip_warning: null });
const review = (id) => ({ proposal_id: id, notes: 1, gross_zatoshis: 100000,
  fee_zatoshis: 10000, net_zatoshis: 90000, params_present: true,
  params_path: "/fixture/sprout.params", lands_in_sapling: "Lands in Sapling",
  active: [], mined: [] });
const lifecycle = (transactions, overrides = {}) => ({
  transactions, mined_zatoshis: 0, pending_zatoshis: 0, unknown_zatoshis: 0,
  skipped: [], rejected: [], warnings: [],
  error: null, fresh_all_mined: false, ...overrides,
});

function functionSource(source, name) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must remain testable`);
  const end = source.indexOf("\n}\n", start);
  assert.notEqual(end, -1, `${name} must have a closing brace`);
  return source.slice(start, end + 3);
}

// The scan code and its real event handlers run in a VM. Only Tauri IPC and
// the DOM boundary are simulated; the returned handles are opaque strings.
function harness(intercept = (_, __, fallback) => fallback(), { failCompletionListener = false } = {}) {
  const ids = new Set([...fs.readFileSync("gui/src/index.html", "utf8").matchAll(/\bid="([^"]+)"/g)]
    .map((match) => match[1]));
  const elements = new Map();
  const listeners = new Map();
  const calls = [];
  let nextHandle = 0;
  function element() {
    return { value: "", textContent: "", hidden: false, disabled: false, checked: false,
      children: [], listeners: {},
      get innerHTML() { return ""; },
      set innerHTML(value) { assert.equal(value, ""); this.children = []; },
      appendChild(child) { this.children.push(child); },
      addEventListener(name, callback) { (this.listeners[name] ??= []).push(callback); },
      dispatch(name) { for (const callback of this.listeners[name] ?? []) callback({ target: this }); },
    };
  }
  const $ = (id) => {
    assert.ok(ids.has(id), `Unknown DOM id: ${id}`);
    if (!elements.has(id)) elements.set(id, element());
    return elements.get(id);
  };
  $("network-select").value = "mainnet";
  $("sprout-scan-keys").value = "SK-fixture";
  $("sprout-scan-sweep").hidden = true;
  $("sprout-scan-sweep-run").disabled = true;
  const context = vm.createContext({
    $, document: { createElement: element }, fmt: (n) => String(n),
    confirmationSourcesFromForm: () => ["backup=https://confirm.example"],
    clearTransientSecrets() {},
    setTimeout: (callback) => setImmediate(callback),
    setStatus: (id, message) => { $(id).textContent = message; },
    listen: async (name, callback) => {
      if (failCompletionListener && name === "sprout-scan-complete") throw new Error("event channel unavailable");
      listeners.set(name, callback);
      return () => {};
    },
    invoke: (command, args) => {
      calls.push({ command, args });
      return intercept(command, args, async () => {
        if (command === "start_sprout_scan" || command === "retry_sprout_scan") return `scan-${++nextHandle}`;
        if (command === "get_sprout_scan") return { handle: args.handle, status: "running", report: null, error: null };
        if (command === "release_sprout_scan" || command === "pause_sprout_scan" || command === "release_sprout_proposal") return null;
        if (command === "propose_sprout_scan_sweep") return review(`proposal-${args.scanHandle}`);
        if (command === "execute_sprout_scan_sweep") return lifecycle([]);
        throw new Error(`Unexpected IPC command: ${command}`);
      });
    },
  });
  const source = fs.readFileSync("gui/src/main.js", "utf8");
  const start = source.indexOf("let sproutScanHandle = null;");
  const end = source.indexOf("// ─── Step 3: Configuration", start);
  vm.runInContext("let walletFile = null; let uncoveredSproutKeys = 0; function renderSproutUncoveredBanners() {} function checkSaplingKeys() {} function invalidateWalletSproutReview() {}", context);
  // Defined outside the scan section on main: the NU7 panel toggle, the
  // broadcast hook, and the settings step's birthday-touched flag.
  vm.runInContext("var sproutNu7Broadcast = false; var sproutScanNu7Broadcast = false; " +
    "var broadcastsNoted = []; function onSproutScanEntryToggle() {} " +
    "function noteSproutBroadcast(report, fromScan) { broadcastsNoted.push({ report, fromScan }); " +
    "sproutNu7Broadcast = true; if (fromScan) sproutScanNu7Broadcast = true; } " +
    "var birthdayTouched = false;", context);
  vm.runInContext([
    "sproutReviewHasLifecycleStatus",
    "sproutReviewMayRun",
    "sproutSourceWarningMayClear",
    "sproutLifecycleAmount",
    "sproutLifecycleRow",
    "renderSproutSweepReport",
  ].map((name) => functionSource(source, name)).join("\n"), context);
  vm.runInContext(source.slice(start, end), context);
  return {
    $, calls,
    edit(id, value, event = "input") { $(id).value = value; $(id).dispatch(event); },
    emit(name, payload) { assert.ok(listeners.has(name), `No ${name} listener`); listeners.get(name)({ payload }); },
    scan: () => vm.runInContext("runSproutScan()", context),
    sweep: () => vm.runInContext("runSproutScanSweep()", context),
    peek: (expression) => vm.runInContext(expression, context),
  };
}

test("Sprout progress and completion are filtered by scan handle", async () => {
  const h = harness();
  await h.scan();
  await flush();
  h.emit("sprout-scan-progress", { handle: "scan-1", height: 50, target: 100, notesFound: 1 });
  assert.match(h.$("sprout-scan-status").textContent, /50/);
  h.emit("sprout-scan-progress", { handle: "old-scan", height: 99, target: 100, notesFound: 9 });
  assert.doesNotMatch(h.$("sprout-scan-status").textContent, /99/);
  h.emit("sprout-scan-complete", { handle: "old-scan", status: "completed", report: report(9), error: null });
  assert.equal(h.$("sprout-scan-sweep").hidden, true);
  h.emit("sprout-scan-complete", { handle: "scan-1", status: "completed", report: report(1), error: null });
  assert.equal(h.$("sprout-scan-sweep").hidden, false);
});

test("an immediate Sprout completion is recovered from the snapshot", async () => {
  const h = harness((command, args, fallback) => command === "get_sprout_scan"
    ? { handle: args.handle, status: "completed", report: report(1), error: null }
    : fallback());
  await h.scan();
  assert.equal(h.$("sprout-scan-sweep").hidden, false);
  assert.match(h.$("sprout-scan-status").textContent, /1 note/);
});

test("zero-note saved scan with lifecycle status opens and executes reconciliation", async () => {
  const statusReview = {
    ...review("status-proposal"),
    notes: 0,
    gross_zatoshis: 0,
    fee_zatoshis: 0,
    net_zatoshis: 0,
    params_present: false,
    active: [{ txid: "pending-tx", value_zatoshis: 7, state: "pending", mined_height: null }],
  };
  const h = harness((command, args, fallback) => {
    if (command === "propose_sprout_scan_sweep") return statusReview;
    if (command === "execute_sprout_scan_sweep") {
      return lifecycle([{ txid: "pending-tx", value_zatoshis: 7, state: "pending", mined_height: null }]);
    }
    return fallback();
  });
  await h.scan();
  await flush();
  h.$("sprout-scan-destination").value = "zs-current-review-only";
  h.emit("sprout-scan-complete", {
    handle: "scan-1",
    status: "completed",
    report: { ...report(0), has_lifecycle_status: true },
    error: null,
  });
  await flush();

  assert.equal(h.$("sprout-scan-sweep").hidden, false);
  assert.equal(h.peek("sproutScanReview?.proposal_id"), "status-proposal");
  assert.equal(h.$("sprout-scan-sweep-run").textContent, "Check status and continue");
  assert.match(h.$("sprout-scan-sweep-plan").textContent, /No note is ready|saved transaction/i);
  assert.doesNotMatch(h.$("sprout-scan-sweep-plan").textContent, /to your address|new transaction will be proved/i);

  h.$("sprout-scan-confirm").checked = true;
  h.$("sprout-scan-confirm").dispatch("change");
  await h.sweep();
  assert.equal(
    h.calls.filter((call) => call.command === "execute_sprout_scan_sweep").length,
    1,
  );
});

test("failed completion listener polls a running scan to its terminal snapshot", async () => {
  let reads = 0;
  const h = harness((command, args, fallback) => {
    if (command === "get_sprout_scan") {
      reads++;
      return reads === 1
        ? { handle: args.handle, status: "running", report: null, error: null }
        : { handle: args.handle, status: "completed", report: report(1), error: null };
    }
    return fallback();
  }, { failCompletionListener: true });
  await h.scan();
  assert.equal(reads, 2);
  assert.equal(h.$("sprout-scan-sweep").hidden, false);
  assert.match(h.$("sprout-scan-status").textContent, /1 note/);
});

test("scan A result cannot be displayed under scan B", async () => {
  const old = deferred();
  const h = harness((command, args, fallback) =>
    command === "get_sprout_scan" && args.handle === "scan-1" ? old.promise : fallback());
  const first = h.scan();
  await flush();
  await h.scan();
  old.resolve({ handle: "scan-1", status: "completed", report: report(9), error: null });
  await first;
  await flush();
  assert.equal(h.$("sprout-scan-sweep").hidden, true);
  h.emit("sprout-scan-complete", { handle: "scan-2", status: "completed", report: report(1), error: null });
  assert.match(h.$("sprout-scan-status").textContent, /1 note/);
});

test("a start response after a source edit releases its stale scan handle", async () => {
  const pending = deferred();
  const h = harness((command, args, fallback) => command === "start_sprout_scan"
    ? pending.promise : fallback());
  const starting = h.scan();
  await flush();
  h.edit("sprout-scan-keys", "SK-other");
  pending.resolve("scan-stale");
  await starting;
  assert.equal(h.peek("sproutScanHandle"), null);
  assert.equal(h.$("sprout-scan-sweep").hidden, true);
  assert.ok(h.calls.some((call) => call.command === "release_sprout_scan" &&
    call.args.handle === "scan-stale"));
});

test("scan source edit releases its handle and hides sweep controls", async () => {
  const h = harness();
  await h.scan();
  await flush();
  h.emit("sprout-scan-complete", { handle: "scan-1", status: "completed", report: report(1), error: null });
  h.$("sprout-scan-destination").value = "zs-destination";
  h.$("sprout-scan-destination").dispatch("change");
  await flush();
  h.$("sprout-scan-confirm").checked = true;
  h.edit("sprout-scan-keys", "SK-other");
  assert.equal(h.$("sprout-scan-sweep").hidden, true);
  assert.equal(h.$("sprout-scan-status").textContent, "");
  assert.equal(h.$("sprout-scan-confirm").checked, false);
  assert.ok(h.calls.some((call) => call.command === "release_sprout_scan" && call.args.handle === "scan-1"));
});

test("scan-derived execution sends only proposal id", async () => {
  const h = harness();
  await h.scan();
  await flush();
  h.emit("sprout-scan-complete", { handle: "scan-1", status: "completed", report: report(1), error: null });
  h.edit("sprout-scan-destination", "zs-destination", "change");
  await flush();
  h.$("sprout-scan-confirm").checked = true;
  h.$("sprout-scan-confirm").dispatch("change");
  await h.sweep();
  assert.deepEqual(h.calls.filter((call) => call.command === "execute_sprout_scan_sweep")
    .map((call) => JSON.parse(JSON.stringify(call.args))), [{ proposalId: "proposal-scan-1" }]);
});

test("destination edit invalidates scan-derived proposal", async () => {
  const pending = deferred();
  const h = harness((command, args, fallback) =>
    command === "propose_sprout_scan_sweep" && args.destination === "zs-new"
      ? pending.promise : fallback());
  await h.scan();
  await flush();
  h.emit("sprout-scan-complete", { handle: "scan-1", status: "completed", report: report(1), error: null });
  h.edit("sprout-scan-destination", "zs-old", "change");
  await flush();
  h.$("sprout-scan-confirm").checked = true;
  h.$("sprout-scan-confirm").dispatch("change");
  h.edit("sprout-scan-destination", "zs-new");
  assert.equal(h.$("sprout-scan-confirm").checked, false);
  assert.equal(h.$("sprout-scan-sweep-run").disabled, true);
  pending.resolve(review("proposal-new"));
});

test("scan review without proving parameters cannot execute", async () => {
  const h = harness((command, args, fallback) => command === "propose_sprout_scan_sweep"
    ? { ...review("missing-params"), params_present: false }
    : fallback());
  await h.scan();
  await flush();
  h.emit("sprout-scan-complete", { handle: "scan-1", status: "completed", report: report(1), error: null });
  h.edit("sprout-scan-destination", "zs-destination", "change");
  await flush();
  h.$("sprout-scan-confirm").checked = true;
  h.$("sprout-scan-confirm").dispatch("change");
  await h.sweep();
  assert.equal(h.$("sprout-scan-sweep-run").disabled, true);
  assert.equal(h.calls.some((call) => call.command === "execute_sprout_scan_sweep"), false);
});

test("scan sweep keeps the wallet caveat when a note was refused", async () => {
  for (const [rejected, kept] of [[[], false], [["note refused"], true]]) {
    const h = harness((command, args, fallback) => command === "execute_sprout_scan_sweep"
      ? lifecycle([{ txid: "aa", value_zatoshis: 5, state: "mined", mined_height: 123 }],
        { mined_zatoshis: 5, rejected, fresh_all_mined: true })
      : fallback());
    h.peek("uncoveredSproutKeys = 1");
    await h.scan();
    await flush();
    h.emit("sprout-scan-complete", { handle: "scan-1", status: "completed", report: report(1), error: null });
    h.edit("sprout-scan-destination", "zs-destination", "change");
    await flush();
    h.$("sprout-scan-confirm").checked = true;
    await h.sweep();
    assert.equal(h.peek("uncoveredSproutKeys") > 0, kept, `rejected=${rejected.length}`);
  }
});

// Review finding 3 on #271: moving between steps used to release a running
// Sprout scan, so pressing Continue threw away an hours-long scan the user
// never meant to stop. Navigation now only drops a reviewed proposal; the
// scan, its handle and its progress survive. (Source edits still release
// it: see "scan source edit releases its handle and hides sweep controls".)
test("navigating between steps keeps a running Sprout scan and drops only its review", async () => {
  const h = harness();
  const source = fs.readFileSync("gui/src/main.js", "utf8");
  const start = source.indexOf("function goTo(step) {");
  const end = source.indexOf("\n}\n", start) + 3;
  h.peek(`var state = { matchedRecovery: null }; var steps = ["welcome", "seed", "config", "scan"];
    var STEP_ALIASES = { "wallet-file": "seed" }; var furthestStep = 0;
    function abandonMatchedRecovery() {} function updateTransparentScanSettingsVisibility() {}`);
  h.peek(`document.querySelectorAll = () => []; document.querySelector = () => null;`);
  h.peek(source.slice(start, end));
  await h.scan();
  await flush();
  h.emit("sprout-scan-complete", { handle: "scan-1", status: "completed", report: report(1), error: null });
  h.edit("sprout-scan-destination", "zs-destination", "change");
  await flush();
  assert.equal(h.peek("sproutScanReview?.proposal_id"), "proposal-scan-1");

  h.peek('goTo("config")');
  h.peek('goTo("wallet-file")');
  assert.equal(h.calls.some((call) => call.command === "release_sprout_scan"), false,
    "navigation must not release the scan");
  assert.equal(h.peek("sproutScanHandle"), "scan-1");
  assert.equal(h.$("sprout-scan-sweep").hidden, false);
  // The review is dropped, so the box must be ticked again on return.
  assert.equal(h.peek("sproutScanReview"), null);
  assert.ok(h.calls.some((call) => call.command === "release_sprout_proposal" &&
    call.args.proposalId === "proposal-scan-1"));
  assert.equal(h.$("sprout-scan-sweep-run").disabled, true);
});

test("a running scan's progress still reaches the panel after navigating away and back", async () => {
  const h = harness();
  const source = fs.readFileSync("gui/src/main.js", "utf8");
  const start = source.indexOf("function goTo(step) {");
  const end = source.indexOf("\n}\n", start) + 3;
  h.peek(`var state = { matchedRecovery: null }; var steps = ["welcome", "seed", "config", "scan"];
    var STEP_ALIASES = { "wallet-file": "seed" }; var furthestStep = 0;
    function abandonMatchedRecovery() {} function updateTransparentScanSettingsVisibility() {}`);
  h.peek(`document.querySelectorAll = () => []; document.querySelector = () => null;`);
  h.peek(source.slice(start, end));
  await h.scan();
  await flush();
  h.peek('goTo("config")');
  h.peek('goTo("wallet-file")');
  h.emit("sprout-scan-progress", { handle: "scan-1", height: 70, target: 100, notesFound: 0 });
  assert.match(h.$("sprout-scan-status").textContent, /70/);
});

// A result that finishes after the panel moved on is still rendered as
// historical evidence, but it cannot mutate the newly selected source.
test("a scan sweep that finishes after the source changed still reports its lifecycle", async () => {
  const pending = deferred();
  const h = harness((command, args, fallback) => command === "execute_sprout_scan_sweep"
    ? pending.promise : fallback());
  await h.scan();
  await flush();
  h.emit("sprout-scan-complete", { handle: "scan-1", status: "completed", report: report(1), error: null });
  h.edit("sprout-scan-destination", "zs-destination", "change");
  await flush();
  h.$("sprout-scan-confirm").checked = true;
  h.$("sprout-scan-confirm").dispatch("change");
  const sweeping = h.sweep();
  await flush();
  // The user edits the key box while proving runs: a new scan source.
  h.edit("sprout-scan-keys", "SK-other");
  assert.equal(h.peek("sproutScanHandle"), null);
  pending.resolve(lifecycle([
    { txid: "moved-tx", value_zatoshis: 90000, state: "pending", mined_height: null },
  ], { pending_zatoshis: 90000 }));
  await sweeping;
  const lines = h.$("sprout-scan-sweep-results").children.map((child) => child.textContent);
  assert.ok(lines.some((line) => /moved-tx/.test(line)), JSON.stringify(lines));
  assert.ok(lines.some((line) => /earlier Sprout scan/.test(line)), JSON.stringify(lines));
  assert.equal(h.$("sprout-scan-sweep").hidden, false, "the report must be visible");
  assert.equal(h.peek("broadcastsNoted.length"), 0);
  assert.equal(h.peek("sproutNu7Broadcast"), false);
  assert.equal(h.peek("sproutScanNu7Broadcast"), false);
});

test("an earlier fresh-mined result cannot clear or relabel the current Sprout source", async () => {
  const pending = deferred();
  const h = harness((command, args, fallback) => command === "execute_sprout_scan_sweep"
    ? pending.promise : fallback());
  h.peek("uncoveredSproutKeys = 1");
  await h.scan();
  await flush();
  h.emit("sprout-scan-complete", {
    handle: "scan-1",
    status: "completed",
    report: report(1),
    error: null,
  });
  h.edit("sprout-scan-destination", "zs-destination", "change");
  await flush();
  h.$("sprout-scan-confirm").checked = true;
  h.$("sprout-scan-confirm").dispatch("change");
  const sweeping = h.sweep();
  await flush();

  // Source B replaces A while A's network operation is still in flight.
  h.edit("sprout-scan-keys", "SK-source-b");
  h.peek("uncoveredSproutKeys = 2");
  const currentAction = h.$("sprout-scan-sweep-run").textContent;
  pending.resolve(lifecycle([
    { txid: "a-mined-tx", value_zatoshis: 90000, state: "mined", mined_height: 456 },
  ], { mined_zatoshis: 90000, fresh_all_mined: true }));
  await sweeping;

  const lines = h.$("sprout-scan-sweep-results").children.map((child) => child.textContent);
  assert.ok(lines.some((line) => /a-mined-tx/.test(line)), JSON.stringify(lines));
  assert.ok(lines.some((line) => /earlier Sprout scan/.test(line)), JSON.stringify(lines));
  assert.equal(h.peek("uncoveredSproutKeys"), 2, "A must not clear B's source caveat");
  assert.equal(h.peek("sproutNu7Broadcast"), false, "A must not relabel B's wallet warning");
  assert.equal(h.peek("sproutScanNu7Broadcast"), false, "A must not relabel B's scan warning");
  assert.equal(h.peek("broadcastsNoted.length"), 0, "A must not run the current-source broadcast hook");
  assert.equal(h.$("sprout-scan-sweep-run").textContent, currentAction);
  assert.equal(h.peek("sproutScanHandle"), null);
  assert.equal(h.peek("sproutScanReview"), null);
});

test("a peer edit during retry keeps only the rotated source and rejects stale results", async () => {
  const pending = deferred();
  let retries = 0;
  const h = harness((command, args, fallback) => {
    if (command === "retry_sprout_scan" && ++retries === 1) return pending.promise;
    if (command === "retry_sprout_scan") return "scan-current";
    return fallback();
  });
  await h.scan();
  const retrying = h.scan();
  await flush();
  h.edit("sprout-scan-peers", "192.0.2.8:8233");
  pending.resolve("scan-rotated");
  await retrying;
  await flush();
  assert.equal(h.peek("sproutScanHandle"), null);
  assert.equal(h.peek("sproutScanRetryHandle"), "scan-rotated");
  assert.ok(h.calls.some(({ command, args }) => command === "pause_sprout_scan" && args.handle === "scan-rotated"));
  h.emit("sprout-scan-complete", { handle: "scan-rotated", status: "completed", report: report(9), error: null });
  assert.equal(h.$("sprout-scan-sweep").hidden, true);
  await h.scan();
  const latest = h.calls.filter(({ command }) => command === "retry_sprout_scan").at(-1);
  assert.equal(latest.args.handle, "scan-rotated");
  assert.deepEqual([...latest.args.peers], ["192.0.2.8:8233"]);
  assert.equal(h.peek("sproutScanHandle"), "scan-current");
});

test("a key change during retry releases the rotated source instead of adopting it", async () => {
  const pending = deferred();
  const h = harness((command, args, fallback) => command === "retry_sprout_scan" ? pending.promise : fallback());
  await h.scan();
  const retrying = h.scan();
  await flush();
  h.edit("sprout-scan-keys", "SK-different-source");
  pending.resolve("scan-obsolete");
  await retrying;
  await flush();
  assert.equal(h.peek("sproutScanHandle"), null);
  assert.equal(h.peek("sproutScanRetryHandle"), null);
  assert.ok(h.calls.some(({ command, args }) => command === "release_sprout_scan" && args.handle === "scan-obsolete"));
});

test("a malformed peer edit does not discard retained Sprout retry keys", async () => {
  const h = harness();
  await h.scan();
  h.edit("sprout-scan-peers", "missing-port");
  await flush();
  await h.scan();
  assert.match(h.$("sprout-scan-status").textContent, /host:port/);
  assert.equal(h.peek("sproutScanRetryHandle"), "scan-1");
  assert.equal(h.calls.filter(({ command }) => command === "release_sprout_scan").length, 0);
  h.edit("sprout-scan-peers", "192.0.2.8:8233");
  await h.scan();
  assert.equal(h.calls.filter(({ command }) => command === "retry_sprout_scan").length, 1);
});

// Review of #290, finding 1: birthday auto-detect, estimate-from-date and the
// network default set the wallet birthday in code, with no input event, so
// retry authority survived and retry reused the old decrypt plan. An earlier
// birthday then left the blocks between the two never trial-decrypted.
test("a birthday changed in code releases retry authority instead of reusing the old plan", async () => {
  const h = harness();
  h.peek("birthdayTouched = true");
  h.$("birthday-height").value = "5000";
  await h.scan();
  await flush();
  h.emit("sprout-scan-complete", { handle: "scan-1", status: "failed", report: null, error: "timed out" });
  assert.equal(h.peek("sproutScanRetryHandle"), "scan-1");

  h.$("birthday-height").value = "1000"; // as auto-detect does: no event
  await h.scan();
  await flush();
  assert.equal(h.calls.filter(({ command }) => command === "retry_sprout_scan").length, 0,
    "retry must not reuse a decrypt plan built from another birthday");
  assert.ok(h.calls.some(({ command, args }) => command === "release_sprout_scan" && args.handle === "scan-1"));
  assert.equal(h.peek("sproutScanRetryHandle"), null);
  assert.match(h.$("sprout-scan-status").textContent, /birthday/i);
});

test("an unchanged birthday still retries with the retained plan", async () => {
  const h = harness();
  h.peek("birthdayTouched = true");
  h.$("birthday-height").value = "5000";
  await h.scan();
  await flush();
  h.emit("sprout-scan-complete", { handle: "scan-1", status: "failed", report: null, error: "timed out" });
  await h.scan();
  await flush();
  const retries = h.calls.filter(({ command }) => command === "retry_sprout_scan");
  assert.equal(retries.length, 1);
  assert.equal(retries[0].args.handle, "scan-1");
});

// Merging #292 into #290: a retry reads blocks from the pack the panel names
// now, as it does with the peers. The pack never decides which notes are
// found (on mainnet only the pinned one opens), so it is not part of the
// retained plan.
test("a retry sends the Sprout pack folder the panel names now", async () => {
  const h = harness();
  h.$("sprout-scan-pack").value = "/packs/first";
  await h.scan();
  await flush();
  assert.equal(h.calls.find(({ command }) => command === "start_sprout_scan").args.sproutPack, "/packs/first");
  h.emit("sprout-scan-complete", { handle: "scan-1", status: "failed", report: null, error: "timed out" });
  h.$("sprout-scan-pack").value = " /packs/second ";
  await h.scan();
  await flush();
  const retry = h.calls.find(({ command }) => command === "retry_sprout_scan");
  assert.equal(retry.args.handle, "scan-1");
  assert.equal(retry.args.sproutPack, "/packs/second");
});
