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
  params_path: "/fixture/sprout.params", lands_in_sapling: "Lands in Sapling" });

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
        if (command === "start_sprout_scan") return `scan-${++nextHandle}`;
        if (command === "get_sprout_scan") return { handle: args.handle, status: "running", report: null, error: null };
        if (command === "release_sprout_scan" || command === "release_sprout_proposal") return null;
        if (command === "propose_sprout_scan_sweep") return review(`proposal-${args.scanHandle}`);
        if (command === "execute_sprout_scan_sweep") return { sent: [], skipped: [], total_swept: 0, error: null };
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
  vm.runInContext("var broadcastsNoted = []; function onSproutScanEntryToggle() {} function noteSproutBroadcast(report, fromScan) { broadcastsNoted.push({ report, fromScan }); } var birthdayTouched = false;", context);
  vm.runInContext(source.slice(source.indexOf("function sweepLeftNothingBehind(report)"),
    source.indexOf("function noteUncoveredSproutKeys(summary)")), context);
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
      ? { sent: [{ txid: "aa", value_swept: 5 }], total_swept: 5,
          skipped: [], rejected, error: null }
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

// Review finding 4 on #271: a sweep that finished after the panel moved on
// to another scan returned before rendering, so its broadcast txids were
// never shown and the NU7 warning never switched to "confirm it is mined".
// Funds that moved must always be reported, labelled as the earlier scan's.
test("a scan sweep that finishes after the source changed still reports its broadcast", async () => {
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
  pending.resolve({ sent: [{ txid: "moved-tx", value_swept: 90000 }], total_swept: 90000,
    skipped: [], rejected: [], error: null });
  await sweeping;
  const lines = h.$("sprout-scan-sweep-results").children.map((child) => child.textContent);
  assert.ok(lines.some((line) => /moved-tx/.test(line)), JSON.stringify(lines));
  assert.ok(lines.some((line) => /earlier Sprout scan/.test(line)), JSON.stringify(lines));
  assert.equal(h.$("sprout-scan-sweep").hidden, false, "the report must be visible");
  assert.equal(h.peek("broadcastsNoted.length"), 1);
  assert.equal(h.peek("broadcastsNoted[0].fromScan"), true);
});
