const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

// Stand-in for the `sprout_nu7_warning` command: distinct text per network
// and per broadcast state, shaped like the real core strings.
function nu7Text({ network, broadcast }) {
  if (broadcast) {
    return `${network} NU7: your Sprout recovery transaction was broadcast, but it must be ` +
      `mined before NU7 activation; confirm it is mined.`;
  }
  return network === "testnet"
    ? "Testnet NU7: the activation height is 4,465,026; broadcast alone is not enough."
    : "URGENT: NU7 mainnet targeted for about November 5, 2026. Start recovery promptly: " +
      "must be mined before activation; broadcast alone is not enough.";
}

function sproutTransaction(state, overrides = {}) {
  return {
    txid: `${state}-tx`,
    value_zatoshis: 5,
    state,
    mined_height: state === "mined" ? 321 : null,
    ...overrides,
  };
}

function sproutLifecycleReport(transactions, overrides = {}) {
  return {
    transactions,
    mined_zatoshis: transactions
      .filter((transaction) => transaction.state === "mined")
      .reduce((sum, transaction) => sum + (transaction.value_zatoshis ?? 0), 0),
    pending_zatoshis: transactions
      .filter((transaction) => transaction.state === "pending")
      .reduce((sum, transaction) => sum + (transaction.value_zatoshis ?? 0), 0),
    unknown_zatoshis: transactions
      .filter((transaction) => transaction.state === "submission_unknown")
      .reduce((sum, transaction) => sum + (transaction.value_zatoshis ?? 0), 0),
    skipped: [],
    rejected: [],
    warnings: [],
    error: null,
    fresh_all_mined: false,
    ...overrides,
  };
}

// Exercise wallet opening, summary rendering and preview together. Only the
// desktop IPC boundary and DOM are stand-ins; no wallet secrets or funds are used.
function harness(intercept = (_, __, fallback) => fallback()) {
  const elements = new Map();
  const ids = new Set([...fs.readFileSync("gui/src/index.html", "utf8").matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]));
  function element() {
    return {
      value: "", textContent: "",
      checked: false,
      listeners: {},
      addEventListener(name, callback) { (this.listeners[name] ??= []).push(callback); },
      dispatch(name) { for (const callback of this.listeners[name] ?? []) callback({ target: this }); },
      get innerHTML() { return ""; },
      set innerHTML(value) { assert.equal(value, ""); this.children = []; },
      hidden: false, disabled: false,
      children: [],
      appendChild(child) { this.children.push(child); },
      get childElementCount() { return this.children.length; },
    };
  }
  const $ = (id) => {
    assert.ok(ids.has(id), `Unknown DOM id: ${id}`);
    if (!elements.has(id)) elements.set(id, element());
    return elements.get(id);
  };
  $("network-select").value = "mainnet";
  $("sprout-destination").value = "fixture-destination";
  $("confirmation-sources").value = "backup=https://confirm.example";
  const previews = [];
  const timers = new Map();
  let nextTimerId = 1;
  let onProgress;
  let failStatus = false;
  const context = vm.createContext({
    listen: async (name, callback) => { assert.equal(name, "sprout-sweep-progress"); onProgress = callback; },
    $, document: { createElement: element, dispatchEvent() {} },
    CustomEvent: class { constructor(type) { this.type = type; } },
    fmt: (value) => String(value),
    confirmationSourcesFromForm: () => $("confirmation-sources").value
      .split("\n").map((line) => line.trim()).filter(Boolean),
    // The scan panel's peer field; replaced by the real helpers when a test
    // loads the scan panel.
    sproutScanPeerEntries: () => ["192.0.2.7:8233"],
    sproutScanPeers: () => ["192.0.2.7:8233"],
    setTimeout(callback, delay) {
      const id = nextTimerId++;
      timers.set(id, { callback, delay, cleared: false });
      return id;
    },
    clearTimeout(id) {
      const timer = timers.get(id);
      if (timer) timer.cleared = true;
    },
    setStatus: (id, text) => {
      if (failStatus) { failStatus = false; throw new Error("fixture DOM failure"); }
      $(id).textContent = text;
    },
    invalidateSproutScanSource() {},
    invoke: (command, args) => {
      const result = intercept(command, args, async () => {
      if (command === "inspect_wallet_file") return {
        review_id: `review:${args.path}`,
        needs_passphrase: false, transparent_keys: 0, sapling_keys: 0,
        sprout_keys: 1, has_mnemonic: false, sprout_spendable_notes: 1,
        sprout_spendable_zatoshis: 100000, sprout_addresses: [], diagnostics: [],
        sprout_has_lifecycle_status: false,
        sprout_nu7_warning: "NU7: Sprout recovery must be mined before activation; broadcasting alone is not enough. Check the current mainnet activation schedule.",
        coverage_notice: null, coverage_may_hide_funds: false, seed_note: null,
      };
      if (command === "sprout_nu7_warning") return nu7Text(args);
      if (command === "propose_wallet_sprout_sweep") {
        previews.push({ ...args });
        return {
          proposal_id: `wallet-proposal-${previews.length}`,
          notes: 1, gross_zatoshis: 100000, fee_zatoshis: 10000,
          net_zatoshis: 90000, lands_in_sapling: "Lands in Sapling",
          params_present: true, params_path: "/fixture/sprout.params",
          active: [], mined: [],
          nu7_warning: "NU7: Sprout recovery must be mined before activation; broadcasting alone is not enough. Check the current mainnet activation schedule.",
        };
      }
      if (command === "release_sprout_proposal" || command === "release_sprout_scan") return null;
      // #271's scan API: a scan returns a backend handle, its result is a
      // snapshot, and a sweep is a reviewed proposal executed by id.
      if (command === "start_sprout_scan") return "scan-1";
      if (command === "get_sprout_scan") return { handle: args.handle, status: "running", report: null, error: null };
      if (command === "propose_sprout_scan_sweep") {
        return {
          proposal_id: `scan-proposal-${args.scanHandle}`,
          notes: 1, gross_zatoshis: 100000, fee_zatoshis: 10000,
          net_zatoshis: 90000, lands_in_sapling: "Lands in Sapling",
          params_present: true, params_path: "/fixture/sprout.params",
          active: [], mined: [],
          nu7_warning: "NU7: Sprout recovery must be mined before activation.",
        };
      }
        throw new Error(`Unexpected IPC command: ${command}`);
      });
      if (command !== "inspect_wallet_file") return result;
      return Promise.resolve(result).then((summary) => {
        if (summary && !summary.needs_passphrase &&
            (summary.transparent_keys + summary.sapling_keys + summary.sprout_keys > 0) &&
            summary.review_id === undefined) {
          return { ...summary, review_id: `review:${args.path}` };
        }
        return summary;
      });
    },
  });
  const source = fs.readFileSync("gui/src/main.js", "utf8");
  vm.runInContext(source.slice(
    source.indexOf("let walletFile = null;"),
    source.indexOf("// The picker itself runs in Rust"),
  ), context);
  const progressStart = source.indexOf("(async () => {", source.indexOf("// Proving runs for minutes"));
  vm.runInContext(source.slice(progressStart, source.indexOf("// ─── Typed Sapling keys", progressStart)), context);
  vm.runInContext(source.slice(source.indexOf('for (const id of ["sprout-scan-keys"'),
    source.indexOf("const sproutScanListenersReady", source.indexOf('for (const id of ["sprout-scan-keys"'))), context);
  return {
    $, previews,
    timers,
    fireTimer(id, { includeCleared = false } = {}) {
      const timer = timers.get(id);
      assert.ok(timer, `unknown timer ${id}`);
      if (!timer.cleared || includeCleared) timer.callback();
    },
    edit(id, value, event = "input") { $(id).value = value; $(id).dispatch(event); },
    failNextStatus: () => { failStatus = true; },
    progress: (payload) => onProgress({ payload }),
    sweep: () => vm.runInContext("runSproutSweep()", context),
    sweepConfirmed() { $("sprout-sweep-confirm").checked = true; $("sprout-sweep-confirm").dispatch("change"); return vm.runInContext("runSproutSweep()", context); },
    peek: (expr) => vm.runInContext(expr, context),
    // Executes a scan-derived sweep the way a user reaches it under #271: a
    // completed scan (its backend handle and report), a destination reviewed
    // through `propose_sprout_scan_sweep`, the box ticked, then the button.
    async scanSweep() {
      this.loadScanPanel();
      vm.runInContext(
        'sproutScanHandle = "scan-1"; sproutScanResult = { notes_found: 1, total_zatoshis: 5, spent_notes: 0 };',
        context,
      );
      if (!$("sprout-scan-destination").value) $("sprout-scan-destination").value = "fixture-destination";
      await vm.runInContext("refreshSproutScanReview()", context);
      $("sprout-scan-confirm").checked = true;
      return vm.runInContext("runSproutScanSweep()", context);
    },
    // The whole Sprout scan section, with its real key and peer helpers, for
    // driving the panel as a user with no wallet file would. Loaded once:
    // its `let` state cannot be declared twice in one context.
    loadScanPanel() {
      if (vm.runInContext("typeof runSproutScanSweep", context) === "function" &&
          vm.runInContext("typeof refreshSproutScanReview", context) === "function") return;
      const start = source.indexOf("// ─── Sprout scan ─");
      const end = source.indexOf('$("sprout-scan-sweep-run").addEventListener', start);
      assert.ok(start > 0 && end > start);
      // Declared on the settings step, outside every slice: the main birthday
      // field counts toward the Sprout decrypt bound only once it was set.
      if (vm.runInContext("typeof birthdayTouched", context) === "undefined") {
        vm.runInContext("var birthdayTouched = false;", context);
      }
      // Declared after the scan section; its listeners are not exercised here.
      vm.runInContext("var sproutScanListenersReady = Promise.resolve(true);", context);
      vm.runInContext(source.slice(start, end), context);
    },
    scan: () => vm.runInContext("runSproutScan()", context),
    async open(path, passphrase = "") {
      $("wallet-path").value = path;
      $("wallet-passphrase").value = passphrase;
      await vm.runInContext("openWalletFile()", context);
      await flush();
    },
    abandonWallet() {
      vm.runInContext("clearTransientSecrets({ abandonWallet: true })", context);
    },
  };
}

test("a successful wallet inspection expires frontend passphrase and review authority", async () => {
  const h = harness();
  await h.open("/fixture/encrypted.dat", "wallet secret");

  const [[timerId, timer]] = [...h.timers.entries()];
  assert.ok(timerId, "successful inspection must schedule an expiry");
  assert.ok(timer.delay <= 30 * 60 * 1000, "frontend expiry must not outlive the backend review");
  assert.equal(h.$("wallet-passphrase").value, "wallet secret");
  assert.equal(h.peek("walletFile.passphrase"), "wallet secret");
  assert.equal(h.peek("walletFile.reviewId"), "review:/fixture/encrypted.dat");

  h.fireTimer(timerId);

  assert.equal(h.$("wallet-passphrase").value, "");
  assert.equal(h.peek("walletFile"), null);
  assert.equal(h.peek("sproutPreviewWallet"), null);
  assert.equal(h.$("wallet-next").disabled, true);
  assert.equal(h.$("wallet-summary").hidden, true);
});

test("a stale wallet expiry callback cannot clear a newer successful inspection", async () => {
  const h = harness();
  await h.open("/fixture/old.dat", "old secret");
  const [oldTimerId] = [...h.timers.keys()];
  h.peek("globalThis.oldWalletReview = walletFile");

  await h.open("/fixture/new.dat", "new secret");
  const newTimerId = [...h.timers.keys()].at(-1);
  assert.notEqual(newTimerId, oldTimerId);
  assert.equal(h.timers.get(oldTimerId).cleared, true);

  // A callback may already be queued when clearTimeout runs. Its generation
  // guard, rather than timer cancellation alone, must protect the new review.
  h.fireTimer(oldTimerId, { includeCleared: true });

  assert.equal(h.$("wallet-passphrase").value, "new secret");
  assert.equal(h.peek("oldWalletReview.passphrase"), null);
  assert.equal(h.peek("walletFile.path"), "/fixture/new.dat");
  assert.equal(h.peek("walletFile.passphrase"), "new secret");
  assert.equal(h.peek("walletFile.reviewId"), "review:/fixture/new.dat");
});

test("successful secret handoff cancels expiry and a queued callback cannot revoke the accepted source", async () => {
  const h = harness();
  await h.open("/fixture/accepted.dat", "accepted secret");
  const [timerId] = [...h.timers.keys()];

  h.peek("clearTransientSecrets()");
  assert.equal(h.timers.get(timerId).cleared, true);
  assert.equal(h.$("wallet-passphrase").value, "");
  assert.equal(h.peek("walletFile.passphrase"), null);

  h.fireTimer(timerId, { includeCleared: true });
  assert.equal(h.peek("walletFile.path"), "/fixture/accepted.dat");
  assert.equal(h.peek("walletFile.reviewId"), "review:/fixture/accepted.dat");
});

test("opaque wallet review ID is passed to every wallet-backed command", async () => {
  const calls = [];
  const h = harness((command, args, fallback) => {
    if (["propose_wallet_sprout_sweep", "start_sprout_scan"].includes(command)) {
      calls.push({ command, args: { ...args } });
    }
    return fallback();
  });
  await h.open("/fixture/wallet.dat", "secret");
  await flush();
  h.loadScanPanel();
  await h.scan();

  for (const call of calls) {
    assert.equal(call.args.reviewId, "review:/fixture/wallet.dat", call.command);
    assert.equal("path" in call.args, false, call.command);
  }
  const source = fs.readFileSync("gui/src/main.js", "utf8");
  for (const command of ["detect_birthday_from_wallet_file"]) {
    const invocation = source.slice(source.indexOf(`invoke(\"${command}\"`), source.indexOf(`invoke(\"${command}\"`) + 700);
    assert.match(invocation, /reviewId:\s*walletFile\.reviewId/, command);
    assert.doesNotMatch(invocation, /path:\s*walletFile\.path/, command);
  }
  const ordinary = source.slice(source.indexOf('invoke("start_scan_from_wallet_file"'), source.indexOf('invoke("start_scan_from_wallet_file"') + 900);
  assert.match(ordinary, /review_id:\s*walletFile\s*\?\s*walletFile\.reviewId/);
  assert.doesNotMatch(ordinary, /path:\s*walletFile\s*\?\s*walletFile\.path/);
});

test("wallet Sprout sweep requires explicit irreversible confirmation", async () => {
  const executions = [];
  const h = harness((command, args, fallback) => {
    if (command === "execute_wallet_sprout_sweep") { executions.push(args); return sproutLifecycleReport([]); }
    return fallback();
  });
  h.$("sprout-destination").value = "zs-wallet";
  await h.open("/fixture/wallet.dat");
  await flush();
  assert.equal(h.$("sprout-sweep-run").disabled, true);
  await h.sweep();
  assert.deepEqual(executions, []);
  h.$("sprout-sweep-confirm").checked = true;
  h.$("sprout-sweep-confirm").dispatch("change");
  assert.equal(h.$("sprout-sweep-run").disabled, false);
});

test("wallet destination edit invalidates the reviewed proposal", async () => {
  const pending = deferred();
  const h = harness((command, args, fallback) =>
    command === "propose_wallet_sprout_sweep" && args.destination === "zs-new"
      ? pending.promise : fallback());
  h.$("sprout-destination").value = "zs-old";
  await h.open("/fixture/wallet.dat");
  await flush();
  h.$("sprout-sweep-confirm").checked = true;
  h.$("sprout-sweep-confirm").dispatch("change");
  h.edit("sprout-destination", "zs-new");
  assert.equal(h.$("sprout-sweep-confirm").checked, false);
  assert.equal(h.$("sprout-sweep-run").disabled, true);
  pending.resolve({ proposal_id: "new-proposal", notes: 1, gross_zatoshis: 100000,
    fee_zatoshis: 10000, net_zatoshis: 90000, params_present: true,
    lands_in_sapling: "Lands in Sapling" });
  h.$("sprout-destination").dispatch("change");
  await flush();
  assert.equal(h.$("sprout-sweep-run").disabled, true);
});

test("wallet execution settings invalidate and repreview confirmation authority", async () => {
  const h = harness();
  await h.open("/fixture/wallet.dat");
  assert.equal(h.peek("walletSproutReview?.proposal_id"), "wallet-proposal-1");

  h.edit("confirmation-sources", "other=https://other.example");
  assert.equal(h.peek("walletSproutReview"), null);
  h.edit("confirmation-sources", "other=https://other.example", "change");
  await flush();
  assert.equal(h.previews.length, 2);
  assert.deepEqual(
    h.previews.at(-1).confirmationSources,
    ["other=https://other.example"],
  );
});

test("late wallet preview cannot publish after unannounced config drift", async () => {
  const pending = deferred();
  const h = harness((command, _args, fallback) =>
    command === "propose_wallet_sprout_sweep" ? pending.promise : fallback());
  const opening = h.open("/fixture/wallet.dat");
  await flush();
  h.$("lightwalletd-url").value = "https://changed.example";
  pending.resolve({
    proposal_id: "stale-config", notes: 1, gross_zatoshis: 100000,
    fee_zatoshis: 10000, net_zatoshis: 90000, params_present: true,
    lands_in_sapling: "Lands in Sapling",
  });
  await opening;
  assert.equal(h.peek("walletSproutReview"), null);
});

test("wallet Sprout execution sends only proposal id", async () => {
  let executed;
  const h = harness((command, args, fallback) => {
    if (command === "execute_wallet_sprout_sweep") { executed = args; return sproutLifecycleReport([]); }
    return fallback();
  });
  h.$("sprout-destination").value = "zs-destination";
  await h.open("/fixture/wallet.dat");
  await flush();
  h.$("sprout-sweep-confirm").checked = true;
  h.$("sprout-sweep-confirm").dispatch("change");
  await h.sweep();
  assert.deepEqual(JSON.parse(JSON.stringify(executed)), { proposalId: "wallet-proposal-1" });
});

test("older wallet Sprout proposal cannot replace the current one", async () => {
  const old = deferred();
  const h = harness((command, args, fallback) =>
    command === "propose_wallet_sprout_sweep" && args.destination === "zs-old"
      ? old.promise : fallback());
  h.$("sprout-destination").value = "zs-old";
  await h.open("/fixture/wallet.dat");
  h.edit("sprout-destination", "zs-new", "change");
  await flush();
  const plan = h.$("sprout-sweep-plan").textContent;
  old.resolve({ proposal_id: "old-proposal", notes: 99, gross_zatoshis: 999,
    fee_zatoshis: 1, net_zatoshis: 998, params_present: true,
    lands_in_sapling: "Old pool" });
  await flush();
  assert.equal(h.$("sprout-sweep-plan").textContent, plan);
  assert.notEqual(h.peek("walletSproutReview?.proposal_id"), "old-proposal");
});

test("changing wallet invalidates its Sprout proposal", async () => {
  const h = harness();
  h.$("sprout-destination").value = "zs-destination";
  await h.open("/fixture/first.dat");
  await flush();
  h.$("sprout-sweep-confirm").checked = true;
  h.$("sprout-sweep-confirm").dispatch("change");
  await h.open("/fixture/second.dat");
  assert.equal(h.$("sprout-sweep-confirm").checked, false);
  assert.equal(h.$("sprout-sweep-run").disabled, true);
});

test("wallet source and endpoint edits revoke the reviewed proposal", async () => {
  for (const id of ["wallet-path", "wallet-passphrase", "network-select", "data-dir", "lightwalletd-url"]) {
    const h = harness();
    await h.open("/fixture/wallet.dat");
    h.$("sprout-sweep-confirm").checked = true;
    h.$("sprout-sweep-confirm").dispatch("change");
    assert.equal(h.$("sprout-sweep-run").disabled, false);
    h.edit(id, "changed");
    assert.equal(h.$("sprout-sweep-confirm").checked, false, id);
    assert.equal(h.$("sprout-sweep-run").disabled, true, id);
  }
});

test("network and data directory edits hide wallet Sprout evidence until reinspection", async () => {
  for (const id of ["network-select", "data-dir"]) {
    const h = harness();
    await h.open("/fixture/wallet.dat");
    assert.equal(h.$("wallet-summary").hidden, false);
    assert.equal(h.$("wallet-sprout-sweep").hidden, false);
    assert.match(h.$("sprout-sweep-plan").textContent, /note\(s\)/);
    h.edit(id, "changed");
    assert.equal(h.peek("walletFile"), null, id);
    assert.equal(h.$("wallet-summary").hidden, true, id);
    assert.equal(h.$("wallet-sprout-sweep").hidden, true, id);
    assert.equal(h.$("wallet-next").disabled, true, id);
    assert.equal(h.$("sprout-sweep-plan").textContent, "", id);
    assert.equal(h.$("sprout-sweep-spent-status").textContent, "", id);
    assert.equal(h.$("wallet-path").value, "/fixture/wallet.dat", id);
  }
});

test("first wallet open displays its Sprout preview with reviewed authority", async () => {
  const h = harness();
  await h.open("/fixture/first.dat");
  assert.deepEqual(h.previews, [{
    reviewId: "review:/fixture/first.dat", passphrase: null, destination: "fixture-destination",
    lightwalletdUrl: "", confirmationSources: ["backup=https://confirm.example"],
    network: "mainnet", dataDir: null, peers: ["192.0.2.7:8233"],
  }]);
  assert.equal(h.$("wallet-sprout-sweep").hidden, false);
  assert.match(h.$("sprout-sweep-plan").textContent, /90000 to your address/);
  assert.equal(h.$("sprout-sweep-status").textContent, "");
  assert.equal(h.$("sprout-sweep-run").disabled, true);
});

test("inspection carries no peers; the review verifies through the scan panel's", async () => {
  const seen = {};
  const h = harness(async (command, args, fallback) => {
    seen[command] = { ...args };
    if (command === "execute_wallet_sprout_sweep") return {
      sent: [], total_swept: 0, skipped: [], rejected: [], warnings: [], error: null,
    };
    return fallback();
  });
  await h.open("/fixture/peers.dat");
  await flush();
  assert.equal("peers" in seen.inspect_wallet_file, false, "opening a wallet never dials");
  assert.equal(seen.propose_wallet_sprout_sweep.reviewId, "review:/fixture/peers.dat");
  assert.equal("path" in seen.propose_wallet_sprout_sweep, false);
  assert.deepEqual(seen.propose_wallet_sprout_sweep.peers, ["192.0.2.7:8233"]);
  h.$("sprout-destination").value = "fixture-destination";
  await h.sweepConfirmed();
  // Under #271 the reviewed proposal carries the verified notes; execute
  // takes only its ID and no peers or other authority.
  assert.deepEqual(Object.keys(seen.execute_wallet_sprout_sweep), ["proposalId"]);
});

test("opening another wallet previews the new review and passphrase", async () => {
  const h = harness();
  await h.open("/fixture/first.dat", "fixture-one");
  await h.open("/fixture/second.dat", "fixture-two");
  assert.deepEqual(h.previews.at(-1), {
    reviewId: "review:/fixture/second.dat", passphrase: "fixture-two", destination: "fixture-destination",
    lightwalletdUrl: "", confirmationSources: ["backup=https://confirm.example"],
    network: "mainnet", dataDir: null, peers: ["192.0.2.7:8233"],
  });
  assert.equal(h.$("sprout-sweep-status").textContent, "");
});

test("the NU7 deadline is visible as soon as Sprout keys are detected, before preview finishes", async () => {
  const preview = deferred();
  const h = harness(async (command, args, fallback) => {
    if (command === "propose_wallet_sprout_sweep") await preview.promise;
    return fallback();
  });
  await h.open("/fixture/sprout.dat");
  const warning = h.$("wallet-sprout-nu7-warning");
  assert.equal(warning.hidden, false);
  assert.match(warning.textContent, /NU7.*mined before activation/);
  assert.match(warning.textContent, /broadcasting alone is not enough/);
  for (const id of ["scan-sprout-uncovered", "complete-sprout-uncovered", "delete-sprout-uncovered"]) {
    assert.equal(h.$(id).hidden, false);
    assert.match(h.$(id).textContent, /NU7.*mined before activation/);
  }
  assert.equal(h.$("sprout-sweep-run").disabled, true);
  preview.resolve();
  await flush();
});

test("Sprout keys with no cached notes still show the NU7 deadline before a full-block scan", async () => {
  const h = harness(inspected({ sprout_spendable_notes: 0, sprout_spendable_zatoshis: 0 }));
  await h.open("/fixture/keys-only.dat");
  assert.equal(h.$("sprout-scan-panel").hidden, false);
  assert.equal(h.$("wallet-sprout-nu7-warning").hidden, false);
  assert.match(h.$("wallet-sprout-nu7-warning").textContent, /NU7/);
});

test("opening a wallet without Sprout clears an earlier NU7 warning", async () => {
  const h = harness(async (command, args, fallback) => {
    const response = await fallback();
    if (command === "inspect_wallet_file" && args.path === "/fixture/no-sprout.dat") {
      return { ...response, sprout_keys: 0, sprout_spendable_notes: 0, sprout_nu7_warning: "" };
    }
    return response;
  });
  await h.open("/fixture/sprout.dat");
  await flush();
  await h.open("/fixture/no-sprout.dat");
  assert.equal(h.$("wallet-sprout-nu7-warning").hidden, true);
  assert.equal(h.$("wallet-sprout-nu7-warning").textContent, "");
});

test("testnet preview refreshes the warning without urging post-activation recovery", async () => {
  const h = harness(async (command, args, fallback) => {
    if (command === "execute_wallet_sprout_sweep") {
      return sproutLifecycleReport([sproutTransaction("pending", { txid: "fixture-tx" })]);
    }
    const response = await fallback();
    if (command === "inspect_wallet_file") return {
      ...response, sprout_nu7_warning: "Testnet NU7: see the activation warning before spending.",
    };
    if (command === "propose_wallet_sprout_sweep") return {
      ...response, nu7_warning: "Testnet NU7: Sprout spending is unavailable at or after block 4,465,026.",
    };
    return response;
  });
  h.$("network-select").value = "testnet";
  await h.open("/fixture/testnet.dat");
  await flush();
  assert.match(h.$("wallet-sprout-nu7-warning").textContent, /Testnet.*4,465,026/);
  h.$("sprout-destination").value = "fixture-destination";
  await h.sweepConfirmed();
  assert.equal(h.$("wallet-sprout-nu7-warning").hidden, false);
  assert.match(h.$("wallet-sprout-nu7-warning").textContent, /NU7/);
});

test("an accepted mainnet broadcast switches the warning to confirming it is mined", async () => {
  const h = harness(async (command, args, fallback) => {
    if (command === "execute_wallet_sprout_sweep") {
      return sproutLifecycleReport([sproutTransaction("pending", { txid: "fixture-tx" })]);
    }
    return fallback();
  });
  await h.open("/fixture/mainnet.dat");
  await flush();
  h.$("sprout-destination").value = "fixture-destination";
  await h.sweepConfirmed();
  await flush();
  const warning = h.$("wallet-sprout-nu7-warning");
  assert.equal(warning.hidden, false);
  assert.match(warning.textContent, /^mainnet NU7: .*broadcast, but it must be mined before NU7 activation; confirm it is mined/);
  assert.doesNotMatch(warning.textContent, /URGENT|Start recovery promptly/);
  for (const id of ["scan-sprout-uncovered", "complete-sprout-uncovered", "delete-sprout-uncovered"]) {
    assert.equal(h.$(id).hidden, false);
    assert.match(h.$(id).textContent, /confirm it is mined/);
    assert.doesNotMatch(h.$(id).textContent, /Start recovery promptly/);
  }
});

test("a sweep that broadcast nothing keeps the start-recovery wording", async () => {
  const requested = [];
  const h = harness(async (command, args, fallback) => {
    if (command === "sprout_nu7_warning") requested.push({ ...args });
    if (command === "execute_wallet_sprout_sweep") {
      return sproutLifecycleReport([], { rejected: ["refused"] });
    }
    return fallback();
  });
  await h.open("/fixture/mainnet.dat");
  await flush();
  h.$("sprout-destination").value = "fixture-destination";
  await h.sweepConfirmed();
  await flush();
  assert.equal(requested.filter((r) => r.broadcast).length, 0);
  assert.match(h.$("wallet-sprout-nu7-warning").textContent, /mined before activation/);
});

test("changing the network after opening a Sprout wallet rebuilds the warning for that network", async () => {
  const h = harness();
  await h.open("/fixture/sprout.dat");
  await flush();
  h.$("network-select").value = "testnet";
  await h.peek("refreshSproutNu7Warning()");
  const ids = ["wallet-sprout-nu7-warning", "scan-sprout-uncovered", "complete-sprout-uncovered", "delete-sprout-uncovered"];
  for (const id of ids) {
    assert.match(h.$(id).textContent, /Testnet NU7: .*4,465,026/, id);
    assert.doesNotMatch(h.$(id).textContent, /mainnet|November/, id);
  }
  h.$("network-select").value = "mainnet";
  await h.peek("refreshSproutNu7Warning()");
  for (const id of ids) assert.match(h.$(id).textContent, /November 5, 2026/, id);
});

test("a network change keeps the post-broadcast wording, for the new network", async () => {
  const h = harness(async (command, args, fallback) => {
    if (command === "execute_wallet_sprout_sweep") {
      return sproutLifecycleReport([sproutTransaction("pending", { txid: "fixture-tx" })]);
    }
    return fallback();
  });
  await h.open("/fixture/sprout.dat");
  await flush();
  h.$("sprout-destination").value = "fixture-destination";
  await h.sweepConfirmed();
  h.$("network-select").value = "testnet";
  await h.peek("refreshSproutNu7Warning()");
  assert.match(h.$("wallet-sprout-nu7-warning").textContent, /^testnet NU7: .*confirm it is mined/);
});

test("a network change with no Sprout wallet open shows no warning", async () => {
  const requested = [];
  const h = harness(async (command, args, fallback) => {
    if (command === "sprout_nu7_warning") requested.push(args);
    const response = await fallback();
    if (command === "inspect_wallet_file") {
      return { ...response, sprout_keys: 0, sprout_spendable_notes: 0, sprout_nu7_warning: "" };
    }
    return response;
  });
  await h.open("/fixture/no-sprout.dat");
  h.$("network-select").value = "testnet";
  await h.peek("refreshSproutNu7Warning()");
  assert.equal(requested.length, 0);
  assert.equal(h.$("wallet-sprout-nu7-warning").hidden, true);
  assert.equal(h.$("scan-sprout-uncovered").hidden, true);
});

test("a stale network refresh cannot overwrite a newer network's warning", async () => {
  const slow = deferred();
  const h = harness(async (command, args, fallback) => {
    if (command === "sprout_nu7_warning" && args.network === "testnet") await slow.promise;
    return fallback();
  });
  await h.open("/fixture/sprout.dat");
  await flush();
  h.$("network-select").value = "testnet";
  const stale = h.peek("refreshSproutNu7Warning()");
  h.$("network-select").value = "mainnet";
  await h.peek("refreshSproutNu7Warning()");
  slow.resolve();
  await stale;
  assert.match(h.$("wallet-sprout-nu7-warning").textContent, /November 5, 2026/);
});

test("the network picker is wired to rebuild the NU7 warning", () => {
  const source = fs.readFileSync("gui/src/main.js", "utf8");
  const start = source.indexOf('$("network-select").addEventListener("change"');
  assert.ok(start > 0);
  const handler = source.slice(start, source.indexOf("\n});", start));
  assert.match(handler, /refreshSproutNu7Warning\(\)/);
});

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const flush = () => new Promise((resolve) => setImmediate(resolve));

test("late wallet reply cannot restore cleared secret state", async () => {
  const inspection = deferred();
  const h = harness(async (command, _args, fallback) => {
    if (command === "inspect_wallet_file") {
      await inspection.promise;
      return fallback();
    }
    return fallback();
  });
  const opening = h.open("/fixture/wallet.dat", "synthetic-passphrase");
  await flush();
  h.abandonWallet();
  inspection.resolve();
  await opening;
  await flush();
  assert.equal(h.peek("walletFile"), null);
  assert.equal(h.peek("sproutPreviewWallet"), null);
  assert.equal(h.peek("walletSproutReview"), null);
  assert.equal(h.$("wallet-passphrase").value, "");
  assert.equal(h.$("wallet-next").disabled, true);
  assert.equal(h.$("sprout-sweep-run").disabled, true);
});

test("abandoning during wallet Sprout execution cannot start a second sweep", async () => {
  const execution = deferred();
  let executions = 0;
  const h = harness((command, _args, fallback) => {
    if (command === "execute_wallet_sprout_sweep") {
      executions++;
      return execution.promise;
    }
    return fallback();
  });
  await h.open("/fixture/old.dat");
  h.$("sprout-destination").value = "zs-old";
  h.$("sprout-destination").dispatch("change");
  await flush();
  const first = h.sweepConfirmed();
  await flush();
  assert.equal(executions, 1);
  assert.equal(h.peek("walletSproutExecutionPending"), true);

  h.abandonWallet();
  await h.open("/fixture/new.dat");
  h.$("sprout-destination").value = "zs-new";
  h.$("sprout-destination").dispatch("change");
  await flush();
  await h.sweepConfirmed();
  assert.equal(executions, 1);
  assert.equal(h.$("sprout-sweep-run").disabled, true);

  execution.resolve(sproutLifecycleReport([]));
  await first;
  assert.equal(h.peek("walletSproutExecutionPending"), false);
});

for (const fails of [false, true]) {
  test(`older wallet inspection ${fails ? "failure" : "success"} cannot replace a newer selection`, async () => {
    const old = deferred();
    const executions = [];
    const h = harness(async (command, args, fallback) => {
      if (command === "inspect_wallet_file" && args.path === "/fixture/old.dat") await old.promise;
      if (command === "execute_wallet_sprout_sweep") {
        executions.push(args.proposalId);
        return sproutLifecycleReport([]);
      }
      return fallback();
    });
    const first = h.open("/fixture/old.dat");
    await h.open("/fixture/new.dat");
    if (fails) old.reject(new Error("old import failed")); else old.resolve();
    await first;
    await flush();
    h.$("sprout-destination").value = "fixture-destination";
    await h.sweepConfirmed();
    assert.deepEqual(executions, ["wallet-proposal-1"]);
    assert.equal(h.$("wallet-next").disabled, false);
    assert.equal(h.$("wallet-summary").hidden, false);
  });

  test(`older preview ${fails ? "failure" : "success"} cannot overwrite the current preview`, async () => {
    const old = deferred();
    const h = harness(async (command, args, fallback) => {
      if (command === "propose_wallet_sprout_sweep" && args.reviewId === "review:/fixture/old.dat") {
        await old.promise;
        return { proposal_id: "old-proposal", notes: 99, gross_zatoshis: 999,
          fee_zatoshis: 1, net_zatoshis: 998, params_present: true };
      }
      return fallback();
    });
    await h.open("/fixture/old.dat");
    await h.open("/fixture/new.dat");
    await flush();
    const plan = h.$("sprout-sweep-plan").textContent;
    if (fails) old.reject(new Error("old preview failed")); else old.resolve();
    await flush();
    assert.equal(h.$("sprout-sweep-plan").textContent, plan);
    assert.equal(h.$("sprout-sweep-status").textContent, "");
    assert.equal(h.$("sprout-sweep-run").disabled, true);
  });
}

test("a new import blocks spending until its own preview is ready", async () => {
  const inspection = deferred(), preview = deferred();
  const executions = [];
  const h = harness(async (command, args, fallback) => {
    if (command === "inspect_wallet_file" && args.path === "/fixture/new.dat") await inspection.promise;
    if (command === "propose_wallet_sprout_sweep" &&
        args.reviewId === "review:/fixture/new.dat") await preview.promise;
    if (command === "execute_wallet_sprout_sweep") {
      executions.push(args.proposalId);
      return sproutLifecycleReport([]);
    }
    return fallback();
  });
  await h.open("/fixture/old.dat");
  await flush();
  h.$("sprout-destination").value = "fixture-destination";
  const opening = h.open("/fixture/new.dat");
  assert.equal(h.$("sprout-sweep-run").disabled, true);
  assert.equal(h.$("wallet-next").disabled, true);
  await h.sweepConfirmed();
  assert.deepEqual(executions, []);
  inspection.resolve();
  await opening;
  assert.equal(h.$("sprout-sweep-run").disabled, true);
  await h.sweepConfirmed();
  assert.deepEqual(executions, []);
  preview.resolve();
  await flush();
  await h.sweepConfirmed();
  assert.deepEqual(executions, ["wallet-proposal-2"]);
});

for (const fails of [false, true]) {
  test(`stale sweep ${fails ? "failure" : "success"} leaves the new wallet's results and warnings intact`, async () => {
    const pending = deferred();
    const h = harness((command, args, fallback) => command === "execute_wallet_sprout_sweep" ? pending.promise : fallback());
    await h.open("/fixture/old.dat");
    h.$("sprout-destination").value = "fixture-destination";
    const sweep = h.sweepConfirmed();
    await h.open("/fixture/new.dat");
    const warning = h.$("delete-sprout-uncovered").textContent;
    if (fails) pending.reject(new Error("old sweep failed"));
    else pending.resolve(sproutLifecycleReport([
      sproutTransaction("pending", { txid: "old-tx", value_zatoshis: 90000 }),
    ]));
    await sweep;
    assert.equal(h.$("sprout-sweep-status").textContent, "");
    assert.equal(h.$("sprout-sweep-results").children.length, 0);
    assert.equal(h.$("delete-sprout-uncovered").hidden, false);
    assert.equal(h.$("delete-sprout-uncovered").textContent, warning);
    assert.equal(h.$("sprout-sweep-run").disabled, true);
  });
}

test("reopening a wallet cannot start a concurrent sweep, and failure releases the lock", async () => {
  const pending = deferred();
  let executions = 0;
  const h = harness((command, args, fallback) => {
    if (command !== "execute_wallet_sprout_sweep") return fallback();
    executions++;
    return pending.promise;
  });
  await h.open("/fixture/wallet.dat");
  h.$("sprout-destination").value = "fixture-destination";
  const sweep = h.sweepConfirmed();
  await h.open("/fixture/wallet.dat");
  assert.equal(h.$("sprout-sweep-run").disabled, true);
  // Invoke the handler even when disabled: the lock must guard execution itself.
  const second = h.sweepConfirmed();
  assert.equal(executions, 1);
  pending.reject(new Error("fixture failure"));
  await Promise.all([sweep, second]);
  assert.equal(h.$("sprout-sweep-run").disabled, false);
  await h.sweepConfirmed();
  assert.equal(executions, 2);
});

test("sweep progress and completion belong only to the active source", async () => {
  const pending = deferred();
  const h = harness((command, args, fallback) => command === "execute_wallet_sprout_sweep" ? pending.promise : fallback());
  await h.open("/fixture/old.dat");
  h.$("sprout-destination").value = "fixture-destination";
  const sweep = h.sweepConfirmed();
  h.progress("Proving note 1");
  assert.match(h.$("sprout-sweep-status").textContent, /Proving note 1/);
  await h.open("/fixture/new.dat");
  h.progress("Proving old note 2");
  assert.equal(h.$("sprout-sweep-status").textContent, "");
  pending.resolve(sproutLifecycleReport([]));
  await sweep;
  h.progress("Late old event");
  assert.equal(h.$("sprout-sweep-status").textContent, "");
});

test("current wallet sweep shows its mined transaction and clears its own warning", async () => {
  const h = harness((command, args, fallback) => command === "execute_wallet_sprout_sweep"
    ? Promise.resolve(sproutLifecycleReport([
      sproutTransaction("mined", { txid: "fixture-tx", value_zatoshis: 90000, mined_height: 444 }),
    ], { mined_zatoshis: 90000, fresh_all_mined: true }))
    : fallback());
  await h.open("/fixture/wallet.dat");
  h.$("sprout-destination").value = "fixture-destination";
  await h.sweepConfirmed();
  assert.match(h.$("sprout-sweep-results").children[0].textContent, /fixture-tx/);
  assert.match(h.$("sprout-sweep-status").textContent, /Mined 90000/);
  assert.doesNotMatch(h.$("sprout-sweep-status").textContent, /Swept/);
  assert.doesNotMatch(h.$("delete-sprout-uncovered").textContent, /does not include Sprout/);
  // The deadline survives the sweep, reworded: broadcast is not mined.
  assert.match(h.$("delete-sprout-uncovered").textContent, /must be mined before NU7 activation; confirm it is mined/);
  assert.equal(h.$("sprout-sweep-run").disabled, true);
  await h.open("/fixture/new.dat");
  assert.equal(h.$("sprout-sweep-results").children.length, 0);
});

test("historical lifecycle reports never claim the current unified destination", async () => {
  const report = sproutLifecycleReport([
    sproutTransaction("pending", { txid: "historical-tx" }),
  ]);
  const h = harness((command, args, fallback) =>
    command === "execute_wallet_sprout_sweep" ? report : fallback());
  h.$("sprout-destination").value = "u1-new-destination";
  await h.open("/fixture/historical.dat");
  await h.sweepConfirmed();
  const rendered = texts(h.$("sprout-sweep-results")).join("\n") +
    h.$("sprout-sweep-status").textContent;
  assert.match(rendered, /historical-tx/);
  assert.doesNotMatch(rendered, /that unified address|these funds land|funds are in/i);
});

test("accepted_transaction_renders_broadcast_pending_without_a_green_check", async () => {
  const pending = sproutLifecycleReport([sproutTransaction("pending")]);
  const h = harness((command, args, fallback) =>
    command === "execute_wallet_sprout_sweep" ? pending : fallback());
  await h.open("/fixture/pending.dat");
  await h.sweepConfirmed();
  const rows = texts(h.$("sprout-sweep-results"));
  assert.ok(rows.some((row) => /pending/i.test(row) && /pending-tx/.test(row)), rows.join("\n"));
  assert.match(h.$("sprout-sweep-status").textContent, /pending/i);
  assert.doesNotMatch(h.$("sprout-sweep-status").textContent, /✓|Swept/i);
  assert.ok(h.peek("uncoveredSproutKeys") > 0);
});

test("submission_unknown_says_later_notes_were_not_attempted", async () => {
  const unknown = sproutLifecycleReport([sproutTransaction("submission_unknown")]);
  const h = harness((command, args, fallback) =>
    command === "execute_wallet_sprout_sweep" ? unknown : fallback());
  await h.open("/fixture/unknown.dat");
  await h.sweepConfirmed();
  const rendered = texts(h.$("sprout-sweep-results")).join("\n");
  assert.match(rendered, /submission (status )?unknown/i);
  assert.match(rendered, /later notes were not attempted/i);
  assert.doesNotMatch(h.$("sprout-sweep-status").textContent, /✓|Swept/i);
});

test("only_fresh_all_mined_results_clear_the_gui_caveat", () => {
  const h = harness();
  const mined = sproutTransaction("mined");
  const clean = sproutLifecycleReport([mined], { fresh_all_mined: true });
  const cases = [
    [clean, true],
    [{ ...clean, fresh_all_mined: false }, false],
    [{ ...clean, transactions: [] }, false],
    [{ ...clean, transactions: [sproutTransaction("pending")] }, false],
    [{ ...clean, transactions: [sproutTransaction("submission_unknown")] }, false],
    [{ ...clean, transactions: [sproutTransaction("expired")] }, false],
    [{ ...clean, transactions: [sproutTransaction("rejected")] }, false],
    [{ ...clean, transactions: [sproutTransaction("mined", { mined_height: null })] }, false],
    [{ ...clean, error: "stopped" }, false],
    [{ ...clean, rejected: ["refused"] }, false],
    [{ ...clean, skipped: ["dust"] }, false],
    [{ ...clean, ready: [{ note: "unbuilt" }] }, false],
  ];
  for (const [report, expected] of cases) {
    assert.equal(
      h.peek(`sproutSourceWarningMayClear(${JSON.stringify(report)})`),
      expected,
      JSON.stringify(report),
    );
  }
});

test("pending_and_contested_results_keep_the_original_wallet_and_checkpoint_warning", async () => {
  const report = sproutLifecycleReport([sproutTransaction("pending")], {
    warnings: ["Confirmation sources disagreed; canonical status is contested."],
  });
  const h = harness((command, args, fallback) =>
    command === "execute_wallet_sprout_sweep" ? report : fallback());
  await h.open("/fixture/contested.dat");
  await h.sweepConfirmed();
  assert.ok(h.peek("uncoveredSproutKeys") > 0);
  const rendered = texts(h.$("sprout-sweep-results")).join("\n");
  assert.match(rendered, /contested/i);
  assert.match(h.$("delete-sprout-uncovered").textContent, /original wallet|Sprout key/i);
});

test("pending_only_preview_enables_check_status_without_sprout_parameters", async () => {
  let executions = 0;
  const h = harness(async (command, args, fallback) => {
    if (command === "inspect_wallet_file") {
      return {
        ...(await fallback()),
        sprout_spendable_notes: 0,
        sprout_spendable_zatoshis: 0,
        sprout_has_lifecycle_status: true,
        sprout_nothing_left: false,
      };
    }
    if (command === "propose_wallet_sprout_sweep") {
      return {
        proposal_id: "status-only",
        notes: 0,
        gross_zatoshis: 0,
        fee_zatoshis: 0,
        net_zatoshis: 0,
        active: [sproutTransaction("pending", { value_zatoshis: null })],
        mined: [],
        lands_in_sapling: "Lands in Sapling",
        params_present: false,
        params_path: "/missing/sprout.params",
        warnings: [],
      };
    }
    if (command === "execute_wallet_sprout_sweep") {
      executions++;
      return sproutLifecycleReport([sproutTransaction("pending", { value_zatoshis: null })]);
    }
    return fallback();
  });
  await h.open("/fixture/status-only.dat");
  assert.equal(h.$("wallet-sprout-sweep").hidden, false);
  assert.match(h.$("wallet-sprout-headline").textContent, /transaction status/i);
  assert.equal(h.$("sprout-sweep-run").textContent, "Check status and continue");
  assert.equal(h.$("sprout-sweep-confirm").disabled, false);
  assert.doesNotMatch(h.$("sprout-sweep-params").textContent, /before (sweeping|continuing)/i);
  await h.sweepConfirmed();
  assert.equal(executions, 1);
});

test("legacy_unknown_entry_keeps_the_source_warning_and_omits_unknown_amount", async () => {
  const legacy = sproutLifecycleReport([
    sproutTransaction("submission_unknown", { txid: "legacy-tx", value_zatoshis: null }),
  ]);
  const h = harness((command, args, fallback) =>
    command === "execute_wallet_sprout_sweep" ? legacy : fallback());
  await h.open("/fixture/legacy.dat");
  await h.sweepConfirmed();
  const rendered = texts(h.$("sprout-sweep-results")).join("\n");
  assert.match(rendered, /legacy-tx/);
  assert.match(rendered, /amount unknown/i);
  assert.doesNotMatch(rendered, /undefined|\b0\b/);
  assert.ok(h.peek("uncoveredSproutKeys") > 0);
});

test("legacy mined entry clears the source warning without inventing a zero amount", async () => {
  const legacy = sproutLifecycleReport([
    sproutTransaction("mined", {
      txid: "legacy-mined-tx",
      value_zatoshis: null,
      mined_height: 654,
    }),
  ], { mined_zatoshis: 0, fresh_all_mined: true });
  const h = harness((command, args, fallback) =>
    command === "execute_wallet_sprout_sweep" ? legacy : fallback());
  await h.open("/fixture/legacy-mined.dat");
  await h.sweepConfirmed();
  const rendered = [
    ...texts(h.$("sprout-sweep-results")),
    h.$("sprout-sweep-status").textContent,
  ].join("\n");
  assert.match(rendered, /legacy-mined-tx/);
  assert.match(rendered, /amount unknown/i);
  assert.doesNotMatch(rendered, /undefined|\b0\b/);
  assert.equal(h.peek("uncoveredSproutKeys"), 0);
});

test("expired and rejected lifecycle rows require recoverable follow-up", async () => {
  const report = sproutLifecycleReport([
    sproutTransaction("expired"),
    sproutTransaction("rejected"),
  ]);
  const h = harness((command, args, fallback) =>
    command === "execute_wallet_sprout_sweep" ? report : fallback());
  await h.open("/fixture/terminal.dat");
  await h.sweepConfirmed();
  const rendered = texts(h.$("sprout-sweep-results")).join("\n");
  assert.match(rendered, /expired.*recover|recover.*expired/i);
  assert.match(rendered, /rejected.*recover|recover.*rejected/i);
  assert.doesNotMatch(h.$("sprout-sweep-status").textContent, /✓|Swept/i);
});

test("wallet_and_scan_sweep_handlers_render_identical_lifecycle_rows", async () => {
  const report = sproutLifecycleReport([
    sproutTransaction("pending"),
    sproutTransaction("submission_unknown", { value_zatoshis: null }),
    sproutTransaction("mined"),
    sproutTransaction("expired"),
    sproutTransaction("rejected"),
  ]);
  const h = harness((command, args, fallback) =>
    command === "execute_wallet_sprout_sweep" || command === "execute_sprout_scan_sweep"
      ? report : fallback());
  await h.open("/fixture/shared-renderer.dat");
  await h.sweepConfirmed();
  const walletRows = texts(h.$("sprout-sweep-results"));
  h.$("sprout-scan-destination").value = "fixture-destination";
  await h.scanSweep();
  const scanRows = texts(h.$("sprout-scan-sweep-results"));
  assert.equal(walletRows.length, 5);
  assert.deepEqual(scanRows, walletRows);
});

test("lifecycle action label resets for a ready-only preview", async () => {
  const h = harness(async (command, args, fallback) => {
    if (command !== "propose_wallet_sprout_sweep") return fallback();
    const review = await fallback();
    return args.reviewId.endsWith("status.dat")
      ? { ...review, notes: 0, gross_zatoshis: 0, fee_zatoshis: 0, net_zatoshis: 0,
        active: [sproutTransaction("pending")], params_present: false }
      : { ...review, active: [], mined: [], params_present: true };
  });
  await h.open("/fixture/status.dat");
  assert.equal(h.$("sprout-sweep-run").textContent, "Check status and continue");
  await h.open("/fixture/ready.dat");
  assert.equal(h.$("sprout-sweep-run").textContent, "Sweep Sprout funds");
});

test("synchronous status failure before proving cannot strand the sweep lock", async () => {
  let executions = 0;
  const h = harness((command, args, fallback) => {
    if (command !== "execute_wallet_sprout_sweep") return fallback();
    executions++;
    return Promise.resolve(sproutLifecycleReport([]));
  });
  await h.open("/fixture/wallet.dat");
  h.$("sprout-destination").value = "fixture-destination";
  h.failNextStatus();
  await h.sweepConfirmed().catch(() => {});
  assert.equal(executions, 0);
  await h.open("/fixture/wallet.dat");
  assert.equal(h.$("sprout-sweep-run").disabled, true);
  await h.sweepConfirmed();
  assert.equal(executions, 1);
});

const SEED_NOTICE = "Incomplete — this file holds an HD seed that Argos does not recover.";
const UNKNOWN_NOTICE = "Some records of a type Argos does not recognise were skipped.";
const LATER_SCREENS = ["scan-sprout-uncovered", "complete-sprout-uncovered", "delete-sprout-uncovered"];

function withCoverage(coverage_notice, coverage_may_hide_funds) {
  return async (command, args, fallback) => {
    const response = await fallback();
    return command === "inspect_wallet_file"
      ? { ...response, diagnostics: ["fixture diagnostic"], coverage_notice, coverage_may_hide_funds }
      : response;
  };
}

function summaryRows(h) {
  return h.$("wallet-summary-list").children.map((row) => row.textContent);
}

test("an unrecovered seed is shown at import and carried to the totals and delete screens", async () => {
  const h = harness(withCoverage(SEED_NOTICE, true));
  await h.open("/fixture/zcashd5.dat");
  assert.ok(summaryRows(h).includes("Seed phrase: not recovered from this file"));
  assert.ok(summaryRows(h).includes(`Recovery coverage: ${SEED_NOTICE}`));
  for (const id of LATER_SCREENS) {
    assert.equal(h.$(id).hidden, false, id);
    assert.match(h.$(id).textContent, /HD seed that Argos does not recover/, id);
  }
});

test("sweeping the file's Sprout notes does not clear the partial-import warning", async () => {
  const h = harness(async (command, args, fallback) => command === "execute_wallet_sprout_sweep"
    ? sproutLifecycleReport([
      sproutTransaction("mined", { txid: "fixture-tx", value_zatoshis: 90000 }),
    ], { mined_zatoshis: 90000, fresh_all_mined: true })
    : withCoverage(SEED_NOTICE, true)(command, args, fallback));
  await h.open("/fixture/zcashd5.dat");
  // The preview is requested without being awaited; let it land.
  await new Promise(setImmediate);
  h.$("sprout-destination").value = "fixture-destination";
  await h.sweepConfirmed();
  assert.match(h.$("sprout-sweep-status").textContent, /Mined 90000/);
  for (const id of LATER_SCREENS) {
    assert.equal(h.$(id).hidden, false, id);
    assert.doesNotMatch(h.$(id).textContent, /Sprout key\(s\)/, id);
    assert.match(h.$(id).textContent, /HD seed/, id);
  }
});

test("a skipped record of unknown type is noted at import but not carried forward", async () => {
  const h = harness(withCoverage(UNKNOWN_NOTICE, false));
  await h.open("/fixture/cscript.dat");
  assert.ok(summaryRows(h).includes(`Recovery coverage: ${UNKNOWN_NOTICE}`));
  for (const id of LATER_SCREENS) assert.doesNotMatch(h.$(id).textContent, /recognise/, id);
});

test("a complete read shows no coverage row, and replaces an earlier partial warning", async () => {
  let partial = true;
  const h = harness(async (command, args, fallback) => partial
    ? withCoverage(SEED_NOTICE, true)(command, args, fallback)
    : fallback());
  await h.open("/fixture/zcashd5.dat");
  partial = false;
  await h.open("/fixture/wallet.dat");
  assert.ok(summaryRows(h).includes("Seed phrase: not recovered from this file"));
  assert.equal(summaryRows(h).some((row) => row.startsWith("Recovery coverage:")), false);
  for (const id of LATER_SCREENS) assert.doesNotMatch(h.$(id).textContent, /HD seed/, id);
});

test("a verified zcashd seed is described in the backend's words", async () => {
  const note = "verified — every key it derived is read from this file";
  const h = harness(async (command, args, fallback) => {
    const response = await fallback();
    return command === "inspect_wallet_file" ? { ...response, seed_note: note } : response;
  });
  await h.open("/fixture/zcashd5.dat");
  assert.ok(summaryRows(h).includes(`Seed phrase: ${note}`));
});

// Review round 2 on #230: the CLI lists seed findings under their own
// heading because calling "this wallet has 2 unified accounts" an unread
// record is false. The GUI must say the same thing about the same file.
test("seed findings are not listed as records that could not be read", async () => {
  const h = harness(async (command, args, fallback) => {
    if (command !== "inspect_wallet_file") return fallback();
    return {
      needs_passphrase: false, transparent_keys: 3, sapling_keys: 1,
      sprout_keys: 0, has_mnemonic: false, sprout_spendable_notes: 0,
      sprout_spendable_zatoshis: 0, sprout_addresses: [],
      diagnostics: ["skipped unparseable key record: truncated"],
      seed_diagnostics: ["this wallet has 2 unified account(s) derived from its seed"],
      coverage_notice: "Incomplete", coverage_may_hide_funds: true, seed_note: null,
    };
  });
  await h.open("/fixture/seed.dat");
  const texts = (id) => h.$(id).children.map((li) => li.textContent);
  assert.deepEqual(texts("wallet-diagnostics-list"), ["skipped unparseable key record: truncated"]);
  assert.deepEqual(texts("wallet-seed-diagnostics-list"), [
    "this wallet has 2 unified account(s) derived from its seed",
  ]);
  assert.equal(h.$("wallet-diagnostics").hidden, false);
  assert.equal(h.$("wallet-seed-diagnostics").hidden, false);
});

test("a wallet with only seed findings shows no unread-records block", async () => {
  const h = harness(async (command, args, fallback) => {
    if (command !== "inspect_wallet_file") return fallback();
    return {
      needs_passphrase: false, transparent_keys: 3, sapling_keys: 1,
      sprout_keys: 0, has_mnemonic: false, sprout_spendable_notes: 0,
      sprout_spendable_zatoshis: 0, sprout_addresses: [], diagnostics: [],
      seed_diagnostics: ["the wallet's seed derived 101 transparent (change) key(s) but only 91 were read from this file"],
      coverage_notice: "Incomplete", coverage_may_hide_funds: true, seed_note: null,
    };
  });
  await h.open("/fixture/seed-only.dat");
  assert.equal(h.$("wallet-diagnostics").hidden, true);
  assert.equal(h.$("wallet-seed-diagnostics").hidden, false);
});

// #239 review: a wallet whose Sprout notes were all spent must not be told
// it needs a multi-day scan for note data it does in fact hold.
function inspected(overrides) {
  return async (command, args, fallback) => {
    if (command === "inspect_wallet_file") return { ...(await fallback()), ...overrides };
    return fallback();
  };
}
const texts = (el) => el.children.map((c) => c.textContent);

test("unverified checkpoint notice stays visible while wallet-file preview remains available", async () => {
  const checkpoint = "/fixture/workspace/sprout-scan-123.checkpoint";
  const notice = `Not using the full-block scan checkpoint at ${checkpoint}. Spent status is the wallet file's own record.`;
  const h = harness(inspected({
    sprout_spendable_notes: 1,
    sprout_spendable_zatoshis: 100000,
    sprout_accounting: [notice],
    sprout_spent_status: "Spent status comes from this wallet file's own history.",
  }));
  await h.open("/fixture/wallet.dat");
  await flush();
  assert.deepEqual(texts(h.$("wallet-sprout-accounting")), [notice]);
  assert.match(h.$("sprout-sweep-spent-status").textContent, /wallet file's own history/);
  // Under #271 the review is sweepable once the irreversible box is ticked.
  assert.equal(h.$("sprout-sweep-confirm").disabled, false);
  h.$("sprout-sweep-confirm").checked = true;
  h.$("sprout-sweep-confirm").dispatch("change");
  assert.equal(h.$("sprout-sweep-run").disabled, false);
  assert.deepEqual(h.previews.at(-1), {
    reviewId: "review:/fixture/wallet.dat", passphrase: null, destination: "fixture-destination",
    lightwalletdUrl: "", confirmationSources: ["backup=https://confirm.example"],
    network: "mainnet", dataDir: null, peers: ["192.0.2.7:8233"],
  });
});

test("deep reorg notice names the preserved checkpoint and source wallet", async () => {
  const checkpoint = "/fixture/workspace/sprout-scan-456.checkpoint";
  const notice = `The scan checkpoint at ${checkpoint} could not be reconciled. Keep the original wallet or key for a safe full rescan.`;
  const h = harness(inspected({
    sprout_spendable_notes: 0,
    sprout_spendable_zatoshis: 0,
    sprout_nothing_left: false,
    sprout_accounting: [notice],
  }));
  await h.open("/fixture/wallet.dat");
  assert.deepEqual(texts(h.$("wallet-sprout-accounting")), [notice]);
  assert.match(h.$("wallet-sprout-accounting").children[0].textContent, /keep the original wallet or key/i);
  assert.match(h.$("wallet-sprout-accounting").children[0].textContent, /sprout-scan-456\.checkpoint/);
});

test("preview shows its fresh verification warning and execute shows a newer one", async () => {
  const previewNotice = "Preview: checkpoint verification is unavailable; use wallet-file evidence.";
  const executeNotice = "Execute: checkpoint changed after preview; use wallet-file evidence.";
  const calls = [];
  const h = harness(async (command, args, fallback) => {
    if (command === "propose_wallet_sprout_sweep") {
      calls.push(command);
      return { ...(await fallback()), scan_warning: previewNotice };
    }
    if (command === "execute_wallet_sprout_sweep") {
      calls.push(command);
      return {
        sent: [], total_swept: 0, skipped: [], rejected: [],
        warnings: [executeNotice], error: null,
      };
    }
    return fallback();
  });
  await h.open("/fixture/wallet.dat");
  await flush();
  assert.match(h.$("sprout-sweep-status").textContent, /Preview: checkpoint verification/);
  assert.equal(h.$("sprout-sweep-confirm").disabled, false);
  h.$("sprout-destination").value = "fixture-destination";
  await h.sweepConfirmed();
  assert.deepEqual(calls, ["propose_wallet_sprout_sweep", "execute_wallet_sprout_sweep"]);
  assert.ok(texts(h.$("sprout-sweep-results")).includes(executeNotice));
  assert.doesNotMatch(h.$("sprout-sweep-status").textContent, /Preview: checkpoint/);
});

test("execute displays a changed spent verdict after a spendable preview", async () => {
  const h = harness(async (command, args, fallback) => {
    if (command === "execute_wallet_sprout_sweep") {
      throw new Error("nothing is left to sweep; fresh checkpoint verification found this note spent");
    }
    return fallback();
  });
  await h.open("/fixture/wallet.dat");
  await flush();
  assert.match(h.$("sprout-sweep-plan").textContent, /1 note\(s\)/);
  h.$("sprout-destination").value = "fixture-destination";
  await h.sweepConfirmed();
  assert.match(h.$("sprout-sweep-status").textContent, /fresh checkpoint verification found this note spent/);
});

test("a wallet that spent every Sprout note says so instead of asking for note data", async () => {
  const h = harness(inspected({
    sprout_spendable_notes: 0, sprout_spendable_zatoshis: 0, sprout_nothing_left: true,
    sprout_accounting: ["257 note(s) were spent by the wallet itself"],
    sprout_scan_warning: [], sprout_issues: [],
  }));
  await h.open("/fixture/spent.dat");
  const headline = h.$("wallet-sprout-headline").textContent;
  assert.doesNotMatch(headline, /scan/i);
  assert.match(headline, /no Sprout funds are left/i);
  assert.equal(h.$("wallet-sprout-sweep").hidden, true);
  assert.deepEqual(h.previews, []);
  assert.deepEqual(texts(h.$("wallet-sprout-accounting")), ["257 note(s) were spent by the wallet itself"]);
});

test("a recoverable wallet shows why its total is what it is, and the file's limit", async () => {
  const h = harness(inspected({
    sprout_accounting: ["3 note(s) were spent"],
    sprout_spent_status: "Spent status comes from this wallet file's own history.",
  }));
  await h.open("/fixture/some-spent.dat");
  assert.deepEqual(texts(h.$("wallet-sprout-accounting")), ["3 note(s) were spent"]);
  assert.equal(h.$("wallet-sprout-accounting").hidden, false);
  assert.match(h.$("sprout-sweep-spent-status").textContent, /own history/);
});

test("notes the network refused are listed after a sweep", async () => {
  const h = harness(async (command, args, fallback) => {
    if (command === "execute_wallet_sprout_sweep") {
      return sproutLifecycleReport([sproutTransaction("pending", { txid: "aa" })], {
        rejected: ["note bb:0:1 was refused by the network: spent"],
      });
    }
    return fallback();
  });
  await h.open("/fixture/first.dat");
  await flush();
  h.$("sprout-destination").value = "fixture-destination";
  await h.sweepConfirmed();
  const lines = texts(h.$("sprout-sweep-results"));
  assert.ok(lines.some((l) => /refused by the network/.test(l)), lines.join("\n"));
  assert.match(h.$("sprout-sweep-status").textContent, /pending/i);
});

// The wallet-file path asks a full-block scan of the same keys to settle
// spends the file cannot see. It must look where the scan panel writes.
test("the Sprout preview, inspection and sweep look in the scan's data directory", async () => {
  const seen = {};
  const executions = [];
  const h = harness(async (command, args, fallback) => {
    if (command === "inspect_wallet_file" || command === "propose_wallet_sprout_sweep") {
      seen[command] = args.dataDir;
    }
    if (command === "execute_wallet_sprout_sweep") {
      executions.push(JSON.parse(JSON.stringify(args)));
      return sproutLifecycleReport([]);
    }
    return fallback();
  });
  h.$("data-dir").value = "/fixture/workspace";
  await h.open("/fixture/first.dat");
  await flush();
  h.$("sprout-destination").value = "fixture-destination";
  await h.sweepConfirmed();
  assert.deepEqual(seen, {
    inspect_wallet_file: "/fixture/workspace",
    propose_wallet_sprout_sweep: "/fixture/workspace",
  });
  assert.deepEqual(executions, [{ proposalId: "wallet-proposal-1" }]);
});

// A broadcast that could not be written to the sweep journal is worth
// saying: a re-run would prove that one note again and see it refused.
test("a sweep journal warning is shown after the sweep", async () => {
  const h = harness(async (command, args, fallback) => {
    if (command === "execute_wallet_sprout_sweep") {
      return sproutLifecycleReport([sproutTransaction("pending", { txid: "aa" })], {
        warnings: ["aa was broadcast, but writing the sweep journal failed"],
      });
    }
    return fallback();
  });
  await h.open("/fixture/first.dat");
  await flush();
  h.$("sprout-destination").value = "fixture-destination";
  await h.sweepConfirmed();
  const lines = texts(h.$("sprout-sweep-results"));
  assert.ok(lines.some((l) => /sweep journal/.test(l)), lines.join("\n"));
});

// #239 review F4: a wallet whose notes all read as spent still offers the
// scan. The verdict is the file's, and a spend recorded against a block
// later reorged out reads exactly the same.
test("a fully spent wallet still offers the full-block scan", async () => {
  const h = harness(inspected({
    sprout_spendable_notes: 0, sprout_spendable_zatoshis: 0, sprout_nothing_left: true,
    sprout_history_read: true, sprout_accounting: ["2 note(s) were spent"],
    sprout_scan_warning: [], sprout_issues: [],
  }));
  await h.open("/fixture/spent.dat");
  assert.equal(h.$("sprout-scan-panel").hidden, false);
  assert.match(h.$("wallet-sprout-headline").textContent, /no Sprout funds are left/i);
});

// #239 review F8: spent notes plus one unusable note. The file's note data
// was read, so the headline must not say it was not.
test("some notes spent and one unusable does not claim the note data is missing", async () => {
  const h = harness(inspected({
    sprout_spendable_notes: 0, sprout_spendable_zatoshis: 0, sprout_nothing_left: false,
    sprout_history_read: true, sprout_accounting: ["256 note(s) were spent"],
    sprout_scan_warning: ["cost"], sprout_issues: ["note x: could not decrypt"],
  }));
  await h.open("/fixture/mixed.dat");
  const said = h.$("wallet-sprout-headline").textContent + h.$("wallet-sprout-detail").textContent;
  assert.doesNotMatch(said, /not the note data/);
  assert.match(said, /could not be used/);
  assert.equal(h.$("sprout-scan-panel").hidden, false);
});

// #239 review F7: a refused note may not have been spent at all, so the
// "Sprout not covered" caveat must survive a sweep with any refusal.
test("the Sprout caveat survives a sweep in which any note was refused", async () => {
  for (const [rejected, kept] of [[[], false], [["note bb:0:1 was refused"], true]]) {
    const h = harness(async (command, args, fallback) => {
      if (command === "execute_wallet_sprout_sweep") {
        return sproutLifecycleReport([
          sproutTransaction("mined", { txid: "aa" }),
        ], { rejected, fresh_all_mined: true });
      }
      return fallback();
    });
    await h.open("/fixture/first.dat");
    await flush();
    h.peek("uncoveredSproutKeys = 1");
    h.$("sprout-destination").value = "fixture-destination";
    await h.sweepConfirmed();
    assert.equal(h.peek("uncoveredSproutKeys") > 0, kept, `rejected=${rejected.length}`);
  }
});

// #239 round 4, findings 5 and 6: a sweep that stopped shows why, and does
// not clear the "keep the original wallet file" caveat; neither does one
// that skipped any note.
test("a sweep that stopped or skipped a note says so and keeps the caveat", async () => {
  for (const [report, stopped] of [
    [sproutLifecycleReport([], { error: "note 1 of 3 could not be built: bad bundle" }), true],
    [sproutLifecycleReport([sproutTransaction("pending", { txid: "aa" })], {
      skipped: ["note 2 of 2: below the fee"],
    }), false],
  ]) {
    const h = harness(async (command, args, fallback) =>
      command === "execute_wallet_sprout_sweep" ? report : fallback());
    await h.open("/fixture/first.dat");
    await flush();
    h.peek("uncoveredSproutKeys = 1");
    h.$("sprout-destination").value = "fixture-destination";
    await h.sweepConfirmed();
    const status = h.$("sprout-sweep-status").textContent;
    if (stopped) {
      assert.match(status, /did not finish: note 1 of 3 could not be built/);
      assert.doesNotMatch(status, /✓/);
    }
    assert.ok(h.peek("uncoveredSproutKeys") > 0, "the caveat must survive");
  }
});

// A backend aggregate is necessary but not sufficient: the frontend also
// checks every rendered transaction and every nonfinal outcome field.
test("the caveat is cleared only by a fresh canonically mined report", () => {
  const h = harness();
  const clean = sproutLifecycleReport([sproutTransaction("mined", { txid: "a" })], {
    fresh_all_mined: true,
  });
  const cases = [
    [clean, true],
    [{ ...clean, transactions: [] }, false],
    [{ ...clean, error: "stopped" }, false],
    [{ ...clean, rejected: ["r"] }, false],
    [{ ...clean, skipped: ["s"] }, false],
    [{ ...clean, transactions: [sproutTransaction("pending", { txid: "h" })] }, false],
  ];
  for (const [report, expected] of cases) {
    assert.equal(h.peek(`sproutSourceWarningMayClear(${JSON.stringify(report)})`), expected, JSON.stringify(report));
  }
});

// Finding 6: a fully spent wallet is offered the scan, so it is quoted the
// scan's cost too.
test("a fully spent wallet quotes the scan's cost beside the offer", async () => {
  const h = harness(inspected({
    sprout_spendable_notes: 0, sprout_spendable_zatoshis: 0, sprout_nothing_left: true,
    sprout_history_read: true, sprout_accounting: ["2 note(s) were spent"],
    sprout_scan_warning: ["Network transfer roughly 276 GB"], sprout_issues: [],
  }));
  await h.open("/fixture/spent.dat");
  assert.equal(h.$("wallet-sprout-scan-cost").hidden, false);
  assert.deepEqual(texts(h.$("wallet-sprout-scan-cost")), ["Network transfer roughly 276 GB"]);
});

// Round-5 finding 4, at the call site: the scan-sweep handler cleared the
// "keep the original wallet file" caveat unconditionally. It must follow
// the same rule as the wallet-file sweep.
test("the scan sweep keeps the caveat when a note was refused", async () => {
  for (const [rejected, kept] of [[[], false], [["note bb:0:1 was refused"], true]]) {
    const h = harness(async (command, args, fallback) =>
      command === "execute_sprout_scan_sweep"
        ? sproutLifecycleReport([
          sproutTransaction("mined", { txid: "aa" }),
        ], { rejected, fresh_all_mined: true })
        : fallback());
    h.peek("uncoveredSproutKeys = 1");
    h.$("sprout-scan-destination").value = "fixture-destination";
    h.$("sprout-scan-confirm").checked = true;
    await h.scanSweep();
    assert.equal(h.peek("uncoveredSproutKeys") > 0, kept, `rejected=${rejected.length}`);
    if (kept) assert.match(h.$("sprout-scan-status").textContent, /recovery|rescan/i);
  }
});

// The sweep resumes the saved scan, and the backend reads the bound that
// scan used from its checkpoint. The form may have changed since — an
// auto-detected or retyped main birthday below the scan's skip — and
// re-deriving the bound from it would make the resume conflict after hours
// of scanning. So the sweep must send no decrypt request at all, and must
// not be stopped by a form value it no longer reads.
test("the scan sweep sends no decrypt bound, whatever the form says now", async () => {
  for (const formNow of [
    "{ birthdayFloor: 1000, decryptEveryBlock: true }",
    "{ error: 'The Sprout scan birthday must be a block number.' }",
  ]) {
    const proposed = [];
    const sent = [];
    const h = harness((command, args, fallback) => {
      if (command === "propose_sprout_scan_sweep") proposed.push({ ...args });
      if (command === "execute_sprout_scan_sweep") {
        sent.push({ ...args });
        return sproutLifecycleReport([]);
      }
      return fallback();
    });
    h.loadScanPanel();
    h.peek(`function currentSproutDecryptRequest() { return ${formNow}; }`);
    h.$("sprout-scan-destination").value = "fixture-destination";
    await h.scanSweep();
    // #271: the review names only the backend scan handle and destination;
    // the backend resumes under the bound saved in that scan's checkpoint.
    assert.equal(proposed.length, 1, formNow);
    assert.deepEqual(Object.keys(proposed[0]).sort(), ["destination", "scanHandle"], JSON.stringify(proposed[0]));
    // Execution carries the reviewed proposal and nothing from the form.
    assert.equal(sent.length, 1, formNow);
    assert.deepEqual(JSON.parse(JSON.stringify(sent[0])), { proposalId: "scan-proposal-scan-1" });
  }
});

test("a scan sweep that broadcast switches the NU7 warning to confirming it is mined", async () => {
  const h = harness(async (command, args, fallback) =>
    command === "execute_sprout_scan_sweep"
      ? sproutLifecycleReport([sproutTransaction("pending", { txid: "aa" })])
      : fallback());
  await h.open("/fixture/sprout.dat");
  await flush();
  h.$("sprout-scan-destination").value = "fixture-destination";
  h.$("sprout-scan-confirm").checked = true;
  await h.scanSweep();
  await flush();
  assert.match(h.$("wallet-sprout-nu7-warning").textContent, /confirm it is mined/);
  assert.match(h.$("complete-sprout-uncovered").textContent, /confirm it is mined/);
  assert.doesNotMatch(h.$("complete-sprout-uncovered").textContent, /Start recovery promptly/);
});

// Pasted Sprout keys. The scan panel sits inside #wallet-sprout-warning,
// whose first child is the NU7 alert, so whenever the panel can be used the
// alert is on screen directly above it, built from the same core text. These
// tests pin that for pasted keys, across a network change and a broadcast,
// and pin that the panel cannot be reached without it.
function keysOnlyHarness() {
  const noNotes = inspected({ sprout_spendable_notes: 0, sprout_spendable_zatoshis: 0 });
  return harness(async (command, args, fallback) => {
    if (command === "execute_sprout_scan_sweep") {
      return sproutLifecycleReport([sproutTransaction("pending", { txid: "aa" })]);
    }
    return noNotes(command, args, fallback);
  });
}

test("pasted Sprout keys in the scan panel sit under the NU7 deadline, for the selected network", async () => {
  const h = keysOnlyHarness();
  await h.open("/fixture/keys-only.dat");
  await flush();
  h.$("sprout-scan-keys").value = "# pasted\nSKfixture";
  assert.equal(h.$("sprout-scan-panel").hidden, false);
  // The panel's container, and the alert that is its first child.
  assert.equal(h.$("wallet-sprout-warning").hidden, false);
  assert.equal(h.$("wallet-sprout-nu7-warning").hidden, false);
  assert.match(h.$("wallet-sprout-nu7-warning").textContent, /NU7/);

  h.$("network-select").value = "testnet";
  await h.peek("refreshSproutNu7Warning()");
  assert.match(h.$("wallet-sprout-nu7-warning").textContent, /Testnet NU7: .*4,465,026/);
});

test("a scan sweep of pasted keys switches the NU7 deadline to the broadcast wording", async () => {
  const h = keysOnlyHarness();
  await h.open("/fixture/keys-only.dat");
  await flush();
  h.$("sprout-scan-keys").value = "SKfixture";
  h.$("network-select").value = "testnet";
  await h.peek("refreshSproutNu7Warning()");
  h.$("sprout-scan-destination").value = "fixture-destination";
  h.$("sprout-scan-confirm").checked = true;
  await h.scanSweep();
  await flush();
  assert.match(h.$("wallet-sprout-nu7-warning").textContent, /^testnet NU7: .*confirm it is mined/);
});

// The panel lives in its own disclosure on the wallet screen, outside
// #wallet-summary, so a user with only a raw SK…/ST… key backup can reach it.
// Its first child is its own NU7 alert, and the panel is never shown without
// that alert's text: these pin the invariant "panel usable ⇒ NU7 visible".
test("the Sprout scan panel carries its own NU7 alert and is reachable with no wallet file", () => {
  const html = fs.readFileSync("gui/src/index.html", "utf8");
  const depthAt = (from, to) => {
    const between = html.slice(from, to);
    return (between.match(/<div\b/g) || []).length - (between.match(/<\/div>/g) || []).length;
  };
  const summary = html.indexOf('id="wallet-summary"');
  const entry = html.indexOf('id="sprout-scan-entry"');
  const panel = html.indexOf('id="sprout-scan-panel"');
  const alert = html.indexOf('id="sprout-scan-nu7-warning"');
  assert.ok(summary > 0 && entry > 0 && panel > entry && alert > panel);
  // Not nested in the wallet summary, which only a wallet file reveals.
  assert.ok(depthAt(summary, entry) <= 0, "the scan entry must sit outside #wallet-summary");
  assert.match(html.slice(entry - 200, entry + 60), /<details[^>]*id="sprout-scan-entry"/);
  // The alert is the panel's first element, ahead of every control.
  const firstChild = html.slice(html.indexOf(">", panel) + 1).match(/<([a-z]+)\b[^>]*\bid="([^"]+)"/);
  assert.equal(firstChild[2], "sprout-scan-nu7-warning");
  for (const control of ["sprout-scan-keys", "sprout-scan-run", "sprout-scan-sweep-run"]) {
    const at = html.indexOf(`id="${control}"`);
    assert.ok(at > alert, `${control} must come after the panel's NU7 alert`);
    assert.ok(depthAt(html.lastIndexOf("<div", panel), at) >= 1, `${control} must stay inside the panel`);
  }
});

function assertPanelUnderDeadline(h, label) {
  if (h.$("sprout-scan-panel").hidden) return;
  assert.equal(h.$("sprout-scan-nu7-warning").hidden, false, `${label}: panel usable without NU7 alert`);
  assert.match(h.$("sprout-scan-nu7-warning").textContent, /NU7/, label);
}

test("with no wallet file, opening the Sprout disclosure shows the panel under the NU7 deadline", async () => {
  const h = harness();
  h.peek("renderSproutScanPanel()");
  assert.equal(h.$("sprout-scan-panel").hidden, true);
  h.$("sprout-scan-entry").open = true;
  await h.peek("onSproutScanEntryToggle()");
  assert.equal(h.peek("walletFile"), null);
  assert.equal(h.$("sprout-scan-panel").hidden, false);
  assert.match(h.$("sprout-scan-nu7-warning").textContent, /November 5, 2026/);
  assertPanelUnderDeadline(h, "opened");
  assert.doesNotMatch(h.$("sprout-scan-keys").placeholder ?? "", /wallet file/);
  // The carried-forward banners belong to a wallet file; none is open, so
  // the panel's alert must not have leaked into their state.
  assert.equal(h.peek("sproutNu7Warning"), "");
  assert.equal(h.$("scan-sprout-uncovered").textContent, "");
  h.$("sprout-scan-entry").open = false;
  await h.peek("onSproutScanEntryToggle()");
  assert.equal(h.$("sprout-scan-panel").hidden, true);
});

test("the no-file panel stays hidden until its NU7 text has arrived", async () => {
  const slow = deferred();
  const h = harness(async (command, args, fallback) => {
    if (command === "sprout_nu7_warning") await slow.promise;
    return fallback();
  });
  h.$("sprout-scan-entry").open = true;
  const pending = h.peek("onSproutScanEntryToggle()");
  assert.equal(h.$("sprout-scan-panel").hidden, true);
  slow.resolve();
  await pending;
  assert.equal(h.$("sprout-scan-panel").hidden, false);
  assertPanelUnderDeadline(h, "after arrival");
});

test("if the NU7 text cannot be fetched, the no-file panel still shows a deadline", async () => {
  const h = harness(async (command, args, fallback) => {
    if (command === "sprout_nu7_warning") throw new Error("ipc down");
    return fallback();
  });
  h.$("sprout-scan-entry").open = true;
  await h.peek("onSproutScanEntryToggle()");
  assert.equal(h.$("sprout-scan-panel").hidden, false);
  assertPanelUnderDeadline(h, "fallback");
});

test("the no-file panel's NU7 deadline follows the network picker", async () => {
  const h = harness();
  h.$("sprout-scan-entry").open = true;
  await h.peek("onSproutScanEntryToggle()");
  assert.equal(h.$("sprout-scan-network").value, "mainnet");
  h.$("network-select").value = "testnet";
  await h.peek("refreshSproutNu7Warning()");
  assert.match(h.$("sprout-scan-nu7-warning").textContent, /Testnet NU7: .*4,465,026/);
  assert.equal(h.$("sprout-scan-network").value, "testnet");
  assertPanelUnderDeadline(h, "testnet");
});

test("the panel's network choice drives the one network picker", () => {
  const source = fs.readFileSync("gui/src/main.js", "utf8");
  const start = source.indexOf('$("sprout-scan-network")?.addEventListener("change"');
  assert.ok(start > 0, "the panel's network select must be wired");
  const handler = source.slice(start, source.indexOf("\n});", start));
  assert.match(handler, /\$\("network-select"\)\.value = /);
  assert.match(handler, /dispatchEvent/);
  const toggle = source.indexOf('$("sprout-scan-entry")?.addEventListener("toggle"');
  assert.ok(toggle > 0, "opening the disclosure must refresh the panel");
  assert.match(source.slice(toggle, source.indexOf("\n", toggle)), /onSproutScanEntryToggle/);
});

test("a no-file scan sends only the pasted lines, with no wallet path or passphrase", async () => {
  const calls = [];
  const h = harness(async (command, args, fallback) => {
    if (command === "start_sprout_scan") {
      calls.push({ ...args });
      return "scan-1";
    }
    if (command === "get_sprout_scan") {
      return {
        handle: args.handle, status: "completed", error: null,
        report: { notes_found: 1, total_zatoshis: 7, spent_notes: 0, tip_warning: null,
          decrypt_from_height: null, decrypt_line: "Every block is decrypted." },
      };
    }
    return fallback();
  });
  h.loadScanPanel();
  h.$("sprout-scan-entry").open = true;
  await h.peek("onSproutScanEntryToggle()");
  h.$("sprout-scan-keys").value = "# paper backup\nSKfixture\n";
  h.$("sprout-scan-peers").value = "";
  h.$("lightwalletd-url").value = "https://zec.rocks:443";
  h.$("data-dir").value = "";
  h.$("birthday-height").value = "419200";
  await h.scan();
  assert.equal(calls.length, 1);
  // The fields that make this a no-file scan; other request fields (the
  // decrypt bound, for one) are owned by their own tests.
  const sent = JSON.parse(JSON.stringify(calls[0]));
  assert.deepEqual(sent.keys, ["# paper backup", "SKfixture", ""]);
  assert.equal(sent.reviewId, null);
  assert.equal(sent.passphrase, null);
  assert.equal(sent.network, "mainnet");
  assert.equal(sent.dataDir, "");
  assert.equal(sent.lightwalletdUrl, "https://zec.rocks:443");
  assert.deepEqual(sent.peers, []);
  // #260's decrypt request, at its default with no wallet file: no key dates,
  // so no floor, and the skip left on. The untouched 419200 default in the
  // main birthday field must not become a floor.
  assert.equal(sent.birthdayFloor, null);
  assert.equal(sent.decryptEveryBlock, false);
  // The completed snapshot reveals the sweep, and the backend's line on
  // where decryption started is shown (#274).
  assert.equal(h.$("sprout-scan-sweep").hidden, false);
  assert.equal(h.$("sprout-scan-plan").textContent, "Every block is decrypted.");
});

test("a no-file scan sweep sends the pasted lines and switches the panel to broadcast wording", async () => {
  const starts = [];
  const executions = [];
  const h = harness(async (command, args, fallback) => {
    if (command === "start_sprout_scan") {
      starts.push({ ...args });
      return "scan-1";
    }
    if (command === "get_sprout_scan") {
      return {
        handle: args.handle, status: "completed", error: null,
        report: { notes_found: 1, total_zatoshis: 5, spent_notes: 0, tip_warning: null,
          decrypt_from_height: null, decrypt_line: "" },
      };
    }
    if (command === "execute_sprout_scan_sweep") {
      executions.push({ ...args });
      return sproutLifecycleReport([sproutTransaction("pending", { txid: "aa" })]);
    }
    return fallback();
  });
  h.loadScanPanel();
  h.$("network-select").value = "testnet";
  h.$("sprout-scan-entry").open = true;
  await h.peek("onSproutScanEntryToggle()");
  h.$("sprout-scan-keys").value = "STfixture";
  h.$("sprout-scan-peers").value = "";
  await h.scan();
  // #271 binds the pasted lines when the scan starts, with no wallet file.
  assert.equal(starts.length, 1);
  assert.equal(starts[0].reviewId, null);
  assert.equal(starts[0].passphrase, null);
  assert.deepEqual([...starts[0].keys], ["STfixture"]);
  assert.equal(starts[0].network, "testnet");
  h.$("sprout-scan-destination").value = "fixture-destination";
  await h.peek("refreshSproutScanReview()");
  h.$("sprout-scan-confirm").checked = true;
  await h.peek("runSproutScanSweep()");
  await flush();
  // The sweep executes the reviewed proposal only; no line is re-sent.
  assert.equal(executions.length, 1);
  assert.deepEqual(JSON.parse(JSON.stringify(executions[0])), { proposalId: "scan-proposal-scan-1" });
  assert.match(h.$("sprout-scan-nu7-warning").textContent, /^testnet NU7: .*confirm it is mined/);
  // Opening a wallet file afterwards must not drop the broadcast wording.
  await h.open("/fixture/sprout.dat");
  await flush();
  await h.peek("refreshSproutNu7Warning()");
  assert.match(h.$("sprout-scan-nu7-warning").textContent, /confirm it is mined/);
  assertPanelUnderDeadline(h, "after a later open");
});

test("a wallet file needing a scan opens the panel, under its own NU7 alert", async () => {
  const h = keysOnlyHarness();
  await h.open("/fixture/keys-only.dat");
  await flush();
  assert.equal(h.$("sprout-scan-entry").open, true);
  assert.equal(h.$("sprout-scan-panel").hidden, false);
  assertPanelUnderDeadline(h, "file needs scan");
  assert.match(h.$("sprout-scan-keys").placeholder, /wallet file/);
  // Forgetting the file closes a panel it opened, if no key was typed.
  h.peek("forgetLoadedWalletFile()");
  assert.equal(h.$("wallet-summary").hidden, true);
  assert.equal(h.$("sprout-scan-panel").hidden, true);
  assert.doesNotMatch(h.$("sprout-scan-keys").placeholder ?? "", /wallet file/);
});

test("a failed open of another file drops the previous file's scan offer", async () => {
  const noNotes = inspected({ sprout_spendable_notes: 0, sprout_spendable_zatoshis: 0 });
  const h = harness(async (command, args, fallback) => {
    if (command === "inspect_wallet_file" && args.path === "/fixture/broken.dat") {
      throw new Error("not a wallet file");
    }
    return noNotes(command, args, fallback);
  });
  await h.open("/fixture/keys-only.dat");
  await flush();
  assert.equal(h.$("sprout-scan-entry").open, true);
  await h.open("/fixture/broken.dat");
  assert.equal(h.peek("walletFile"), null);
  assert.ok(!h.$("sprout-scan-entry").open);
  assert.equal(h.$("sprout-scan-panel").hidden, true);
  assert.doesNotMatch(h.$("sprout-scan-entry-label").textContent, /this wallet/);
  assert.doesNotMatch(h.$("sprout-scan-keys").placeholder, /wallet file/);
});

test("forgetting a wallet file keeps a typed Sprout key and its panel", async () => {
  const h = keysOnlyHarness();
  await h.open("/fixture/keys-only.dat");
  await flush();
  h.$("sprout-scan-keys").value = "SKfixture";
  h.peek("forgetLoadedWalletFile()");
  assert.equal(h.$("sprout-scan-keys").value, "SKfixture");
  assert.equal(h.$("sprout-scan-panel").hidden, false);
  assertPanelUnderDeadline(h, "after forget");
});

test("a wallet whose Sprout notes are cached does not open the scan panel", async () => {
  const h = harness();
  await h.open("/fixture/first.dat");
  await flush();
  assert.ok(!h.$("sprout-scan-entry").open);
  assert.equal(h.$("sprout-scan-panel").hidden, true);
});

test("Start over clears the raw Sprout key box and closes the panel", async () => {
  const h = harness();
  h.$("sprout-scan-entry").open = true;
  await h.peek("onSproutScanEntryToggle()");
  h.$("sprout-scan-keys").value = "SKfixture";
  h.$("sprout-scan-destination").value = "fixture-destination";
  h.$("sprout-scan-confirm").checked = true;
  h.$("sprout-scan-sweep").hidden = false;
  h.$("sprout-scan-birthday").value = "300000";
  h.$("sprout-scan-every-block").checked = true;
  h.peek("forgetSproutScanInputs()");
  assert.equal(h.$("sprout-scan-birthday").value, "");
  assert.equal(h.$("sprout-scan-every-block").checked, false);
  assert.equal(h.$("sprout-scan-keys").value, "");
  assert.equal(h.$("sprout-scan-destination").value, "");
  assert.equal(h.$("sprout-scan-confirm").checked, false);
  assert.equal(h.$("sprout-scan-sweep").hidden, true);
  assert.ok(!h.$("sprout-scan-entry").open);
  assert.equal(h.$("sprout-scan-panel").hidden, true);

  // Wired at every site that resets recovery inputs, beside the Sapling box.
  const source = fs.readFileSync("gui/src/main.js", "utf8");
  const sites = [...source.matchAll(/\$\("sapling-scan-keys"\)\.value = "";/g)].map((m) => m.index);
  assert.ok(sites.length >= 2);
  for (const at of sites) {
    assert.match(source.slice(at, at + 300), /forgetSproutScanInputs\(\)/);
  }
});

// Review finding 6 on #271: a forged Sprout key is dropped from the sweep
// as inspect drops it, and the review says so, so a user is never quoted a
// smaller sweep with no reason given. The genuine notes stay sweepable.
test("a wallet review names a dropped forged Sprout key and stays sweepable", async () => {
  const forged = "a Sprout key in this file does not control the address it is stored under " +
    "(stored aa, derived bb). It was skipped: spending with it would build a transaction for " +
    "someone else's note.";
  const h = harness(async (command, args, fallback) => {
    const response = await fallback();
    if (command === "propose_wallet_sprout_sweep") return { ...response, warnings: [forged] };
    return response;
  });
  await h.open("/fixture/forged.dat");
  await flush();
  assert.match(h.$("sprout-sweep-plan").textContent, /1 note/);
  assert.match(h.$("sprout-sweep-plan").textContent, /does not control the address/);
  h.$("sprout-sweep-confirm").checked = true;
  h.$("sprout-sweep-confirm").dispatch("change");
  assert.equal(h.$("sprout-sweep-run").disabled, false);
});

test("a malformed scan peer does not fail the preview; the backend warns and the sweep still refuses", async () => {
  const seen = {};
  const h = harness(async (command, args, fallback) => {
    seen[command] = { ...args };
    if (command === "propose_wallet_sprout_sweep") {
      const response = await fallback();
      return {
        ...response,
        scan_warning: "The scan panel's peers were not used: custom peer \"no-port-here\" is not valid.",
      };
    }
    return fallback();
  });
  h.loadScanPanel();
  h.$("sprout-scan-peers").value = "192.0.2.7:8233, no-port-here";
  await h.open("/fixture/bad-peer.dat");
  await flush();
  // The raw entries reach the backend, which decides how to degrade.
  assert.deepEqual([...seen.propose_wallet_sprout_sweep.peers], ["192.0.2.7:8233", "no-port-here"]);
  assert.match(h.$("sprout-sweep-plan").textContent, /90000 to your address/);
  assert.match(h.$("sprout-sweep-status").textContent, /peers were not used/);
  // Sweeping with the same field refuses before anything is sent.
  h.$("sprout-destination").value = "fixture-destination";
  await h.sweepConfirmed();
  await flush();
  assert.equal("execute_wallet_sprout_sweep" in seen, false);
  assert.match(h.$("sprout-sweep-status").textContent, /no-port-here.*host:port/);
});
