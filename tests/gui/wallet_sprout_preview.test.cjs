const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

// Exercise wallet opening, summary rendering and preview together. Only the
// desktop IPC boundary and DOM are stand-ins; no wallet secrets or funds are used.
function harness(intercept = (_, __, fallback) => fallback()) {
  const elements = new Map();
  const ids = new Set([...fs.readFileSync("gui/src/index.html", "utf8").matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]));
  function element() {
    return {
      value: "", textContent: "",
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
  const previews = [];
  let onProgress;
  let failStatus = false;
  const context = vm.createContext({
    listen: async (name, callback) => { assert.equal(name, "sprout-sweep-progress"); onProgress = callback; },
    $, document: { createElement: element },
    fmt: (value) => String(value),
    setStatus: (id, text) => {
      if (failStatus) { failStatus = false; throw new Error("fixture DOM failure"); }
      $(id).textContent = text;
    },
    invoke: (command, args) => intercept(command, args, async () => {
      if (command === "inspect_wallet_file") return {
        needs_passphrase: false, transparent_keys: 0, sapling_keys: 0,
        sprout_keys: 1, has_mnemonic: false, sprout_spendable_notes: 1,
        sprout_spendable_zatoshis: 100000, sprout_addresses: [], diagnostics: [],
        coverage_notice: null, coverage_may_hide_funds: false,
      };
      if (command === "preview_sprout_sweep") {
        previews.push({ ...args });
        return {
          notes: 1, gross_zatoshis: 100000, fee_zatoshis: 10000,
          net_zatoshis: 90000, lands_in_sapling: "Lands in Sapling",
          params_present: true, params_path: "/fixture/sprout.params",
        };
      }
      throw new Error(`Unexpected IPC command: ${command}`);
    }),
  });
  const source = fs.readFileSync("gui/src/main.js", "utf8");
  vm.runInContext(source.slice(
    source.indexOf("let walletFile = null;"),
    source.indexOf("// The picker itself runs in Rust"),
  ), context);
  const progressStart = source.indexOf("(async () => {", source.indexOf("// Proving runs for minutes"));
  vm.runInContext(source.slice(progressStart, source.indexOf("// ─── Typed Sapling keys", progressStart)), context);
  return {
    $, previews,
    failNextStatus: () => { failStatus = true; },
    progress: (payload) => onProgress({ payload }),
    sweep: () => vm.runInContext("runSproutSweep()", context),
    peek: (expr) => vm.runInContext(expr, context),
    async open(path, passphrase = "") {
      $("wallet-path").value = path;
      $("wallet-passphrase").value = passphrase;
      await vm.runInContext("openWalletFile()", context);
    },
  };
}

test("first wallet open displays its Sprout preview without a null-path error", async () => {
  const h = harness();
  await h.open("/fixture/first.dat");
  assert.deepEqual(h.previews, [{
    path: "/fixture/first.dat", passphrase: null, network: "mainnet", dataDir: null,
  }]);
  assert.equal(h.$("wallet-sprout-sweep").hidden, false);
  assert.match(h.$("sprout-sweep-plan").textContent, /90000 to your address/);
  assert.equal(h.$("sprout-sweep-status").textContent, "");
  assert.equal(h.$("sprout-sweep-run").disabled, false);
});

test("opening another wallet previews the new path and passphrase", async () => {
  const h = harness();
  await h.open("/fixture/first.dat", "fixture-one");
  await h.open("/fixture/second.dat", "fixture-two");
  assert.deepEqual(h.previews.at(-1), {
    path: "/fixture/second.dat", passphrase: "fixture-two", network: "mainnet", dataDir: null,
  });
  assert.equal(h.$("sprout-sweep-status").textContent, "");
});

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const flush = () => new Promise((resolve) => setImmediate(resolve));

for (const fails of [false, true]) {
  test(`older wallet inspection ${fails ? "failure" : "success"} cannot replace a newer selection`, async () => {
    const old = deferred();
    const executions = [];
    const h = harness(async (command, args, fallback) => {
      if (command === "inspect_wallet_file" && args.path === "/fixture/old.dat") await old.promise;
      if (command === "execute_sprout_sweep") {
        executions.push(args.path);
        return { sent: [], skipped: [], error: null };
      }
      return fallback();
    });
    const first = h.open("/fixture/old.dat");
    await h.open("/fixture/new.dat");
    if (fails) old.reject(new Error("old import failed")); else old.resolve();
    await first;
    await flush();
    h.$("sprout-destination").value = "fixture-destination";
    await h.sweep();
    assert.deepEqual(executions, ["/fixture/new.dat"]);
    assert.equal(h.$("wallet-next").disabled, false);
    assert.equal(h.$("wallet-summary").hidden, false);
  });

  test(`older preview ${fails ? "failure" : "success"} cannot overwrite the current preview`, async () => {
    const old = deferred();
    const h = harness(async (command, args, fallback) => {
      if (command === "preview_sprout_sweep" && args.path === "/fixture/old.dat") {
        await old.promise;
        return { notes: 99, gross_zatoshis: 999, fee_zatoshis: 1, net_zatoshis: 998, params_present: true };
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
    assert.equal(h.$("sprout-sweep-run").disabled, false);
  });
}

test("a new import blocks spending until its own preview is ready", async () => {
  const inspection = deferred(), preview = deferred();
  const executions = [];
  const h = harness(async (command, args, fallback) => {
    if (args.path === "/fixture/new.dat") {
      if (command === "inspect_wallet_file") await inspection.promise;
      if (command === "preview_sprout_sweep") await preview.promise;
    }
    if (command === "execute_sprout_sweep") {
      executions.push(args.path);
      return { sent: [], skipped: [], error: null };
    }
    return fallback();
  });
  await h.open("/fixture/old.dat");
  await flush();
  h.$("sprout-destination").value = "fixture-destination";
  const opening = h.open("/fixture/new.dat");
  assert.equal(h.$("sprout-sweep-run").disabled, true);
  assert.equal(h.$("wallet-next").disabled, true);
  await h.sweep();
  assert.deepEqual(executions, []);
  inspection.resolve();
  await opening;
  assert.equal(h.$("sprout-sweep-run").disabled, true);
  await h.sweep();
  assert.deepEqual(executions, []);
  preview.resolve();
  await flush();
  await h.sweep();
  assert.deepEqual(executions, ["/fixture/new.dat"]);
});

for (const fails of [false, true]) {
  test(`stale sweep ${fails ? "failure" : "success"} leaves the new wallet's results and warnings intact`, async () => {
    const pending = deferred();
    const h = harness((command, args, fallback) => command === "execute_sprout_sweep" ? pending.promise : fallback());
    await h.open("/fixture/old.dat");
    h.$("sprout-destination").value = "fixture-destination";
    const sweep = h.sweep();
    await h.open("/fixture/new.dat");
    const warning = h.$("delete-sprout-uncovered").textContent;
    if (fails) pending.reject(new Error("old sweep failed"));
    else pending.resolve({ sent: [{ txid: "old-tx", value_swept: 90000 }], skipped: [], total_swept: 90000, error: null });
    await sweep;
    assert.equal(h.$("sprout-sweep-status").textContent, "");
    assert.equal(h.$("sprout-sweep-results").children.length, 0);
    assert.equal(h.$("delete-sprout-uncovered").hidden, false);
    assert.equal(h.$("delete-sprout-uncovered").textContent, warning);
    assert.equal(h.$("sprout-sweep-run").disabled, false);
  });
}

test("reopening a wallet cannot start a concurrent sweep, and failure releases the lock", async () => {
  const pending = deferred();
  let executions = 0;
  const h = harness((command, args, fallback) => {
    if (command !== "execute_sprout_sweep") return fallback();
    executions++;
    return pending.promise;
  });
  await h.open("/fixture/wallet.dat");
  h.$("sprout-destination").value = "fixture-destination";
  const sweep = h.sweep();
  await h.open("/fixture/wallet.dat");
  assert.equal(h.$("sprout-sweep-run").disabled, true);
  // Invoke the handler even when disabled: the lock must guard execution itself.
  const second = h.sweep();
  assert.equal(executions, 1);
  pending.reject(new Error("fixture failure"));
  await Promise.all([sweep, second]);
  assert.equal(h.$("sprout-sweep-run").disabled, false);
  await h.sweep();
  assert.equal(executions, 2);
});

test("sweep progress and completion belong only to the active source", async () => {
  const pending = deferred();
  const h = harness((command, args, fallback) => command === "execute_sprout_sweep" ? pending.promise : fallback());
  await h.open("/fixture/old.dat");
  h.$("sprout-destination").value = "fixture-destination";
  const sweep = h.sweep();
  h.progress("Proving note 1");
  assert.match(h.$("sprout-sweep-status").textContent, /Proving note 1/);
  await h.open("/fixture/new.dat");
  h.progress("Proving old note 2");
  assert.equal(h.$("sprout-sweep-status").textContent, "");
  pending.resolve({ sent: [], skipped: [], total_swept: 90000, error: null });
  await sweep;
  h.progress("Late old event");
  assert.equal(h.$("sprout-sweep-status").textContent, "");
});

test("current wallet sweep still shows its transaction and clears its own warning", async () => {
  const h = harness((command, args, fallback) => command === "execute_sprout_sweep"
    ? Promise.resolve({ sent: [{ txid: "fixture-tx", value_swept: 90000 }], skipped: [], total_swept: 90000, error: null })
    : fallback());
  await h.open("/fixture/wallet.dat");
  h.$("sprout-destination").value = "fixture-destination";
  await h.sweep();
  assert.match(h.$("sprout-sweep-results").children[0].textContent, /fixture-tx/);
  assert.match(h.$("sprout-sweep-status").textContent, /Swept 90000/);
  assert.equal(h.$("delete-sprout-uncovered").hidden, true);
  assert.equal(h.$("sprout-sweep-run").disabled, true);
  await h.open("/fixture/new.dat");
  assert.equal(h.$("sprout-sweep-results").children.length, 0);
});

test("synchronous status failure before proving cannot strand the sweep lock", async () => {
  let executions = 0;
  const h = harness((command, args, fallback) => {
    if (command !== "execute_sprout_sweep") return fallback();
    executions++;
    return Promise.resolve({ sent: [], skipped: [], total_swept: 0, error: null });
  });
  await h.open("/fixture/wallet.dat");
  h.$("sprout-destination").value = "fixture-destination";
  h.failNextStatus();
  await h.sweep().catch(() => {});
  assert.equal(executions, 0);
  await h.open("/fixture/wallet.dat");
  assert.equal(h.$("sprout-sweep-run").disabled, false);
  await h.sweep();
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
  const h = harness(async (command, args, fallback) => command === "execute_sprout_sweep"
    ? { sent: [{ txid: "fixture-tx", value_swept: 90000 }], skipped: [], total_swept: 90000, error: null }
    : withCoverage(SEED_NOTICE, true)(command, args, fallback));
  await h.open("/fixture/zcashd5.dat");
  // The preview is requested without being awaited; let it land.
  await new Promise(setImmediate);
  h.$("sprout-destination").value = "fixture-destination";
  await h.sweep();
  assert.match(h.$("sprout-sweep-status").textContent, /Swept 90000/);
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

// #239 review: a wallet whose Sprout notes were all spent must not be told
// it needs a multi-day scan for note data it does in fact hold.
function inspected(overrides) {
  return async (command, args, fallback) => {
    if (command === "inspect_wallet_file") return { ...(await fallback()), ...overrides };
    return fallback();
  };
}
const texts = (el) => el.children.map((c) => c.textContent);

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
    if (command === "execute_sprout_sweep") return {
      sent: [{ value_swept: 5, txid: "aa" }], total_swept: 5, skipped: [],
      rejected: ["note bb:0:1 was refused by the network: spent"], error: null,
    };
    return fallback();
  });
  await h.open("/fixture/first.dat");
  await flush();
  h.$("sprout-destination").value = "fixture-destination";
  await h.sweep();
  const lines = texts(h.$("sprout-sweep-results"));
  assert.ok(lines.some((l) => /refused by the network/.test(l)), lines.join("\n"));
  assert.match(h.$("sprout-sweep-status").textContent, /1 note\(s\) refused/);
});

// The wallet-file path asks a full-block scan of the same keys to settle
// spends the file cannot see. It must look where the scan panel writes.
test("the Sprout preview, inspection and sweep look in the scan's data directory", async () => {
  const seen = {};
  const h = harness(async (command, args, fallback) => {
    seen[command] = args.dataDir;
    if (command === "execute_sprout_sweep") return { sent: [], skipped: [], rejected: [], error: null };
    return fallback();
  });
  h.$("data-dir").value = "/fixture/workspace";
  await h.open("/fixture/first.dat");
  await flush();
  h.$("sprout-destination").value = "fixture-destination";
  await h.sweep();
  assert.deepEqual(seen, {
    inspect_wallet_file: "/fixture/workspace",
    preview_sprout_sweep: "/fixture/workspace",
    execute_sprout_sweep: "/fixture/workspace",
  });
});

// A broadcast that could not be written to the sweep journal is worth
// saying: a re-run would prove that one note again and see it refused.
test("a sweep journal warning is shown after the sweep", async () => {
  const h = harness(async (command, args, fallback) => {
    if (command === "execute_sprout_sweep") return {
      sent: [{ value_swept: 5, txid: "aa" }], total_swept: 5, skipped: [], rejected: [],
      warnings: ["aa was broadcast, but writing the sweep journal failed"], error: null,
    };
    return fallback();
  });
  await h.open("/fixture/first.dat");
  await flush();
  h.$("sprout-destination").value = "fixture-destination";
  await h.sweep();
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
      if (command === "execute_sprout_sweep") return {
        sent: [{ value_swept: 5, txid: "aa" }], total_swept: 5, skipped: [], rejected, error: null,
      };
      return fallback();
    });
    await h.open("/fixture/first.dat");
    await flush();
    h.peek("uncoveredSproutKeys = 1");
    h.$("sprout-destination").value = "fixture-destination";
    await h.sweep();
    assert.equal(h.peek("uncoveredSproutKeys") > 0, kept, `rejected=${rejected.length}`);
  }
});

// #239 round 4, findings 5 and 6: a sweep that stopped shows why, and does
// not clear the "keep the original wallet file" caveat; neither does one
// that skipped any note.
test("a sweep that stopped or skipped a note says so and keeps the caveat", async () => {
  for (const [report, stopped] of [
    [{ sent: [], total_swept: 0, skipped: [], rejected: [], error: "note 1 of 3 could not be built: bad bundle" }, true],
    [{ sent: [{ value_swept: 5, txid: "aa" }], total_swept: 5, skipped: ["note 2 of 2: below the fee"], rejected: [], error: null }, false],
  ]) {
    const h = harness(async (command, args, fallback) =>
      command === "execute_sprout_sweep" ? report : fallback());
    await h.open("/fixture/first.dat");
    await flush();
    h.peek("uncoveredSproutKeys = 1");
    h.$("sprout-destination").value = "fixture-destination";
    await h.sweep();
    const status = h.$("sprout-sweep-status").textContent;
    if (stopped) {
      assert.match(status, /did not finish: note 1 of 3 could not be built/);
      assert.doesNotMatch(status, /✓/);
    }
    assert.ok(h.peek("uncoveredSproutKeys") > 0, "the caveat must survive");
  }
});
