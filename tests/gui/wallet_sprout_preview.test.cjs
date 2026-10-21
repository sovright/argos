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
        sprout_nu7_warning: "NU7: Sprout recovery must be mined before activation; broadcasting alone is not enough. Check the current mainnet activation schedule.",
        coverage_notice: null, coverage_may_hide_funds: false,
      };
      if (command === "sprout_nu7_warning") return nu7Text(args);
      if (command === "preview_sprout_sweep") {
        previews.push({ ...args });
        return {
          notes: 1, gross_zatoshis: 100000, fee_zatoshis: 10000,
          net_zatoshis: 90000, lands_in_sapling: "Lands in Sapling",
          params_present: true, params_path: "/fixture/sprout.params",
          nu7_warning: "NU7: Sprout recovery must be mined before activation; broadcasting alone is not enough. Check the current mainnet activation schedule.",
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
    // The scan-sweep handler lives outside the slices above; load it on its
    // own, with its input helpers stubbed only if not already present.
    scanSweep() {
      const start = source.indexOf("async function runSproutScanSweep()");
      const end = source.indexOf("\n}\n", start) + 3;
      vm.runInContext(source.slice(start, end), context);
      for (const helper of ["sproutScanPeers", "sproutScanKeyLines", "sproutScanKeyEntries", "sproutScanKeys"]) {
        if (vm.runInContext(`typeof ${helper}`, context) !== "function") {
          vm.runInContext(`function ${helper}() { return []; }`, context);
        }
      }
      return vm.runInContext("runSproutScanSweep()", context);
    },
    // The whole Sprout scan section, with its real key and peer helpers, for
    // driving the panel as a user with no wallet file would.
    loadScanPanel() {
      const start = source.indexOf("// ─── Sprout scan ─");
      const end = source.indexOf('$("sprout-scan-sweep-run").addEventListener', start);
      assert.ok(start > 0 && end > start);
      // Declared on the settings step, outside every slice: the main birthday
      // field counts toward the Sprout decrypt bound only once it was set.
      if (vm.runInContext("typeof birthdayTouched", context) === "undefined") {
        vm.runInContext("var birthdayTouched = false;", context);
      }
      vm.runInContext(source.slice(start, end), context);
    },
    scan: () => vm.runInContext("runSproutScan()", context),
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

test("the NU7 deadline is visible as soon as Sprout keys are detected, before preview finishes", async () => {
  const preview = deferred();
  const h = harness(async (command, args, fallback) => {
    if (command === "preview_sprout_sweep") await preview.promise;
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
    if (command === "execute_sprout_sweep") return {
      sent: [{ value_swept: 5, txid: "fixture-tx" }], total_swept: 5,
      skipped: [], rejected: [], warnings: [], error: null,
    };
    const response = await fallback();
    if (command === "inspect_wallet_file") return {
      ...response, sprout_nu7_warning: "Testnet NU7: see the activation warning before spending.",
    };
    if (command === "preview_sprout_sweep") return {
      ...response, nu7_warning: "Testnet NU7: Sprout spending is unavailable at or after block 4,465,026.",
    };
    return response;
  });
  h.$("network-select").value = "testnet";
  await h.open("/fixture/testnet.dat");
  await flush();
  assert.match(h.$("wallet-sprout-nu7-warning").textContent, /Testnet.*4,465,026/);
  h.$("sprout-destination").value = "fixture-destination";
  await h.sweep();
  assert.equal(h.$("wallet-sprout-nu7-warning").hidden, false);
  assert.match(h.$("wallet-sprout-nu7-warning").textContent, /NU7/);
});

test("an accepted mainnet broadcast switches the warning to confirming it is mined", async () => {
  const h = harness(async (command, args, fallback) => {
    if (command === "execute_sprout_sweep") return {
      sent: [{ value_swept: 5, txid: "fixture-tx" }], total_swept: 5,
      skipped: [], rejected: [], warnings: [], error: null,
    };
    return fallback();
  });
  await h.open("/fixture/mainnet.dat");
  await flush();
  h.$("sprout-destination").value = "fixture-destination";
  await h.sweep();
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
    if (command === "execute_sprout_sweep") return {
      sent: [], total_swept: 0, skipped: [], rejected: ["refused"], warnings: [], error: null,
    };
    return fallback();
  });
  await h.open("/fixture/mainnet.dat");
  await flush();
  h.$("sprout-destination").value = "fixture-destination";
  await h.sweep();
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
    if (command === "execute_sprout_sweep") return {
      sent: [{ value_swept: 5, txid: "fixture-tx" }], total_swept: 5,
      skipped: [], rejected: [], warnings: [], error: null,
    };
    return fallback();
  });
  await h.open("/fixture/sprout.dat");
  await flush();
  h.$("sprout-destination").value = "fixture-destination";
  await h.sweep();
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

test("current wallet sweep shows its transaction and clears the uncovered-key notice", async () => {
  const h = harness((command, args, fallback) => command === "execute_sprout_sweep"
    ? Promise.resolve({ sent: [{ txid: "fixture-tx", value_swept: 90000 }], skipped: [], total_swept: 90000, error: null })
    : fallback());
  await h.open("/fixture/wallet.dat");
  h.$("sprout-destination").value = "fixture-destination";
  await h.sweep();
  assert.match(h.$("sprout-sweep-results").children[0].textContent, /fixture-tx/);
  assert.match(h.$("sprout-sweep-status").textContent, /Swept 90000/);
  assert.doesNotMatch(h.$("delete-sprout-uncovered").textContent, /does not include Sprout/);
  // The deadline survives the sweep, reworded: broadcast is not mined.
  assert.match(h.$("delete-sprout-uncovered").textContent, /must be mined before NU7 activation; confirm it is mined/);
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

// Round-5 findings 3 and 4: one rule for both sweep handlers. The caveat
// goes only when something was sent and nothing stopped, was refused, or
// was skipped.
test("the caveat is cleared only by a sweep that left nothing behind", () => {
  const h = harness();
  const clean = { sent: [{ txid: "a" }], error: null, rejected: [], skipped: [] };
  const cases = [
    [clean, true],
    [{ ...clean, sent: [] }, false],
    [{ ...clean, error: "stopped" }, false],
    [{ ...clean, rejected: ["r"] }, false],
    [{ ...clean, skipped: ["s"] }, false],
    // Round 6: held by the node but not mined is not "left nothing behind".
    [{ ...clean, already_held: [{ txid: "h", value_swept: 1 }] }, false],
  ];
  for (const [report, expected] of cases) {
    assert.equal(h.peek(`sweepLeftNothingBehind(${JSON.stringify(report)})`), expected, JSON.stringify(report));
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
      command === "sweep_sprout_from_scan"
        ? { sent: [{ value_swept: 5, txid: "aa" }], total_swept: 5, skipped: [], rejected, error: null }
        : fallback());
    h.peek("uncoveredSproutKeys = 1");
    h.$("sprout-scan-destination").value = "fixture-destination";
    h.$("sprout-scan-confirm").checked = true;
    await h.scanSweep();
    assert.equal(h.peek("uncoveredSproutKeys") > 0, kept, `rejected=${rejected.length}`);
    if (kept) assert.match(h.$("sprout-scan-status").textContent, /1 note\(s\) refused/);
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
    const sent = [];
    const h = harness((command, args, fallback) => {
      if (command === "sweep_sprout_from_scan") {
        sent.push({ ...args });
        return { sent: [], total_swept: 0, skipped: [], rejected: [], error: null };
      }
      return fallback();
    });
    h.peek(`function currentSproutDecryptRequest() { return ${formNow}; }`);
    h.$("sprout-scan-destination").value = "fixture-destination";
    h.$("sprout-scan-confirm").checked = true;
    await h.scanSweep();
    assert.equal(sent.length, 1, formNow);
    assert.equal("birthdayFloor" in sent[0], false, JSON.stringify(sent[0]));
    assert.equal("decryptEveryBlock" in sent[0], false, JSON.stringify(sent[0]));
  }
});

test("a scan sweep that broadcast switches the NU7 warning to confirming it is mined", async () => {
  const h = harness(async (command, args, fallback) =>
    command === "sweep_sprout_from_scan"
      ? { sent: [{ value_swept: 5, txid: "aa" }], total_swept: 5, skipped: [], rejected: [], error: null }
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
    if (command === "sweep_sprout_from_scan") {
      return { sent: [{ value_swept: 5, txid: "aa" }], total_swept: 5, skipped: [], rejected: [], error: null };
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
      return { notes_found: 1, total_zatoshis: 7, spent_notes: 0, tip_warning: null };
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
  assert.equal(sent.path, null);
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
  assert.equal(h.$("sprout-scan-sweep").hidden, false);
});

test("a no-file scan sweep sends the pasted lines and switches the panel to broadcast wording", async () => {
  const calls = [];
  const h = harness(async (command, args, fallback) => {
    if (command === "sweep_sprout_from_scan") {
      calls.push({ ...args });
      return { sent: [{ value_swept: 5, txid: "aa" }], total_swept: 5, skipped: [], rejected: [], error: null };
    }
    return fallback();
  });
  h.loadScanPanel();
  h.$("network-select").value = "testnet";
  h.$("sprout-scan-entry").open = true;
  await h.peek("onSproutScanEntryToggle()");
  h.$("sprout-scan-keys").value = "STfixture";
  h.$("sprout-scan-peers").value = "";
  h.$("sprout-scan-destination").value = "fixture-destination";
  h.$("sprout-scan-confirm").checked = true;
  await h.peek("runSproutScanSweep()");
  await flush();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].path, null);
  assert.equal(calls[0].passphrase, null);
  assert.deepEqual([...calls[0].keys], ["STfixture"]);
  assert.equal(calls[0].network, "testnet");
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
