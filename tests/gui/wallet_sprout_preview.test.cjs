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
        coverage_notice: null, coverage_may_hide_funds: false, seed_note: null,
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
    // own, with its two input helpers stubbed only if not already present.
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

test("the Sprout scan panel is only reachable beneath the NU7 alert", async () => {
  const html = fs.readFileSync("gui/src/index.html", "utf8");
  const container = html.indexOf('id="wallet-sprout-warning"');
  const alert = html.indexOf('id="wallet-sprout-nu7-warning"');
  const panel = html.indexOf('id="sprout-scan-panel"');
  // If the panel is ever moved out of this container, so that pasted keys can
  // be scanned with no wallet open, it needs a NU7 warning of its own.
  assert.ok(container > 0 && container < alert && alert < panel);
  const between = html.slice(container, panel);
  const opened = (between.match(/<div\b/g) || []).length;
  const closed = (between.match(/<\/div>/g) || []).length;
  assert.ok(opened - closed >= 1, "sprout-scan-panel must stay inside wallet-sprout-warning");

  const h = keysOnlyHarness();
  await h.open("/fixture/keys-only.dat");
  await flush();
  h.peek("forgetLoadedWalletFile()");
  assert.equal(h.$("wallet-summary").hidden, true);
});
