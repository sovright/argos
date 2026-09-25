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
  const context = vm.createContext({
    listen: async (name, callback) => { assert.equal(name, "sprout-sweep-progress"); onProgress = callback; },
    $, document: { createElement: element },
    fmt: (value) => String(value),
    setStatus: (id, text) => { $(id).textContent = text; },
    invoke: (command, args) => intercept(command, args, async () => {
      if (command === "inspect_wallet_file") return {
        needs_passphrase: false, transparent_keys: 0, sapling_keys: 0,
        sprout_keys: 1, has_mnemonic: false, sprout_spendable_notes: 1,
        sprout_spendable_zatoshis: 100000, sprout_addresses: [], diagnostics: [],
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
    progress: (payload) => onProgress({ payload }),
    sweep: () => vm.runInContext("runSproutSweep()", context),
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
  assert.deepEqual(h.previews, [{ path: "/fixture/first.dat", passphrase: null }]);
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
    path: "/fixture/second.dat", passphrase: "fixture-two",
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
