const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

// Exercise wallet import, source authority, diagnostics and expiry through the real frontend functions.
function harness(intercept = (_, __, fallback) => fallback()) {
  const elements = new Map();
  const ids = new Set([...fs.readFileSync("gui/src/index.html", "utf8").matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]));
  function element() {
    return { value: "", textContent: "", hidden: false, disabled: false, children: [],
      get innerHTML() { return ""; },
      set innerHTML(value) { assert.equal(value, ""); this.children = []; },
      appendChild(child) { this.children.push(child); },
    };
  }
  const $ = (id) => {
    assert.ok(ids.has(id), `Unknown DOM id: ${id}`);
    if (!elements.has(id)) elements.set(id, element());
    return elements.get(id);
  };
  $("network-select").value = "mainnet";
  const timers = new Map();
  let nextTimerId = 1;
  const calls = [];
  const context = vm.createContext({
    $, document: { createElement: element, dispatchEvent() {} },
    CustomEvent: class { constructor(type) { this.type = type; } },
    setTimeout(callback, delay) { const id = nextTimerId++; timers.set(id, { callback, delay, cleared: false }); return id; },
    clearTimeout(id) { const timer = timers.get(id); if (timer) timer.cleared = true; },
    setStatus: (id, text) => { $(id).textContent = text; },
    invoke: async (command, args) => {
      calls.push({ command, args });
      const result = await intercept(command, args, async () => {
        if (command === "inspect_wallet_file") return {
          review_id: `review:${args.path}`, needs_passphrase: false,
          transparent_keys: 2, sapling_keys: 1, has_mnemonic: false,
          sprout_records: 0, sprout_notice: "", diagnostics: [],
          coverage_notice: null, coverage_may_hide_funds: false, seed_note: null,
        };
        throw new Error(`Unexpected IPC command: ${command}`);
      });
      return result && !result.needs_passphrase && result.review_id === undefined
        ? { ...result, review_id: `review:${args.path}` } : result;
    },
  });
  const source = fs.readFileSync("gui/src/main.js", "utf8");
  vm.runInContext(source.slice(source.indexOf("let walletFile = null;"), source.indexOf("// The picker itself runs in Rust")), context);
  return { $, timers, calls,
    peek: (expr) => vm.runInContext(expr, context),
    fireTimer(id, { includeCleared = false } = {}) { const timer = timers.get(id); if (!timer.cleared || includeCleared) timer.callback(); },
    async open(path, passphrase = "") {
      $("wallet-path").value = path; $("wallet-passphrase").value = passphrase;
      await vm.runInContext("openWalletFile()", context); await flush();
    },
    abandonWallet() { vm.runInContext("clearTransientSecrets({ abandonWallet: true })", context); },
  };
}
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
const flush = () => new Promise((resolve) => setImmediate(resolve));
test("a successful wallet inspection expires frontend passphrase and review authority", async () => {
  const h = harness();
  await h.open("/fixture/encrypted.dat", "wallet secret");

  const [[timerId, timer]] = [...h.timers.entries()];
  assert.ok(timerId, "successful inspection must schedule an expiry");
  assert.ok(timer.delay <= 30 * 60 * 1000, "frontend expiry must not outlive the backend review");
  assert.equal(h.$("wallet-passphrase").value, "wallet secret");
  assert.equal(h.peek("walletFile.passphrase"), "wallet secret");
  assert.equal(h.peek("walletFile.reviewId"), "review:/fixture/encrypted.dat");

  h.$("sapling-scan-keys").value = "pasted Sapling secret";
  h.fireTimer(timerId);

  assert.equal(h.$("sapling-scan-keys").value, "");
  assert.equal(h.$("wallet-passphrase").value, "");
  assert.equal(h.peek("walletFile"), null);
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
  assert.equal(h.$("wallet-passphrase").value, "");
  assert.equal(h.$("wallet-next").disabled, true);
});

const SEED_NOTICE = "Incomplete — this file holds an HD seed that Argos does not recover.";
const UNKNOWN_NOTICE = "Some records of a type Argos does not recognise were skipped.";
const LATER_SCREENS = ["scan-wallet-caveat", "complete-wallet-caveat", "delete-wallet-caveat"];

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
      sprout_records: 0, has_mnemonic: false,

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
      sprout_records: 0, has_mnemonic: false,
 diagnostics: [],
      seed_diagnostics: ["the wallet's seed derived 101 transparent (change) key(s) but only 91 were read from this file"],
      coverage_notice: "Incomplete", coverage_may_hide_funds: true, seed_note: null,
    };
  });
  await h.open("/fixture/seed-only.dat");
  assert.equal(h.$("wallet-diagnostics").hidden, true);
  assert.equal(h.$("wallet-seed-diagnostics").hidden, false);
});


test("a mixed wallet continues supported recovery while carrying the Sprout retirement notice", async () => {
  const h = harness(async (command, args, fallback) => ({ ...(await fallback()),
    sprout_records: 2, sprout_notice: "Sprout funds are unspendable under NU7." }));
  await h.open("/fixture/mixed.dat");
  assert.equal(h.$("wallet-next").disabled, false);
  assert.equal(h.peek("walletFile.reviewId"), "review:/fixture/mixed.dat");
  assert.match(h.$("wallet-sprout-warning").textContent, /unspendable under NU7/);
  for (const id of LATER_SCREENS) assert.match(h.$(id).textContent, /unspendable under NU7/);
  assert.deepEqual(h.calls.map(c => c.command), ["inspect_wallet_file"]);
});

test("a Sprout-only wallet shows its limitation without starting a recoverable session", async () => {
  const h = harness(async (command, args, fallback) => ({ ...(await fallback()),
    transparent_keys: 0, sapling_keys: 0, sprout_records: 2, review_id: null,
    sprout_notice: "Sprout funds are unspendable under NU7." }));
  await h.open("/fixture/sprout-only.dat");
  assert.equal(h.peek("walletFile"), null);
  assert.equal(h.$("wallet-next").disabled, true);
  assert.equal(h.$("wallet-summary").hidden, false);
  assert.match(h.$("wallet-status").textContent, /No supported spending keys/);
  assert.match(h.$("wallet-sprout-warning").textContent, /unspendable under NU7/);
});

for (const fails of [false, true]) {
  test(`older wallet inspection ${fails ? "failure" : "success"} cannot replace a newer selection`, async () => {
    const old = deferred();
    const h = harness(async (command, args, fallback) => {
      if (command === "inspect_wallet_file" && args.path === "/fixture/old.dat") await old.promise;
      return fallback();
    });
    const first = h.open("/fixture/old.dat", "old secret");
    await h.open("/fixture/new.dat", "new secret");
    if (fails) old.reject(new Error("old import failed")); else old.resolve();
    await first;
    assert.equal(h.peek("walletFile.path"), "/fixture/new.dat");
    assert.equal(h.peek("walletFile.passphrase"), "new secret");
    assert.equal(h.$("wallet-next").disabled, false);
    assert.equal(h.$("wallet-summary").hidden, false);
  });
}
