const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("gui/src/main.js", "utf8");

// Text of a top-level function declaration, sync or async.
function declaration(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must remain testable`);
  const end = source.indexOf("\n}\n", start);
  assert.notEqual(end, -1, `${name} must have a closing brace`);
  const asyncStart = source.lastIndexOf("async ", start);
  const isAsync = asyncStart !== -1 && asyncStart + "async ".length === start;
  return source.slice(isAsync ? asyncStart : start, end + 3);
}

const pick = vm.runInNewContext(`${declaration("birthdayAutodetectSource")}; birthdayAutodetectSource`, {});
const plain = (x) => JSON.parse(JSON.stringify(x));

test("a typed seed is used when no wallet file is loaded", () => {
  assert.deepEqual(plain(pick("  abandon art ", null)), { kind: "seed" });
});

test("a loaded wallet file is detected from the backend, which decides whether it has a mnemonic", () => {
  const wallet = { path: "/w", passphrase: null, summary: { has_mnemonic: true } };
  assert.deepEqual(plain(pick("", wallet)), { kind: "wallet" });
  // The scan uses the file's keys, so detection must follow the file too.
  assert.deepEqual(plain(pick("typed seed", wallet)), { kind: "wallet" });
  // A seedless file is refused by the backend (`mnemonic_of`), not restated
  // here, so the wording cannot drift between the two.
  const seedless = { path: "/w", passphrase: null, summary: { has_mnemonic: false } };
  assert.deepEqual(plain(pick("", seedless)), { kind: "wallet" });
});

test("the frontend does not carry its own copy of the seedless refusal", () => {
  assert.doesNotMatch(source, /Auto-detect needs a seed phrase, and this wallet file has none/);
});

test("an encrypted wallet whose passphrase was cleared asks for it again", () => {
  const wallet = { path: "/w", passphrase: null, passphraseCleared: true, summary: { has_mnemonic: true } };
  const out = plain(pick("typed seed", wallet));
  assert.equal(out.kind, "none");
  assert.match(out.message, /re-enter the passphrase on the wallet screen/i);
});

test("a plaintext wallet with no passphrase is not treated as cleared", () => {
  const wallet = { path: "/w", passphrase: null, summary: { has_mnemonic: true } };
  assert.deepEqual(plain(pick("", wallet)), { kind: "wallet" });
});

test("nothing loaded keeps the original prompt", () => {
  const out = plain(pick("   ", null));
  assert.equal(out.kind, "none");
  assert.equal(out.message, "Enter your seed phrase on step 2 first.");
});

// --- the click handler itself ---------------------------------------------

function harness({ walletFile, seed = "", invoke }) {
  const els = new Map();
  const el = (id) => {
    if (!els.has(id)) els.set(id, { value: "", disabled: false });
    return els.get(id);
  };
  el("lightwalletd-url").value = " https://lwd.example:443 ";
  el("network-select").value = "mainnet";
  const hints = [];
  const ctx = {
    $: el,
    seedInput: { value: seed },
    walletFile,
    walletOpenGeneration: 1,
    listen: async () => () => {},
    invoke,
    setBirthdayHint: (text, kind) => hints.push({ text, kind }),
    setStatus: () => {},
    updateScanEstimate: () => {},
    formatApproxMonth: () => "Jan 2020",
    approxDateFromHeight: () => null,
  };
  vm.createContext(ctx);
  const run = vm.runInContext(
    `${declaration("birthdayAutodetectSource")}\n${declaration("runBirthdayAutodetect")}\nrunBirthdayAutodetect`,
    ctx,
  );
  return { run, ctx, els, hints };
}

test("the click handler passes the wallet path and passphrase to the backend", async () => {
  const calls = [];
  const h = harness({
    walletFile: { path: "/wallets/zwl.dat", passphrase: "hunter2", summary: { has_mnemonic: true } },
    seed: "ignored typed seed",
    invoke: async (cmd, args) => {
      calls.push({ cmd, args: plain(args) });
      return { birthday: 1234567 };
    },
  });
  await h.run();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].cmd, "detect_birthday_from_wallet_file");
  assert.equal(calls[0].args.path, "/wallets/zwl.dat");
  assert.equal(calls[0].args.passphrase, "hunter2");
  assert.equal(calls[0].args.lightwalletdUrl, "https://lwd.example:443");
  assert.equal(calls[0].args.network, "mainnet");
  assert.ok(!("seed" in calls[0].args), "the typed seed must not go with a wallet file");
  assert.equal(h.els.get("birthday-height").value, 1234567);
});

test("the click handler sends the typed seed lower-cased when no wallet is loaded", async () => {
  const calls = [];
  const h = harness({
    walletFile: null,
    seed: "  Abandon ART ",
    invoke: async (cmd, args) => {
      calls.push({ cmd, args: plain(args) });
      return { birthday: 42 };
    },
  });
  await h.run();
  assert.equal(calls[0].cmd, "detect_birthday");
  assert.equal(calls[0].args.seed, "abandon art");
});

test("a result is dropped when another wallet was opened during detection", async () => {
  const h = harness({
    walletFile: { path: "/old.dat", passphrase: null, summary: { has_mnemonic: true } },
    invoke: async () => {
      h.ctx.walletOpenGeneration += 1; // user opened a different wallet meanwhile
      return { birthday: 999 };
    },
  });
  await h.run();
  assert.equal(h.els.has("birthday-height"), false, "the stale birthday must not be written");
  assert.match(h.hints.at(-1).text, /discarded/);
  assert.equal(h.els.get("birthday-autodetect").disabled, false, "buttons are re-enabled");
});

test("a typed-seed result is dropped when the seed changed during detection", async () => {
  const h = harness({
    walletFile: null,
    seed: "abandon art",
    invoke: async () => {
      h.ctx.seedInput.value = "something else";
      return { birthday: 999 };
    },
  });
  await h.run();
  assert.equal(h.els.has("birthday-height"), false);
});

test("a cleared-passphrase wallet never reaches the backend", async () => {
  let called = false;
  const h = harness({
    walletFile: { path: "/w", passphrase: null, passphraseCleared: true, summary: { has_mnemonic: true } },
    invoke: async () => {
      called = true;
      return { birthday: 1 };
    },
  });
  await h.run();
  assert.equal(called, false);
  assert.match(h.hints.at(-1).text, /passphrase/);
});
