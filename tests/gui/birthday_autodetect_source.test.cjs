const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("gui/src/main.js", "utf8");

function loadFunction(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must remain testable`);
  const end = source.indexOf("\n}\n", start);
  assert.notEqual(end, -1, `${name} must have a closing brace`);
  return vm.runInNewContext(`${source.slice(start, end + 3)}; ${name}`, {});
}

const pick = loadFunction("birthdayAutodetectSource");
const plain = (x) => JSON.parse(JSON.stringify(x));

test("a typed seed is used when no wallet file is loaded", () => {
  assert.deepEqual(plain(pick("  abandon art ", null)), { kind: "seed" });
});

test("a wallet file with a recovered mnemonic is detected from the backend", () => {
  const wallet = { path: "/w", passphrase: null, summary: { has_mnemonic: true } };
  assert.deepEqual(plain(pick("", wallet)), { kind: "wallet" });
  // The scan uses the file's keys, so detection must follow the file too.
  assert.deepEqual(plain(pick("typed seed", wallet)), { kind: "wallet" });
});

test("a seedless wallet file is detected from the backend too", () => {
  // A zcashd wallet.dat dates itself from its key creation times; the
  // backend decides, and refuses a seedless ZecWallet Lite file itself.
  const wallet = { path: "/w", passphrase: null, summary: { has_mnemonic: false } };
  assert.deepEqual(plain(pick("", wallet)), { kind: "wallet" });
});

test("nothing loaded keeps the original prompt", () => {
  const out = plain(pick("   ", null));
  assert.equal(out.kind, "none");
  assert.equal(out.message, "Enter your seed phrase on step 2 first.");
});
