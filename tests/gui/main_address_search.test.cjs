const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("gui/src/main.js", "utf8");

function loadFunction(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must remain testable`);
  const nextSection = source.indexOf("\n}\n", start);
  assert.notEqual(nextSection, -1, `${name} must have a closing brace`);
  const declaration = source.slice(start, nextSection + 3);
  return vm.runInNewContext(`${declaration}; ${name}`);
}

test("matched recovery config contains no seed and fixes exact-source scan bounds", () => {
  const configForMatchedRecovery = loadFunction("configForMatchedRecovery");
  const input = {
    seed: "must-not-cross-ipc",
    birthday: 500000,
    num_accounts: null,
    gap_limit: 20,
    lightwalletd_url: "https://fixture.invalid",
    data_dir: "/fixture",
    network: "mainnet",
    label: "Matched backup",
  };
  const output = configForMatchedRecovery(input);
  assert.equal("seed" in output, false);
  assert.equal(output.num_accounts, 1);
  assert.equal(output.gap_limit, 1);
  assert.equal(output.network, "mainnet");
});

test("return to retained matches is gated on a terminal recovery without unswept funds", () => {
  const canReturn = loadFunction("canReturnToAddressMatches");
  assert.equal(canReturn({ phase: "scanning", summary: { total_zatoshis: 0 } }, "search-1"), false);
  assert.equal(canReturn({ phase: "complete", summary: { total_zatoshis: 12 } }, "search-1"), false);
  assert.equal(canReturn({ phase: "complete", summary: { total_zatoshis: 0 } }, "search-1"), true);
  assert.equal(canReturn({ phase: "cancelled" }, "search-1"), true);
  assert.equal(canReturn({ phase: "error" }, "search-1"), true);
  assert.equal(canReturn({ phase: "complete", summary: { total_zatoshis: 0 } }, null), false);
});

test("BIP39 passphrase is supplied only for a matched-session resume", () => {
  const passphraseForResumedSession = loadFunction("passphraseForResumedSession");
  assert.equal(passphraseForResumedSession({ match_coordinates: { path: "fixture" } }, "secret"), "secret");
  assert.equal(passphraseForResumedSession({ match_coordinates: null }, "secret"), null);
});
