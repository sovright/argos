const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("gui/src/main.js", "utf8");

function loadFunction(name, context = {}) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must remain testable`);
  const nextSection = source.indexOf("\n}\n", start);
  assert.notEqual(nextSection, -1, `${name} must have a closing brace`);
  const declaration = source.slice(start, nextSection + 3);
  return vm.runInNewContext(`${declaration}; ${name}`, context);
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
  assert.equal(output.transparent_scan, null);
  assert.equal(output.network, "mainnet");
});

test("ordinary transparent scans default to receive indices 0 through 999 and validate bounds", () => {
  const transparentScanFromInputs = loadFunction("transparentScanFromInputs");
  assert.deepEqual(
    JSON.parse(JSON.stringify(transparentScanFromInputs("0", "1000", false))),
    { index_start: 0, index_count: 1000, include_change: false },
  );
  assert.deepEqual(
    JSON.parse(JSON.stringify(transparentScanFromInputs("2000", "25", true))),
    { index_start: 2000, index_count: 25, include_change: true },
  );
  assert.throws(() => transparentScanFromInputs("2147483647", "2", false), /range must end/);
  assert.throws(() => transparentScanFromInputs("0", "0", false), /from 1 to 10,000/);
  assert.throws(() => transparentScanFromInputs("0", "10001", false), /from 1 to 10,000/);
});

test("additional transparent controls hide for known standalone key sources", () => {
  const shouldShow = loadFunction("shouldShowTransparentRange");
  assert.equal(shouldShow(false, true, false, false, false), true);
  assert.equal(shouldShow(false, false, true, true, false), true);
  assert.equal(shouldShow(false, false, true, false, false), false);
  assert.equal(shouldShow(false, false, false, false, true), false);
  assert.equal(shouldShow(false, false, false, false, false), true);
  assert.equal(shouldShow(true, true, false, false, false), false);
});

test("transparent range summary follows valid edits and reports invalid ranges", () => {
  const transparentScanFromInputs = loadFunction("transparentScanFromInputs");
  const transparentScanSummary = loadFunction("transparentScanSummary", { transparentScanFromInputs });
  const defaults = transparentScanSummary("0", "1000", false);
  assert.equal(defaults.valid, true);
  assert.match(defaults.text, /receive indices 0–999/);
  const changed = transparentScanSummary("997", "3", true);
  assert.equal(changed.valid, true);
  assert.match(changed.text, /receive \+ change indices 997–999/);
  const invalid = transparentScanSummary("2147483647", "2", false);
  assert.equal(invalid.valid, false);
  assert.match(invalid.text, /Fix the transparent range/);
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
