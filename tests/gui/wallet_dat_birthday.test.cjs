const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("gui/src/main.js", "utf8");

function functionText(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must remain testable`);
  const end = source.indexOf("\n}\n", start);
  assert.notEqual(end, -1, `${name} must have a closing brace`);
  return source.slice(start, end + 3);
}

function loadFunction(name, prelude = "") {
  return vm.runInNewContext(`${prelude}\n${functionText(name)}; ${name}`, {});
}

const plain = (x) => JSON.parse(JSON.stringify(x));

// The height-to-date constants live beside the function, not inside it.
const dateConstants = (() => {
  const start = source.indexOf("const SAPLING_ACTIVATION_HEIGHT_JS");
  const end = source.indexOf("function approxDateFromHeight(");
  assert.ok(start !== -1 && end > start, "date constants must stay beside approxDateFromHeight");
  return source.slice(start, end);
})();
const approxDateFromHeight = loadFunction("approxDateFromHeight", dateConstants);
const isoDay = (d) => d.toISOString().slice(0, 10);

test("pre-Sapling heights get pre-Sapling dates, never before genesis", () => {
  const one = isoDay(approxDateFromHeight(1));
  assert.match(one, /^2016-1[01]-/);
  assert.ok(one >= "2016-10-28", one);
  assert.match(isoDay(approxDateFromHeight(200_000)), /^2017-/);
  assert.equal(isoDay(approxDateFromHeight(419_200)), "2018-10-28");
  const days = [1, 100_000, 300_000, 419_199, 419_200, 500_000].map((h) =>
    approxDateFromHeight(h).getTime(),
  );
  for (let i = 1; i < days.length; i++) assert.ok(days[i - 1] <= days[i]);
});

const hint = loadFunction("birthdayDetectHint");

test("a seed-path result keeps its short hint", () => {
  const text = hint({ birthday: 1_500_000, method: "transparent", message: "m" }, "Jan 2022");
  const block = (1_500_000).toLocaleString();
  assert.equal(text, `✓ Auto-detected birthday: block ${block} (≈ Jan 2022).`);
});

test("a wallet.dat result names the key creation times and keeps the core's caveat", () => {
  const text = hint(
    {
      birthday: 300_000,
      method: "wallet_metadata",
      message: "Block 300000 (about 2018-03-01), from the wallet file's key creation times. If older, enter an earlier birthday.",
    },
    "Mar 2018",
  );
  assert.ok(text.includes(`block ${(300_000).toLocaleString()}`), text);
  assert.match(text, /key creation times/);
  assert.match(text, /earlier birthday/);
});

test("the chain fallback says it may be later than the wallet's real age", () => {
  const text = hint(
    { birthday: 1_200_000, method: "transparent_utxos", message: "Block 1200000, from x." },
    "Feb 2021",
  );
  assert.match(text, /on-chain unspent outputs/);
  assert.match(text, /later than the wallet's real age/);
});

const request = loadFunction("sproutDecryptRequest");

test("nothing entered asks for the wallet's own skip", () => {
  assert.deepEqual(plain(request("", false, "419200", false)), {
    birthdayFloor: null,
    decryptEveryBlock: false,
  });
});

test("the default birthday field is not mistaken for a manual entry", () => {
  // 419200 is the field's starting value; it must not cap a later skip.
  assert.equal(request("  ", false, "419200", false).birthdayFloor, null);
  assert.equal(request("", false, "300000", true).birthdayFloor, 300_000);
});

test("the panel's own birthday wins over the main field", () => {
  assert.equal(request("1000", false, "300000", true).birthdayFloor, 1000);
  assert.equal(request("0", false, "", false).birthdayFloor, 0);
});

test("decrypt every block is passed through", () => {
  assert.equal(request("", true, "", false).decryptEveryBlock, true);
});

test("a birthday that is not a block number is refused, not ignored", () => {
  assert.ok(request("12ab", false, "", false).error);
  assert.ok(request("-5", false, "", false).error);
});
