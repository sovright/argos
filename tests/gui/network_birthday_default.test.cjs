const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("gui/src/main.js", "utf8");

function declaration(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must remain testable`);
  const end = source.indexOf("\n}\n", start);
  assert.notEqual(end, -1, `${name} must have a closing brace`);
  return source.slice(start, end + 3);
}

function harness(touched = false, value = "419200") {
  const birthday = { value };
  const ctx = {
    birthdayTouched: touched,
    $: (id) => {
      assert.equal(id, "birthday-height");
      return birthday;
    },
    updateScanEstimate() {},
    updateBirthdayHint() {},
  };
  vm.createContext(ctx);
  const helpers = vm.runInContext(
    [
      "defaultBirthdayForNetwork",
      "syncUntouchedBirthdayToNetwork",
      "scanBirthdayFromForm",
    ].map(declaration).join("\n") +
      "\n({ defaultBirthdayForNetwork, syncUntouchedBirthdayToNetwork, scanBirthdayFromForm })",
    ctx,
  );
  return { birthday, ctx, helpers };
}

test("an untouched birthday follows the selected network", () => {
  const h = harness(false);
  h.helpers.syncUntouchedBirthdayToNetwork("testnet");
  assert.equal(h.birthday.value, "280000");
  h.helpers.syncUntouchedBirthdayToNetwork("mainnet");
  assert.equal(h.birthday.value, "419200");
});

test("a user or auto-detected birthday survives a network change", () => {
  const h = harness(true, "123456");
  h.helpers.syncUntouchedBirthdayToNetwork("testnet");
  assert.equal(h.birthday.value, "123456");
});

test("scan config uses the selected network default only when the field is blank", () => {
  const h = harness(false, "");
  assert.equal(h.helpers.scanBirthdayFromForm("testnet", ""), 280000);
  assert.equal(h.helpers.scanBirthdayFromForm("mainnet", ""), 419200);
  assert.equal(h.helpers.scanBirthdayFromForm("testnet", "123456"), 123456);
  assert.equal(h.helpers.scanBirthdayFromForm("testnet", "0"), 0);
});

test("manual and matched network changes both synchronize an untouched birthday", () => {
  const manualStart = source.indexOf('$("network-select").addEventListener("change"');
  const manualEnd = source.indexOf("// The Sprout scan panel", manualStart);
  assert.match(
    source.slice(manualStart, manualEnd),
    /syncUntouchedBirthdayToNetwork\(\)/,
  );

  const matchedStart = source.indexOf('$("network-select").value = snapshot.network');
  const matchedEnd = source.indexOf('$("server-preset").value', matchedStart);
  assert.match(
    source.slice(matchedStart, matchedEnd),
    /syncUntouchedBirthdayToNetwork\(snapshot\.network\)/,
  );
});
