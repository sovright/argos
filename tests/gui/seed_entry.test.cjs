const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("gui/src/main.js", "utf8");

function loadFunction(name, context = {}) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must remain testable`);
  const end = source.indexOf("\n}\n", start);
  assert.notEqual(end, -1, `${name} must have a closing brace`);
  return vm.runInNewContext(`${source.slice(start, end + 3)}; ${name}`, context);
}

test("a valid 24-word seed gets the plain confirmation", () => {
  const seedValidMessage = loadFunction("seedValidMessage");
  assert.equal(seedValidMessage(24), "✓ Seed phrase is valid.");
});

test("a valid shorter seed warns that it did not come from ZecWallet Lite", () => {
  const seedValidMessage = loadFunction("seedValidMessage");
  for (const count of [12, 15, 18, 21]) {
    const message = seedValidMessage(count);
    assert.match(message, /^✓ Seed phrase is valid\./, `${count}`);
    assert.match(message, new RegExp(`${count}-word`), `${count}`);
    assert.match(message, /ZecWallet Lite/, `${count}`);
    assert.match(message, /different derivation/, `${count}`);
    assert.match(message, /ZIP 32/, `${count}`);
    assert.match(message, /m\/44'\/133'\/0'\/0\/0–999/, `${count}`);
  }
});
