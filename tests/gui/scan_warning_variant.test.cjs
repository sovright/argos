const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("gui/src/main.js", "utf8");
const html = fs.readFileSync("gui/src/index.html", "utf8");

function loadFunction(name, context = {}) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must remain testable`);
  const end = source.indexOf("\n}\n", start);
  assert.notEqual(end, -1, `${name} must have a closing brace`);
  return vm.runInNewContext(`${source.slice(start, end + 3)}; ${name}`, context);
}

const transparentOnlyFile = { path: "/w.dat", summary: { transparent_only: true } };
const saplingFile = { path: "/w.dat", summary: { transparent_only: false } };

test("a transparent-only wallet file gets the no-block-sync banner", () => {
  const scanWarningVariant = loadFunction("scanWarningVariant");
  assert.equal(scanWarningVariant(transparentOnlyFile, 0, false), "transparent-only");
});

test("everything else keeps the shielded-sync banner", () => {
  const scanWarningVariant = loadFunction("scanWarningVariant");
  // A typed seed, a file with Sapling keys, or a summary we never received.
  assert.equal(scanWarningVariant(null, 0, false), "shielded");
  assert.equal(scanWarningVariant(saplingFile, 0, false), "shielded");
  assert.equal(scanWarningVariant({ path: "/w.dat" }, 0, false), "shielded");
  // Pasted Sapling keys move the scan onto the imported-account route,
  // which does run a block sync.
  assert.equal(scanWarningVariant(transparentOnlyFile, 1, false), "shielded");
  assert.equal(scanWarningVariant(null, 2, false), "shielded");
  // Matched-address recovery ignores the loaded file.
  assert.equal(scanWarningVariant(transparentOnlyFile, 0, true), "shielded");
});

test("both banner variants exist and only the shielded one shows by default", () => {
  assert.match(html, /id="scan-warning-shielded"(?![^>]*hidden)/);
  assert.match(html, /id="scan-warning-transparent-only"[^>]*hidden/);
  assert.match(html, /no shielded block sync/);
});
