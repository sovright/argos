const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("gui/src/main.js", "utf8");

function applyDefault(dir, configured = "") {
  const added = [];
  const input = { value: configured, insertAdjacentElement(position, notice) { added.push(notice); } };
  const state = {};
  const at = source.lastIndexOf('invoke("default_data_dir")');
  const start = source.indexOf(".then((dir) => {", at) + ".then(".length;
  const end = source.indexOf("\n  })", start) + 4;
  const callback = vm.runInNewContext(`(${source.slice(start, end)})`, {
    state, $: (id) => id === "data-dir" ? input : null,
    document: { createElement: () => ({}) },
  });
  callback(dir);
  return { input, state, added };
}

test("upgraded default shows preservation and rescan notice alongside the data directory", () => {
  const h = applyDefault("/AppData/Argos/workspace-v2");
  assert.equal(h.input.value, "/AppData/Argos/workspace-v2");
  const text = h.added.map((el) => el.textContent).join(" ");
  assert.match(text, /previous.*preserved/i);
  assert.match(text, /rescan/i);
  assert.match(text, /workspace-v2/);
});

test("a configured data directory is not replaced or shown a default migration notice", () => {
  const h = applyDefault("/AppData/Argos/workspace-v2", "/chosen");
  assert.equal(h.input.value, "/chosen");
  assert.equal(h.added.length, 0);
});

test("an ordinary default needs no upgrade notice", () => {
  const h = applyDefault("/AppData/Argos/workspace");
  assert.equal(h.input.value, "/AppData/Argos/workspace");
  assert.equal(h.added.length, 0);
});
