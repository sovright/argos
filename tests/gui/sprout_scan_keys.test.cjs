const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("gui/src/main.js", "utf8");

function loadFunctions(names, context) {
  const declarations = names.map((name) => {
    const start = source.indexOf(`function ${name}(`);
    assert.notEqual(start, -1, `${name} must remain testable`);
    const end = source.indexOf("\n}\n", start);
    assert.notEqual(end, -1, `${name} must have a closing brace`);
    return source.slice(start, end + 3);
  });
  return vm.runInNewContext(`${declarations.join("\n")}; ({ ${names.join(", ")} })`, context);
}

function load(text) {
  return loadFunctions(
    ["sproutScanKeyLines", "sproutScanKeyEntries", "sproutScanKeys"],
    { $: () => ({ value: text }) },
  );
}

test("sproutScanKeys skips blank lines and # comments like the CLI key file", () => {
  const { sproutScanKeys } = load("# my keys\n\nSKone\n   \nSKtwo\n");
  assert.deepEqual([...sproutScanKeys()], ["SKone", "SKtwo"]);
});

test("sproutScanKeys skips an indented comment and trims keys", () => {
  const { sproutScanKeys } = load("   # indented note\n  SKone  \n\t# tabbed\nSKtwo");
  assert.deepEqual([...sproutScanKeys()], ["SKone", "SKtwo"]);
});

test("sproutScanKeys keeps keys in order and returns nothing for a comment-only box", () => {
  assert.deepEqual([...load("SKc\nSKa\nSKb").sproutScanKeys()], ["SKc", "SKa", "SKb"]);
  assert.deepEqual([...load("# only\n\n# comments").sproutScanKeys()], []);
});

test("sproutScanKeyEntries reports the textarea line each key sits on", () => {
  const { sproutScanKeyEntries } = load("# note\n\nSKone\n# mid\nSKtwo");
  assert.deepEqual(
    JSON.parse(JSON.stringify(sproutScanKeyEntries())),
    [{ key: "SKone", line: 3 }, { key: "SKtwo", line: 5 }],
  );
});

test("sproutScanKeyLines is unfiltered so the backend numbers by visible line", () => {
  const { sproutScanKeyLines } = load("# note\n\nSKone");
  assert.deepEqual([...sproutScanKeyLines()], ["# note", "", "SKone"]);
});

// Drive the real click handlers with a stand-in IPC boundary and capture what
// they send. Only the DOM and `invoke` are fakes.
function driveHandler(name, boxText, report) {
  const els = new Map();
  const el = () => ({
    value: "", textContent: "", innerHTML: "", className: "",
    hidden: false, disabled: false, checked: true,
    appendChild() {},
  });
  const $ = (id) => {
    if (!els.has(id)) els.set(id, el());
    return els.get(id);
  };
  $("sprout-scan-keys").value = boxText;
  $("sprout-scan-destination").value = "zs1destination";
  $("network-select").value = "mainnet";
  const calls = [];
  const context = {
    $,
    walletFile: null,
    document: { createElement: el },
    fmt: String,
    setStatus() {},
    sproutScanPeers: () => [],
    invoke: async (command, args) => {
      calls.push({ command, args });
      return report;
    },
  };
  // `async function` must be kept whole, so slice from its own keyword.
  const start = source.indexOf(`async function ${name}(`);
  assert.notEqual(start, -1, `${name} must remain testable`);
  const end = source.indexOf("\n}\n", start) + 3;
  Object.assign(
    context,
    loadFunctions(["sproutScanKeyLines", "sproutScanKeyEntries", "sproutScanKeys"], context),
  );
  vm.createContext(context);
  const run = vm.runInContext(`${source.slice(start, end)}; ${name}`, context);
  return { run, calls };
}

const BOX = "# my keys\n\nSKone\n   \n# mid\nSKtwo\n";
const RAW_LINES = ["# my keys", "", "SKone", "   ", "# mid", "SKtwo", ""];

test("runSproutScan sends the unfiltered lines so backend line numbers match the box", async () => {
  const { run, calls } = driveHandler("runSproutScan", BOX, {
    notes_found: 0, total_zatoshis: 0, spent_notes: 0,
  });
  await run();
  assert.equal(calls.length, 1, "comments and blanks must not block a real key");
  assert.equal(calls[0].command, "start_sprout_scan");
  assert.deepEqual([...calls[0].args.keys], RAW_LINES);
});

test("runSproutScanSweep sends the unfiltered lines so backend line numbers match the box", async () => {
  const { run, calls } = driveHandler("runSproutScanSweep", BOX, { sent: [] });
  await run();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "sweep_sprout_from_scan");
  assert.deepEqual([...calls[0].args.keys], RAW_LINES);
});
