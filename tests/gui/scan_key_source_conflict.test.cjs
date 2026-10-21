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

test("a single key source is accepted", () => {
  const conflict = loadFunction("scanKeySourceConflict");
  assert.equal(conflict(true, false, false), null);
  assert.equal(conflict(false, true, false), null);
  assert.equal(conflict(false, false, true), null);
});

test("a wallet file combines with a pasted Sapling key, as the CLI allows", () => {
  const conflict = loadFunction("scanKeySourceConflict");
  assert.equal(conflict(false, true, true), null);
});

test("a seed phrase with a loaded wallet file is refused", () => {
  const conflict = loadFunction("scanKeySourceConflict");
  const message = conflict(true, true, false);
  assert.equal(typeof message, "string");
  assert.match(message, /seed phrase/);
  assert.match(message, /wallet file/);
});

test("a seed phrase with a pasted Sapling key is still refused", () => {
  const conflict = loadFunction("scanKeySourceConflict");
  const message = conflict(true, false, true);
  assert.equal(typeof message, "string");
  assert.match(message, /Sapling spending key/);
  assert.equal(typeof conflict(true, true, true), "string");
});

test("the start-scan handler consults the conflict check", () => {
  const start = source.indexOf('$("start-scan").addEventListener("click"');
  assert.notEqual(start, -1);
  const end = source.indexOf("\n});\n", start);
  assert.match(source.slice(start, end), /scanKeySourceConflict\(/);
});

// Slice the start-scan click handler out of main.js and return it as a
// callable function, so the test exercises the real code path rather than
// matching its source text.
function loadStartScanHandler(context) {
  const start = source.indexOf('$("start-scan").addEventListener("click"');
  assert.notEqual(start, -1, "start-scan handler must exist");
  const bodyStart = source.indexOf("async () => {", start);
  const end = source.indexOf("\n});\n", start);
  return vm.runInNewContext(`(${source.slice(bodyStart, end + 2)})`, context);
}

test("start-scan with a seed and a loaded wallet file invokes nothing", async () => {
  const invoked = [];
  const statuses = [];
  const context = {
    state: { matchedRecovery: null },
    walletFile: { path: "/tmp/wallet.dat", passphrase: null, summary: {} },
    seedInput: { value: "abandon abandon abandon" },
    hasSaplingScanKeys: () => false,
    scanKeySourceConflict: loadFunction("scanKeySourceConflict"),
    setStatus: (id, message, kind) => statuses.push({ id, message, kind }),
    invoke: async (command) => { invoked.push(command); },
    $: () => { throw new Error("handler must refuse before touching other fields"); },
  };
  await loadStartScanHandler(context)();
  assert.deepEqual(invoked, []);
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0].id, "config-status");
  assert.equal(statuses[0].kind, "error");
  assert.match(statuses[0].message, /Forget this file/);
});

test("the wallet screen has a Forget this file control wired to the reset", () => {
  const html = fs.readFileSync("gui/src/index.html", "utf8");
  assert.match(html, /id="wallet-forget"[^>]*>\s*Forget this file/);
  assert.match(
    source,
    /\$\("wallet-forget"\)\?\.addEventListener\("click", forgetLoadedWalletFile\)/,
  );
});

test("Start over also clears the pasted Sapling keys", () => {
  const start = source.indexOf('$("restart-flow").addEventListener("click"');
  const end = source.indexOf("\n});\n", start);
  const handler = source.slice(start, end);
  assert.match(handler, /\$\("sapling-scan-keys"\)\.value = ""/);
  assert.match(handler, /\$\("sapling-key-addresses"\)\.replaceChildren\(\)/);
});

test("matched-address recovery resets the wallet file through the shared helper", () => {
  const start = source.indexOf("// A matched capability is the sole recovery source");
  assert.notEqual(start, -1);
  const segment = source.slice(start, start + 600);
  assert.match(segment, /forgetLoadedWalletFile\(\)/);
  assert.doesNotMatch(segment, /walletFile = null/);
});

test("Start over drops the loaded wallet file and its caveats", () => {
  const start = source.indexOf('$("restart-flow").addEventListener("click"');
  assert.notEqual(start, -1);
  const end = source.indexOf("\n});\n", start);
  const handler = source.slice(start, end);
  assert.match(handler, /forgetLoadedWalletFile\(\)/);

  const reset = loadFunction("forgetLoadedWalletFile");
  assert.match(reset.toString(), /walletFile = null;/);
  assert.match(reset.toString(), /forgetWalletCaveats\(\);/);
});
