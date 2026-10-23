const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const source = fs.readFileSync("gui/src/main.js", "utf8");
function load(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must exist`);
  const end = source.indexOf("\n}\n", start);
  return vm.runInNewContext(`${source.slice(start, end + 3)}; ${name}`);
}
test("the displayed forty-account count does not claim the extension finished", () => {
  const label = load("scanAccountTotalText")({
    phase: "scanning_shielded", accounts: Array.from({length:40}, (_,i)=>({account_index:i})),
    summary: {authoritative_balances:true},
  }, "1.00000000 ZEC");
  assert.match(label, /Found so far: 1\.00000000 ZEC/);
  assert.match(label, /40 accounts loaded/);
  assert.match(label, /scan in progress/);
  assert.doesNotMatch(label, /complete|Grand total|40.*scanned/i);
});
test("cancelled and failed scans keep an explicitly unfinished total", () => {
  for(const phase of ["cancelled","error"]) {
    const label=load("scanAccountTotalText")({phase,accounts:[{},{}],summary:{authoritative_balances:false}},"1 ZEC");
    assert.match(label,/Partial total/);assert.match(label,/unfinished/);assert.match(label,/estimates/);
  }
});
test("a completed scan can label its checked account range", () => {
  const label=load("scanAccountTotalText")({phase:"complete",accounts:Array(40).fill({}),summary:{authoritative_balances:true}},"1 ZEC");
  assert.match(label,/Scan total: 1 ZEC across 40 checked accounts/);
  assert.doesNotMatch(label,/in progress|unfinished/);
});
test("account one triggering extension is described without a false edge claim", () => {
  const detail=load("gapExtensionDetail")({trigger_account_index:1,accounts_from:20,accounts_to:39,pass:1});
  assert.match(detail,/account 1/);assert.match(detail,/20–39/);assert.match(detail,/being checked/);
  assert.doesNotMatch(detail,/near.*edge|already.*scanned|complete/i);
  const html=fs.readFileSync("gui/src/index.html","utf8");
  const banner=html.slice(html.indexOf('id="scan-gap-extension-banner"'),html.indexOf('class="metric-panel"',html.indexOf('id="scan-gap-extension-banner"')));
  assert.match(banner,/consecutive unused accounts/);
  assert.doesNotMatch(banner,/near the edge|not a restart/);
});
