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

function controls(autoChecked) {
  const els = {
    "auto-gap-limit": { checked: autoChecked },
    "gap-limit-row": { style: {} },
    "accounts-range": { disabled: null },
    "accounts-range-value": { style: {} },
  };
  return { els, $: (id) => els[id] };
}

// start-scan sends `gap_limit` from #gap-limit in gap mode and the slider's
// count in fixed mode; each control must be editable exactly when it is sent.
test("gap mode shows the gap-limit row and locks the account slider", () => {
  const { els, $ } = controls(true);
  loadFunction("syncAccountScanControls", { $ })();
  assert.equal(els["gap-limit-row"].style.display, "block");
  assert.equal(els["accounts-range"].disabled, true);
});

test("fixed mode unlocks the account slider and hides the gap-limit row", () => {
  const { els, $ } = controls(false);
  loadFunction("syncAccountScanControls", { $ })();
  assert.equal(els["gap-limit-row"].style.display, "none");
  assert.equal(els["accounts-range"].disabled, false);
});

test("start-scan sends the slider count only in fixed mode", () => {
  assert.match(source, /num_accounts:[^\n]*autoGap \? null : parseInt\(\$\("accounts-range"\)\.value, 10\)/);
  assert.match(source, /gap_limit:[^\n]*autoGap \? parseInt\(\$\("gap-limit"\)\.value, 10\)/);
});
