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
  // The decrypt-bound inputs (#260): an empty panel birthday, the untouched
  // main field and the skip left on, so the wallet's own skip applies.
  $("sprout-scan-every-block").checked = false;
  $("birthday-height").value = "419200";
  const calls = [];
  const context = {
    $,
    walletFile: null,
    birthdayTouched: false,
    document: { createElement: el },
    fmt: String,
    confirmationSourcesFromForm: () => ["backup=https://confirm.example"],
    setStatus() {},
    sproutScanPeers: () => [],
    invoke: async (command, args) => {
      calls.push({ command, args });
      // #271: the scan returns a backend handle and its result arrives as a
      // snapshot; the sweep executes a reviewed proposal by id.
      if (command === "start_sprout_scan") return "scan-1";
      if (command === "get_sprout_scan") return { handle: args.handle, status: "running", report: null, error: null };
      return report;
    },
    // Reviewed-intent state the handlers read (#271). The scan panel holds
    // a completed scan and a proposal reviewed for this destination.
    sproutScanHandle: null,
    sproutScanRetryHandle: null,
    sproutScanPausePromise: Promise.resolve(),
    sproutScanGeneration: 0,
    sproutScanResult: null,
    sproutScanReview: null,
    sproutScanReviewDestination: null,
    sproutScanExecutionPending: false,
    sproutScanListenersReady: Promise.resolve(true),
    invalidateSproutScanSource() {},
    invalidateSproutScanReview() {},
    updateSproutScanSweepButton() {},
    publishSproutScanSnapshot() {},
    noteSproutBroadcast() {},
    uncoveredSproutKeys: 0,
    renderSproutUncoveredBanners() {},
    clearTransientSecrets() {},
  };
  // `async function` must be kept whole, so slice from its own keyword.
  const start = source.indexOf(`async function ${name}(`);
  assert.notEqual(start, -1, `${name} must remain testable`);
  const end = source.indexOf("\n}\n", start) + 3;
  Object.assign(
    context,
    loadFunctions(
      [
        "sproutReviewHasLifecycleStatus",
        "sproutReviewMayRun",
        "sproutSourceWarningMayClear",
        "sproutLifecycleAmount",
        "sproutLifecycleRow",
        "renderSproutSweepReport",
        "sproutScanKeyLines",
        "sproutScanKeyEntries",
        "sproutScanKeys",
        "sproutDecryptRequest",
        "currentSproutDecryptRequest",
      ],
      context,
    ),
  );
  vm.createContext(context);
  const run = vm.runInContext(`${source.slice(start, end)}; ${name}`, context);
  return { run, calls, context };
}

const BOX = "# my keys\n\nSKone\n   \n# mid\nSKtwo\n";
const RAW_LINES = ["# my keys", "", "SKone", "   ", "# mid", "SKtwo", ""];

test("runSproutScan sends the unfiltered lines so backend line numbers match the box", async () => {
  const { run, calls } = driveHandler("runSproutScan", BOX, null);
  await run();
  const starts = calls.filter((call) => call.command === "start_sprout_scan");
  assert.equal(starts.length, 1, "comments and blanks must not block a real key");
  assert.deepEqual([...starts[0].args.keys], RAW_LINES);
  // Nothing chosen: no floor, skip left to the wallet's own key times.
  assert.equal(starts[0].args.birthdayFloor, null);
  assert.equal(starts[0].args.decryptEveryBlock, false);
  assert.deepEqual(
    [...starts[0].args.confirmationSources],
    ["backup=https://confirm.example"],
  );
});

// #271 binds the keys at scan start: the box's raw lines go to
// `start_sprout_scan` (above), and the sweep can no longer re-send a box
// that may have been edited since. Executing sends only the reviewed
// proposal's id, so no line from the box, wallet path or passphrase leaves
// the frontend at sweep time.
test("runSproutScanSweep sends only the reviewed proposal, never the box's lines", async () => {
  const { run, calls, context } = driveHandler("runSproutScanSweep", BOX, {
    transactions: [], mined_zatoshis: 0, pending_zatoshis: 0, unknown_zatoshis: 0,
    skipped: [], rejected: [], warnings: [],
    error: null, fresh_all_mined: false,
  });
  context.sproutScanHandle = "scan-1";
  context.sproutScanResult = { notes_found: 1 };
  context.sproutScanReview = { proposal_id: "proposal-1", params_present: true };
  context.sproutScanReviewDestination = "zs1destination";
  await run();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "execute_sprout_scan_sweep");
  assert.deepEqual(JSON.parse(JSON.stringify(calls[0].args)), { proposalId: "proposal-1" });
});
