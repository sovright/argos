const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("gui/src/main.js", "utf8");

function loadFunctions(names, context = {}) {
  const declarations = names.map((name) => {
    const start = source.indexOf(`function ${name}(`);
    assert.notEqual(start, -1, `${name} must remain testable`);
    const end = source.indexOf("\n}\n", start);
    assert.notEqual(end, -1, `${name} must have a closing brace`);
    return source.slice(start, end + 3);
  });
  return vm.runInNewContext(
    `${declarations.join("\n")}; ({ ${names.join(", ")} })`,
    context,
  );
}

const fns = () =>
  loadFunctions(["txStatusKind", "txStatusLabel", "sweepStatusCounts", "sweepCompleteSummary"]);

// Seedless sweeps (imported wallet.dat, pasted Sapling key, transparent-only)
// report "broadcast"; the seed-phrase route reports "pending"/"confirmed".
const seedless = [
  { source_account: 0, txid: "aa", status: "broadcast" },
  { source_account: 1, txid: "bb", status: "broadcast" },
];

test("a seedless broadcast result is counted as sent, not failed", () => {
  const { sweepStatusCounts } = fns();
  assert.deepEqual(
    JSON.parse(JSON.stringify(sweepStatusCounts(seedless))),
    { confirmed: 0, pending: 2, failed: 0, broadcast: 2 },
  );
});

test("a seedless broadcast result is labelled awaiting confirmation, not Failed", () => {
  const { txStatusLabel, txStatusKind } = fns();
  assert.equal(txStatusLabel("broadcast"), "Broadcast — awaiting confirmation");
  assert.notEqual(txStatusKind("broadcast"), "failed");
});

test("a successful seedless sweep summary reports the transactions it sent", () => {
  const { sweepCompleteSummary } = fns();
  assert.equal(
    sweepCompleteSummary(seedless, null),
    "2 transactions broadcast to the Zcash network. Confirmation usually takes 1–2 minutes.",
  );
});

test("a partial-abort summary counts seedless broadcasts as already sent", () => {
  const { sweepCompleteSummary } = fns();
  const summary = sweepCompleteSummary([seedless[0]], "transparent leg failed");
  assert.match(summary, /but 1 transaction was already broadcast and cannot be undone/);
});

test("seed-phrase statuses classify as before", () => {
  const { sweepStatusCounts, txStatusLabel, sweepCompleteSummary } = fns();
  const hd = [
    { source_account: 0, status: "confirmed" },
    { source_account: 1, status: "pending" },
  ];
  assert.deepEqual(
    JSON.parse(JSON.stringify(sweepStatusCounts(hd))),
    { confirmed: 1, pending: 1, failed: 0, broadcast: 2 },
  );
  assert.equal(txStatusLabel("confirmed"), "Confirmed");
  assert.equal(txStatusLabel("pending"), "Broadcast — awaiting confirmation");
  assert.equal(
    sweepCompleteSummary(hd, null),
    "1 transaction confirmed on-chain. Your funds are on their way.",
  );
});

test("a failed status still reads Failed", () => {
  const { sweepStatusCounts, txStatusLabel, txStatusKind, sweepCompleteSummary } = fns();
  const failed = [{ source_account: 0, status: "failed" }];
  assert.equal(txStatusLabel("failed"), "Failed");
  assert.equal(txStatusKind("failed"), "failed");
  assert.equal(sweepStatusCounts(failed).failed, 1);
  assert.equal(sweepStatusCounts(failed).broadcast, 0);
  assert.equal(
    sweepCompleteSummary(failed, null),
    "All transactions failed to broadcast. No funds were moved.",
  );
});
