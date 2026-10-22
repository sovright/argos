const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

function functionSource(source, name) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must remain testable`);
  const end = source.indexOf("\n}\n", start);
  assert.notEqual(end, -1, `${name} must have a closing brace`);
  return source.slice(start, end + 3);
}

function element() {
  return {
    children: [], className: "", textContent: "", hidden: false,
    appendChild(child) { this.children.push(child); return child; },
  };
}

function harness() {
  const elements = new Map();
  const $ = (id) => {
    if (!elements.has(id)) elements.set(id, element());
    return elements.get(id);
  };
  const context = vm.createContext({
    $, document: { createElement: element }, fmt: (n) => String(n),
    setStatus: (id, message, kind) => { $(id).textContent = message; $(id).kind = kind; },
  });
  const source = fs.readFileSync("gui/src/main.js", "utf8");
  vm.runInContext([
    "sproutSourceWarningMayClear",
    "sproutLifecycleAmount",
    "sproutLifecycleRow",
    "renderSproutSweepReport",
  ].map((name) => functionSource(source, name)).join("\n"), context);
  return { $, context };
}

const report = (transactions) => ({
  transactions, mined_zatoshis: 0, pending_zatoshis: 7, unknown_zatoshis: 0,
  skipped: [], rejected: [], warnings: [], error: null, fresh_all_mined: false,
});

test("an expired transaction replaced by a new one stays listed as superseded", () => {
  const h = harness();
  const list = element();
  h.context.list = list;
  h.context.report = report([
    { txid: "old-tx", value_zatoshis: 7, state: "expired", mined_height: null, superseded: true },
    { txid: "new-tx", value_zatoshis: 7, state: "pending", mined_height: null, superseded: false },
  ]);
  vm.runInContext("renderSproutSweepReport(report, { list, statusId: 'status' })", h.context);
  const rows = list.children.map((child) => child.textContent);
  assert.equal(rows.length, 2);
  assert.match(rows[0], /old-tx/);
  assert.match(rows[0], /superseded/i);
  assert.doesNotMatch(rows[0], /before creating a replacement/i);
  // The superseded row does not ask for recovery; the live pending one decides the status.
  assert.match(h.$("status").textContent, /1 transaction\(s\) broadcast pending/);
});

test("a superseded expiry alone is not counted as needing recovery", () => {
  const h = harness();
  const list = element();
  h.context.list = list;
  h.context.report = report([
    { txid: "old-tx", value_zatoshis: 7, state: "expired", mined_height: null, superseded: true },
    { txid: "new-tx", value_zatoshis: 7, state: "rejected", mined_height: null, superseded: false },
  ]);
  vm.runInContext("renderSproutSweepReport(report, { list, statusId: 'status' })", h.context);
  assert.match(h.$("status").textContent, /^1 transaction\(s\) need recovery/);
});
