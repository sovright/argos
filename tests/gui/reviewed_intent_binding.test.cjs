const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("gui/src/main.js", "utf8");
const start = source.indexOf("function donationParamsFromForm()");
const end = source.indexOf("// ─── Step 6: Complete", start);
assert.ok(start >= 0 && end > start);

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function harness(propose = async () => review("proposal-current")) {
  const elements = new Map();
  const calls = [];
  const chips = ["10", "99", "custom"].map((pct) => element({ pct }));
  function element(dataset = {}) {
    const listeners = new Map();
    return {
      value: "", checked: false, disabled: false, hidden: false,
      textContent: "", title: "", dataset, children: [], style: {},
      classList: { add() {}, remove() {} },
      addEventListener(type, callback) { listeners.set(type, callback); },
      fire(type) { return listeners.get(type)?.({ target: this }); },
      setAttribute() {},
      querySelector() { return element(); },
      appendChild(child) { this.children.push(child); },
      replaceChildren(...children) { this.children = children; },
      closest() { return null; },
    };
  }
  const $ = (id) => {
    if (!elements.has(id)) elements.set(id, element());
    return elements.get(id);
  };
  $("destination-input").value = "zs-reviewed";
  $("sweep-memo").value = "reviewed memo";
  $("max-fee-zec").value = "0.01";
  $("donate-enabled").checked = true;
  $("donate-rate").value = "10";
  const state = {
    scanHandle: { id: "scan-current" }, destination: "zs-reviewed",
    memo: "reviewed memo", maxFeeZec: "0.01", donationEnabled: true,
    scanConfig: { network: "mainnet" }, lastProgress: { phase: "complete" },
    sweepReview: null, proposalGeneration: 0, proposalPending: false,
  };
  const context = vm.createContext({
    state, $, fmt: (value) => String(value),
    document: {
      querySelectorAll: () => chips,
      createElement: () => element(),
      createTextNode: (text) => ({ textContent: text }),
    },
    invoke: async (command, args) => {
      calls.push({ command, args });
      if (command === "propose_sweep") return propose(args);
      if (command === "execute_sweep") return {
        transactions: [], skipped_accounts: [], total_donation_zatoshis: 0,
      };
      throw new Error(`unexpected command ${command}`);
    },
    setStatus: (id, message) => { $(id).textContent = message; },
    goTo: () => {},
    renderCompleteScreen: () => {},
  });
  vm.runInContext(source.slice(start, end), context);
  return {
    $, state, chips, calls,
    refresh: () => vm.runInContext("refreshSweepProposal()", context),
    fire: (id, type) => $(id).fire(type),
    executeArgs: () => calls.filter((call) => call.command === "execute_sweep").map((call) => call.args),
  };
}

function review(id, overrides = {}) {
  const proposal = {
    transactions: [], skipped_accounts: [], net_received_zatoshis: 100000,
    total_fee_zatoshis: 1000, total_donation_zatoshis: 10000,
    ...overrides,
  };
  return { proposal_id: id, proposal };
}

async function accepted(h) {
  await h.refresh();
  h.$("irreversible-check").checked = true;
  h.fire("irreversible-check", "change");
  assert.equal(h.$("execute-sweep").disabled, false);
}

test("reviewed 10 percent donation executes only its proposal id", async () => {
  const h = harness();
  await accepted(h);
  await h.fire("execute-sweep", "click");
  assert.deepEqual(JSON.parse(JSON.stringify(h.executeArgs()[0])), {
    handle: { id: "scan-current" }, proposalId: "proposal-current",
  });
});

test("changing donation to 99 percent disables execution immediately", async () => {
  const pending = deferred();
  const h = harness(async (args) => args.donationRate === 0.99 ? pending.promise : review("proposal-current"));
  await accepted(h);
  h.$("donate-rate").value = "99";
  h.fire("donate-rate", "input");
  assert.equal(h.$("irreversible-check").checked, false);
  assert.equal(h.$("irreversible-check").disabled, true);
  assert.equal(h.$("execute-sweep").disabled, true);
  const next = h.fire("donate-rate", "change");
  assert.equal(h.$("execute-sweep").disabled, true);
  pending.resolve(review("proposal-new"));
  await next;
});

test("older proposal success cannot replace a newer review", async () => {
  const old = deferred();
  const h = harness(async (args) => args.donationRate === 0.1 ? old.promise : review("proposal-new"));
  const first = h.refresh();
  h.$("donate-rate").value = "99";
  await h.refresh();
  old.resolve(review("proposal-old", { net_received_zatoshis: 1 }));
  await first;
  assert.equal(h.state.sweepReview.proposal_id, "proposal-new");
  assert.match(h.$("sweep-summary").textContent, /100000/);
});

test("older proposal failure cannot disable a newer review", async () => {
  const old = deferred();
  const h = harness(async (args) => args.donationRate === 0.1 ? old.promise : review("proposal-new"));
  const first = h.refresh();
  h.$("donate-rate").value = "99";
  await h.refresh();
  old.reject(new Error("old proposal failed"));
  await Promise.allSettled([first]);
  h.$("irreversible-check").checked = true;
  h.fire("irreversible-check", "change");
  assert.equal(h.state.sweepReview.proposal_id, "proposal-new");
  assert.equal(h.$("execute-sweep").disabled, false);
  assert.doesNotMatch(h.$("sweep-execute-status").textContent, /old proposal failed/);
});

test("proposal failure leaves irreversible controls disabled", async () => {
  let fail = false;
  const h = harness(async () => {
    if (fail) throw new Error("proposal unavailable");
    return review("proposal-current");
  });
  await accepted(h);
  fail = true;
  await Promise.allSettled([h.refresh()]);
  assert.equal(h.$("irreversible-check").checked, false);
  assert.equal(h.$("irreversible-check").disabled, true);
  assert.equal(h.$("execute-sweep").disabled, true);
  h.$("irreversible-check").checked = true;
  h.fire("irreversible-check", "change");
  assert.equal(h.$("execute-sweep").disabled, true);
});

test("destination memo fee and donor email edits invalidate review", async () => {
  for (const id of ["destination-input", "sweep-memo", "max-fee-zec", "donate-email"]) {
    const h = harness();
    await accepted(h);
    h.$(id).value = "edited";
    h.fire(id, "input");
    assert.equal(h.state.sweepReview, null, `${id} retained old review`);
    assert.equal(h.$("irreversible-check").disabled, true, `${id} left checkbox enabled`);
    assert.equal(h.$("execute-sweep").disabled, true, `${id} left execution enabled`);
  }
});

test("execute_sweep sends no mutable request fields", async () => {
  const h = harness();
  await accepted(h);
  await h.fire("execute-sweep", "click");
  assert.deepEqual(JSON.parse(JSON.stringify(h.executeArgs())), [{
    handle: { id: "scan-current" }, proposalId: "proposal-current",
  }]);
});
