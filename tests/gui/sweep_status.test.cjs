const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("gui/src/main.js", "utf8");

function loadFunctions(names, context = {}) {
  const declarations = names.map((name) => {
    const asyncStart = source.indexOf(`async function ${name}(`);
    const start = asyncStart >= 0 ? asyncStart : source.indexOf(`function ${name}(`);
    assert.notEqual(start, -1, `${name} must remain testable`);
    const end = source.indexOf("\n}\n", start);
    assert.notEqual(end, -1, `${name} must have a closing brace`);
    return source.slice(start, end + 3);
  });
  return vm.runInNewContext(`${declarations.join("\n")}; ({ ${names.join(", ")} })`, context);
}

function result(status, detail = "") {
  return { source_account: 0, txid: "abc123", status, fee_zatoshis: 12345,
    detail, confirmed_height: 2222222 };
}

function screen() {
  const elements = new Map();
  function element() {
    return { textContent: "", innerHTML: "", hidden: false, disabled: false,
      className: "", style: {}, dataset: {}, children: [],
      appendChild(child) { this.children.push(child); },
      replaceChildren(...children) { this.children = children; },
      addEventListener() {},
    };
  }
  const $ = (id) => {
    if (!elements.has(id)) elements.set(id, element());
    return elements.get(id);
  };
  const context = { $, state: { retainedAddressSearchId: null, scanConfig: null,
      lastProgress: null }, fmt: (n) => `${(n / 1e8).toFixed(8)} ZEC`,
    document: { createElement: element }, Date };
  const names = ["txStatusKind", "txStatusLabel", "sweepStatusCounts",
    "sweepCompleteSummary", "renderCompleteScreen", "buildReport", "buildDefaultReportPath"];
  return { $, ...loadFunctions(names, context) };
}

test("submission_unknown is not rendered as failed or zero broadcasts", () => {
  const h = screen();
  const unknown = result("submission_unknown", "transport reply was lost");
  h.renderCompleteScreen([unknown], [], 0, null, null, null);
  assert.match(h.$("complete-summary").textContent, /may already have moved/i);
  assert.doesNotMatch(h.$("complete-summary").textContent, /no funds were moved|failed to broadcast/i);
  assert.equal(h.$("complete-txids").children[0].className.includes("failed"), false);
  assert.match(h.$("complete-txids").children[0].children[0].textContent,
    /Submission uncertain — may already be on the network\. Do not retry\./);
  assert.equal(h.sweepStatusCounts([unknown]).unknown, 1);
});

test("secondary disagreement never renders confirmed or mined", () => {
  const h = screen();
  h.renderCompleteScreen([result("pending", "Independent servers disagree on block inclusion")],
    [], 0, null, null, null);
  const card = h.$("complete-txids").children[0];
  assert.match(card.children[0].textContent, /Broadcast — awaiting independent confirmation/);
  assert.doesNotMatch(card.children.map((x) => x.textContent).join(" "), /Mined at block|independently confirmed/i);
  assert.match(card.children.map((x) => x.textContent).join(" "), /Independent servers disagree/);
});

test("pending and unknown keep the original wallet warning", () => {
  for (const status of ["pending", "submission_unknown"]) {
    const h = screen();
    h.renderCompleteScreen([result(status)], [], 0, null, null, null);
    assert.match(h.$("complete-summary").textContent, /keep the source wallet/i);
    assert.equal(h.$("delete-workspace").disabled, true);
  }
});

test("only all-mined results enable final cleanup", () => {
  const h = screen();
  h.renderCompleteScreen([result("mined"), result("pending")], [], 0, null, null, null);
  assert.equal(h.$("delete-workspace").disabled, true);
  h.renderCompleteScreen([result("mined"), result("mined")], [], 0, null, null, null);
  assert.equal(h.$("delete-workspace").disabled, false);
  assert.match(h.$("complete-summary").textContent, /2 transactions mined/i);
});

test("proposal fee populates a blank execution cap", async () => {
  const input = { value: "" };
  const state = { scanHandle: { id: "scan" }, proposalGeneration: 0,
    sweepExecutionPending: false, sweepReview: null, proposalPending: false };
  const context = { state, $: (id) => id === "max-fee-zec" ? input :
      { checked: false, disabled: false },
    invalidateSweepReview() { state.proposalGeneration += 1; },
    setSweepProposalPending() {}, sweepRequestFromForm: () => ({ maxFeeZec: null }),
    invoke: async () => ({ proposal_id: "reviewed", proposal: { total_fee_zatoshis: 12345 } }),
    renderSweepProposal() {}, setStatus() {} };
  const { refreshSweepProposal } = loadFunctions(["refreshSweepProposal"], context);
  await refreshSweepProposal();
  assert.equal(input.value, "0.00012345");
  assert.equal(state.maxFeeZec, "0.00012345");
  assert.equal(state.sweepReview.proposal_id, "reviewed");
});

test("follow-up review does not say sweep complete", () => {
  const h = screen();
  h.renderCompleteScreen([result("mined")], [], 0, null, null, null,
    { followUpReviewRequired: true });
  assert.doesNotMatch(h.$("complete-summary").textContent, /sweep complete|recovery complete/i);
  assert.match(h.$("complete-summary").textContent, /rescan.*review/i);
  assert.equal(h.$("delete-workspace").disabled, true);
});

test("saved report includes exact fee and evidence but no unmined height", () => {
  const h = screen();
  const report = h.buildReport([result("pending", "servers disagree"), result("mined", "two matching blocks")]);
  assert.match(report, /pending[\s\S]*fee: 0\.00012345 ZEC[\s\S]*servers disagree/);
  assert.match(report, /mined[\s\S]*mined at block 2222222/);
  assert.equal((report.match(/mined at block/g) || []).length, 1);
});

test("legacy broadcast from merged seedless routes remains pending", () => {
  const h = screen();
  assert.equal(h.txStatusKind("broadcast"), "pending");
  assert.equal(h.sweepStatusCounts([result("broadcast")]).pending, 1);
});

test("legacy confirmed does not qualify for independent-mining cleanup", () => {
  const h = screen();
  h.renderCompleteScreen([result("confirmed")], [], 0, null, null, null);
  assert.equal(h.$("delete-workspace").disabled, true);
  assert.doesNotMatch(h.$("complete-summary").textContent, /Recovery complete/);
});

test("an explicit user fee cap remains unchanged after review", async () => {
  const input = { value: "0.002" };
  const state = { scanHandle: { id: "scan" }, proposalGeneration: 0,
    sweepExecutionPending: false, sweepReview: null, proposalPending: false };
  const context = { state, $: (id) => id === "max-fee-zec" ? input :
      { checked: false, disabled: false },
    invalidateSweepReview() { state.proposalGeneration += 1; },
    setSweepProposalPending() {}, sweepRequestFromForm: () => ({ maxFeeZec: input.value }),
    invoke: async () => ({ proposal_id: "reviewed", proposal: { total_fee_zatoshis: 12345 } }),
    renderSweepProposal() {}, setStatus() {} };
  const { refreshSweepProposal } = loadFunctions(["refreshSweepProposal"], context);
  await refreshSweepProposal();
  assert.equal(input.value, "0.002");
});

test("uncertain shielding follow-up retains no-retry guidance", () => {
  const h = screen();
  h.renderCompleteScreen([result("submission_unknown")], [], 0, null, null, null,
    { followUpReviewRequired: true });
  assert.match(h.$("complete-summary").textContent, /may already have moved/i);
  assert.match(h.$("complete-summary").textContent, /do not retry/i);
  assert.match(h.$("complete-summary").textContent, /rescan.*review/i);
});

test("partially mined outcome does not claim nothing was submitted", () => {
  const h = screen();
  h.renderCompleteScreen([result("mined"), result("not_submitted")], [], 0, null, null, null);
  assert.doesNotMatch(h.$("complete-summary").textContent, /No transaction was submitted/);
  assert.match(h.$("complete-summary").textContent, /1 transaction mined/i);
  assert.equal(h.$("delete-workspace").disabled, true);
});
