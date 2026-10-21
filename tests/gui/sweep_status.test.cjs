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

test("auto-derived fee cap refreshes when a later proposal quote rises", async () => {
  const input = { value: "" };
  const state = { scanHandle: { id: "scan" }, proposalGeneration: 0,
    sweepExecutionPending: false, sweepReview: null, proposalPending: false };
  const calls = [];
  const totals = [12345, 23456];
  const context = { state, $: (id) => id === "max-fee-zec" ? input :
      { checked: false, disabled: false },
    invalidateSweepReview() { state.proposalGeneration += 1; },
    setSweepProposalPending() {}, sweepRequestFromForm: () => ({ maxFeeZec: input.value || null }),
    invoke: async (_command, request) => {
      calls.push(request.maxFeeZec);
      return { proposal_id: `review-${calls.length}`, proposal: { total_fee_zatoshis: totals.shift() } };
    }, renderSweepProposal() {}, setStatus() {} };
  const { refreshSweepProposal } = loadFunctions(["refreshSweepProposal"], context);
  await refreshSweepProposal();
  await refreshSweepProposal();
  assert.deepEqual(calls, [null, null]);
  assert.equal(input.value, "0.00023456");
  assert.equal(state.maxFeeZec, "0.00023456");
});

test("user override remains an authoritative ceiling on later proposal", async () => {
  const input = { value: "" };
  const state = { scanHandle: { id: "scan" }, proposalGeneration: 0,
    sweepExecutionPending: false, sweepReview: null, proposalPending: false };
  const calls = [];
  const context = { state, $: (id) => id === "max-fee-zec" ? input :
      { checked: false, disabled: false },
    invalidateSweepReview() { state.proposalGeneration += 1; },
    setSweepProposalPending() {}, sweepRequestFromForm: () => ({ maxFeeZec: input.value || null }),
    invoke: async (_command, request) => {
      calls.push(request.maxFeeZec);
      return { proposal_id: "reviewed", proposal: { total_fee_zatoshis: 12345 } };
    }, renderSweepProposal() {}, setStatus() {} };
  const { refreshSweepProposal } = loadFunctions(["refreshSweepProposal"], context);
  await refreshSweepProposal();
  input.value = "0.009";
  await refreshSweepProposal();
  assert.deepEqual(calls, [null, "0.009"]);
  assert.equal(input.value, "0.009");
});

test("failed refresh clears an obsolete auto-derived fee cap", async () => {
  const input = { value: "" };
  const state = { scanHandle: { id: "scan" }, proposalGeneration: 0,
    sweepExecutionPending: false, sweepReview: null, proposalPending: false };
  let calls = 0;
  const context = { state, $: (id) => id === "max-fee-zec" ? input :
      { checked: false, disabled: false },
    invalidateSweepReview() { state.proposalGeneration += 1; },
    setSweepProposalPending() {}, sweepRequestFromForm: () => ({ maxFeeZec: input.value || null }),
    invoke: async () => {
      if (++calls === 2) throw new Error("fresh quote unavailable");
      return { proposal_id: "reviewed", proposal: { total_fee_zatoshis: 12345 } };
    }, renderSweepProposal() {}, setStatus() {} };
  const { refreshSweepProposal } = loadFunctions(["refreshSweepProposal"], context);
  await refreshSweepProposal();
  await assert.rejects(refreshSweepProposal(), /fresh quote unavailable/);
  assert.equal(input.value, "");
  assert.equal(state.maxFeeZec, null);
});

test("partial abort report includes error, skipped balances, and incomplete status", () => {
  const h = screen();
  const outcome = { transactions: [result("pending", "one node accepted")],
    skipped_accounts: [{ account_index: 4, gross_zatoshis: 500000, reason: "dust" }],
    total_donation_zatoshis: 0, error: "later account failed", follow_up_review_required: false };
  h.renderCompleteScreen(outcome.transactions, outcome.skipped_accounts, 0, null,
    outcome.error, null, { outcome });
  const report = h.$("save-report").dataset.report;
  assert.match(report, /Status: Incomplete/i);
  assert.match(report, /later account failed/);
  assert.match(report, /Account 4: dust \(0\.00500000 ZEC\)/);
  assert.doesNotMatch(report, /Status: Recovery complete/i);
});

test("shield-only report identifies required fresh review", () => {
  const h = screen();
  const outcome = { transactions: [result("mined")], skipped_accounts: [],
    total_donation_zatoshis: 0, error: null, follow_up_review_required: true };
  h.renderCompleteScreen(outcome.transactions, [], 0, null, null, null, { outcome });
  const report = h.$("save-report").dataset.report;
  assert.match(report, /Status: Shielding stage/i);
  assert.match(report, /Follow-up review required: yes/i);
  assert.match(report, /rescan and review/i);
  assert.doesNotMatch(report, /Status: Recovery complete/i);
});

test("unknown submission keeps donation amount uncertain even when recorded total is zero", () => {
  const h = screen();
  h.renderCompleteScreen([result("submission_unknown")], [], 0, 0.1, null, null);
  assert.match(h.$("complete-donation").textContent, /donation.*uncertain/i);
  assert.doesNotMatch(h.$("complete-donation").textContent, /No donation was sent|Donated 0/);
});

test("all mined with skipped balance is incomplete and cannot delete workspace", () => {
  const h = screen();
  const skipped = [{ account_index: 2, gross_zatoshis: 100000, reason: "dust" }];
  h.renderCompleteScreen([result("mined")], skipped, 0, null, null, null);
  assert.equal(h.$("delete-workspace").disabled, true);
  assert.doesNotMatch(h.$("complete-summary").textContent, /Recovery complete/);
  assert.match(h.$("complete-summary").textContent, /skipped|not swept/i);
});

test("expired rejected and not-submitted messages do not imply future mining", () => {
  for (const status of ["expired", "rejected", "not_submitted"]) {
    const h = screen();
    h.renderCompleteScreen([result(status)], [], 0, null, null, null);
    const copy = `${h.$("complete-summary").textContent} ${h.$("complete-confirmation-note").textContent}`;
    assert.doesNotMatch(copy, /until.*mined|may still mine|pending or uncertain/i, status);
    assert.equal(h.$("delete-workspace").disabled, true);
  }
});

test("legacy failed does not become definite rejection", () => {
  const h = screen();
  h.renderCompleteScreen([result("failed")], [], 0, null, null, null);
  assert.equal(h.txStatusKind("failed"), "submission_unknown");
  assert.match(h.$("complete-summary").textContent, /may already have moved/i);
  assert.doesNotMatch(h.$("complete-txids").children[0].children[0].textContent, /Rejected/);
});

test("donation receipt waits for canonical mining", () => {
  for (const [status, expected] of [
    ["pending", /awaiting independent confirmation/i],
    ["expired", /not confirmed.*rescan/i],
  ]) {
    const h = screen();
    h.renderCompleteScreen([result(status)], [], 100000, 0.1, null, null);
    const copy = h.$("complete-donation").textContent;
    assert.match(copy, expected, status);
    assert.doesNotMatch(copy, /Donated /, status);
  }
  const zeroPending = screen();
  zeroPending.renderCompleteScreen([result("pending")], [], 0, 0.1, null, null);
  assert.doesNotMatch(zeroPending.$("complete-donation").textContent, /No donation was sent|Donated /);
  for (const status of ["rejected", "not_submitted"]) {
    const h = screen();
    h.renderCompleteScreen([result(status)], [], 100000, 0.1, null, null);
    assert.match(h.$("complete-donation").textContent, /No donation was sent or confirmed/i, status);
  }
  const mined = screen();
  mined.renderCompleteScreen([result("mined")], [], 100000, 0.1, null, null);
  assert.match(mined.$("complete-donation").textContent, /^Donated 0\.00100000 ZEC/);
});

test("mixed pending or unknown and expired results give both recovery actions", () => {
  for (const first of ["pending", "submission_unknown"]) {
    for (const followUpReviewRequired of [false, true]) {
      const h = screen();
      h.renderCompleteScreen([result(first), result("expired")], [], 0, null, null, null,
        { followUpReviewRequired });
      const copy = `${h.$("complete-summary").textContent} ${h.$("complete-confirmation-note").textContent}`;
      assert.match(copy, /reconcile/i, `${first} follow-up=${followUpReviewRequired}`);
      assert.match(copy, /rescan/i, `${first} follow-up=${followUpReviewRequired}`);
      assert.doesNotMatch(copy, /every submitted transaction.*mine/i, first);
    }
  }
});
