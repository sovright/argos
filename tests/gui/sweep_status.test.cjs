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

// The completion text is the backend's (argos_core::sweep_guidance, whose
// Rust tests pin the wording and precedence). This stub echoes its input so
// the tests can check what the screen sent and where it put the answer.
function stubGuidance(input) {
  const statuses = input.transactions.map((tx) => tx.status);
  return {
    recovery_complete: false,
    summary: `summary:${statuses.join(",")}`,
    next_steps: `next:${statuses.join(",")}`,
    donation: input.donation_requested || input.donated_zatoshis ? `donation:${input.donated_zatoshis}` : null,
    status_labels: statuses.map((status) => `label:${status}`),
  };
}

function screen(override = () => ({})) {
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
  const inputs = [];
  const invoke = async (command, args) => {
    assert.equal(command, "sweep_completion_guidance");
    inputs.push(JSON.parse(JSON.stringify(args.input)));
    return { ...stubGuidance(args.input), ...override(args.input) };
  };
  const context = { $, invoke, state: { retainedAddressSearchId: null, scanConfig: null,
      lastProgress: null }, fmt: (n) => `${(n / 1e8).toFixed(8)} ZEC`,
    document: { createElement: element }, Date };
  const names = ["txStatusKind", "sweepStatusCounts", "completionGuidanceInput",
    "loadCompletionGuidance", "renderCompleteScreen", "buildReport", "buildDefaultReportPath"];
  return { $, inputs, ...loadFunctions(names, context) };
}

function label(h, index = 0) {
  return h.$("complete-txids").children[index].children[0].textContent;
}

test("backend guidance fills the summary, next steps, labels, and report", async () => {
  const h = screen();
  await h.renderCompleteScreen([result("submission_unknown", "transport reply was lost")],
    [], 0, null, null, null);
  assert.equal(h.$("complete-summary").textContent, "summary:submission_unknown");
  assert.equal(h.$("complete-confirmation-note").textContent, "next:submission_unknown");
  assert.equal(label(h), "Account 0 · label:submission_unknown");
  assert.match(h.$("save-report").dataset.report, /Guidance: summary:submission_unknown/);
  assert.equal(h.$("complete-txids").children[0].className.includes("failed"), false);
  assert.equal(h.sweepStatusCounts([result("submission_unknown")]).unknown, 1);
});

test("the screen sends normalized statuses and every flag the text depends on", async () => {
  const h = screen();
  const outcome = { transactions: [{ ...result("mined"), safe_to_discard: true }, result("broadcast"),
      result("confirmed"), result("failed")],
    skipped_accounts: [{ account_index: 4, gross_zatoshis: 1, reason: "dust" }],
    error: "later account failed", follow_up_review_required: true };
  await h.renderCompleteScreen(outcome.transactions, outcome.skipped_accounts, 100000, 0.1,
    outcome.error, "route note", { outcome });
  assert.deepEqual(h.inputs, [{
    transactions: [
      { status: "mined", safe_to_discard: true },
      { status: "pending", safe_to_discard: false },
      { status: "pending", safe_to_discard: false },
      { status: "submission_unknown", safe_to_discard: false },
    ],
    skipped_accounts: 1,
    follow_up_review_required: true,
    error: "later account failed",
    status_only: false,
    donation_requested: true,
    donated_zatoshis: 100000,
    donation_note: "route note",
  }]);
});

test("a zero donation rate is not a donation request", async () => {
  const h = screen();
  await h.renderCompleteScreen([result("mined")], [], 0, 0, null, null);
  assert.equal(h.inputs[0].donation_requested, false);
  assert.equal(h.$("complete-donation").hidden, true);
  assert.equal(h.$("complete-donation").textContent, "");
});

test("the donation line is the backend's and hidden when it has none", async () => {
  const h = screen();
  await h.renderCompleteScreen([result("pending")], [], 100000, 0.1, null, null);
  assert.equal(h.$("complete-donation").hidden, false);
  assert.equal(h.$("complete-donation").textContent, "donation:100000");
});

test("only the backend can say recovery is complete", async () => {
  const deep = { ...result("mined"), safe_to_discard: true };
  const incomplete = screen();
  await incomplete.renderCompleteScreen([deep], [], 0, null, null, null);
  assert.equal(incomplete.$("complete-heading").textContent, "Sweep status");
  const complete = screen(() => ({ recovery_complete: true }));
  await complete.renderCompleteScreen([deep], [], 0, null, null, null);
  assert.equal(complete.$("complete-heading").textContent, "Recovery complete");
  assert.match(complete.$("save-report").dataset.report, /Status: Recovery complete/);
});

test("a saved-journal view asks for status-only guidance and keeps its heading", async () => {
  const h = screen(() => ({ recovery_complete: true }));
  const outcome = { transactions: [result("mined")], skipped_accounts: [] };
  await h.renderCompleteScreen(outcome.transactions, [], 0, null, null, null,
    { outcome, statusOnly: true });
  assert.equal(h.inputs[0].status_only, true);
  assert.equal(h.$("complete-heading").textContent, "Saved transaction status");
  assert.equal(h.$("delete-workspace").disabled, true);
});

test("a failed guidance lookup keeps the transaction cards and a conservative instruction", async () => {
  const h = screen();
  const failing = loadFunctions(["txStatusKind", "sweepStatusCounts", "completionGuidanceInput",
    "loadCompletionGuidance", "renderCompleteScreen", "buildReport", "buildDefaultReportPath"], {
    $: h.$, invoke: async () => { throw new Error("ipc down"); },
    state: { retainedAddressSearchId: null }, fmt: (n) => `${n}`,
    document: { createElement: () => ({ children: [], style: {}, dataset: {},
      appendChild(child) { this.children.push(child); }, addEventListener() {} }) },
    Date,
  });
  await failing.renderCompleteScreen([result("submission_unknown")], [], 0, null, null, null);
  assert.equal(h.$("complete-txids").children.length, 1);
  const text = (node) => [node.textContent || "", ...(node.children || []).map(text)].join(" ");
  assert.match(text(h.$("complete-txids").children[0]), /abc123/);
  assert.match(h.$("complete-summary").textContent, /Keep the source wallet/);
  assert.match(h.$("complete-confirmation-note").textContent, /ipc down/);
  assert.notEqual(h.$("complete-heading").textContent, "Recovery complete");
});

test("an older render's late guidance cannot overwrite a newer screen", async () => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  let calls = 0;
  const h = screen();
  const shared = { retainedAddressSearchId: null };
  const slow = loadFunctions(["txStatusKind", "sweepStatusCounts", "completionGuidanceInput",
    "loadCompletionGuidance", "renderCompleteScreen", "buildReport", "buildDefaultReportPath"], {
    $: h.$, state: shared, fmt: (n) => `${n}`, Date,
    document: { createElement: () => ({ children: [], style: {}, dataset: {},
      appendChild(child) { this.children.push(child); }, addEventListener() {} }) },
    invoke: async (_command, args) => {
      calls += 1;
      if (calls === 1) await gate;
      return stubGuidance(args.input);
    },
  });
  const first = slow.renderCompleteScreen([result("pending")], [], 0, null, null, null);
  await slow.renderCompleteScreen([result("mined")], [], 0, null, null, null);
  release();
  await first;
  assert.equal(h.$("complete-summary").textContent, "summary:mined");
});

test("secondary disagreement never renders mined evidence for a pending row", async () => {
  const h = screen();
  await h.renderCompleteScreen([result("pending", "Independent servers disagree on block inclusion")],
    [], 0, null, null, null);
  const card = h.$("complete-txids").children[0];
  assert.doesNotMatch(card.children.map((x) => x.textContent).join(" "), /Mined at block/);
  assert.match(card.children.map((x) => x.textContent).join(" "), /Independent servers disagree/);
});

test("unresolved results disable workspace deletion; resolved ones allow it", async () => {
  const h = screen();
  for (const status of ["pending", "submission_unknown", "confirmed", "not_submitted"]) {
    await h.renderCompleteScreen([result("mined"), result(status)], [], 0, null, null, null);
    assert.equal(h.$("delete-workspace").disabled, true, status);
  }
  for (const status of ["mined", "mined_single_source", "expired", "rejected"]) {
    await h.renderCompleteScreen([result(status)], [], 0, null, null, null);
    assert.equal(h.$("delete-workspace").disabled, false, status);
  }
});

test("a staged sweep keeps its workspace for the follow-up review", async () => {
  const h = screen();
  await h.renderCompleteScreen([result("mined")], [], 0, null, null, null,
    { followUpReviewRequired: true });
  assert.equal(h.inputs[0].follow_up_review_required, true);
  assert.equal(h.$("delete-workspace").disabled, true);
  assert.equal(h.$("restart-flow").textContent, "Rescan and review");
});

test("partial abort report includes error, skipped balances, and incomplete status", async () => {
  const h = screen();
  const outcome = { transactions: [result("pending", "one node accepted")],
    skipped_accounts: [{ account_index: 4, gross_zatoshis: 500000, reason: "dust" }],
    total_donation_zatoshis: 0, error: "later account failed", follow_up_review_required: false };
  await h.renderCompleteScreen(outcome.transactions, outcome.skipped_accounts, 0, null,
    outcome.error, null, { outcome });
  const report = h.$("save-report").dataset.report;
  assert.match(report, /Status: Incomplete/i);
  assert.match(report, /later account failed/);
  assert.match(report, /Account 4: dust \(0\.00500000 ZEC\)/);
  assert.doesNotMatch(report, /Status: Recovery complete/i);
});

test("shield-only report identifies required fresh review", async () => {
  const h = screen();
  const outcome = { transactions: [result("mined")], skipped_accounts: [],
    total_donation_zatoshis: 0, error: null, follow_up_review_required: true };
  await h.renderCompleteScreen(outcome.transactions, [], 0, null, null, null, { outcome });
  const report = h.$("save-report").dataset.report;
  assert.match(report, /Status: Shielding stage/i);
  assert.match(report, /Follow-up review required: yes/i);
  assert.doesNotMatch(report, /Status: Recovery complete/i);
});

test("legacy failed is sent as an uncertain submission, never a rejection", async () => {
  const h = screen();
  await h.renderCompleteScreen([result("failed")], [], 0, null, null, null);
  assert.equal(h.txStatusKind("failed"), "submission_unknown");
  assert.equal(h.inputs[0].transactions[0].status, "submission_unknown");
  assert.doesNotMatch(label(h), /Rejected/);
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
