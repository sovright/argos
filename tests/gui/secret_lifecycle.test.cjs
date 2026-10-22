const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("gui/src/main.js", "utf8");

function functionSource(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must remain a named, testable lifecycle boundary`);
  const bodyStart = source.indexOf(") {", start) + 2;
  assert.ok(bodyStart > start, `${name} must have a function body`);
  let depth = 0;
  let opened = false;
  for (let index = bodyStart; index < source.length; index++) {
    if (source[index] === "{") { depth++; opened = true; }
    if (source[index] === "}" && opened && --depth === 0) return source.slice(start, index + 1);
  }
  throw new Error(`${name} has no closing brace`);
}

function element(value = "secret") {
  const classes = new Set(["revealed"]);
  return {
    value, checked: true, disabled: false,
    classList: {
      add(name) { classes.add(name); },
      remove(name) { classes.delete(name); },
      contains(name) { return classes.has(name); },
    },
  };
}

function lifecycleHarness() {
  const ids = [
    "seed-input", "seed-visibility", "wallet-passphrase", "sapling-scan-keys",
    "sprout-scan-keys", "resume-seed-input", "resume-seed-visibility",
    "resume-bip39-passphrase",
  ];
  const elements = new Map(ids.map((id) => [id, element()]));
  const events = [];
  const calls = [];
  const state = { scanHandle: { id: "scan-secret" }, sweepExecutionPending: false };
  const context = vm.createContext({
    $: (id) => elements.get(id) ?? null,
    document: { dispatchEvent(event) { events.push(event.type); } },
    CustomEvent: class { constructor(type) { this.type = type; } },
    walletFile: { path: "/wallet.dat", review_id: "review-secret", passphrase: "wallet-secret" },
    walletOpenGeneration: 7,
    sproutPreviewWallet: { path: "/wallet.dat" },
    sproutSweepSource: { path: "/wallet.dat" },
    pendingResumeRow: { workspace_path: "/secret" },
    resumeGeneration: 4,
    state,
    cancelWalletReviewExpiry() { calls.push("wallet-expiry"); },
    invalidateWalletSproutReview() { calls.push("wallet-review"); },
    invalidateSproutScanSource() { calls.push("sprout-source"); },
    invalidateSweepReview() { calls.push("sweep-review"); },
    invalidateScanAuthority() { calls.push("scan-authority"); state.scanHandle = null; },
    invoke(command, args) { calls.push([command, args]); return Promise.resolve(); },
  });
  vm.runInContext(`${functionSource("clearTransientSecrets")}; ${functionSource("abandonRecoveryFlow")}`, context);
  return { context, elements, events, calls };
}

for (const exit of [
  "successful handoff", "completion", "cancellation", "terminal backend error",
  "navigation away", "Start over", "beforeunload",
]) {
  test(`${exit} clears every transient recovery secret and restores hidden inputs`, () => {
    const h = lifecycleHarness();
    vm.runInContext("clearTransientSecrets()", h.context);
    for (const id of [
      "seed-input", "wallet-passphrase", "sapling-scan-keys", "sprout-scan-keys",
      "resume-seed-input", "resume-bip39-passphrase",
    ]) assert.equal(h.elements.get(id).value, "", `${exit}: ${id}`);
    assert.equal(h.context.walletFile.passphrase, null);
    assert.equal(h.elements.get("seed-visibility").checked, false);
    assert.equal(h.elements.get("resume-seed-visibility").checked, false);
    assert.equal(h.elements.get("seed-input").classList.contains("masked"), true);
    assert.equal(h.elements.get("resume-seed-input").classList.contains("masked"), true);
    assert.ok(h.calls.includes("wallet-expiry"), `${exit}: wallet expiry timer`);
  });
}

test("abandoning a flow revokes every reviewed source and clears address-search candidates", () => {
  const h = lifecycleHarness();
  vm.runInContext("abandonRecoveryFlow()", h.context);
  assert.equal(h.context.walletFile, null);
  assert.equal(h.context.sproutPreviewWallet, null);
  assert.equal(h.context.sproutSweepSource, null);
  assert.equal(h.context.pendingResumeRow, null);
  assert.equal(h.context.walletOpenGeneration, 8);
  assert.equal(h.context.resumeGeneration, 5);
  assert.deepEqual(h.events, ["argos:clear-transient-secrets"]);
  assert.ok(h.calls.includes("wallet-review"));
  assert.ok(h.calls.includes("sprout-source"));
  assert.ok(h.calls.includes("scan-authority"));
});

test("every scan-authority invalidation releases the backend secret owner", () => {
  assert.match(
    functionSource("invalidateScanAuthority"),
    /invoke\("release_scan", \{ handle \}\)/,
  );
});

test("orphaned start and resume replies release their backend sessions", () => {
  const staleStartAt = source.indexOf("The backend may have started scan A");
  const staleStart = source.slice(
    staleStartAt,
    source.indexOf("return;", staleStartAt),
  );
  assert.match(staleStart, /invoke\("release_scan", \{ handle \}\)/);
  const staleResume = source.slice(
    source.indexOf("if (!isCurrent())", source.indexOf('await invoke("resume_session"')),
    source.indexOf("resetRecoveryFlowState", source.indexOf('await invoke("resume_session"')),
  );
  assert.match(staleResume, /invoke\("release_scan", \{ handle: resumed\.handle \}\)/);
});

for (const [edge, pattern] of [
  ["successful handoff", /state\.scanHandle = handle;[\s\S]*?clearTransientSecrets\(\)/],
  ["completion", /const terminal = \["complete", "cancelled", "error"\][\s\S]*?if \(terminal\) clearTransientSecrets\(\)/],
  ["cancellation", /\$\("cancel-scan"\).*?clearTransientSecrets\(\)/s],
  ["navigation away", /btn\.dataset\.prev === "welcome"\) abandonRecoveryFlow\(\)/],
  ["Start over", /\$\("restart-flow"\).*?abandonRecoveryFlow\(\)/s],
  ["beforeunload", /beforeunload[\s\S]*?abandonRecoveryFlow\(\)/],
]) {
  test(`${edge} is wired to the shared lifecycle boundary`, () => {
    assert.match(source, pattern);
  });
}

test("address search consumes the shared transient-secret event", () => {
  const addressSearch = fs.readFileSync("gui/src/address-search.js", "utf8");
  assert.match(addressSearch, /argos:clear-transient-secrets/);
  assert.match(addressSearch, /argos:clear-transient-secrets[\s\S]*?clearSecrets\(\)/);
});

function startScanHarness({ fail = true, wallet = true, keys = true } = {}) {
  const h = lifecycleHarness();
  const context = h.context;
  context.state.scanHandle = null;
  context.state.scanAuthorityGeneration = 1;
  context.state.matchedRecovery = null;
  context.seedInput = h.elements.get("seed-input");
  context.seedInput.value = !wallet && !keys ? "seed phrase for scan" : "";
  if (!wallet) context.walletFile = null;
  const values = {
    "destination-input": "fixture-destination", "network-select": "mainnet",
    "data-dir": "/unmarked-old-dir", "sweep-memo": "", "max-fee-zec": "",
    "birthday-height": "1528061", "lightwalletd-url": "http://127.0.0.1:1",
    "scan-label": "retry", "gap-limit": "20", "accounts-range": "1",
  };
  for (const [id, value] of Object.entries(values)) h.elements.set(id, element(value));
  for (const id of ["auto-gap-limit", "start-scan", "sapling-key-addresses"])
    h.elements.set(id, element(""));
  context.hasSaplingScanKeys = () => keys;
  context.scanKeySourceConflict = () => null;
  context.shouldShowTransparentRange = () => false;
  context.scanBirthdayFromForm = () => 1528061;
  context.confirmationSourcesFromForm = () => [];
  context.defaultScanLabel = () => "retry";
  context.saplingScanKeyLines = () => [h.elements.get("sapling-scan-keys").value];
  context.showScanWarning = () => {};
  context.scanWarningVariant = () => "shielded";
  context.goTo = () => {};
  context.startProgressListeners = async () => {};
  context.setStatus = (id, message) => { h.lastStatus = message; };
  context.scheduleWalletReviewExpiry = () => h.calls.push("scheduled-expiry");
  context.walletReviewExpiryTimer = wallet ? 123 : null;
  h.fail = fail;
  context.invoke = async (command, args) => {
    if (command === "validate_address") return { destination_ok: true };
    assert.equal(command, wallet || keys ? "start_scan_from_wallet_file" : "start_scan");
    h.submitted = args;
    if (h.fail) throw new Error("choose a new empty directory");
    return { id: "accepted" };
  };
  const start = source.indexOf('$(' + '"start-scan").addEventListener("click"');
  const body = source.indexOf("async () => {", start);
  const end = source.indexOf("\n});\n", body);
  h.run = vm.runInContext(`(${source.slice(body, end + 2)})`, context);
  return h;
}

test("failed wallet scan start preserves passphrase, pasted keys and original expiry for retry", async () => {
  const h = startScanHarness();
  await h.run();
  assert.match(h.lastStatus, /choose a new empty directory/);
  assert.equal(h.context.walletFile.passphrase, "wallet-secret");
  assert.equal(h.elements.get("wallet-passphrase").value, "secret");
  assert.equal(h.elements.get("sapling-scan-keys").value, "secret");
  assert.equal(h.elements.get("sprout-scan-keys").value, "secret");
  assert.equal(h.calls.includes("wallet-expiry"), false, "failed start must retain existing expiry");
  assert.equal(h.calls.includes("scheduled-expiry"), false, "retry must not extend wallet review");
  assert.equal(h.elements.get("seed-input").value, "");
  assert.equal(h.elements.get("seed-visibility").checked, false);
  assert.equal(h.elements.get("start-scan").disabled, false);
});

test("failed pasted-key-only scan retains keys with a bounded expiry", async () => {
  const h = startScanHarness({ wallet: false });
  await h.run();
  assert.equal(h.elements.get("sapling-scan-keys").value, "secret");
  assert.equal(h.calls.includes("scheduled-expiry"), true);
  assert.equal(h.calls.includes("wallet-expiry"), false);
});

test("accepted wallet scan start clears passphrase and pasted keys", async () => {
  const h = startScanHarness({ fail: false });
  await h.run();
  assert.equal(h.context.state.scanHandle.id, "accepted");
  assert.equal(h.context.walletFile.passphrase, null);
  for (const id of ["wallet-passphrase", "sapling-scan-keys", "sprout-scan-keys"])
    assert.equal(h.elements.get(id).value, "", id);
  assert.equal(h.calls.includes("wallet-expiry"), true);
});


test("correcting the directory after a rejected start retries with retained wallet credentials and keys", async () => {
  const h = startScanHarness();
  await h.run();
  h.elements.get("data-dir").value = "/new-empty-dir";
  h.fail = false;
  await h.run();
  assert.equal(h.context.state.scanHandle.id, "accepted");
  assert.equal(h.submitted.config.data_dir, "/new-empty-dir");
  assert.equal(h.submitted.config.passphrase, "wallet-secret");
  assert.equal(h.submitted.config.sapling_keys[0], "secret");
  assert.equal(h.context.walletFile.passphrase, null);
  assert.equal(h.elements.get("sapling-scan-keys").value, "");
});

test("failed seed-only start still clears the seed and restores masking", async () => {
  const h = startScanHarness({ wallet: false, keys: false });
  await h.run();
  assert.equal(h.submitted.config.seed, "seed phrase for scan");
  assert.equal(h.elements.get("seed-input").value, "");
  assert.equal(h.elements.get("seed-visibility").checked, false);
  assert.equal(h.elements.get("seed-input").classList.contains("masked"), true);
  assert.equal(h.calls.includes("scheduled-expiry"), false);
});
