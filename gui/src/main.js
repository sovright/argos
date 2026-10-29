function invoke(...args) {
  return window.__TAURI__.core.invoke(...args);
}
function listen(...args) {
  return window.__TAURI__.event.listen(...args);
}

// External links open in the OS default app. The Tauri webview has no in-app
// browser and a strict CSP, so a bare target="_blank" would die silently —
// route http(s)/mailto clicks through the `open_external_url` command. That
// command enforces a hard-coded allowlist in Rust (audit Issue D); the broad
// `opener:default` grant has been removed, so this is the only egress path and
// it only opens vetted URLs.
document.addEventListener("click", (event) => {
  const link = event.target.closest("a[href]");
  if (!link) return;
  const href = link.getAttribute("href");
  if (!href || !/^(https?|mailto):/i.test(href)) return;
  event.preventDefault();
  invoke("open_external_url", { url: href }).catch((err) => {
    console.error("Failed to open external link:", href, err);
  });
});

document.addEventListener("DOMContentLoaded", () => {

// ─── State ────────────────────────────────────────────────────────────────────

const state = {
  scanHandle: null,
  scanAuthorityGeneration: 0,
  completedScanHandle: null,
  lastProgress: null,
  sweepReview: null,
  proposalGeneration: 0,
  proposalPending: false,
  sweepExecutionPending: false,
  destination: null,
  memo: null,
  maxFeeZec: null,
  autoFeeCapZec: null,
  unlistenProgress: null,
  unlistenComplete: null,
  unlistenDiscovered: null,
  scanConfig: null,
  defaultDataDir: null,
  savedReportPath: null,
  donationEnabled: false,
  matchedRecovery: null,
  retainedAddressSearchId: null,
  addressMatchRecoveryLocked: false,
  addressMatchRecoveryStartGeneration: null,
  completionContext: null,
  reconciliationPending: false,
  completionRender: 0,
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

const $ = (id) => document.getElementById(id);
const fmt = (n) => (Number(n) / 1e8).toFixed(8) + " ZEC";

// ─── Terms of Service gate ──────────────────────────────────────────────────
// The #tos-overlay starts visible (display:flex in markup) so the wizard is
// never reachable before acceptance is resolved. If the current TOS version is
// already accepted, hide it; otherwise show the full terms with Accept/Reject.
// Reject exits the app; Accept records acceptance and reveals the wizard.
(async function initTosGate() {
  const overlay = $("tos-overlay");
  const accept = $("tos-accept");
  const reject = $("tos-reject");
  reject.addEventListener("click", () => {
    invoke("reject_tos").catch((err) => console.error("reject_tos failed:", err));
  });
  accept.addEventListener("click", async () => {
    accept.disabled = true;
    reject.disabled = true;
    try {
      await invoke("accept_tos");
      overlay.style.display = "none";
    } catch (err) {
      accept.disabled = false;
      reject.disabled = false;
      $("tos-text").textContent = `Could not record acceptance: ${err}\n\n` + $("tos-text").textContent;
    }
  });
  try {
    const status = await invoke("tos_status");
    if (status.accepted) {
      overlay.style.display = "none";
    } else {
      $("tos-text").textContent = status.text;
    }
  } catch (err) {
    // Fail closed: keep the gate up with an error rather than letting the
    // wizard through if the status check fails.
    $("tos-text").textContent = `Unable to load the Terms of Service: ${err}`;
    console.error("tos_status failed:", err);
  }
})();

function phaseLabel(phase) {
  const labels = {
    idle: "Idle",
    validating_seed: "Validating seed…",
    deriving_keys: "Deriving keys…",
    probing_lightwalletd: "Probing lightwalletd…",
    scanning_transparent: "Scanning transparent…",
    scanning_shielded: "Scanning shielded…",
    complete: "Complete ✓",
    cancelled: "Cancelled",
    error: "Error",
  };
  return labels[phase] ?? phase;
}

function setStatus(id, msg, kind) {
  const el = $(id);
  if (!el) return;
  el.textContent = msg;
  el.className = "status-line" + (kind ? ` ${kind}` : "");
}

function fmtSeconds(s) {
  if (s == null) return "—";
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const r = s % 60;
  return r > 0 ? `${m}m ${r}s` : `${m}m`;
}

function fmtDurationCoarse(secs) {
  // Like fmtSeconds but rounded for human-readable banner copy: "1h 33m"
  // rather than "1h 33m 04s". Anything under a minute reads as "<1m".
  if (secs == null || secs < 60) return "less than a minute";
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function formatSleepDetail(event) {
  const slept = new Date(event.slept_at_unix * 1000).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
  const resumed = new Date(event.resumed_at_unix * 1000).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
  const last = fmtDurationCoarse(event.last_sleep_seconds);
  if (event.event_count <= 1) {
    return ` Last paused at ${slept}, resumed at ${resumed} — ${last} not syncing.`;
  }
  const total = fmtDurationCoarse(event.total_lost_seconds);
  return ` Last paused at ${slept}, resumed at ${resumed} — ${last} not syncing. ` +
    `Total across ${event.event_count} sleeps: ${total}.`;
}

// Friendly, deliberately imprecise ETA banding. Mirrors `format_eta_range` in
// argos-cli; if you change one, change both.
function formatEtaRange(secs) {
  if (secs == null || !Number.isFinite(secs) || secs < 0) return null;
  if (secs < 60) return "less than a minute remaining";
  if (secs < 5 * 60) return "less than 5 minutes remaining";
  if (secs < 30 * 60) {
    const mins = Math.round(secs / 60 / 5) * 5;
    return `about ${mins} minutes remaining`;
  }
  if (secs < 60 * 60) return "less than an hour remaining";
  const hours = secs / 3600;
  if (hours < 2) return "about 1-2 hours remaining";
  const lo = Math.floor(hours);
  return `about ${lo}-${lo + 1} hours remaining`;
}

// Map a block height to its approximate calendar year on mainnet so users can
// feel the scan moving through time. Mirrors `era_hint` in argos-cli.
function eraHint(height) {
  if (!height) return null;
  const SAPLING_HEIGHT = 419_200;
  const SAPLING_YEAR = 2018;
  const SECONDS_PER_BLOCK = 82;
  if (height < SAPLING_HEIGHT) return "pre-Sapling era";
  const elapsedSecs = (height - SAPLING_HEIGHT) * SECONDS_PER_BLOCK;
  const elapsedYears = elapsedSecs / (365.25 * 86400);
  return String(SAPLING_YEAR + Math.floor(elapsedYears + 0.18));
}

// Sliding-window ETA tracker — see `EtaTracker` in argos-cli.
const eta = (() => {
  const WINDOW_MS = 45_000;
  let samples = [];
  let lastTotal = 0;
  let startedAt = null;
  let lastRate = null; // blocks/sec — reused mid-batch when scannedInWindow=0

  return {
    reset() {
      samples = [];
      lastTotal = 0;
      startedAt = performance.now();
      lastRate = null;
    },
    observe(scanned, total) {
      if (!total) return;
      lastTotal = total;
      const now = performance.now();
      samples.push([now, scanned]);
      const cutoff = now - WINDOW_MS;
      while (samples.length > 2 && samples[0][0] < cutoff) samples.shift();
    },
    estimate() {
      if (startedAt == null || samples.length < 2 || !lastTotal) return { kind: "warmup" };
      const [tLast, blocksLast] = samples[samples.length - 1];
      const remaining = lastTotal - blocksLast;
      if (remaining <= 0) return { kind: "done" };
      const [tFirst, blocksFirst] = samples[0];
      const windowMs = tLast - tFirst;
      const scannedInWindow = blocksLast - blocksFirst;
      // Only update the rate when blocks actually moved within the window.
      // zcash_client_sqlite commits in ~1000-block batches so scannedInWindow
      // is 0 between commits — reuse lastRate so the ETA stays visible mid-batch.
      // Never use startedAt as the origin: on a resume scan blocks_scanned
      // starts large, which would make the rate look astronomically high.
      if (windowMs >= 500 && scannedInWindow >= 1) {
        lastRate = scannedInWindow / (windowMs / 1000);
      }
      if (!lastRate) return { kind: "warmup" };
      const secs = Math.round(remaining / lastRate);
      return { kind: "range", text: formatEtaRange(secs) };
    },
  };
})();

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// ─── Navigation ───────────────────────────────────────────────────────────────

const steps = ["welcome", "seed", "config", "scan", "sweep", "complete"];
let furthestStep = 0; // tracks how far the user has reached

// `wallet-file` is an alternative to `seed`, not a step after it: a user
// arrives with either a seed phrase or a wallet file, never both. It shares
// the seed step's position so the sidebar indicator still tracks progress.
const STEP_ALIASES = { "wallet-file": "seed" };

function goTo(step) {
  if (step !== "wallet-file") {
    // Leaving the wallet screen drops reviewed proposals, so a sweep is
    // re-reviewed on return. A running Sprout scan is not stopped: it can
    // run for hours, and moving between steps does not change its keys or
    // settings. Changing those does release it (see the input listeners).
    invalidateWalletSproutReview();
    invalidateSproutScanReview();
  }
  const leavingMatchedConfig = state.matchedRecovery &&
    document.querySelector('.screen[data-step="config"]')?.classList.contains("active") &&
    step !== "config" && step !== "scan";
  if (leavingMatchedConfig) abandonMatchedRecovery();
  const stepIdx = steps.indexOf(STEP_ALIASES[step] ?? step);
  if (stepIdx > furthestStep) furthestStep = stepIdx;

  document.querySelectorAll(".screen").forEach((s) => s.classList.remove("active"));
  document.querySelectorAll(".step-list li").forEach((li) => {
    const s = li.dataset.stepIndicator;
    const liIdx = steps.indexOf(s);
    li.classList.remove("active", "complete", "reachable");
    if (liIdx < stepIdx) li.classList.add("complete");
    if (liIdx === stepIdx) li.classList.add("active");
    if (liIdx <= furthestStep) li.classList.add("reachable");
  });
  const screen = document.querySelector(`.screen[data-step="${step}"]`);
  if (screen) screen.classList.add("active");
  if (step === "config") updateTransparentScanSettingsVisibility();
}

// Make sidebar steps clickable — only allow jumping to already-reached steps
document.querySelectorAll(".step-list li").forEach((li) => {
  li.style.cursor = "pointer";
  li.addEventListener("click", () => {
    const target = li.dataset.stepIndicator;
    const targetIdx = steps.indexOf(target);
    if (targetIdx <= furthestStep) {
      if (target === "welcome") abandonRecoveryFlow();
      if (target === "config") {
        $("start-scan").disabled = false;
        setStatus("config-status", "", "");
      }
      goTo(target);
    } else {
      // Show a brief tooltip on the step that can't be reached yet
      const prev = steps[targetIdx - 1];
      const prevLabel = li.parentElement.querySelector(`[data-step-indicator="${prev}"]`);
      const originalText = li.textContent;
      li.textContent = "Complete previous steps first";
      setTimeout(() => { li.textContent = originalText; }, 1800);
    }
  });
});

document.querySelectorAll("[data-next]").forEach((btn) => {
  btn.addEventListener("click", () => goTo(btn.dataset.next));
});

document.querySelectorAll("[data-prev]").forEach((btn) => {
  btn.addEventListener("click", () => {
    if (btn.dataset.prev === "welcome") abandonRecoveryFlow();
    if (btn.dataset.prev === "seed" && state.matchedRecovery) {
      returnToAddressMatches();
      return;
    }
    if (btn.dataset.prev === "config") {
      $("start-scan").disabled = false;
      setStatus("config-status", "", "");
    }
    goTo(btn.dataset.prev);
  });
});

// ─── Step 2: Seed Entry ───────────────────────────────────────────────────────

const seedInput = $("seed-input");
const seedVisibility = $("seed-visibility");
const seedNextBtn = $("seed-next");

seedVisibility.addEventListener("change", () => {
  seedInput.classList.toggle("masked", !seedVisibility.checked);
});

// ZecWallet Lite only generated 24-word phrases, so a shorter one came from
// another wallet. Argos derives the standard paths (ZIP 32 shielded accounts,
// BIP-44 account 0 transparent receive addresses), so a wallet that used
// other paths scans to zero.
function seedValidMessage(wordCount) {
  const valid = "✓ Seed phrase is valid.";
  if (wordCount === 24) return valid;
  return `${valid} ZecWallet Lite only made 24-word phrases, so this ${wordCount}-word ` +
    "phrase is from another wallet. Argos checks the standard paths: ZIP 32 shielded " +
    "accounts and BIP-44 transparent addresses m/44'/133'/0'/0/0–999. If that wallet " +
    "used a different derivation path, the scan will find no funds.";
}

// Which scan-screen banner applies. Only a wallet file whose keys are all
// transparent skips the block sync: pasted Sapling keys move the scan onto
// the imported-account route, and matched-address recovery ignores the file.
function scanWarningVariant(walletFile, typedSaplingKeyCount, matchedRecovery) {
  if (matchedRecovery || typedSaplingKeyCount > 0) return "shielded";
  return walletFile?.summary?.transparent_only === true ? "transparent-only" : "shielded";
}

function showScanWarning(variant) {
  $("scan-warning-shielded").hidden = variant !== "shielded";
  $("scan-warning-transparent-only").hidden = variant !== "transparent-only";
}

async function validateSeed() {
  const words = seedInput.value.trim().toLowerCase().split(/\s+/);
  setStatus("seed-status", "Validating…", "");
  seedNextBtn.disabled = true;
  try {
    await invoke("validate_seed", { words });
    setStatus("seed-status", seedValidMessage(words.length), "success");
    seedNextBtn.disabled = false;
  } catch (err) {
    setStatus("seed-status", `✗ ${err}`, "error");
  }
}

$("seed-validate").addEventListener("click", validateSeed);
seedInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); validateSeed(); }
});

// Clear-clipboard affordance. Overwrites the OS clipboard with empty text so
// the user's pasted seed phrase isn't sitting in the bare OS buffer after
// they've moved past the seed step. This does NOT defeat clipboard-history
// managers (Maccy, ClipboardFusion, the iOS handoff clipboard), which may
// have snapshotted the seed at paste time — the inline guidance below the
// button says so. We deliberately do not block paste itself: pasting from a
// password manager is safer than retyping under a keylogger, and
// `oncopy="return false"` on a textarea is bypassable theatre. See
// THREAT_MODEL.md §6.1 T-S4.
async function clearOsClipboard(statusEl) {
  // navigator.clipboard requires a secure context. Tauri serves the UI from
  // tauri://localhost which qualifies. If the Clipboard API is unavailable
  // (very old WebKitGTK), fall back gracefully — overwriting via a hidden
  // textarea + execCommand is also blocked in modern WebKit, so we just
  // surface the limitation rather than fake it.
  if (!navigator.clipboard || !navigator.clipboard.writeText) {
    setStatus(statusEl, "Clipboard API not available in this WebView; clear your clipboard manually.", "error");
    return;
  }
  try {
    await navigator.clipboard.writeText("");
    setStatus(statusEl, "OS clipboard cleared. Clipboard-history apps may still have a copy.", "success");
  } catch (err) {
    setStatus(statusEl, `Could not clear clipboard: ${err}`, "error");
  }
}

$("seed-clear-clipboard")?.addEventListener("click", () => clearOsClipboard("seed-status"));

// ─── Step 2 (alternative): Wallet file ────────────────────────────────────────

// Set once a wallet file has been opened successfully. Its presence is what
// routes the scan down the imported-key path instead of the seed path.
//
// The passphrase is held here for the same reason the seed is passed to
// `start_scan`: the backend needs it again to re-read the file when the scan
// actually starts. It is cleared as soon as the scan is under way.
let walletFile = null;
let sproutNu7Status = { state: "unknown", tip_height: null };
let sproutNu7StatusSource = null;
let sproutNu7StatusBinding = null;
let sproutNu7StatusGeneration = 0;
let sproutNu7StatusTimer = null;
// This timer expires evidence; only backend-validated height decides activation.
const SPROUT_NU7_STATUS_MAX_AGE_MS = 60_000;
const SPROUT_NU7_UNKNOWN = "NU7 status is unknown: a fresh, independently corroborated network height is unavailable. " +
  "New Sprout recovery and rebroadcast are disabled. Historical inspection and saved mined-status checks remain available. " +
  "Keep your wallet, keys, checkpoint, and backups.";

// Only the newest import may publish state; previews are bound to that exact
// wallet object, including when the same path is reopened with a new password.
let walletOpenGeneration = 0;
let sproutPreviewWallet = null;
// Independent of the selected wallet: reopening must not permit a second sweep.
let sproutSweepSource = null;
let walletSproutReview = null;
let walletSproutReviewDestination = null;
let walletSproutReviewConfig = null;
let walletSproutProposalGeneration = 0;
let walletSproutExecutionPending = false;
// The backend drops an unclaimed wallet review after 30 minutes. Expire the
// webview's plaintext and opaque review source first, with enough margin that
// IPC response time cannot make the frontend outlive that backend authority.
const WALLET_REVIEW_EXPIRY_MS = 29 * 60 * 1000;
let walletReviewExpiryTimer = null;
let walletReviewExpiryGeneration = 0;

function cancelWalletReviewExpiry() {
  ++walletReviewExpiryGeneration;
  if (walletReviewExpiryTimer !== null) {
    clearTimeout(walletReviewExpiryTimer);
    walletReviewExpiryTimer = null;
  }
}

function scheduleWalletReviewExpiry() {
  cancelWalletReviewExpiry();
  const generation = walletReviewExpiryGeneration;
  walletReviewExpiryTimer = setTimeout(() => {
    // clearTimeout cannot retract a callback already queued by the webview.
    // The generation guard prevents an old callback from revoking newer state.
    if (generation !== walletReviewExpiryGeneration) return;
    walletReviewExpiryTimer = null;
    for (const id of ["sapling-scan-keys", "sprout-scan-keys"]) {
      const input = $(id);
      if (input) input.value = "";
    }
    forgetLoadedWalletFile();
    setStatus("wallet-status", "Wallet review expired. Open the wallet file again.", "error");
  }, WALLET_REVIEW_EXPIRY_MS);
}

// Clear plaintext authority as soon as the backend has accepted it, and from
// every exit that abandons the current recovery attempt. The browser event
// gives the separate address-search module the same lifecycle boundary.
function clearTransientSecrets({ abandonWallet = false } = {}) {
  cancelWalletReviewExpiry();
  for (const id of [
    "seed-input", "wallet-passphrase", "sapling-scan-keys", "sprout-scan-keys",
    "resume-seed-input", "resume-bip39-passphrase", "resume-wallet-passphrase", "resume-sapling-keys",
  ]) {
    const input = $(id);
    if (input) input.value = "";
  }
  for (const [toggleId, inputId] of [
    ["seed-visibility", "seed-input"],
    ["resume-seed-visibility", "resume-seed-input"],
  ]) {
    const toggle = $(toggleId);
    const input = $(inputId);
    if (toggle) toggle.checked = false;
    input?.classList?.add("masked");
  }
  if (walletFile?.passphrase != null) walletFile.passphraseCleared = true;
  if (walletFile) walletFile.passphrase = null;

  if (!abandonWallet) return;
  ++walletOpenGeneration;
  walletFile = null;
  sproutPreviewWallet = null;
  sproutSweepSource = null;
  invalidateWalletSproutReview();
  invalidateSproutScanSource();
  document.dispatchEvent(new CustomEvent("argos:clear-transient-secrets"));
}

function abandonRecoveryFlow() {
  // `invalidateScanAuthority` releases every backend session after first
  // invalidating late replies locally. Release waits for an active worker to
  // stop before the backend drops its final key owner.
  invalidateScanAuthority();
  ++resumeGeneration;
  pendingResumeRow = null;
  clearTransientSecrets({ abandonWallet: true });
}

function walletSproutExecutionConfig() {
  return {
    network: $("network-select").value,
    lightwalletdUrl: $("lightwalletd-url").value.trim(),
    confirmationSources: confirmationSourcesFromForm(),
    dataDir: $("data-dir").value.trim() || null,
    peers: sproutScanPeerEntries(),
  };
}

function sproutNu7StatusConfig() {
  return JSON.stringify({
    network: $("network-select").value,
    lightwalletdUrl: $("lightwalletd-url").value.trim(),
    confirmationSources: confirmationSourcesFromForm(),
  });
}

function sproutNu7StatusCurrent() {
  return sproutNu7StatusSource === walletFile &&
    sproutNu7StatusBinding === sproutNu7StatusConfig()
    ? sproutNu7Status : { state: "unknown", tip_height: null };
}

function invalidateSproutNu7Status() {
  ++sproutNu7StatusGeneration;
  if (sproutNu7StatusTimer !== null) clearTimeout(sproutNu7StatusTimer);
  sproutNu7StatusTimer = null;
  sproutNu7Status = { state: "unknown", tip_height: null };
  sproutNu7StatusBinding = null;
  sproutNu7StatusSource = null;
  renderSproutNu7Availability();
}

function renderSproutNu7Availability() {
  const status = sproutNu7StatusCurrent();
  const allowed = status.state === "before_activation" && status.allow_new_spends === true;
  const warning = status.warning || SPROUT_NU7_UNKNOWN;
  const broadcastWarning = `${$("network-select").value} NU7: your Sprout recovery transaction was broadcast, ` +
    "but it must be mined before NU7 activation; confirm it is mined. " + warning;
  if ((walletFile?.summary?.sprout_keys ?? 0) > 0) {
    sproutNu7Warning = allowed && sproutNu7Broadcast ? broadcastWarning : warning;
    showSproutNu7Warning(sproutNu7Warning);
    if (allowed) {
      const summary = walletFile.summary;
      $("wallet-sprout-headline").textContent = summary.sprout_spendable_notes > 0
        ? "Sprout note data is available for recovery before NU7."
        : summary.sprout_has_lifecycle_status
          ? "Sprout transaction status is available for this file."
          : summary.sprout_nothing_left ? "No Sprout funds are left in this file."
          : summary.sprout_history_read ? "No spendable Sprout notes were recovered from this file."
          : "Sprout funds need a full-block scan before NU7.";
    } else {
      $("wallet-sprout-headline").textContent = status.state === "activated"
        ? "Sprout history is available. New recovery is disabled after NU7."
        : status.state === "before_activation"
          ? "The Sprout mining deadline has passed. Historical status remains available."
          : "Sprout history is available. Recovery eligibility is unknown.";
    }
    renderSproutUncoveredBanners();
  }
  sproutScanNu7Warning = allowed && sproutScanNu7Broadcast ? broadcastWarning : warning;
  $("sprout-scan-run").textContent = allowed ? "Start scan" : "Scan Sprout history";
  $("sprout-sweep-heading").textContent = allowed ? "Move these funds before NU7" : "Saved Sprout transaction status";
  renderSproutScanPanel();
  updateWalletSproutSweepButton();
  if (typeof updateSproutScanSweepButton === "function") updateSproutScanSweepButton();
}

async function refreshSproutNu7Status() {
  const source = walletFile;
  const binding = sproutNu7StatusConfig();
  const generation = ++sproutNu7StatusGeneration;
  if (sproutNu7StatusTimer !== null) clearTimeout(sproutNu7StatusTimer);
  sproutNu7StatusTimer = null;
  sproutNu7Status = { state: "unknown", tip_height: null };
  sproutNu7StatusSource = source;
  sproutNu7StatusBinding = binding;
  renderSproutNu7Availability();
  let result;
  try {
    result = await invoke("sprout_nu7_status", JSON.parse(binding));
  } catch {
    result = { state: "unknown", warning: SPROUT_NU7_UNKNOWN };
  }
  if (generation !== sproutNu7StatusGeneration || source !== walletFile ||
      binding !== sproutNu7StatusConfig()) return null;
  const activation = { mainnet: 3_543_405, testnet: 4_465_026 }[$("network-select").value];
  const validHeight = Number.isInteger(result?.tip_height) && result.tip_height >= 0 &&
    result.activation_height === activation;
  const coherent = validHeight && (
    (result.state === "before_activation" && result.tip_height < activation) ||
    (result.state === "activated" && result.tip_height >= activation));
  sproutNu7Status = coherent
    ? { ...result, allow_new_spends: result.allow_new_spends === true && result.tip_height + 1 < activation }
    : { state: "unknown", tip_height: null, allow_new_spends: false, warning: SPROUT_NU7_UNKNOWN };
  renderSproutNu7Availability();
  sproutNu7StatusTimer = setTimeout(() => {
    if (generation !== sproutNu7StatusGeneration || source !== walletFile ||
        binding !== sproutNu7StatusConfig()) return;
    invalidateSproutNu7Status();
    if ((walletFile?.summary?.sprout_keys ?? 0) > 0 || $("sprout-scan-entry").open) {
      void refreshSproutNu7Status();
    }
  }, SPROUT_NU7_STATUS_MAX_AGE_MS);
  return sproutNu7Status;
}

function walletSproutConfigMatches(left, right = walletSproutExecutionConfig()) {
  return left !== null && JSON.stringify(left) === JSON.stringify(right);
}

function invalidateWalletSproutReview() {
  ++walletSproutProposalGeneration;
  if (walletSproutReview) {
    invoke("release_sprout_proposal", { proposalId: walletSproutReview.proposal_id }).catch(() => {});
  }
  walletSproutReview = null;
  walletSproutReviewDestination = null;
  walletSproutReviewConfig = null;
  $("sprout-sweep-confirm").checked = false;
  $("sprout-sweep-confirm").disabled = true;
  $("sprout-sweep-run").disabled = true;
  $("sprout-sweep-run").textContent = "Sweep Sprout funds";
}

function sproutReviewHasLifecycleStatus(review) {
  return (review?.active ?? []).length > 0 || (review?.mined ?? []).length > 0;
}

function sproutReviewMayRun(review) {
  return !!review && (sproutReviewHasLifecycleStatus(review) ||
    (review.allow_new_spends === true && review.params_present === true));
}

function updateWalletSproutSweepButton() {
  const allowed = sproutNu7StatusCurrent().state === "before_activation" &&
    sproutNu7StatusCurrent().allow_new_spends === true && walletSproutReview?.allow_new_spends === true;
  const confirmationLabel = allowed
    ? "I understand this may rebroadcast a saved transaction or move funds and cannot be undone."
    : "Check saved transaction status only. No new proof or rebroadcast is allowed.";
  // Consent belongs to the displayed mode, so a status-only acknowledgement
  // cannot become spending authority when a pending height refresh succeeds.
  if ($("sprout-sweep-confirm-label").textContent !== confirmationLabel) {
    $("sprout-sweep-confirm").checked = false;
  }
  $("sprout-sweep-confirm-label").textContent = confirmationLabel;
  $("sprout-sweep-run").textContent = sproutReviewHasLifecycleStatus(walletSproutReview)
    ? (allowed ? "Check status and continue" : "Check saved status only") : "Sweep Sprout funds";
  $("sprout-sweep-run").disabled = !sproutReviewMayRun(walletSproutReview) ||
    (!allowed && !sproutReviewHasLifecycleStatus(walletSproutReview)) ||
    walletSproutReviewDestination !== $("sprout-destination").value.trim() ||
    !walletSproutConfigMatches(walletSproutReviewConfig) ||
    sproutPreviewWallet !== walletFile || !$("sprout-sweep-confirm").checked ||
    walletSproutExecutionPending;
}

function renderWalletSummary(summary) {
  const list = $("wallet-summary-list");
  list.innerHTML = "";
  const rows = [
    ["Transparent keys", summary.transparent_keys],
    ["Sapling keys", summary.sapling_keys],
    ["Sprout keys", summary.sprout_keys],
    [
      "Seed phrase",
      summary.has_mnemonic
        ? "recovered — this wallet scans like a typed seed phrase"
        : summary.seed_note || "not recovered from this file",
    ],
  ];
  // Graded in argos-core, which the CLI prints verbatim: a lost seed and a
  // skipped record of unknown type must not read as the same warning.
  if (summary.coverage_notice) {
    rows.push(["Recovery coverage", summary.coverage_notice]);
  }
  for (const [label, value] of rows) {
    const li = document.createElement("li");
    li.textContent = `${label}: ${value}`;
    list.appendChild(li);
  }

  // Sprout splits into two very different situations, and conflating them
  // is what misleads people. If the wallet file yielded spendable notes,
  // the funds are already in hand and no scan is needed. If it did not, the
  // only route is a full-block scan that costs hours and tens of gigabytes
  // -- which the user must be told before starting, not during.
  const sproutWarning = $("wallet-sprout-warning");
  const sproutHeadline = $("wallet-sprout-headline");
  const sproutDetail = $("wallet-sprout-detail");
  const sproutScanCost = $("wallet-sprout-scan-cost");
  sproutWarning.hidden = summary.sprout_keys === 0;
  showSproutNu7Warning(summary.sprout_keys > 0 ? summary.sprout_nu7_warning : "");
  sproutScanCost.hidden = true;
  sproutScanCost.innerHTML = "";
  sproutDetail.innerHTML = "";
  // Why the total is what it is: notes the wallet spent, dust, unconfirmed
  // spends, unreadable transactions. The same argos-core sentences the CLI
  // prints, shown in every branch below.
  const sproutAccounting = $("wallet-sprout-accounting");
  sproutAccounting.innerHTML = "";
  for (const line of summary.sprout_accounting ?? []) {
    const p = document.createElement("p");
    p.className = "muted";
    p.textContent = line;
    sproutAccounting.appendChild(p);
  }
  sproutAccounting.hidden = sproutAccounting.childElementCount === 0;
  $("sprout-sweep-spent-status").textContent = summary.sprout_spent_status ?? "";
  // Reset every time: reopening a different wallet file must never leave the
  // previous one's sweep panel, plan or results on screen.
  $("wallet-sprout-sweep").hidden = true;
  // The scan panel lives outside this summary so raw keys can reach it with
  // no file. A previous file's offer goes; a panel the user opened for a
  // typed key stays.
  sproutScanOfferedForFile = false;
  if (!hasTypedSproutScanText()) $("sprout-scan-entry").open = false;
  $("sprout-scan-sweep").hidden = true;
  $("sprout-scan-sweep-results").innerHTML = "";
  $("sprout-scan-addresses").innerHTML = "";
  setStatus("sprout-scan-status", "", "");
  $("sprout-sweep-results").innerHTML = "";
  setStatus("sprout-sweep-status", "", "");

  if (summary.sprout_keys > 0) {
    const recoverable = summary.sprout_spendable_notes > 0;
    const hasLifecycleStatus = summary.sprout_has_lifecycle_status === true;
    if (recoverable) {
      sproutHeadline.textContent = "Sprout funds were recovered from this file.";
      sproutDetail.textContent =
        ` ${summary.sprout_spendable_notes} note(s), ` +
        `${fmt(summary.sprout_spendable_zatoshis)}. No scan is needed — the ` +
        `note data was in the wallet file itself.`;
      showSproutSweep();
    } else if (hasLifecycleStatus) {
      sproutHeadline.textContent = "Sprout transaction status is available for this file.";
      sproutDetail.textContent =
        " Check the saved transaction before creating another. Keep the original" +
        " wallet file and private scan checkpoint until fresh canonical evidence" +
        " shows every transaction mined.";
      showSproutSweep();
    } else if (summary.sprout_nothing_left) {
      // Not a case for the scan: the file holds the note data, and every
      // note was spent by the wallet itself or is not worth moving.
      sproutHeadline.textContent = "No Sprout funds are left in this file.";
      sproutDetail.textContent =
        " Every Sprout note it records was spent by the wallet itself, or is" +
        " worth less than the fee to move it. That is the file's record; the" +
        " full-block scan below checks it against the chain.";
      // Still offered: a spend recorded against a block later reorged out
      // reads exactly like this, and only the scan can tell — with its cost,
      // as everywhere the scan is offered.
      for (const line of summary.sprout_scan_warning || []) {
        const p = document.createElement("p");
        p.textContent = line === "" ? "\u00a0" : line;
        sproutScanCost.appendChild(p);
      }
      sproutScanCost.hidden = sproutScanCost.childElementCount === 0;
      offerSproutScanForFile(summary);
    } else {
      if (summary.sprout_history_read) {
        // Some note data was read — spent notes, dust — so saying the file
        // holds none would contradict the accounting lines beside it.
        sproutHeadline.textContent = "No spendable Sprout notes were recovered from this file.";
        sproutDetail.textContent =
          " Some of its note data could not be used (reasons below). The" +
          " full-block scan reads from the chain what the file could not." +
          " Keep the original file: these keys exist only there.";
      } else {
        sproutHeadline.textContent = "Sprout funds need a full-block scan.";
        sproutDetail.textContent =
          " This file holds Sprout keys, but not the note data needed to spend" +
          " them. Keep the original file: these keys exist only there.";
      }

      for (const issue of (summary.sprout_issues || []).slice(0, 5)) {
        const p = document.createElement("p");
        p.className = "muted";
        p.textContent = issue;
        sproutScanCost.appendChild(p);
      }
      // Rendered from the same argos-core text the CLI prints, so the two
      // cannot tell the user different things.
      for (const line of summary.sprout_scan_warning || []) {
        const p = document.createElement("p");
        if (line === "") {
          p.innerHTML = "&nbsp;";
        } else {
          p.textContent = line;
        }
        sproutScanCost.appendChild(p);
      }
      sproutScanCost.hidden = sproutScanCost.childElementCount === 0;
      offerSproutScanForFile(summary);
    }

    // Rebuilt each time rather than appended to: reopening a wallet file
    // used to stack a fresh copy of the address list under the old one.
    if (summary.sprout_addresses.length > 0) {
      const addrs = document.createElement("ul");
      for (const addr of summary.sprout_addresses) {
        const li = document.createElement("li");
        li.textContent = addr;
        addrs.appendChild(li);
      }
      sproutDetail.appendChild(addrs);
    }
  }

  // Two blocks, as the CLI prints them: findings about the seed (unified
  // accounts, keys its chain says are missing) were read fine and are not
  // "records that could not be read".
  const renderList = (blockId, listId, entries) => {
    const list = $(listId);
    list.innerHTML = "";
    $(blockId).hidden = entries.length === 0;
    for (const entry of entries) {
      const li = document.createElement("li");
      li.textContent = entry;
      list.appendChild(li);
    }
  };
  renderList("wallet-seed-diagnostics", "wallet-seed-diagnostics-list", summary.seed_diagnostics || []);
  renderList("wallet-diagnostics", "wallet-diagnostics-list", summary.diagnostics);

  $("wallet-summary").hidden = false;
  renderSproutScanPanel();
  if (summary.sprout_keys > 0 && !summary.sprout_spendable_notes && !summary.sprout_has_lifecycle_status) {
    void refreshSproutNu7Status();
  }
}

// ─── Sprout sweep ───────────────────────────────────────────────────────────

function showSproutNu7Warning(warning) {
  const el = $("wallet-sprout-nu7-warning");
  el.textContent = warning ?? "";
  el.hidden = !warning;
}

// ─── Sprout scan panel: reachable with or without a wallet file ─────────────
// The panel sits in its own disclosure on the wallet screen, outside
// #wallet-summary, so a user with only a raw SK…/ST… key backup can reach it.
// It carries its own NU7 alert, and is never shown until that alert has text:
// panel usable ⇒ deadline on screen.

// Set while the open wallet file holds Sprout keys but no spendable note
// data, the one case where the file itself sends the user to the scan.
let sproutScanOfferedForFile = false;
// The panel's own NU7 text, separate from `sproutNu7Warning`: that one is a
// wallet file's caveat and is carried onto the totals screens, which a raw
// key with no file never reaches.
let sproutScanNu7Warning = "";
// Set once a scan sweep has broadcast. Survives opening another wallet file:
// the transaction it describes still has to be mined. Start over resets it.
let sproutScanNu7Broadcast = false;
// Shown only if the core's text cannot be fetched at all, so the panel never
// opens with no deadline in view.
const SPROUT_NU7_FALLBACK =
  "NU7: Sprout funds become unspendable once NU7 activates. A Sprout recovery " +
  "transaction must be mined before activation; broadcasting alone is not enough.";

// Any text in the raw key box, comments included: a box the user has
// written in is theirs, and is not closed under them.
function hasTypedSproutScanText() {
  return ($("sprout-scan-keys").value ?? "").trim() !== "";
}

function offerSproutScanForFile(summary) {
  sproutScanOfferedForFile = true;
  $("sprout-scan-entry").open = true;
  // Immediately, from the same core text as the wallet's own alert; the
  // broadcast wording of an earlier scan sweep is not overwritten.
  if (!sproutScanNu7Broadcast && summary.sprout_nu7_warning) {
    sproutScanNu7Warning = summary.sprout_nu7_warning;
  }
}

function renderSproutScanPanel() {
  const open = !!$("sprout-scan-entry").open;
  const alert = $("sprout-scan-nu7-warning");
  alert.textContent = sproutScanNu7Warning;
  alert.hidden = !sproutScanNu7Warning;
  $("sprout-scan-panel").hidden = !(open && sproutScanNu7Warning);
  const fileKeys = (walletFile?.summary?.sprout_keys ?? 0) > 0;
  $("sprout-scan-entry-label").textContent = sproutScanOfferedForFile
    ? "Scan the chain for this wallet's Sprout notes"
    : "I only have a Sprout spending key (SK… or ST…)";
  $("sprout-scan-keys").placeholder = fileKeys
    ? "Leave blank to use the Sprout keys already in your wallet file"
    : "SK… (mainnet) or ST… (testnet), one key per line";
  // The one network picker lives on the settings step, which a user with no
  // wallet file cannot reach; this select mirrors it.
  const network = $("network-select");
  const mirror = $("sprout-scan-network");
  mirror.value = network.value;
  mirror.disabled = !!network.disabled;
}

// The disclosure was opened or closed by the user (or by a wallet file).
async function onSproutScanEntryToggle() {
  renderSproutScanPanel();
  if ($("sprout-scan-entry").open) await refreshSproutNu7Warning();
}

// Start over, and a matched address-search recovery: no raw Sprout key, no
// destination and no result may carry into the next run. Accepted scans
// clear plaintext inputs and retain only backend-owned key authority.
function forgetSproutScanInputs() {
  $("sprout-scan-keys").value = "";
  $("sprout-scan-addresses").innerHTML = "";
  $("sprout-scan-destination").value = "";
  $("sprout-scan-confirm").checked = false;
  // The decrypt-bound overrides belong to the run they were set for.
  $("sprout-scan-birthday").value = "";
  $("sprout-scan-every-block").checked = false;
  $("sprout-scan-plan").textContent = "";
  $("sprout-scan-sweep").hidden = true;
  $("sprout-scan-sweep-results").innerHTML = "";
  setStatus("sprout-scan-status", "", "");
  $("sprout-scan-entry").open = false;
  sproutScanOfferedForFile = false;
  sproutScanNu7Warning = "";
  sproutScanNu7Broadcast = false;
  renderSproutScanPanel();
}

// Distinct from the ordinary sweep in every respect: the notes come from the
// wallet file rather than a scan, the destination must be Sapling-capable,
// and proving takes minutes per note against a 725 MB parameter file.

async function showSproutSweep() {
  const source = walletFile;
  invalidateWalletSproutReview();
  sproutPreviewWallet = null;
  $("sprout-sweep-run").disabled = true;
  $("sprout-sweep-plan").textContent = "";
  $("sprout-sweep-pool").textContent = "";
  $("sprout-sweep-params").textContent = "";
  $("sprout-sweep-run").textContent = "Sweep Sprout funds";
  if (!source) return;
  const panel = $("wallet-sprout-sweep");
  panel.hidden = false;

  const destination = $("sprout-destination").value.trim();
  if (!destination) {
    $("sprout-sweep-plan").textContent = "Enter the saved or intended destination to review recovery or transaction status.";
    void refreshSproutNu7Status();
    return;
  }
  const generation = walletSproutProposalGeneration;
  const previewConfig = walletSproutExecutionConfig();

  try {
    const availability = await refreshSproutNu7Status();
    if (!availability || walletFile !== source || generation !== walletSproutProposalGeneration ||
        !walletSproutConfigMatches(previewConfig)) return;
    const previewNetwork = previewConfig.network;
    // A malformed entry in the scan panel's peer field must not cost the
    // preview: the raw entries go to the backend, which skips live
    // verification, keeps the wallet file's own spent record and says why
    // in the scan warning. The sweep itself still refuses the field, and the
    // backend refuses to execute a proposal reviewed with it.
    let previewPeers;
    try {
      previewPeers = sproutScanPeers();
    } catch {
      previewPeers = previewConfig.peers;
    }
    const preview = await invoke("propose_wallet_sprout_sweep", {
      reviewId: source.reviewId,
      passphrase: source.passphrase,
      destination,
      lightwalletdUrl: previewConfig.lightwalletdUrl,
      confirmationSources: previewConfig.confirmationSources,
      network: previewNetwork,
      // Where the scan panel keeps its checkpoint: a scan of these keys
      // settles spends the wallet file cannot see.
      dataDir: previewConfig.dataDir,
      // The scan panel's peers, dialled first when that checkpoint is
      // verified against live headers. Opening the wallet never dials.
      peers: previewPeers,
    });

    if (walletFile !== source || generation !== walletSproutProposalGeneration ||
        destination !== $("sprout-destination").value.trim() ||
        !walletSproutConfigMatches(previewConfig)) {
      invoke("release_sprout_proposal", { proposalId: preview.proposal_id }).catch(() => {});
      return;
    }

    // Verification runs again for this preview. Show its current verdict
    // beside the plan, even if inspection used an earlier checkpoint view.
    setStatus("sprout-sweep-status", preview.scan_warning || "", "");
    // A preview for a network the user has since moved off, or one that
    // lands after a broadcast, would put back the wrong warning.
    if (preview.nu7_warning && availability.allow_new_spends === true &&
        sproutNu7StatusCurrent().allow_new_spends === true &&
        previewNetwork === $("network-select").value && !sproutNu7Broadcast) {
      showSproutNu7Warning(preview.nu7_warning);
    }

    preview.allow_new_spends = preview.allow_new_spends === true && availability.state === "before_activation" && availability.allow_new_spends === true;
    const lifecycleCount = (preview.active ?? []).length + (preview.mined ?? []).length;
    const readyPlan = !preview.allow_new_spends
      ? "Historical Sprout notes cannot be spent while NU7 recovery is disabled. Keep all recovery material."
      : preview.notes > 0
      ? `${preview.notes} note(s): ${fmt(preview.gross_zatoshis)} gross, ` +
        `${fmt(preview.fee_zatoshis)} fee, ${fmt(preview.net_zatoshis)} to your address.`
      : "No note is ready for a new transaction.";
    const lifecyclePlan = lifecycleCount > 0
      ? ` ${lifecycleCount} saved transaction(s) will be checked first.`
      : "";
    $("sprout-sweep-plan").textContent = readyPlan + lifecyclePlan +
      // Keys dropped as forged, in inspect's words: the quote is for the
      // genuine keys' notes only, and says why the rest are not in it.
      (preview.warnings ?? []).map((warning) => ` ${warning}`).join("");

    // Stated before the user commits. Pasting a unified address reasonably
    // creates the expectation that funds land in its best pool, and for
    // Sprout that can never be Orchard.
    $("sprout-sweep-pool").textContent = preview.lands_in_sapling;

    // Said before the user commits, not discovered halfway through: without
    // the parameters the sweep cannot start at all.
    const canCheckLifecycle = sproutReviewHasLifecycleStatus(preview);
    $("sprout-sweep-run").textContent = canCheckLifecycle
      ? "Check status and continue"
      : "Sweep Sprout funds";
    if (sproutReviewMayRun(preview)) {
      $("sprout-sweep-params").textContent = "";
      if (!preview.allow_new_spends) {
        $("sprout-sweep-params").textContent = "Saved status checks are observation-only: no new proof or rebroadcast.";
      } else if (!preview.params_present) {
        $("sprout-sweep-params").textContent =
          "Sprout proving parameters are missing. Saved transaction status and exact-byte " +
          "retries can still be checked; a new transaction cannot be proved.";
      }
      sproutPreviewWallet = source;
      walletSproutReview = preview;
      walletSproutReviewDestination = destination;
      walletSproutReviewConfig = previewConfig;
      $("sprout-sweep-confirm").disabled = false;
      updateWalletSproutSweepButton();
    } else {
      $("sprout-sweep-params").textContent = !preview.allow_new_spends
        ? "New Sprout recovery is disabled. Historical records and backups are retained."
        : `Sprout proving parameters are missing. Download the 725 MB file to ` +
        `${preview.params_path} before sweeping:  ` +
        `curl -o ${preview.params_path} https://download.z.cash/downloads/sprout-groth16.params`;
      $("sprout-sweep-run").disabled = true;
      invoke("release_sprout_proposal", { proposalId: preview.proposal_id }).catch(() => {});
    }
  } catch (err) {
    if (walletFile !== source || generation !== walletSproutProposalGeneration ||
        !walletSproutConfigMatches(previewConfig)) return;
    $("sprout-sweep-plan").textContent = "";
    setStatus("sprout-sweep-status", `✗ ${err}`, "error");
    $("sprout-sweep-run").disabled = true;
  }
}

async function runSproutSweep() {
  if (walletSproutExecutionPending) return;
  const source = walletFile;
  const destination = $("sprout-destination").value.trim();
  if (!destination) {
    setStatus("sprout-sweep-status", "Enter a destination address first.", "error");
    return;
  }
  if (!walletFile) {
    setStatus("sprout-sweep-status", "Open a wallet file first.", "error");
    return;
  }

  if (sproutPreviewWallet !== walletFile || !walletSproutReview ||
      walletSproutReviewDestination !== destination ||
      !walletSproutConfigMatches(walletSproutReviewConfig)) {
    setStatus("sprout-sweep-status", "Wait for this wallet’s Sprout preview before sweeping.", "error");
    return;
  }
  if (!sproutReviewMayRun(walletSproutReview) ||
      (!sproutReviewHasLifecycleStatus(walletSproutReview) &&
       sproutNu7StatusCurrent().allow_new_spends !== true)) {
    setStatus("sprout-sweep-status", "New Sprout recovery is unavailable. Saved status checks remain available; keep all recovery material.", "error");
    return;
  }
  if (!$("sprout-sweep-confirm").checked) {
    setStatus("sprout-sweep-status", "Tick the box to confirm this moves funds irreversibly.", "error");
    return;
  }
  const proposalId = walletSproutReview.proposal_id;

  const button = $("sprout-sweep-run");
  try {
    walletSproutExecutionPending = true;
    sproutSweepSource = source;
    button.disabled = true;
    $("sprout-sweep-results").innerHTML = "";
    setStatus(
      "sprout-sweep-status",
      sproutReviewHasLifecycleStatus(walletSproutReview)
        ? "Checking saved transaction status before any new proof…"
        : "Proving… this takes a few minutes per note and cannot be interrupted safely.",
      "",
    );

    // Refuses a malformed scan peer field before anything is sent (#272).
    sproutScanPeers();
    const report = await invoke("execute_wallet_sprout_sweep", {
      proposalId,
      observationOnly: walletSproutReview.allow_new_spends !== true ||
        sproutNu7StatusCurrent().allow_new_spends !== true,
    });

    if (walletFile !== source) return;

    const list = $("sprout-sweep-results");
    const nu7Refresh = noteSproutBroadcast(report);
    renderSproutSweepReport(report, {
      list,
      statusId: "sprout-sweep-status",
      destination,
    });
    if (sproutSourceWarningMayClear(report)) {
      uncoveredSproutKeys = 0;
      renderSproutUncoveredBanners();
    }
    await nu7Refresh;
  } catch (err) {
    if (walletFile !== source) return;
    setStatus("sprout-sweep-status", `✗ ${err}`, "error");
    button.disabled = false;
  } finally {
    sproutSweepSource = null;
    walletSproutExecutionPending = false;
    if (walletFile === source && walletSproutReview?.proposal_id === proposalId) {
      invalidateWalletSproutReview();
    }
    clearTransientSecrets();
    updateWalletSproutSweepButton();
  }
}

$("sprout-destination").addEventListener("input", invalidateWalletSproutReview);
$("sprout-destination").addEventListener("change", showSproutSweep);
$("sprout-sweep-confirm").addEventListener("change", updateWalletSproutSweepButton);

/// Sprout keys a scan and sweep will not cover, remembered across screens.
///
/// The scan totals, the sweep review and the completion screen all report
/// only the pools the HD/imported pipeline reaches. A wallet file's Sprout
/// keys are not among them. The CLI prints a loud banner at exactly these
/// moments; the GUI said nothing, so a user could read a Sprout-excluding
/// total as their entire balance — and then use the Delete workspace button
/// sitting on that same screen, discarding the only copy of the keys.
let uncoveredSproutKeys = 0;
// A broadcast is not mined confirmation. This warning survives clearing the
// uncovered-key count and is reset only when the wallet source changes.
let sproutNu7Warning = "";
// Set once a Sprout sweep has broadcast: the warning then asks the user to
// confirm the transaction is mined instead of urging them to start.
let sproutNu7Broadcast = false;

/// Rebuild both NU7 warnings for the network now selected and the current
/// broadcast state: the open wallet file's, and the Sprout scan panel's,
/// which is there with or without a wallet file. The wallet screen comes
/// before the network picker, so text built at wallet open can name the
/// wrong network. Asks for nothing unless one of them is in use.
async function refreshSproutNu7Warning() {
  const availability = await refreshSproutNu7Status();
  if (availability?.state === "before_activation" && availability.allow_new_spends === true) {
    await Promise.all([refreshWalletSproutNu7Warning(), refreshSproutScanNu7Warning()]);
  }
}

/// The scan panel's alert, while the panel is open. If the core text cannot
/// be had, an existing text stays (a deadline for the wrong network is still
/// better than none), and an empty one takes the fallback so the panel can
/// open with a deadline in view.
async function refreshSproutScanNu7Warning() {
  if (!$("sprout-scan-entry").open) return;
  const network = $("network-select").value;
  const broadcast = sproutScanNu7Broadcast;
  let text;
  try {
    text = await invoke("sprout_nu7_warning", { network, broadcast });
  } catch (err) {
    globalThis.console?.error("could not refresh the Sprout scan NU7 warning:", err);
    if (!sproutScanNu7Warning) sproutScanNu7Warning = SPROUT_NU7_FALLBACK;
    renderSproutScanPanel();
    return;
  }
  if (
    !text ||
    $("network-select").value !== network ||
    sproutScanNu7Broadcast !== broadcast ||
    sproutNu7StatusCurrent().allow_new_spends !== true
  ) {
    return;
  }
  sproutScanNu7Warning = text;
  renderSproutScanPanel();
}

/// The open wallet file's alert and the banners it feeds. Does nothing
/// unless a wallet with Sprout keys is open.
async function refreshWalletSproutNu7Warning() {
  if (!sproutNu7Warning) return;
  const source = walletFile;
  const network = $("network-select").value;
  const broadcast = sproutNu7Broadcast;
  let text;
  try {
    text = await invoke("sprout_nu7_warning", { network, broadcast });
  } catch (err) {
    // Keep the existing text: a deadline warning for the wrong network is
    // still better than none.
    console.error("could not refresh the NU7 warning:", err);
    return;
  }
  if (
    walletFile !== source ||
    !sproutNu7Warning ||
    !text ||
    $("network-select").value !== network ||
    sproutNu7Broadcast !== broadcast ||
    sproutNu7StatusCurrent().allow_new_spends !== true
  ) {
    return;
  }
  sproutNu7Warning = text;
  showSproutNu7Warning(text);
  renderSproutUncoveredBanners();
}

/// After a Sprout submission could have reached the network, switch the
/// warning to "broadcast, but must be mined before activation". A scan sweep
/// also switches the scan panel's own alert, which outlives the wallet file.
function noteSproutBroadcast(report, fromScan = false) {
  const mayHaveBeenBroadcast = (report.transactions ?? []).some((transaction) =>
    ["pending", "submission_unknown", "mined"].includes(transaction.state));
  if (!mayHaveBeenBroadcast) return;
  sproutNu7Broadcast = true;
  if (fromScan) sproutScanNu7Broadcast = true;
  return refreshSproutNu7Warning();
}

/// Fresh canonical mined evidence is the only basis for clearing the source
/// warning. The checks around the backend's aggregate flag fail closed if the
/// payload is incomplete or internally inconsistent.
function sproutSourceWarningMayClear(report) {
  // A superseded row is a replaced expired or rejected transaction: history,
  // judged by its replacement. Only live rows must all be mined.
  const transactions = Array.isArray(report?.transactions)
    ? report.transactions.filter((transaction) => transaction?.superseded !== true)
    : report?.transactions;
  return (
    report?.fresh_all_mined === true &&
    Array.isArray(transactions) &&
    transactions.length > 0 &&
    transactions.every((transaction) =>
      transaction?.state === "mined" &&
      transaction.unmineable_after_nu7 !== true &&
      Number.isInteger(transaction.mined_height) &&
      transaction.mined_height >= 0) &&
    !report.error &&
    (report.rejected ?? []).length === 0 &&
    (report.skipped ?? []).length === 0 &&
    (report.ready ?? []).length === 0 &&
    (report.ready_notes ?? []).length === 0
  );
}

function sproutLifecycleAmount(transaction) {
  return transaction.value_zatoshis == null
    ? "amount unknown"
    : fmt(transaction.value_zatoshis);
}

function sproutLifecycleRow(transaction) {
  const subject = `${sproutLifecycleAmount(transaction)} — ${transaction.txid}`;
  if (transaction.unmineable_after_nu7 === true) {
    return `${subject}: unmined when NU7 activated; this Sprout transaction cannot be mined or rebroadcast. ` +
      "Historical mined-status checks remain available. Keep the source, checkpoint, and backups.";
  }
  switch (transaction.state) {
    case "pending":
      return `${subject}: broadcast pending; it is not mined. Keep the source and checkpoint.`;
    case "submission_unknown":
      return `${subject}: submission status unknown; it may have reached the network. ` +
        "Later notes were not attempted. Keep the source and checkpoint.";
    case "mined":
      return transaction.mined_height == null
        ? `${subject}: mined; the block height was not reported.`
        : `${subject}: mined at block ${Number(transaction.mined_height).toLocaleString()}.`;
    case "expired":
      if (transaction.superseded === true) {
        return `${subject}: expired and superseded by a newer transaction for the same note.`;
      }
      return `${subject}: expired without canonical mined confirmation. ` +
        "Recover or rescan the note before creating a replacement.";
    case "rejected":
      if (transaction.superseded === true) {
        return `${subject}: rejected and superseded by a newer transaction for the same note.`;
      }
      return `${subject}: rejected. Recover or rescan the note before creating a replacement.`;
    case "not_submitted":
      return `${subject}: saved but not submitted. No funds were moved.`;
    default:
      return `${subject}: lifecycle status is unknown. Keep the source and checkpoint.`;
  }
}

/// Shared by wallet-file and saved-scan execution. No lifecycle state is
/// translated into "swept": pending and uncertain submissions remain open,
/// and only a fresh all-mined report receives a green completion status.
function renderSproutSweepReport(report, { list, statusId, destination, statusPrefix = "" }) {
  // The reviewed destination is intentionally not repeated in lifecycle
  // results: a saved raw transaction may predate the value now in the form.
  void destination;
  const transactions = Array.isArray(report?.transactions) ? report.transactions : [];
  for (const transaction of transactions) {
    const li = document.createElement("li");
    li.className = transaction.state === "mined" ? "" : "muted";
    li.textContent = sproutLifecycleRow(transaction);
    list.appendChild(li);
  }
  for (const reason of report?.skipped ?? []) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = `not moved — ${reason}`;
    list.appendChild(li);
  }
  for (const reason of report?.rejected ?? []) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = `rejected — ${reason} Recover or rescan before creating a replacement.`;
    list.appendChild(li);
  }
  for (const warning of report?.warnings ?? []) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = warning;
    list.appendChild(li);
  }

  // A superseded row is history: a later plan replaced it, so it needs no action.
  const count = (state) => transactions.filter(
    (transaction) => transaction.state === state && transaction.superseded !== true,
  ).length;
  const unknown = count("submission_unknown");
  const pending = count("pending");
  const retired = transactions.filter((transaction) => transaction.unmineable_after_nu7 === true &&
    transaction.superseded !== true).length;
  const expired = count("expired");
  const rejected = count("rejected") + (report?.rejected ?? []).length;
  const mined = count("mined");
  let text;
  let kind = "";
  if (retired > 0) {
    text = `${retired} unmined Sprout transaction(s) became invalid at NU7. ` +
      "Recovery is not confirmed for those notes; keep the source, checkpoint, and backups and check historical mined status.";
  } else if (report?.error) {
    text = `✗ The sweep did not finish: ${report.error} ` +
      "Reconcile every saved transaction before another proposal.";
    kind = "error";
  } else if (unknown > 0) {
    text = `Submission status unknown for ${unknown} transaction(s). ` +
      "Later notes were not attempted; reconcile this transaction before continuing.";
    kind = "error";
  } else if (pending > 0) {
    text = `${pending} transaction(s) broadcast pending. They are not mined; check status again.`;
  } else if (expired > 0 || rejected > 0) {
    text = `${expired + rejected} transaction(s) need recovery or a rescan before replacement.`;
  } else if (sproutSourceWarningMayClear(report)) {
    const allAmountsKnown = transactions.every((transaction) => transaction.value_zatoshis != null);
    const hasKnownTotal = Number.isSafeInteger(report.mined_zatoshis) && report.mined_zatoshis >= 0;
    text = allAmountsKnown && hasKnownTotal
      ? `✓ Mined ${fmt(report.mined_zatoshis)}. Fresh canonical evidence covers every transaction.`
      : `✓ All ${mined} transaction(s) mined. ` +
        "Fresh canonical evidence covers every transaction; an amount was not recorded.";
    kind = "success";
  } else if (mined > 0) {
    text = `${mined} transaction(s) appear mined, but fresh canonical evidence does not cover every transaction.`;
  } else {
    text = "No transaction reached fresh canonical mined status. Keep the source and checkpoint.";
  }
  setStatus(statusId, `${statusPrefix}${text}`, kind);

}

function noteUncoveredSproutKeys(summary) {
  // Only counts as uncovered if the file's own notes were not already
  // recovered and swept from the Sprout panel.
  uncoveredSproutKeys = summary.sprout_keys || 0;
  sproutNu7Warning = summary.sprout_nu7_warning ?? "";
  sproutNu7Broadcast = false;
  renderSproutUncoveredBanners();
}

/// The import's own coverage caveat, carried to the same screens for the
/// same reason. Only set when the skipped records may hold funds; a skipped
/// record of unknown type is noted on the import screen alone. Unlike the
/// Sprout count, a Sprout sweep does not clear it.
let partialImportNotice = null;

function notePartialImport(summary) {
  partialImportNotice = summary.coverage_may_hide_funds ? summary.coverage_notice : null;
  renderSproutUncoveredBanners();
}

function forgetWalletCaveats() {
  uncoveredSproutKeys = 0;
  sproutNu7Warning = "";
  sproutNu7Broadcast = false;
  partialImportNotice = null;
  renderSproutUncoveredBanners();
}

// Start over must not carry a wallet file into the next run: the seed step
// never clears it, so a seed typed afterwards would otherwise be scanned as
// the old file and its balance shown as the seed's answer.
function forgetLoadedWalletFile() {
  cancelWalletReviewExpiry();
  ++walletOpenGeneration;
  if (walletFile?.passphrase != null) walletFile.passphrase = null;
  walletFile = null;
  sproutPreviewWallet = null;
  invalidateWalletSproutReview();
  invalidateSproutScanSource();
  forgetWalletCaveats();
  $("wallet-path").value = "";
  $("wallet-passphrase").value = "";
  $("wallet-passphrase-field").hidden = true;
  $("wallet-summary").hidden = true;
  $("wallet-next").disabled = true;
  $("wallet-sprout-sweep").hidden = true;
  $("sprout-sweep-run").disabled = true;
  $("sprout-sweep-plan").textContent = "";
  $("sprout-sweep-pool").textContent = "";
  $("sprout-sweep-params").textContent = "";
  $("sprout-sweep-spent-status").textContent = "";
  $("sprout-sweep-status").textContent = "";
  $("wallet-open").disabled = false;
  setStatus("wallet-status", "", "");
  // A panel the file opened goes with it; one holding a typed key stays.
  sproutScanOfferedForFile = false;
  if (!hasTypedSproutScanText()) $("sprout-scan-entry").open = false;
  renderSproutScanPanel();
}

function renderSproutUncoveredBanners() {
  const tail = "Open it on the wallet screen to inspect Sprout history, recovery eligibility, and saved transaction status.";
  const parts = [];
  if (uncoveredSproutKeys > 0) {
    parts.push(
      `This total does not include Sprout funds. Your wallet file holds ` +
        `${uncoveredSproutKeys} Sprout key(s), which this scan and sweep do not ` +
        `cover. Keep the original wallet file — it is the only copy of those keys. ` +
        tail,
    );
  }
  if (sproutNu7Warning) parts.push(sproutNu7Warning);
  if (partialImportNotice) {
    parts.push(`This total may not be your whole balance. ${partialImportNotice}`);
  }
  const text = parts.join(" ");
  for (const id of [
    "scan-sprout-uncovered",
    "complete-sprout-uncovered",
    "delete-sprout-uncovered",
  ]) {
    const el = $(id);
    if (!el) continue;
    el.textContent = text;
    el.hidden = text === "";
  }
}

async function openWalletFile() {
  cancelWalletReviewExpiry();
  const generation = ++walletOpenGeneration;
  if (walletFile?.passphrase != null) walletFile.passphrase = null;
  walletFile = null;
  sproutPreviewWallet = null;
  invalidateWalletSproutReview();
  invalidateSproutScanSource();
  // The previous file's caveats must not outlive it, even if this open fails.
  forgetWalletCaveats();
  $("wallet-summary").hidden = true;
  $("wallet-next").disabled = true;
  $("wallet-sprout-sweep").hidden = true;
  $("sprout-sweep-run").disabled = true;
  $("sprout-sweep-plan").textContent = "";
  $("sprout-sweep-pool").textContent = "";
  $("sprout-sweep-params").textContent = "";
  showSproutNu7Warning("");
  // The panel is outside #wallet-summary now, so hiding the summary no longer
  // takes it along: drop the previous file's offer here, so a failed open
  // (wrong passphrase, no keys, unreadable) cannot leave it in place.
  sproutScanOfferedForFile = false;
  if (!hasTypedSproutScanText()) $("sprout-scan-entry").open = false;
  renderSproutScanPanel();
  $("wallet-open").disabled = false;
  const path = $("wallet-path").value.trim();
  if (!path) {
    setStatus("wallet-status", "Choose a wallet file first.", "error");
    return;
  }
  const passphraseInput = $("wallet-passphrase");
  const passphrase = passphraseInput.value ? passphraseInput.value : null;

  setStatus("wallet-status", "Reading wallet file…", "");
  $("wallet-open").disabled = true;
  try {
    const summary = await invoke("inspect_wallet_file", {
      path,
      passphrase,
      network: $("network-select").value,
      dataDir: $("data-dir").value.trim() || null,
    });

    if (generation !== walletOpenGeneration) return;

    if (summary.needs_passphrase) {
      $("wallet-passphrase-field").hidden = false;
      $("wallet-summary").hidden = true;
      $("wallet-next").disabled = true;
      walletFile = null;
      setStatus(
        "wallet-status",
        passphrase
          ? "✗ That passphrase did not open this wallet."
          : "This wallet is encrypted — enter its passphrase.",
        passphrase ? "error" : "",
      );
      return;
    }

    if (summary.transparent_keys + summary.sapling_keys + summary.sprout_keys === 0) {
      walletFile = null;
      $("wallet-next").disabled = true;
      setStatus("wallet-status", "✗ No keys could be recovered from this file.", "error");
      return;
    }

    // Rendering can immediately request a Sprout preview, so install the
    // newly opened file before it reads the path and passphrase.
    if (!summary.review_id) {
      throw new Error("wallet inspection did not return review authority; inspect it again");
    }
    walletFile = { path, reviewId: summary.review_id, passphrase, summary };
    scheduleWalletReviewExpiry();
    renderWalletSummary(summary);
    // Carried forward so every later screen can say what the totals leave
    // out. Recorded at open time because the summary is not in scope later.
    noteUncoveredSproutKeys(summary);
    notePartialImport(summary);
    $("wallet-next").disabled = false;
    setStatus("wallet-status", "✓ Wallet file read.", "success");
  } catch (err) {
    if (generation !== walletOpenGeneration) return;
    cancelWalletReviewExpiry();
    if (walletFile?.passphrase != null) walletFile.passphrase = null;
    walletFile = null;
    $("wallet-next").disabled = true;
    $("wallet-summary").hidden = true;
    setStatus("wallet-status", `✗ ${err}`, "error");
  } finally {
    if (generation === walletOpenGeneration) $("wallet-open").disabled = false;
  }
}

// The picker itself runs in Rust — the webview holds no `dialog:`
// permission, so this cannot open anything but a single file chooser.
$("wallet-browse")?.addEventListener("click", async () => {
  try {
    const path = await invoke("pick_wallet_file");
    // Cancelling is not an error, and must not clear a file already chosen.
    if (!path) return;
    invalidateScanAuthority();
    $("wallet-path").value = path;
    // A freshly chosen file is not the one the old passphrase belongs to.
    $("wallet-passphrase").value = "";
    $("wallet-passphrase-field").hidden = true;
    await openWalletFile();
  } catch (err) {
    setStatus("wallet-status", `✗ ${err}`, "error");
  }
});

$("wallet-open")?.addEventListener("click", () => {
  invalidateScanAuthority();
  openWalletFile();
});
$("wallet-forget")?.addEventListener("click", () => {
  invalidateScanAuthority();
  forgetLoadedWalletFile();
});
$("wallet-path")?.addEventListener("keydown", (e) => {
  if (e.key === "Enter") { e.preventDefault(); invalidateScanAuthority(); openWalletFile(); }
});
$("wallet-passphrase")?.addEventListener("keydown", (e) => {
  if (e.key === "Enter") { e.preventDefault(); invalidateScanAuthority(); openWalletFile(); }
});

// Drag-and-drop, using Tauri's core webview event rather than an HTML5 drop
// handler: only the native event carries a real filesystem path. A browser
// `File` has none, and Argos needs the path so the backend reads the file
// itself instead of the wallet crossing the IPC boundary as bytes.
//
// A native file picker would be friendlier still, but that needs
// tauri-plugin-dialog — a new dependency, so not added here unprompted.
(async () => {
  try {
    const { listen } = window.__TAURI__.event;
    const dropZone = $("wallet-drop");
    await listen("tauri://drag-enter", () => dropZone?.classList.add("drop-active"));
    await listen("tauri://drag-leave", () => dropZone?.classList.remove("drop-active"));
    await listen("tauri://drag-drop", (event) => {
      dropZone?.classList.remove("drop-active");
      const paths = event.payload?.paths ?? [];
      if (paths.length === 0) return;
      // Only act while the wallet screen is showing, so a stray drop
      // elsewhere in the app cannot silently swap the selected file.
      const screen = document.querySelector('.screen[data-step="wallet-file"]');
      if (!screen?.classList.contains("active")) return;
      invalidateScanAuthority();
      $("wallet-path").value = paths[0];
      // As with the picker: a new file is not the one the old passphrase
      // belongs to.
      $("wallet-passphrase").value = "";
      $("wallet-passphrase-field").hidden = true;
      openWalletFile();
    });
  } catch (_) {
    // No drag-drop available: the path field still works.
  }
})();

$("sprout-sweep-run").addEventListener("click", runSproutSweep);

// Proving runs for minutes per note with nothing else on screen, and a
// silent multi-minute window is indistinguishable from a hang.
(async () => {
  try {
    await listen("sprout-sweep-progress", (event) => {
      if (sproutSweepSource && walletFile === sproutSweepSource) {
        setStatus("sprout-sweep-status", `${event.payload}…`, "");
      }
    });
  } catch (_) {
    // No event channel: the final result still reports.
  }
})();


// ─── Typed Sapling keys ─────────────────────────────────────────────────────
// The route for a user who has a spending key string and no wallet file.

// The raw lines of the textarea, in the order and at the positions the user
// sees them. Deliberately unfiltered: `keys_from_sapling_strings` is the one
// place that decides what a key file means — which lines are skipped and how
// they are numbered — and dropping blanks here would both hide `#` comments
// from that rule and shift every reported line number away from what the
// textarea shows.
function saplingScanKeyLines() {
  const box = $("sapling-scan-keys");
  if (!box) return [];
  return box.value.split("\n");
}

// The one skip rule, mirroring `keys_from_sapling_strings`: blank lines and
// `#` comments are annotation, not input.
function isSaplingKeyLine(line) {
  const t = line.trim();
  return t !== "" && !t.startsWith("#");
}

// Whether the user actually supplied any key, as opposed to an empty box or
// one holding only comments.
function hasSaplingScanKeys() {
  return saplingScanKeyLines().some(isSaplingKeyLine);
}

async function checkSaplingKeys() {
  const list = $("sapling-key-addresses");
  list.innerHTML = "";
  // Keep each key paired with the line it sits on, so a failure names the
  // line the user can see rather than a position in a filtered array.
  const keys = saplingScanKeyLines()
    .map((line, i) => ({ key: line.trim(), line: i + 1 }))
    .filter(({ key }) => isSaplingKeyLine(key));
  if (!keys.length) {
    setStatus(
      "sapling-key-status",
      walletFile
        ? "The Sapling keys in your wallet file will be used."
        : "Paste a Sapling spending key, or open a wallet file that holds some.",
      "",
    );
    return;
  }
  // Checked before the scan, not an hour into it.
  for (const { key, line } of keys) {
    try {
      const addr = await invoke("check_sapling_key", {
        key,
        network: $("network-select").value,
      });
      const li = document.createElement("li");
      li.textContent = addr;
      list.appendChild(li);
    } catch (err) {
      setStatus("sapling-key-status", `✗ line ${line}: ${err}`, "error");
      return;
    }
  }
  setStatus("sapling-key-status", `${keys.length} key(s) look valid.`, "success");
}

// ─── Sprout scan ────────────────────────────────────────────────────────────
// The fallback for a wallet whose note data is missing, and the only route
// for a raw key with no wallet file. Hours, so it checkpoints and resumes.

let sproutScanHandle = null;
// Opaque authority for backend-held keys, retained after a failed/paused scan.
// Peer edits may reuse it; changing the wallet, keys or chain configuration
// releases it. No passphrase or spending key needs to return to the webview.
let sproutScanRetryHandle = null;
// The decrypt request the retained source's plan was built from. A retry
// reuses that plan, so it may only run while the form still asks for it.
let sproutScanRetryDecrypt = null;
let sproutScanPausePromise = Promise.resolve();
let sproutScanGeneration = 0;
let sproutScanResult = null;
let sproutScanReview = null;
let sproutScanReviewDestination = null;
let sproutScanProposalGeneration = 0;
let sproutScanExecutionPending = false;

function invalidateSproutScanReview() {
  ++sproutScanProposalGeneration;
  if (sproutScanReview) {
    invoke("release_sprout_proposal", { proposalId: sproutScanReview.proposal_id }).catch(() => {});
  }
  sproutScanReview = null;
  sproutScanReviewDestination = null;
  $("sprout-scan-sweep-plan").textContent = "";
  $("sprout-scan-confirm").checked = false;
  $("sprout-scan-confirm").disabled = true;
  $("sprout-scan-sweep-run").disabled = true;
  $("sprout-scan-sweep-run").textContent = "Sweep found funds";
}

function updateSproutScanSweepButton() {
  const allowed = sproutNu7StatusCurrent().state === "before_activation" &&
    sproutNu7StatusCurrent().allow_new_spends === true && sproutScanReview?.allow_new_spends === true;
  const confirmationLabel = allowed
    ? "I understand this may rebroadcast a saved transaction or move funds and cannot be undone."
    : "Check saved transaction status only. No new proof or rebroadcast is allowed.";
  // Consent belongs to the displayed mode, so a status-only acknowledgement
  // cannot become spending authority when a pending height refresh succeeds.
  if ($("sprout-scan-confirm-label").textContent !== confirmationLabel) {
    $("sprout-scan-confirm").checked = false;
  }
  $("sprout-scan-confirm-label").textContent = confirmationLabel;
  $("sprout-scan-sweep-run").textContent = sproutReviewHasLifecycleStatus(sproutScanReview)
    ? (allowed ? "Check status and continue" : "Check saved status only") : "Sweep found funds";
  $("sprout-scan-sweep-run").disabled = (!allowed && !sproutReviewHasLifecycleStatus(sproutScanReview)) || !sproutScanResult || !sproutScanReview ||
    !sproutReviewMayRun(sproutScanReview) ||
    sproutScanReviewDestination !== $("sprout-scan-destination").value.trim() ||
    !$("sprout-scan-confirm").checked || sproutScanExecutionPending;
}

function pauseSproutRetrySource(handle, generation) {
  const paused = sproutScanPausePromise.catch(() => {}).then(() =>
    invoke("pause_sprout_scan", { handle }));
  sproutScanPausePromise = paused;
  paused.catch((err) => {
    if (generation !== sproutScanGeneration || handle !== sproutScanRetryHandle) return;
    setStatus("sprout-scan-status", `Could not pause the scan: ${err}. Retry or reopen the wallet.`, "error");
  });
}

function invalidateSproutScanSource({ preserveRetry = false, pause = true } = {}) {
  ++sproutScanGeneration;
  const handles = new Set([sproutScanHandle, sproutScanRetryHandle].filter(Boolean));
  const retained = preserveRetry ? sproutScanRetryHandle : null;
  sproutScanRetryHandle = retained;
  if (!retained) sproutScanRetryDecrypt = null;
  sproutScanHandle = null;
  sproutScanResult = null;
  invalidateSproutScanReview();
  $("sprout-scan-sweep").hidden = true;
  $("sprout-scan-bar").hidden = true;
  $("sprout-scan-run").disabled = false;
  $("sprout-scan-sweep-results").innerHTML = "";
  setStatus("sprout-scan-status", "", "");
  for (const handle of handles) {
    if (handle === retained) {
      if (pause) pauseSproutRetrySource(handle, sproutScanGeneration);
    } else {
      invoke("release_sprout_scan", { handle }).catch(() => {});
    }
  }
}

function publishSproutScanSnapshot(snapshot, generation = sproutScanGeneration) {
  if (generation !== sproutScanGeneration || !sproutScanHandle ||
      snapshot.handle !== sproutScanHandle) return;
  if (snapshot.status === "running") return;
  if (sproutScanResult) return;
  $("sprout-scan-bar").hidden = true;
  $("sprout-scan-run").disabled = false;
  if (snapshot.status === "failed") {
    setStatus("sprout-scan-status", `✗ ${snapshot.error || "The scan did not finish."}`, "error");
    return;
  }
  const report = snapshot.report;
  if (!report) return;
  sproutScanResult = report;
  const canReview = report.notes_found > 0 || report.has_lifecycle_status === true;
  // The bound actually used: after a resume, the saved scan's.
  $("sprout-scan-plan").textContent =
    report.decrypt_from_height != null
      ? `${report.decrypt_line} Trial decryption ran from block ${Number(report.decrypt_from_height).toLocaleString()}.`
      : report.decrypt_line;
  const caveat = report.tip_warning ? ` ${report.tip_warning}` : "";
  setStatus(
    "sprout-scan-status",
    (report.notes_found > 0
      ? `✓ Found ${report.notes_found} note(s), ${fmt(report.total_zatoshis)}. ` +
        `${report.spent_notes} already spent.`
      : report.has_lifecycle_status
        ? "Scan complete. No new unspent Sprout notes were found; saved transaction status still needs reconciliation."
        : "Scan complete. No unspent Sprout notes were found for these keys.") + caveat,
    report.notes_found > 0 ? "success" : "",
  );
  $("sprout-scan-sweep").hidden = !canReview;
  if (canReview && $("sprout-scan-destination").value.trim()) {
    refreshSproutScanReview();
  }
}

async function refreshSproutScanReview() {
  invalidateSproutScanReview();
  const handle = sproutScanHandle;
  const destination = $("sprout-scan-destination").value.trim();
  if (!handle || !sproutScanResult || !destination) return;
  const generation = sproutScanGeneration;
  const proposalGeneration = sproutScanProposalGeneration;
  try {
    const availability = await refreshSproutNu7Status();
    if (!availability || generation !== sproutScanGeneration || proposalGeneration !== sproutScanProposalGeneration) return;
    const review = await invoke("propose_sprout_scan_sweep", { scanHandle: handle, destination });
    if (generation !== sproutScanGeneration || proposalGeneration !== sproutScanProposalGeneration ||
        handle !== sproutScanHandle || destination !== $("sprout-scan-destination").value.trim()) {
      invoke("release_sprout_proposal", { proposalId: review.proposal_id }).catch(() => {});
      return;
    }
    review.allow_new_spends = review.allow_new_spends === true && availability.state === "before_activation" && availability.allow_new_spends === true;
    sproutScanReview = review;
    sproutScanReviewDestination = destination;
    const lifecycleCount = (review.active ?? []).length + (review.mined ?? []).length;
    $("sprout-scan-sweep-plan").textContent =
      (!review.allow_new_spends
        ? "Historical Sprout notes cannot be spent while NU7 recovery is disabled. Keep all recovery material. "
        : review.notes > 0
        ? `${review.notes} note(s): ${fmt(review.gross_zatoshis)} gross, ` +
          `${fmt(review.fee_zatoshis)} fee, ${fmt(review.net_zatoshis)} to your address. `
        : "No note is ready for a new transaction. ") +
      (lifecycleCount > 0 ? `${lifecycleCount} saved transaction(s) will be checked first. ` : "") +
      `${review.lands_in_sapling}`;
    const canCheckLifecycle = sproutReviewHasLifecycleStatus(review);
    $("sprout-scan-sweep-run").textContent = canCheckLifecycle
      ? "Check status and continue"
      : "Sweep found funds";
    $("sprout-scan-confirm").disabled = !sproutReviewMayRun(review);
    if (!review.allow_new_spends) {
      $("sprout-scan-sweep-plan").textContent += " Saved status checks are observation-only: no new proof or rebroadcast.";
    } else if (!review.params_present) {
      $("sprout-scan-sweep-plan").textContent += canCheckLifecycle
        ? " Sprout proving parameters are missing. Saved transaction status and exact-byte retries " +
          "can still be checked; a new transaction cannot be proved."
        : ` Sprout proving parameters are missing: ${review.params_path}`;
    }
    updateSproutScanSweepButton();
  } catch (err) {
    if (generation !== sproutScanGeneration || proposalGeneration !== sproutScanProposalGeneration) return;
    setStatus("sprout-scan-status", `✗ ${err}`, "error");
  }
}

// The raw lines of the key box, unfiltered. The backend (`collect_scan_keys`)
// owns the skip rule and numbers a failure by the line the user can see, so
// dropping blanks here would shift every reported number away from the box.
function sproutScanKeyLines() {
  const box = $("sprout-scan-keys");
  if (!box) return [];
  return box.value.split("\n");
}

// Each key paired with the line it sits on. Blank lines and `#` comments are
// annotation, the same rule as the CLI key file and the Sapling box.
function sproutScanKeyEntries() {
  return sproutScanKeyLines()
    .map((line, i) => ({ key: line.trim(), line: i + 1 }))
    .filter(({ key }) => key !== "" && !key.startsWith("#"));
}

function sproutScanKeys() {
  return sproutScanKeyEntries().map(({ key }) => key);
}

// A Sprout pack folder. Checked with the backend's own rules as soon as it
// is chosen, so a wrong folder or an unpinned mainnet pack is reported here
// rather than when the scan starts.
async function describeSproutPack() {
  const path = $("sprout-scan-pack").value.trim();
  if (!path) {
    setStatus("sprout-scan-pack-status", "", "");
    return;
  }
  try {
    const pack = await invoke("describe_sprout_pack", {
      path,
      network: $("network-select").value,
    });
    const gb = (pack.bytes / 1e9).toFixed(1);
    const trust = pack.pinned
      ? "pinned by this version of Argos"
      : "not pinned (accepted only on testnet)";
    setStatus(
      "sprout-scan-pack-status",
      `✓ Blocks 1 to ${pack.endHeight.toLocaleString()}, ` +
        `${pack.joinsplits.toLocaleString()} Sprout transactions, ${gb} GB; ${trust}.`,
      "success",
    );
  } catch (err) {
    setStatus("sprout-scan-pack-status", `✗ ${err}`, "error");
  }
}

$("sprout-scan-pack")?.addEventListener("change", describeSproutPack);
$("sprout-scan-pack-browse")?.addEventListener("click", async () => {
  try {
    const path = await invoke("pick_sprout_pack_folder");
    if (!path) return;
    $("sprout-scan-pack").value = path;
    await describeSproutPack();
  } catch (err) {
    setStatus("sprout-scan-pack-status", `✗ ${err}`, "error");
  }
});

// Custom P2P peers, for when every public peer's inbound slots are full.
// A light mirror of `parse_custom_peers` in the backend, which is the
// authority: this only catches the obvious typo before a connection attempt.
//
// Deliberately approximate, and only ever in one direction: it must never
// refuse an entry the backend would accept, because the user would then be
// blocked by the weaker of the two checks. It may let through things the
// backend refuses (a leading `-`, an empty label such as `node..example`);
// those come back as the backend's own, more specific error.
const MAX_CUSTOM_PEERS = 8;

function sproutScanPeerEntries() {
  const entries = $("sprout-scan-peers").value
    .split(/[\n,]/)
    .map((p) => p.trim().toLowerCase())
    .filter(Boolean);
  return [...new Set(entries)];
}

function sproutScanPeers() {
  const peers = sproutScanPeerEntries();
  for (const peer of peers) {
    const match = /^(\[[0-9a-f:.]+\]|[a-z0-9._-]+):(\d+)$/.exec(peer);
    const port = match ? Number(match[2]) : 0;
    if (!match || port < 1 || port > 65535) {
      throw new Error(
        `custom peer "${peer}" is not host:port with a port from 1 to 65535 ` +
          "(for example 192.0.2.10:8233 or [2001:db8::1]:8233)",
      );
    }
  }
  if (peers.length > MAX_CUSTOM_PEERS) {
    throw new Error(
      `at most ${MAX_CUSTOM_PEERS} custom peers are accepted; ${peers.length} were given`,
    );
  }
  return peers;
}

// What the Sprout scan is asked to decrypt. The backend derives any skip
// from the wallet file's key times; this only carries what the user chose
// to undo it. The panel's own birthday wins; otherwise the main birthday
// field counts only once the user has set it, because its 419200 default
// would otherwise cap every later skip. Either can only lower the skip.
//
// The backend takes the bound as a u32, and a larger number fails Tauri's
// deserialisation with a raw serde error the user cannot act on, so it is
// refused here in words. Number() of a long digit string is not exact past
// 2^53, which is why the safe-integer check comes first.
function sproutDecryptRequest(panelText, everyBlock, mainText, mainTouched) {
  const MAX_BLOCK_HEIGHT = 4294967295;
  const tooLarge = (n) => !Number.isSafeInteger(n) || n > MAX_BLOCK_HEIGHT;
  const tooLargeError = (field) => ({
    error: `The ${field} is too large: no block number is above ${MAX_BLOCK_HEIGHT.toLocaleString("en-US")}.`,
  });
  const panel = String(panelText || "").trim();
  let birthdayFloor = null;
  if (panel) {
    if (!/^\d+$/.test(panel)) {
      return { error: "The Sprout scan birthday must be a block number." };
    }
    birthdayFloor = Number(panel);
    if (tooLarge(birthdayFloor)) return tooLargeError("Sprout scan birthday");
  } else if (mainTouched && /^\d+$/.test(String(mainText || "").trim())) {
    birthdayFloor = Number(String(mainText).trim());
    if (tooLarge(birthdayFloor)) return tooLargeError("wallet birthday");
  }
  return { birthdayFloor, decryptEveryBlock: !!everyBlock };
}

function sameSproutDecrypt(a, b) {
  return !!a && !!b && !a.error && !b.error &&
    a.birthdayFloor === b.birthdayFloor && a.decryptEveryBlock === b.decryptEveryBlock;
}

function currentSproutDecryptRequest() {
  return sproutDecryptRequest(
    $("sprout-scan-birthday").value,
    $("sprout-scan-every-block").checked,
    $("birthday-height").value,
    birthdayTouched,
  );
}

async function checkSproutKeys() {
  const list = $("sprout-scan-addresses");
  list.innerHTML = "";
  const keys = sproutScanKeyEntries();
  if (!keys.length) {
    setStatus(
      "sprout-scan-status",
      walletFile
        ? "The Sprout keys in your wallet file will be used."
        : "Paste a Sprout key, or open a wallet file that holds some.",
      "",
    );
    return;
  }
  // Checked before the scan, not six hours into it.
  for (const { key, line } of keys) {
    try {
      const addr = await invoke("check_sprout_key", { key, network: $("network-select").value });
      const li = document.createElement("li");
      li.textContent = addr;
      list.appendChild(li);
    } catch (err) {
      setStatus("sprout-scan-status", `✗ line ${line}: ${err}`, "error");
      return;
    }
  }
  setStatus("sprout-scan-status", `${keys.length} key(s) look valid.`, "success");
}

async function runSproutScan() {
  const retryHandle = sproutScanRetryHandle;
  const keys = sproutScanKeys();
  if (!retryHandle && !keys.length && !walletFile) {
    setStatus(
      "sprout-scan-status",
      "Paste at least one Sprout spending key, or open a wallet file that holds some.",
      "error",
    );
    return;
  }

  let peers;
  try {
    peers = sproutScanPeers();
  } catch (err) {
    setStatus("sprout-scan-status", `✗ ${err.message}`, "error");
    return;
  }

  // A retry uses its original backend-owned decrypt plan, not a re-derived
  // wallet birthday after the passphrase and pasted keys have been wiped. So
  // it may only run while the form asks for the plan it was built from.
  // Birthday auto-detect, estimate-from-date and the network default change
  // the birthday in code, without the input events that release the source;
  // an earlier birthday would otherwise leave the blocks between the two
  // never trial-decrypted.
  const requested = currentSproutDecryptRequest();
  if (retryHandle && !sameSproutDecrypt(requested, sproutScanRetryDecrypt)) {
    invalidateSproutScanSource();
    setStatus(
      "sprout-scan-status",
      "✗ The wallet birthday or the decrypt setting changed since this scan stopped, " +
        "so its keys were released instead of scanning under the old setting. Paste the " +
        "Sprout keys again or reopen the wallet file, then run the scan.",
      "error",
    );
    return;
  }
  const decrypt = retryHandle ? null : requested;
  if (decrypt?.error) {
    setStatus("sprout-scan-status", `✗ ${decrypt.error}`, "error");
    return;
  }

  const pausing = sproutScanPausePromise;
  invalidateSproutScanSource({ preserveRetry: !!retryHandle, pause: false });
  const generation = sproutScanGeneration;
  const button = $("sprout-scan-run");
  button.disabled = true;
  $("sprout-scan-bar").hidden = false;
  $("sprout-scan-plan").textContent = "";
  setStatus("sprout-scan-status", "Connecting to the Zcash network…", "");

  try {
    await pausing.catch(() => {});
    if (generation !== sproutScanGeneration) return;
    // Like the peers, the pack only changes where blocks are read from, so a
    // retry takes the folder the panel names now.
    const sproutPack = $("sprout-scan-pack").value.trim() || null;
    const handle = retryHandle
      ? await invoke("retry_sprout_scan", { handle: retryHandle, peers, sproutPack })
      : await invoke("start_sprout_scan", {
        keys: sproutScanKeyLines(),
        // The wallet file's own Sprout keys are merged in by the backend, so
        // leaving the box blank genuinely works now.
        reviewId: walletFile ? walletFile.reviewId : null,
        passphrase: walletFile ? walletFile.passphrase : null,
        network: $("network-select").value,
        dataDir: $("data-dir").value.trim(),
        // Only to confirm the chain tip independently of the peer; the scan
        // itself reads blocks from the p2p network.
        lightwalletdUrl: $("lightwalletd-url").value.trim(),
        confirmationSources: confirmationSourcesFromForm(),
        peers,
        birthdayFloor: decrypt.birthdayFloor,
        decryptEveryBlock: decrypt.decryptEveryBlock,
        sproutPack,
      });
    if (generation !== sproutScanGeneration) {
      // A peer edit may land while a retry rotates its opaque handle. Keep
      // the new key authority only if that exact original source is still
      // retained; never display its stale progress or result under new peers.
      if (retryHandle && sproutScanRetryHandle === retryHandle) {
        sproutScanRetryHandle = handle;
        pauseSproutRetrySource(handle, sproutScanGeneration);
      } else {
        invoke("release_sprout_scan", { handle }).catch(() => {});
      }
      return;
    }
    sproutScanHandle = handle;
    sproutScanRetryHandle = handle;
    if (!retryHandle) sproutScanRetryDecrypt = decrypt;
    clearTransientSecrets();
    const listenersReady = await sproutScanListenersReady;
    if (generation !== sproutScanGeneration || handle !== sproutScanHandle) return;
    let snapshot = await invoke("get_sprout_scan", { handle });
    publishSproutScanSnapshot(snapshot, generation);
    while (!listenersReady && snapshot.status === "running" &&
           generation === sproutScanGeneration && handle === sproutScanHandle) {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      if (generation !== sproutScanGeneration || handle !== sproutScanHandle) return;
      snapshot = await invoke("get_sprout_scan", { handle });
      publishSproutScanSnapshot(snapshot, generation);
    }
  } catch (err) {
    if (generation !== sproutScanGeneration) return;
    // Stop an accepted scan whose completion channel failed, but retain its
    // backend key source. A rejected initial start has not accepted any
    // secrets: leave those inputs under their original review expiry.
    invalidateSproutScanSource({ preserveRetry: !!sproutScanRetryHandle });
    setStatus("sprout-scan-status", `✗ ${err}`, "error");
  }
  if (generation === sproutScanGeneration && !sproutScanHandle) button.disabled = false;
}

/// Sweep what the scan found.
///
/// Resuming a saved scan only catches up from its checkpoint to the current
/// tip, so this is a button rather than another full scan.
async function runSproutScanSweep() {
  const destination = $("sprout-scan-destination").value.trim();
  if (!destination) {
    setStatus("sprout-scan-status", "Enter a destination address first.", "error");
    return;
  }
  if (!sproutScanHandle || !sproutScanResult || !sproutScanReview ||
      !sproutReviewMayRun(sproutScanReview) ||
      (!sproutReviewHasLifecycleStatus(sproutScanReview) && sproutNu7StatusCurrent().allow_new_spends !== true) ||
      sproutScanReviewDestination !== destination || !$("sprout-scan-confirm").checked) {
    setStatus(
      "sprout-scan-status",
      "Review this destination and tick the box before moving funds irreversibly.",
      "error",
    );
    return;
  }
  if (sproutScanExecutionPending) return;
  const handle = sproutScanHandle;
  const generation = sproutScanGeneration;
  const proposalId = sproutScanReview.proposal_id;
  sproutScanExecutionPending = true;

  // No decrypt bound is sent: the backend resumes under the one the saved
  // scan used, read from its checkpoint. Re-deriving it from the form would
  // pick up any birthday change made since — auto-detect, an estimate, a
  // retyped field — and a lower one makes the resume conflict after hours
  // of scanning. Lowering the bound means starting a new scan, which says
  // why when it has to refuse.

  const button = $("sprout-scan-sweep-run");
  button.disabled = true;
  const list = $("sprout-scan-sweep-results");
  list.innerHTML = "";
  setStatus(
    "sprout-scan-status",
    sproutReviewHasLifecycleStatus(sproutScanReview)
      ? "Checking saved transaction status before any new proof…"
      : "Proving… a few minutes per note. Do not close the app.",
    "",
  );

  try {
    const report = await invoke("execute_sprout_scan_sweep", {
      proposalId,
      observationOnly: sproutScanReview.allow_new_spends !== true ||
        sproutNu7StatusCurrent().allow_new_spends !== true,
    });
    // The panel may have moved on to another scan source while proving ran.
    // These funds moved regardless, so the report is always shown, labelled
    // as the earlier scan's, never dropped.
    const earlier = generation !== sproutScanGeneration || handle !== sproutScanHandle;
    const prefix = earlier ? "Earlier Sprout scan: " : "";
    if (earlier) {
      $("sprout-scan-sweep").hidden = false;
      const li = document.createElement("li");
      li.className = "muted";
      li.textContent =
        "This result belongs to the earlier Sprout scan started before its keys or settings changed.";
      list.appendChild(li);
    }

    if (!earlier) noteSproutBroadcast(report, true);
    renderSproutSweepReport(report, {
      list,
      statusId: "sprout-scan-status",
      destination,
      statusPrefix: prefix,
    });
    if (!earlier && sproutSourceWarningMayClear(report)) {
      uncoveredSproutKeys = 0;
      renderSproutUncoveredBanners();
    }
  } catch (err) {
    // Execution refuses only when nothing was broadcast; still say so, for
    // the earlier scan too, rather than leave the click unanswered.
    const earlier = generation !== sproutScanGeneration || handle !== sproutScanHandle;
    setStatus("sprout-scan-status", `${earlier ? "Earlier Sprout scan: " : ""}✗ ${err}`, "error");
  } finally {
    sproutScanExecutionPending = false;
    clearTransientSecrets();
    if (generation === sproutScanGeneration && handle === sproutScanHandle &&
        sproutScanReview?.proposal_id === proposalId) invalidateSproutScanReview();
    updateSproutScanSweepButton();
  }
}

$("sprout-scan-sweep-run").addEventListener("click", runSproutScanSweep);
$("sprout-scan-check").addEventListener("click", checkSproutKeys);
$("sapling-keys-check")?.addEventListener("click", checkSaplingKeys);
$("sprout-scan-run").addEventListener("click", runSproutScan);
$("sprout-scan-entry")?.addEventListener("toggle", onSproutScanEntryToggle);
$("sprout-scan-destination").addEventListener("input", invalidateSproutScanReview);
$("sprout-scan-destination").addEventListener("change", refreshSproutScanReview);
$("sprout-scan-confirm").addEventListener("change", updateSproutScanSweepButton);
for (const id of ["sprout-scan-keys", "network-select",
  "data-dir", "lightwalletd-url", "confirmation-sources", "server-preset", "wallet-path", "wallet-passphrase",
  "sprout-scan-birthday", "sprout-scan-every-block", "birthday-height"]) {
  $(id)?.addEventListener("input", invalidateSproutScanSource);
  $(id)?.addEventListener("change", invalidateSproutScanSource);
}
// Peer selection does not change the keys or decrypt plan. Pause the old
// worker and invalidate its result/proposals while retaining retry authority.
for (const event of ["input", "change"]) {
  $("sprout-scan-peers").addEventListener(event, () =>
    invalidateSproutScanSource({ preserveRetry: true }));
}
// The scan panel's peers verify the saved scan behind a wallet review (#272),
// so they define its notes as much as the data directory does.
for (const id of ["wallet-path", "wallet-passphrase", "network-select", "data-dir", "lightwalletd-url", "confirmation-sources", "server-preset", "sprout-scan-peers"]) {
  $(id)?.addEventListener("input", invalidateWalletSproutReview);
  $(id)?.addEventListener("change", invalidateWalletSproutReview);
  $(id)?.addEventListener("input", invalidateSproutNu7Status);
  $(id)?.addEventListener("change", invalidateSproutNu7Status);
}
for (const id of ["lightwalletd-url", "confirmation-sources", "sprout-scan-peers"]) {
  $(id)?.addEventListener("change", () => {
    if (typeof showSproutSweep === "function") void showSproutSweep();
  });
}
for (const id of ["network-select", "data-dir"]) {
  for (const event of ["input", "change"]) {
    $(id)?.addEventListener(event, () => {
      // Inspection and its spendable balance used these settings. Require a
      // fresh read before showing any wallet-derived Sprout evidence again.
      if (id === "data-dir") {
        // A directory correction must retain the immutable wallet source and
        // its original expiry for retry. All derived evidence and proposals
        // are invalidated by the listeners above and hidden until reinspection.
        ++walletOpenGeneration;
        $("wallet-open").disabled = false;
        sproutPreviewWallet = null;
        $("wallet-summary").hidden = true;
        $("wallet-sprout-sweep").hidden = true;
        $("wallet-next").disabled = true;
        for (const field of ["sprout-sweep-plan", "sprout-sweep-pool", "sprout-sweep-params", "sprout-sweep-spent-status", "sprout-sweep-status"]) {
          $(field).textContent = "";
        }
      } else {
        const path = $("wallet-path").value;
        forgetLoadedWalletFile();
        $("wallet-path").value = path;
      }
    });
  }
}

const sproutScanListenersReady = (async () => {
  try {
    await Promise.all([
      // The backend's sentence on where decryption starts, before the hours.
      listen("sprout-scan-plan", (event) => {
        $("sprout-scan-plan").textContent = event.payload;
      }),
      listen("sprout-scan-progress", (event) => {
        const p = event.payload;
        if (!sproutScanHandle || p.handle !== sproutScanHandle) return;
        const pct = p.target ? (p.height / p.target) * 100 : 0;
        $("sprout-scan-bar").value = pct;
        // Waiting for a peer, not scanning. The bar keeps the scan's position
        // and the line says why nothing is moving, so a busy network does not
        // look like a hung app. The sentence comes from the backend.
        if (p.peerWait) {
          setStatus("sprout-scan-status", `${p.peerWait} Safe to stop; progress is saved every 500 blocks.`, "");
          return;
        }
        setStatus(
          "sprout-scan-status",
          `Scanning ${p.height.toLocaleString()} / ${p.target.toLocaleString()} ` +
            `(${pct.toFixed(1)}%) — ${p.notesFound} note(s) found. Safe to stop; progress is saved every 500 blocks.`,
          "",
        );
      }),
      listen("sprout-scan-complete", (event) => {
        publishSproutScanSnapshot(event.payload);
      }),
    ]);
    return true;
  } catch (_) {
    return false;
  }
})();

// ─── Step 3: Configuration ────────────────────────────────────────────────────

// Keep in sync with DEFAULT_MAINNET_LIGHTWALLETD / DEFAULT_TESTNET_LIGHTWALLETD
// in crates/zeck-core/src/lightwalletd.rs.
const SERVER_PRESETS = {
  mainnet: "https://zec.rocks:443,https://na.zec.rocks:443",
  testnet: "https://testnet.zec.rocks:443",
};

const CONFIRMATION_SOURCES_STORAGE_KEY = "argos-confirmation-sources-v1";

function confirmationSourcesFromForm(id = "confirmation-sources") {
  return $(id).value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}

function clearMatchedRecoveryUi() {
  state.matchedRecovery = null;
  $("matched-recovery-banner").hidden = true;
  $("matched-recovery-summary").textContent = "";
  $("network-select").disabled = false;
  $("birthday-autodetect").disabled = false;
  $("accounts-heading").hidden = false;
  $("accounts-range-field").hidden = false;
  $("auto-gap-limit-field").hidden = false;
  $("gap-limit-row").hidden = false;
  $("transparent-scan-settings").hidden = false;
}

function configForMatchedRecovery(config) {
  const { seed: _unused, ...seedless } = config;
  return { ...seedless, num_accounts: 1, gap_limit: 1, transparent_scan: null };
}

function transparentScanFromInputs(startRaw, countRaw, includeChange) {
  const indexStart = Number(startRaw);
  const indexCount = Number(countRaw);
  const limit = 2147483648;
  if (!Number.isSafeInteger(indexStart) || indexStart < 0 || indexStart >= limit) {
    throw new Error("First transparent index must be a whole number from 0 to 2,147,483,647.");
  }
  if (!Number.isSafeInteger(indexCount) || indexCount < 1 || indexCount > 10000) {
    throw new Error("Transparent indexes to check must be a whole number from 1 to 10,000.");
  }
  if (indexStart + indexCount > limit) {
    throw new Error("The transparent index range must end at or before 2,147,483,647.");
  }
  return { index_start: indexStart, index_count: indexCount, include_change: !!includeChange };
}

function transparentScanSummary(startRaw, countRaw, includeChange) {
  try {
    const range = transparentScanFromInputs(startRaw, countRaw, includeChange);
    const end = range.index_start + range.index_count - 1;
    const branches = range.include_change ? "receive + change" : "receive";
    return {
      valid: true,
      text: `Seed-based wallets: account 0 ${branches} indices ${range.index_start.toLocaleString()}–${end.toLocaleString()} are checked as an additional complete range.`,
    };
  } catch (error) {
    return { valid: false, text: `Fix the transparent range: ${error.message || error}` };
  }
}

function updateTransparentScanSummary() {
  const summary = transparentScanSummary(
    $("transparent-index-start").value,
    $("transparent-index-count").value,
    $("transparent-include-change").checked,
  );
  $("transparent-scan-summary").textContent = summary.text;
  $("transparent-scan-summary").style.color = summary.valid ? "" : "var(--danger)";
}

function shouldShowTransparentRange(matched, hasSeed, hasWallet, walletHasMnemonic, hasStandaloneKeys) {
  if (matched) return false;
  if (hasSeed) return true;
  if (hasWallet) return !!walletHasMnemonic;
  if (hasStandaloneKeys) return false;
  return true;
}

function updateTransparentScanSettingsVisibility() {
  $("transparent-scan-settings").hidden = !shouldShowTransparentRange(
    !!state.matchedRecovery,
    !!seedInput.value.trim(),
    !!walletFile,
    !!walletFile?.summary?.has_mnemonic,
    hasSaplingScanKeys(),
  );
}

$("transparent-index-start").addEventListener("input", updateTransparentScanSummary);
$("transparent-index-count").addEventListener("input", updateTransparentScanSummary);
$("transparent-include-change").addEventListener("change", updateTransparentScanSummary);
updateTransparentScanSummary();

window.addEventListener("beforeunload", () => {
  abandonRecoveryFlow();
  // Backend-owned cleanup survives the webview unloading during configuration.
  const id = state.retainedAddressSearchId || state.matchedRecovery?.searchId;
  if (id) invoke("release_address_search", { id }).catch(() => {});
});

function abandonMatchedRecovery() {
  const searchId = state.matchedRecovery?.searchId;
  clearMatchedRecoveryUi();
  state.retainedAddressSearchId = null;
  document.dispatchEvent(new CustomEvent("address-search-release", { detail: { searchId } }));
}

document.addEventListener("address-match-recovery", async (event) => {
  const { searchId, matchId } = event.detail || {};
  if (!searchId || !matchId || state.addressMatchRecoveryLocked) return;
  try {
    const snapshot = await invoke("get_address_search", { id: searchId });
    const retainedMatch = (snapshot.matches || []).find((candidate) => candidate.id === matchId);
    if (!retainedMatch) {
      throw new Error("The selected address match is no longer available.");
    }
    // Selecting a match changes both source and network without a DOM input
    // event. Revoke the prior scan and proposal before exposing the match.
    invalidateScanAuthority();
    state.matchedRecovery = { searchId, matchId, match: retainedMatch, network: snapshot.network };
    state.retainedAddressSearchId = searchId;
    // A matched capability is the sole recovery source. Clear any inputs left
    // from an earlier wizard visit so secret provenance cannot be ambiguous.
    seedInput.value = "";
    forgetLoadedWalletFile();
    $("sapling-scan-keys").value = "";
    $("sapling-key-addresses").replaceChildren();
    forgetSproutScanInputs();
    $("network-select").value = snapshot.network;
    syncUntouchedBirthdayToNetwork(snapshot.network);
    $("network-select").disabled = true;
    // The Sprout panel's network mirror follows the now-locked picker.
    renderSproutScanPanel();
    $("server-preset").value = "recommended";
    $("lightwalletd-url").value = SERVER_PRESETS[snapshot.network] ?? SERVER_PRESETS.mainnet;
    $("birthday-autodetect").disabled = true;
    $("accounts-heading").hidden = true;
    $("accounts-range-field").hidden = true;
    $("auto-gap-limit-field").hidden = true;
    $("gap-limit-row").hidden = true;
    $("transparent-scan-settings").hidden = true;
    const recoveryScope = retainedMatch.pool === "transparent"
      ? "Transparent recovery scans only the exact matched address."
      : "Shielded recovery scans the matched account, including supported external and internal receivers.";
    $("matched-recovery-summary").textContent =
      `${retainedMatch.seed_label || `Candidate ${Number(retainedMatch.seed_index) + 1}`} matched ${retainedMatch.address} at ${retainedMatch.path}. ${recoveryScope}`;
    $("matched-recovery-banner").hidden = false;
    setStatus("config-status", "", "");
    furthestStep = Math.max(furthestStep, steps.indexOf("config"));
    goTo("config");
  } catch (err) {
    clearMatchedRecoveryUi();
    state.retainedAddressSearchId = searchId;
    document.dispatchEvent(new CustomEvent("address-search-reopen", {
      detail: { searchId, error: `Could not open the matched recovery: ${err}` },
    }));
  }
});

function defaultBirthdayForNetwork(network) {
  return network === "testnet" ? 280_000 : 419_200;
}

function syncUntouchedBirthdayToNetwork(network = $("network-select").value) {
  if (birthdayTouched) return;
  $("birthday-height").value = String(defaultBirthdayForNetwork(network));
  updateScanEstimate();
  updateBirthdayHint();
}

function scanBirthdayFromForm(network, rawValue) {
  const raw = String(rawValue ?? "").trim();
  if (/^\d+$/.test(raw)) return Number(raw);
  return defaultBirthdayForNetwork(network);
}

$("network-select").addEventListener("change", () => {
  if ($("server-preset").value === "recommended") {
    $("lightwalletd-url").value = SERVER_PRESETS[$("network-select").value] ?? SERVER_PRESETS.mainnet;
  }
  syncUntouchedBirthdayToNetwork();
  renderSproutScanPanel();
  refreshSproutNu7Warning();
});

// The Sprout scan panel's network select is a mirror of the one above, for
// a user with no wallet file who cannot reach the settings step. It drives
// that picker, so the endpoint preset and every NU7 warning follow it.
$("sprout-scan-network")?.addEventListener("change", () => {
  $("network-select").value = $("sprout-scan-network").value;
  $("network-select").dispatchEvent(new Event("change"));
});

$("server-preset").addEventListener("change", () => {
  const preset = $("server-preset").value;
  if (preset === "custom") return;
  const key = preset === "recommended" ? $("network-select").value : preset;
  $("lightwalletd-url").value = SERVER_PRESETS[key] ?? SERVER_PRESETS.mainnet;
  if (walletFile) void showSproutSweep();
});

$("accounts-range").addEventListener("input", () => {
  $("accounts-range-value").textContent = $("accounts-range").value;
});

$("sweep-memo").addEventListener("input", () => {
  const bytes = new TextEncoder().encode($("sweep-memo").value).length;
  const counter = $("memo-byte-count");
  counter.textContent = `${bytes} / 512 bytes`;
  counter.style.color = bytes > 512 ? "var(--danger)" : "";
});

// Gap scanning sends `gap_limit` (from #gap-limit) and no account count; a
// fixed scan sends the slider's count. So the gap row belongs to gap mode and
// the slider to fixed mode — each control is live only when it is sent.
function syncAccountScanControls() {
  const auto = $("auto-gap-limit").checked;
  $("gap-limit-row").style.display = auto ? "block" : "none";
  $("accounts-range").disabled = auto;
  $("accounts-range-value").style.opacity = auto ? "0.4" : "1";
}

$("auto-gap-limit").addEventListener("change", syncAccountScanControls);

// Approximate mainnet chain tip and scan rate for time estimates
const APPROX_CHAIN_TIP = 2_730_000;
const BLOCKS_PER_MINUTE = 38_000;

function updateScanEstimate() {
  // The Sapling scan starts no earlier than activation, so a pre-Sapling
  // birthday (which only the Sprout scan uses) costs no extra here.
  const activation = defaultBirthdayForNetwork($("network-select").value);
  const birthday = Math.max(parseInt($("birthday-height").value, 10) || 0, activation);
  const blocks = Math.max(0, APPROX_CHAIN_TIP - birthday);
  const minutes = Math.round(blocks / BLOCKS_PER_MINUTE);
  const el = $("birthday-scan-estimate");
  if (minutes <= 1) {
    el.textContent = "Estimated scan time: under 1 minute.";
  } else if (minutes < 60) {
    el.textContent = `Estimated scan time: ~${minutes} minutes.`;
  } else {
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    el.textContent = `Estimated scan time: ~${hours}h ${mins}m.`;
  }
}

// Approximate height→date with historical 150/75-second timing, then
// 25 seconds from each network's NU7 height. Calendar estimates never decide
// whether a transaction may spend. This lets us
// give the user instant round-trip feedback as they type a height.
const SAPLING_ACTIVATION_HEIGHT_JS = 419_200;
const SAPLING_ACTIVATION_DATE_JS = Date.UTC(2018, 9, 28); // Oct 28 2018
const BLOSSOM_ACTIVATION_HEIGHT_JS = 653_600;
const BLOSSOM_ACTIVATION_DATE_JS = Date.UTC(2019, 11, 11); // Dec 11 2019
const PRE_BLOSSOM_BLOCK_SECONDS = 150;
const POST_BLOSSOM_BLOCK_SECONDS = 75;
const POST_NU7_BLOCK_SECONDS = 25;
const NU7_ACTIVATION_HEIGHTS_JS = { mainnet: 3_543_405, testnet: 4_465_026 };

// Below Sapling it counts back at the same 150 s, floored at the genesis
// date: a wallet.dat birthday can be pre-Sapling, and a hint stuck at 2018
// beside it would misstate the wallet's age.
const MAINNET_GENESIS_DATE_JS = Date.UTC(2016, 9, 28); // Oct 28 2016

function approxDateFromHeight(height, network = "mainnet") {
  if (!Number.isFinite(height)) {
    return new Date(SAPLING_ACTIVATION_DATE_JS);
  }
  let anchorMs, anchorHeight, blockSeconds;
  if (height <= BLOSSOM_ACTIVATION_HEIGHT_JS) {
    anchorMs = SAPLING_ACTIVATION_DATE_JS;
    anchorHeight = SAPLING_ACTIVATION_HEIGHT_JS;
    blockSeconds = PRE_BLOSSOM_BLOCK_SECONDS;
  } else {
    anchorMs = BLOSSOM_ACTIVATION_DATE_JS;
    anchorHeight = BLOSSOM_ACTIVATION_HEIGHT_JS;
    blockSeconds = POST_BLOSSOM_BLOCK_SECONDS;
    const activation = NU7_ACTIVATION_HEIGHTS_JS[network];
    if (activation != null && height >= activation) {
      anchorMs += (activation - anchorHeight) * POST_BLOSSOM_BLOCK_SECONDS * 1000;
      anchorHeight = activation;
      blockSeconds = POST_NU7_BLOCK_SECONDS;
    }
  }
  return new Date(
    Math.max(MAINNET_GENESIS_DATE_JS, anchorMs + (height - anchorHeight) * blockSeconds * 1000),
  );
}

function formatApproxMonth(date) {
  return date.toLocaleString(undefined, { month: "short", year: "numeric", timeZone: "UTC" });
}

function setBirthdayHint(text, tone) {
  const el = $("birthday-probe-status");
  el.textContent = text;
  el.style.color =
    tone === "success" ? "var(--color-success,#137a3a)" :
    tone === "error" ? "var(--color-danger,#a8181f)" :
    "var(--color-muted,#888)";
}

function updateBirthdayHint() {
  const height = parseInt($("birthday-height").value, 10);
  if (!Number.isFinite(height) || height <= 0) {
    setBirthdayHint("", "");
    return;
  }
  const approx = formatApproxMonth(approxDateFromHeight(height, $("network-select").value));
  setBirthdayHint(`Block ${height.toLocaleString()} ≈ ${approx}.`, "");
}

// Whether the birthday field holds a value the user chose (typed, estimated
// or auto-detected) rather than its 419200 starting value. Only a chosen
// value may lower where the Sprout scan starts decrypting.
let birthdayTouched = false;

$("birthday-height").addEventListener("input", () => {
  birthdayTouched = true;
  updateScanEstimate();
  updateBirthdayHint();
});
updateScanEstimate();
updateBirthdayHint();

// Which seed auto-detect can use. A loaded wallet file wins over the typed
// box because the scan will use the file's keys; its mnemonic stays in the
// backend, so the frontend only chooses the command. A seedless zcashd
// wallet.dat is dated from its key creation times, so a loaded file always
// goes to the backend; whether it has a mnemonic, or is a seedless ZecWallet
// Lite file to refuse, is the backend's call, so its refusal is shown as
// returned rather than restated here where it could drift.
function birthdayAutodetectSource(seedText, wallet) {
  if (wallet) {
    // The passphrase is dropped once a scan starts (T-S2), so after
    // back-to-config the backend could not reopen an encrypted file.
    if (wallet.passphraseCleared && wallet.passphrase == null) {
      return {
        kind: "none",
        message:
          "This wallet file is encrypted and its passphrase was cleared when the scan started. Re-enter the passphrase on the wallet screen, then try Auto-detect again.",
      };
    }
    return { kind: "wallet" };
  }
  if (String(seedText || "").trim()) return { kind: "seed" };
  return { kind: "none", message: "Enter your seed phrase on step 2 first." };
}

// The hint for an auto-detected birthday. A seed-path result keeps its short
// form; a wallet-file result carries the backend's sentence, which names the
// source and the caveat.
function birthdayDetectHint(result, approxMonth) {
  const block = Number(result.birthday).toLocaleString();
  if (result.method === "wallet_metadata" || result.method === "transparent_utxos") {
    let text = `✓ Auto-detected birthday: block ${block} (≈ ${approxMonth}). ${result.message}`;
    if (result.method === "transparent_utxos" && !/on-chain unspent outputs/.test(text)) {
      text += " This comes from on-chain unspent outputs and may be later than the wallet's real age.";
    }
    return text;
  }
  return `✓ Auto-detected birthday: block ${block} (≈ ${approxMonth}).`;
}

async function runBirthdayAutodetect() {
  const source = birthdayAutodetectSource(seedInput.value, walletFile);
  if (source.kind === "none") {
    setBirthdayHint(source.message, "error");
    return;
  }
  const seedVal = seedInput.value.trim();
  // Phase-2 detection can run for minutes. If the user opens another wallet
  // or edits the seed meanwhile, the result belongs to the old source.
  const generation = walletOpenGeneration;
  const isCurrent = () =>
    generation === walletOpenGeneration &&
    (source.kind === "wallet" || seedInput.value.trim() === seedVal);
  $("birthday-autodetect").disabled = true;
  $("birthday-estimate").disabled = true;
  setBirthdayHint("Starting detection…", "");
  setStatus("config-status", "", "");

  const unlistenProbe = await listen("birthday-probe-progress", (event) => {
    if (isCurrent()) setBirthdayHint(event.payload, "");
  });

  try {
    const probe = {
      lightwalletdUrl: $("lightwalletd-url").value.trim(),
      network: $("network-select").value,
    };
    const result =
      source.kind === "wallet"
        ? await invoke("detect_birthday_from_wallet_file", {
            ...probe,
            reviewId: walletFile.reviewId,
            passphrase: walletFile.passphrase,
            // Scanned with the file, and undated, so they must be counted.
            saplingKeys: hasSaplingScanKeys() ? saplingScanKeyLines() : [],
          })
        : await invoke("detect_birthday", { ...probe, seed: seedVal.toLowerCase() });
    if (!isCurrent()) {
      setBirthdayHint("Auto-detect result discarded: the wallet or seed changed while it ran.", "");
      return;
    }
    $("birthday-height").value = result.birthday;
    invalidateScanAuthority();
    birthdayTouched = true;
    updateScanEstimate();
    const approx = formatApproxMonth(approxDateFromHeight(result.birthday, probe.network));
    setBirthdayHint(birthdayDetectHint(result, approx), "success");
  } catch (err) {
    if (isCurrent()) setBirthdayHint(`✗ Auto-detect failed: ${err}`, "error");
  } finally {
    $("birthday-autodetect").disabled = false;
    $("birthday-estimate").disabled = false;
    unlistenProbe();
  }
}

$("birthday-autodetect").addEventListener("click", runBirthdayAutodetect);

$("birthday-estimate").addEventListener("click", async () => {
  const dateVal = $("birthday-date").value;
  if (!dateVal) {
    setBirthdayHint("Pick a date first.", "error");
    return;
  }
  $("birthday-estimate").disabled = true;
  setBirthdayHint("Looking up block height for that date…", "");
  setStatus("config-status", "", "");
  try {
    const height = await invoke("estimate_birthday_from_date", {
      date: dateVal,
      network: $("network-select").value,
      lightwalletdUrl: $("lightwalletd-url").value.trim(),
    });
    $("birthday-height").value = height;
    invalidateScanAuthority();
    birthdayTouched = true;
    updateScanEstimate();
    const approx = formatApproxMonth(approxDateFromHeight(height, $("network-select").value));
    setBirthdayHint(
      `✓ Birthday set to block ${Number(height).toLocaleString()} (≈ ${approx}, with a conservative safety margin).`,
      "success",
    );
  } catch (err) {
    setBirthdayHint(`✗ Estimate failed: ${err}`, "error");
  } finally {
    $("birthday-estimate").disabled = false;
  }
});

async function validateDestination() {
  const address = $("destination-input").value.trim();
  if (!address) {
    setStatus("config-status", "Enter a destination address first.", "error");
    return;
  }
  try {
    const info = await invoke("validate_address", { address, network: $("network-select").value });
    if (!info.destination_ok) {
      setStatus("config-status", "✗ Address must have an Orchard or Sapling receiver.", "error");
    } else {
      const pools = [info.has_orchard && "Orchard", info.has_sapling && "Sapling"]
        .filter(Boolean)
        .join(" + ");
      setStatus("config-status", `✓ Valid Unified Address — receivers: ${pools}`, "success");
    }
  } catch (err) {
    setStatus("config-status", `✗ ${err}`, "error");
  }
}

$("destination-validate").addEventListener("click", validateDestination);
$("destination-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") { e.preventDefault(); validateDestination(); }
});

// A seed phrase is a different provenance model from a wallet file or a
// standalone Sapling key, and only one of them can drive a scan. Taking both
// and quietly preferring one would scan a wallet the user did not ask for and
// report its balance as the answer. The CLI refuses the same pairs outright
// (`--wallet-file` and `--sapling-key-file` each conflict with `--seed-file`);
// refuse them here too rather than letting the two surfaces mean different
// things. A wallet file and pasted Sapling keys do combine, as in the CLI.
function scanKeySourceConflict(hasSeed, hasWallet, hasSaplingKeys) {
  if (hasSeed && hasWallet) {
    return "A seed phrase and a wallet file cannot be scanned together — \
they are separate wallets. Run two scans: clear the seed phrase to scan the \
wallet file, or go back to the wallet screen and press Forget this file to \
scan the seed phrase.";
  }
  if (hasSeed && hasSaplingKeys) {
    return "A seed phrase and a pasted Sapling spending key cannot be scanned together — \
they are separate wallets. Run two scans: clear the key box to scan the seed \
phrase, or clear the seed phrase to scan the pasted key.";
  }
  return null;
}

$("start-scan").addEventListener("click", async () => {
  if (state.sweepExecutionPending) return;
  const generation = state.scanAuthorityGeneration;
  // Three routes to the same scan: a seed phrase, a wallet file, or a
  // pasted Sapling spending key.
  const hasTypedSaplingKeys = hasSaplingScanKeys();
  if (!state.matchedRecovery && !walletFile && !seedInput.value.trim() && !hasTypedSaplingKeys) {
    setStatus(
      "config-status",
      "A seed phrase, a wallet file, or a Sapling spending key is required — \
go back and provide one.",
      "error",
    );
    return;
  }

  const conflict = scanKeySourceConflict(
    !!seedInput.value.trim(), !!walletFile, hasTypedSaplingKeys,
  );
  if (conflict) {
    setStatus("config-status", conflict, "error");
    return;
  }

  let transparentScan = null;
  if (shouldShowTransparentRange(
    !!state.matchedRecovery, !!seedInput.value.trim(), !!walletFile,
    !!walletFile?.summary?.has_mnemonic, hasTypedSaplingKeys,
  )) {
    try {
      transparentScan = transparentScanFromInputs(
        $("transparent-index-start").value,
        $("transparent-index-count").value,
        $("transparent-include-change").checked,
      );
    } catch (err) {
      setStatus("config-status", `✗ ${err.message || err}`, "error");
      return;
    }
  }

  const address = $("destination-input").value.trim();
  if (!address) {
    setStatus("config-status", "A destination Unified Address is required.", "error");
    return;
  }

  try {
    const info = await invoke("validate_address", { address, network: $("network-select").value });
    if (generation !== state.scanAuthorityGeneration) return;
    if (!info.destination_ok) {
      setStatus("config-status", "✗ Address must have an Orchard or Sapling receiver.", "error");
      return;
    }
  } catch (err) {
    if (generation !== state.scanAuthorityGeneration) return;
    setStatus("config-status", `✗ ${err}`, "error");
    return;
  }

  state.destination = address;
  state.memo = $("sweep-memo").value.trim() || null;
  const maxFeeRaw = $("max-fee-zec").value.trim();
  if (maxFeeRaw && !/^\d*\.?\d{0,8}$/.test(maxFeeRaw)) {
    setStatus("config-status", "✗ Max fee must be a valid ZEC amount (e.g. 0.0002)", "error");
    $("start-scan").disabled = false;
    return;
  }
  state.maxFeeZec = maxFeeRaw || null;

  let dataDirVal = $("data-dir").value.trim();
  if (!dataDirVal) {
    try {
      dataDirVal = await invoke("default_data_dir");
      if (generation !== state.scanAuthorityGeneration) return;
      $("data-dir").value = dataDirVal;
    } catch (_) {
      if (generation !== state.scanAuthorityGeneration) return;
      setStatus("config-status", "✗ Could not determine a data directory. Please enter one manually.", "error");
      $("start-scan").disabled = false;
      return;
    }
  }

  const autoGap = $("auto-gap-limit").checked;
  const labelRaw = ($("scan-label")?.value ?? "").trim();
  const network = $("network-select").value;
  const config = {
    seed: seedInput.value.trim().toLowerCase(),
    birthday: scanBirthdayFromForm(network, $("birthday-height").value),
    num_accounts: state.matchedRecovery ? 1 : (autoGap ? null : parseInt($("accounts-range").value, 10)),
    gap_limit: state.matchedRecovery ? 1 : (autoGap ? parseInt($("gap-limit").value, 10) : 20),
    lightwalletd_url: $("lightwalletd-url").value.trim(),
    confirmation_sources: confirmationSourcesFromForm(),
    data_dir: dataDirVal,
    network,
    label: labelRaw || defaultScanLabel(),
    transparent_scan: transparentScan,
  };
  // Store a seed-less copy. The seed is passed to `start_scan` below, but
  // must not persist in JS state for the lifetime of the scan→sweep→complete
  // flow (threat model T-S2).
  const { seed: _seed, ...configForState } = config;
  state.scanConfig = configForState;

  setStatus("config-status", "Starting scan…", "");
  $("start-scan").disabled = true;

  let matched = null;
  try {
    let handle;
    // Raw lines, so the backend applies its own skip rule and its errors
    // number the lines the user sees. Empty when the box holds nothing but
    // comments, so a wallet-file-only scan is not handed a key set to reject.
    const typedSaplingKeys = hasTypedSaplingKeys ? saplingScanKeyLines() : [];
    showScanWarning(
      scanWarningVariant(walletFile, typedSaplingKeys.length, !!state.matchedRecovery),
    );
    if (state.matchedRecovery) {
      matched = state.matchedRecovery;
      const matchedConfig = configForMatchedRecovery(config);
      state.addressMatchRecoveryLocked = true;
      state.addressMatchRecoveryStartGeneration = generation;
      document.dispatchEvent(new CustomEvent("address-search-lock-recovery", { detail: { locked: true } }));
      handle = await invoke("start_matched_recovery", {
        searchId: matched.searchId,
        matchId: matched.matchId,
        // The backend refuses a memo this sweep cannot send before scanning;
        // the sweep screen has no memo field to remove it from afterwards.
        config: { ...matchedConfig, sweep_memo: state.memo },
      });
    } else if (walletFile || typedSaplingKeys.length) {
      // Routing between the HD path and the imported-account path lives in
      // the core service, not here: it depends on whether the file yielded a
      // mnemonic, which only the backend knows. The GUI just hands over the
      // key material it was given.
      const { seed: _unused, ...rest } = config;
      handle = await invoke("start_scan_from_wallet_file", {
        config: {
          ...rest,
          review_id: walletFile ? walletFile.reviewId : null,
          passphrase: walletFile ? walletFile.passphrase : null,
          sapling_keys: typedSaplingKeys,
          // Checked against the key source before the scan starts.
          sweep_memo: state.memo,
          // Checked before the scan: a seedless sweep's transparent leg
          // cannot pay an Orchard-only address.
          destination: state.destination,
        },
      });
    } else {
      handle = await invoke("start_scan", { config });
    }
    if (generation !== state.scanAuthorityGeneration) {
      // The backend may have started scan A after its form was edited into B.
      // It is no longer UI authority; release it without disturbing B.
      invoke("release_scan", { handle }).catch(() => {});
      if (matched && state.matchedRecovery === matched &&
          state.addressMatchRecoveryStartGeneration === generation) {
        state.addressMatchRecoveryLocked = false;
        state.addressMatchRecoveryStartGeneration = null;
        document.dispatchEvent(new CustomEvent("address-search-lock-recovery", { detail: { locked: false } }));
      }
      return;
    }
    if (matched) {
      state.matchedRecovery = null;
      clearMatchedRecoveryUi();
    }
    state.scanHandle = handle;
    if (state.retainedAddressSearchId) {
      document.dispatchEvent(new CustomEvent("address-search-lock-recovery", { detail: { locked: true } }));
    }
    // The backend now owns the scan authority. Drop every transient plaintext
    // input while retaining only the opaque backend handles needed to resume.
    clearTransientSecrets();
    $("sapling-key-addresses").innerHTML = "";
    goTo("scan");
    await startProgressListeners(handle);
  } catch (err) {
    if (generation !== state.scanAuthorityGeneration) {
      if (matched && state.matchedRecovery === matched &&
          state.addressMatchRecoveryStartGeneration === generation) {
        state.addressMatchRecoveryLocked = false;
        state.addressMatchRecoveryStartGeneration = null;
        document.dispatchEvent(new CustomEvent("address-search-lock-recovery", { detail: { locked: false } }));
      }
      return;
    }
    if (state.matchedRecovery) {
      state.addressMatchRecoveryLocked = false;
      state.addressMatchRecoveryStartGeneration = null;
      document.dispatchEvent(new CustomEvent("address-search-lock-recovery", { detail: { locked: false } }));
    }
    setStatus("config-status", `✗ ${err}`, "error");
    // A rejected start has not accepted these secrets. Keep the wallet
    // passphrase and pasted keys available for a corrected-directory retry,
    // without extending an existing wallet review deadline.
    if (walletReviewExpiryTimer === null && (walletFile || hasTypedSaplingKeys)) scheduleWalletReviewExpiry();
    $("start-scan").disabled = false;
  } finally {
    // Clear the seed phrase from the DOM regardless of whether start_scan
    // succeeded; on failure the user can retype, and a successful scan no
    // longer needs the cleartext phrase visible. Wallet/key inputs are
    // cleared only after acceptance, abandonment, or their review expiry.
    if (generation === state.scanAuthorityGeneration) {
      seedInput.value = "";
      $("seed-visibility").checked = false;
      seedInput.classList.add("masked");
    }
  }
});

// ─── Step 4: Scan Progress ────────────────────────────────────────────────────

async function startProgressListeners(expectedHandle) {
  const expectedId = expectedHandle.id;
  const expectedGeneration = state.scanAuthorityGeneration;
  const isCurrent = () => state.scanAuthorityGeneration === expectedGeneration &&
    state.scanHandle?.id === expectedId;
  let terminalEventSeen = false;
  $("scan-phase").textContent = "Starting…";
  $("scan-server").textContent = "Connecting…";
  $("scan-progress-text").textContent = "0 / 0";
  $("scan-eta").textContent = "Calculating…";
  $("scan-progress-bar").style.width = "0%";
  $("scan-rows").innerHTML = "";
  setStatus("scan-message", "", "");
  $("review-sweep").disabled = true;
  $("scan-saved-transactions").disabled = true;
  $("back-to-config").style.display = "none";
  $("scan-return-address-matches").hidden = true;
  $("cancel-scan").disabled = false;
  // Reset the sleep + sandblasting + gap-extension banners so a previous
  // scan's state doesn't carry over into a fresh start.
  $("scan-sleep-banner").style.display = "none";
  $("scan-sleep-detail").textContent = "";
  $("scan-sandblasting-banner").style.display = "none";
  $("scan-gap-extension-banner").style.display = "none";
  $("scan-gap-extension-detail").textContent = "";
  eta.reset();

  // Await all three subscriptions before returning. If we stored the unlisten
  // handles via .then() callbacks, a fast scan-complete event could fire and
  // run cleanupListeners() before the handles were assigned, leaking the
  // subscriptions across scans.
  $("scan-discoveries").innerHTML = "";
  $("scan-discoveries").style.display = "none";

  const [unlistenProgress, unlistenComplete, unlistenDiscovered] = await Promise.all([
    listen("scan-progress", (event) => {
      if (event.payload.handle?.id !== expectedId || !isCurrent() || terminalEventSeen) return;
      updateScanUI(event.payload);
    }),
    listen("scan-complete", (event) => {
      if (event.payload.handle?.id !== expectedId || !isCurrent() || terminalEventSeen) return;
      terminalEventSeen = true;
      updateScanUI(event.payload);
      notifyScanComplete(event.payload);
      cleanupListeners();
    }),
    listen("scan-discovery", (event) => {
      if (event.payload.handle?.id !== expectedId || !isCurrent() || terminalEventSeen) return;
      const d = event.payload.discovery;
      const div = document.createElement("div");
      div.className = "discovery-toast";
      // at_block_height is the scan frontier when first observed, not the
      // mined height of the funding transaction — label it that way.
      const heightHint = d.at_block_height
        ? ` (scanned through block ${d.at_block_height.toLocaleString()})`
        : "";
      div.textContent =
        `Found ${fmt(d.zatoshis)} on account ${d.account_index} — ${d.pool}${heightHint}. `;
      // Removed by updateScanUI once the scan ends, so a finished scan never
      // still claims to be running.
      const pending = document.createElement("span");
      pending.className = "discovery-pending";
      pending.textContent = "Shielded scan still running — Review & Sweep will unlock when complete.";
      div.appendChild(pending);
      const container = $("scan-discoveries");
      container.appendChild(div);
      container.style.display = "";
    }),
  ]);
  if (!isCurrent()) {
    unlistenProgress();
    unlistenComplete();
    unlistenDiscovered();
    return;
  }
  state.unlistenProgress = unlistenProgress;
  state.unlistenComplete = unlistenComplete;
  state.unlistenDiscovered = unlistenDiscovered;
  if (terminalEventSeen) {
    cleanupListeners();
    return;
  }
  // A fast scan can finish before the completion subscription exists. Query
  // the backend after registration and apply only this scan's live snapshot.
  try {
    const progress = await invoke("get_scan_progress", { handle: { id: expectedId } });
    if (!isCurrent() || terminalEventSeen || progress?.handle?.id !== expectedId) return;
    updateScanUI(progress);
    if (["complete", "cancelled", "error"].includes(progress.phase)) {
      notifyScanComplete(progress);
      cleanupListeners();
    }
  } catch (err) {
    if (isCurrent() && !terminalEventSeen) {
      setStatus("scan-message", `Could not refresh scan progress: ${err}`, "error");
    }
  }
}

function scanCompletionSummary(progress) {
  if (progress.error) return progress.error;
  // Reserve "no funds were found" for actually-completed scans. A
  // cancelled scan that hadn't yet observed any funds shouldn't claim
  // the seed is empty — it just stopped early.
  if (progress.phase === "cancelled") {
    return "Scan stopped before completion. Re-run with the same flags to resume.";
  }
  const funded = (progress.accounts || []).filter((a) => Number(a.total_zatoshis) > 0);
  if (funded.length === 0) return "No funds were found across all scanned accounts.";
  const total = funded.reduce((sum, a) => sum + Number(a.total_zatoshis), 0);
  const noun = funded.length === 1 ? "account" : "accounts";
  return `Found ${fmt(total)} ${funded.length === 1 ? "on 1" : `across ${funded.length}`} ${noun}.`;
}

function notifyScanComplete(progress) {
  let title;
  switch (progress.phase) {
    case "complete":  title = "Argos scan complete"; break;
    case "cancelled": title = "Argos scan cancelled"; break;
    case "error":     title = "Argos scan failed"; break;
    default: return;
  }
  invoke("notify_user", { title, body: scanCompletionSummary(progress) }).catch(() => {});
}

function cleanupListeners() {
  state.unlistenProgress?.();
  state.unlistenComplete?.();
  state.unlistenDiscovered?.();
  state.unlistenProgress = null;
  state.unlistenComplete = null;
  state.unlistenDiscovered = null;
}

// What the scan status row shows, as a pure function of the progress payload.
//
// The "Connecting…", "0 / 0" and "Calculating…" placeholders are only replaced
// by a block scan. A transparent-only wallet has no block scan, so it used to
// finish as "Complete ✓" next to all three, plus an era hint for the chain tip.
// Once the scan has ended, anything it never reported reads as "—" instead.
// `server: null` means leave the field as it is.
function scanStatusFields(progress, etaState, era, primaryEndpoint) {
  const terminal = ["complete", "cancelled", "error"].includes(progress.phase);
  const scanned = Number(progress.blocks_scanned);
  const total = Number(progress.blocks_total);

  let server = null;
  let serverTitle = "";
  const endpoint = progress.server?.endpoint;
  if (endpoint) {
    const isFallback = endpoint !== primaryEndpoint;
    server = endpoint + (isFallback ? " (fallback)" : "");
    if (isFallback) {
      serverTitle = "Connected to a fallback server — a different operator can see your scan activity";
    }
  } else if (terminal) {
    server = "—";
  }

  const progressText = total === 0 && terminal
    ? "—"
    : `${scanned.toLocaleString()} / ${total.toLocaleString()}`;

  let barPercent = null;
  if (progress.phase === "complete") {
    barPercent = 100;
  } else if (total > 0) {
    barPercent = Math.min(100, (scanned / total) * 100);
  }

  let etaText = "";
  if (!terminal) {
    if (etaState.kind === "warmup") etaText = "Calculating…";
    else if (etaState.kind !== "done") etaText = etaState.text;
    if (era) etaText = etaText ? `${etaText} · scanning ~${era}` : `scanning ~${era}`;
  }

  return { terminal, server, serverTitle, progressText, barPercent, etaText };
}

function scanAccountTotalText(progress, amount) {
  const count = progress.accounts.length;
  const estimate = progress.summary.authoritative_balances ? "" : " (estimates)";
  if (progress.phase === "complete") return `Scan total: ${amount}${estimate} across ${count} checked accounts.`;
  if (["cancelled", "error"].includes(progress.phase)) {
    return `Partial total: ${amount}${estimate} · ${count} accounts loaded; scan unfinished.`;
  }
  return `Found so far: ${amount}${estimate} · ${count} accounts loaded; scan in progress.`;
}

function gapExtensionDetail(extension) {
  return `Activity was found in account ${extension.trigger_account_index}. ` +
    `Additional accounts ${extension.accounts_from}–${extension.accounts_to} are being checked ` +
    `(extension #${extension.pass}). `;
}

function updateScanUI(progress) {
  state.lastProgress = progress;

  $("scan-phase").textContent = phaseLabel(progress.phase);

  const scanned = Number(progress.blocks_scanned);
  const total = Number(progress.blocks_total);
  eta.observe(scanned, total);
  // eraHint expects an absolute Zcash chain height. blocks_scanned is a
  // delta from effective_birthday — passing it directly mislabels the era
  // for any wallet whose birthday is past Sapling activation. Use
  // synced_to_height (set by the backend) when available.
  const era = progress.synced_to_height ? eraHint(Number(progress.synced_to_height)) : null;
  const primary = $("lightwalletd-url").value.split(",")[0].trim();
  const fields = scanStatusFields(progress, eta.estimate(), era, primary);

  if (fields.server !== null) {
    $("scan-server").textContent = fields.server;
    $("scan-server").title = fields.serverTitle;
  }
  $("scan-progress-text").textContent = fields.progressText;
  if (fields.barPercent !== null) {
    $("scan-progress-bar").style.width = `${fields.barPercent.toFixed(1)}%`;
  }
  $("scan-eta").textContent = fields.etaText;
  if (fields.terminal) {
    document.querySelectorAll("#scan-discoveries .discovery-pending").forEach((el) => el.remove());
  }

  if (progress.error) {
    setStatus("scan-message", progress.error, "error");
    $("back-to-config").style.display = state.retainedAddressSearchId ? "none" : "";
  } else if (progress.message) {
    setStatus("scan-message", progress.message, "");
  }

  if (progress.summary) {
    const s = progress.summary;
    $("scan-totals").textContent = scanAccountTotalText(progress, fmt(s.total_zatoshis));
    $("scan-workspace").textContent = `Workspace: ${s.workspace_dir}`;
  }

  renderAccountRows(progress.accounts);

  // sleep_event is sticky on the backend — once the poller spots a suspend
  // the banner stays up for the rest of the scan, with timestamps and lost
  // time refreshed if the machine sleeps again. Reset happens on the next
  // start, in startProgressListeners.
  if (progress.sleep_event) {
    $("scan-sleep-banner").style.display = "";
    $("scan-sleep-detail").textContent = formatSleepDetail(progress.sleep_event);
  }

  // Sandblasting era toggles based on the current cursor — the banner
  // appears while traversing the slow zone and disappears once past it.
  $("scan-sandblasting-banner").style.display = progress.in_sandblasting_zone ? "" : "none";

  // Gap extension: the block counter resets to zero when the search widens to
  // a new slice of accounts. Without explanation that reads as the scan
  // restarting, so surface a banner naming the trigger and the new range.
  // Only while actively scanning — the completion screen tells the full story.
  const inTerminalPhase = ["complete", "cancelled", "error"].includes(progress.phase);
  if (progress.gap_extension && !inTerminalPhase) {
    $("scan-gap-extension-detail").textContent = gapExtensionDetail(progress.gap_extension);
    $("scan-gap-extension-banner").style.display = "";
  } else {
    $("scan-gap-extension-banner").style.display = "none";
  }

  const terminal = ["complete", "cancelled", "error"].includes(progress.phase);
  if (terminal) clearTransientSecrets();
  if (progress.phase === "cancelled" && !state.retainedAddressSearchId) {
    $("back-to-config").style.display = "";
    $("start-scan").disabled = false;
  }
  if (terminal && state.retainedAddressSearchId) {
    const canReturn = canReturnToAddressMatches(progress, state.retainedAddressSearchId);
    state.addressMatchRecoveryLocked = !canReturn;
    document.dispatchEvent(new CustomEvent("address-search-lock-recovery", {
      detail: { locked: !canReturn },
    }));
  }
  $("cancel-scan").style.display = terminal ? "none" : "";
  $("scan-return-address-matches").hidden =
    !canReturnToAddressMatches(progress, state.retainedAddressSearchId);
  if (progress.phase === "complete") {
    $("review-sweep").disabled = false;
    $("scan-saved-transactions").disabled = false;
  }
}

function canReturnToAddressMatches(progress, retainedSearchId) {
  const terminal = ["complete", "cancelled", "error"].includes(progress.phase);
  const completedWithFunds = progress.phase === "complete" &&
    Number(progress.summary?.total_zatoshis || 0) > 0;
  return !!retainedSearchId && terminal && !completedWithFunds;
}

function returnToAddressMatches() {
  const searchId = state.retainedAddressSearchId || state.matchedRecovery?.searchId;
  if (!searchId) return;
  const handle = state.scanHandle;
  if (handle) invoke("release_scan", { handle }).catch(() => {});
  cleanupListeners();
  clearMatchedRecoveryUi();
  state.scanHandle = null;
  state.lastProgress = null;
  invalidateSweepReview();
  $("scan-saved-transactions").disabled = true;
  state.addressMatchRecoveryLocked = false;
  $("start-scan").disabled = false;
  setStatus("config-status", "", "");
  $("scan-return-address-matches").hidden = true;
  $("complete-return-address-matches").hidden = true;
  document.dispatchEvent(new CustomEvent("address-search-reopen", { detail: { searchId } }));
}

$("scan-return-address-matches").addEventListener("click", returnToAddressMatches);
$("complete-return-address-matches").addEventListener("click", returnToAddressMatches);
document.addEventListener("address-search-released", (event) => {
  if (!event.detail?.searchId || event.detail.searchId === state.retainedAddressSearchId) {
    state.retainedAddressSearchId = null;
    state.addressMatchRecoveryLocked = false;
    $("scan-return-address-matches").hidden = true;
    $("complete-return-address-matches").hidden = true;
  }
});

function renderAccountRows(accounts) {
  const tbody = $("scan-rows");
  tbody.replaceChildren();
  accounts.forEach((acc) => {
    const tr = document.createElement("tr");
    appendCell(tr, String(acc.account_index));
    appendCell(tr, fmt(acc.sapling_zatoshis));
    appendCell(tr, fmt(acc.orchard_zatoshis));
    appendCell(tr, fmt(acc.transparent_zatoshis));
    appendCell(tr, fmt(acc.total_zatoshis));
    appendCell(tr, String(acc.status));
    tbody.appendChild(tr);
  });
}

function appendCell(tr, text) {
  const td = document.createElement("td");
  td.textContent = text;
  tr.appendChild(td);
}

$("back-to-config").addEventListener("click", () => {
  invalidateScanAuthority();
  $("back-to-config").style.display = "none";
  $("start-scan").disabled = false;
  goTo("config");
});

$("cancel-scan").addEventListener("click", async () => {
  if (!state.scanHandle) return;
  try {
    await invoke("cancel_scan", { handle: state.scanHandle });
    clearTransientSecrets();
    $("cancel-scan").disabled = true;
    setStatus("scan-message", "Cancellation requested… waiting for the scan to stop safely.", "");
    // Refresh in case the terminal event arrived before the cancel response.
    const progress = await invoke("get_scan_progress", { handle: state.scanHandle });
    if (progress.handle?.id === state.scanHandle?.id) updateScanUI(progress);
  } catch (err) {
    setStatus("scan-message", `Cancel failed: ${err}`, "error");
  }
});

function invalidateScanAuthority() {
  state.scanAuthorityGeneration += 1;
  const handles = [state.scanHandle, state.completedScanHandle]
    .filter((handle, index, all) => handle &&
      all.findIndex((candidate) => candidate?.id === handle.id) === index);
  for (const handle of handles) {
    invoke("release_scan", { handle }).catch(() => {});
  }
  cleanupListeners();
  invalidateSweepReview();
  state.scanHandle = null;
  state.completedScanHandle = null;
  state.lastProgress = null;
  state.scanConfig = null;
  state.savedReportPath = null;
  $("scan-phase").textContent = "Idle";
  $("scan-server").textContent = "Not connected";
  $("scan-progress-text").textContent = "0 / 0";
  $("scan-eta").textContent = "Calculating…";
  $("scan-progress-bar").style.width = "0%";
  $("scan-rows").innerHTML = "";
  $("scan-discoveries").innerHTML = "";
  $("scan-discoveries").style.display = "none";
  $("scan-totals").textContent = "Balance: 0.00000000 ZEC · 0 accounts loaded.";
  $("scan-workspace").textContent = "Workspace: not initialized";
  $("scan-sleep-banner").style.display = "none";
  $("scan-sandblasting-banner").style.display = "none";
  $("scan-gap-extension-banner").style.display = "none";
  $("scan-sleep-detail").textContent = "";
  $("scan-gap-extension-detail").textContent = "";
  $("sweep-rows").innerHTML = "";
  $("sweep-skipped").innerHTML = "";
  $("sweep-summary").textContent = "";
  $("copy-report-path").style.display = "none";
  setStatus("scan-message", "", "");
  $("review-sweep").disabled = true;
  $("scan-saved-transactions").disabled = true;
  $("back-to-config").style.display = "none";
  $("cancel-scan").disabled = true;
  $("start-scan").disabled = state.sweepExecutionPending;
  eta.reset();
}

for (const id of [
  "seed-input", "wallet-path", "wallet-passphrase", "sapling-scan-keys",
  "network-select", "birthday-height", "accounts-range", "auto-gap-limit",
  "gap-limit", "transparent-index-start", "transparent-index-count",
  "transparent-include-change", "lightwalletd-url", "confirmation-sources", "server-preset", "data-dir",
  "sprout-scan-peers",
]) {
  $(id)?.addEventListener("input", invalidateScanAuthority);
  $(id)?.addEventListener("change", invalidateScanAuthority);
}

$("wallet-path")?.addEventListener("input", () => {
  const path = $("wallet-path").value;
  forgetLoadedWalletFile();
  $("wallet-path").value = path;
});

function donationParamsFromForm() {
  if (!state.donationEnabled) return { donationRate: null, donorEmail: null };
  const enabled = $("donate-enabled").checked;
  const pct = parseFloat($("donate-rate").value);
  const donationRate = enabled && Number.isFinite(pct) && pct > 0 ? pct / 100 : null;
  const donorEmail = enabled ? ($("donate-email").value.trim() || null) : null;
  return { donationRate, donorEmail };
}

function invalidateSweepReview() {
  state.proposalGeneration += 1;
  state.sweepReview = null;
  state.proposalPending = false;
  $("irreversible-check").checked = false;
  $("irreversible-check").disabled = true;
  $("execute-sweep").disabled = true;
  if (!state.sweepExecutionPending) setStatus("sweep-execute-status", "", "");
}

function setSweepProposalPending(pending) {
  state.proposalPending = pending;
  if (pending) {
    state.sweepReview = null;
    $("irreversible-check").checked = false;
    $("irreversible-check").disabled = true;
    $("execute-sweep").disabled = true;
    setStatus("sweep-execute-status", "", "");
  }
}

function sweepRequestFromForm() {
  const { donationRate, donorEmail } = donationParamsFromForm();
  return {
    handle: state.scanHandle,
    destination: $("destination-input").value.trim(),
    memo: $("sweep-memo").value.trim() || null,
    maxFeeZec: $("max-fee-zec").value.trim() || null,
    donationRate,
    donorEmail,
  };
}

async function refreshSweepProposal() {
  if (state.sweepExecutionPending) return null;
  invalidateSweepReview();
  setSweepProposalPending(true);
  const generation = state.proposalGeneration;
  const handleId = state.scanHandle?.id;
  const request = sweepRequestFromForm();
  const autoFeeCap = state.autoFeeCapZec != null &&
    $("max-fee-zec").value.trim() === state.autoFeeCapZec;
  if (autoFeeCap) {
    request.maxFeeZec = null;
    $("max-fee-zec").value = "";
    state.maxFeeZec = null;
    state.autoFeeCapZec = null;
  }
  try {
    const review = await invoke("propose_sweep", request);
    if (generation !== state.proposalGeneration || handleId !== state.scanHandle?.id) return null;
    if (!$("max-fee-zec").value.trim() || autoFeeCap) {
      const zatoshis = BigInt(review.proposal.total_fee_zatoshis);
      const exactCap = `${zatoshis / 100000000n}.${String(zatoshis % 100000000n).padStart(8, "0")}`;
      $("max-fee-zec").value = exactCap;
      state.maxFeeZec = exactCap;
      state.autoFeeCapZec = exactCap;
    } else {
      state.autoFeeCapZec = null;
    }
    state.sweepReview = { ...review, handleId, donationRateForDisplay: request.donationRate };
    setSweepProposalPending(false);
    renderSweepProposal(review.proposal);
    return review;
  } catch (err) {
    if (generation !== state.proposalGeneration || handleId !== state.scanHandle?.id) return null;
    invalidateSweepReview();
    setStatus("sweep-execute-status", `✗ ${err}`, "error");
    throw err;
  }
}

async function maybeRefreshProposal() {
  if (state.sweepExecutionPending || !state.scanHandle || state.lastProgress?.phase !== "complete") return;
  try {
    await refreshSweepProposal();
  } catch (err) {
    // refreshSweepProposal displays errors only for the current generation.
  }
}

$("review-sweep").addEventListener("click", async () => {
  if (state.sweepExecutionPending) return;
  setStatus("scan-message", "Fetching sweep proposal…", "");
  $("review-sweep").disabled = true;

  try {
    if (await refreshSweepProposal()) goTo("sweep");
  } catch (err) {
    const message = String(err);
    const guidance = message.includes("unresolved prepared transaction history")
      ? " Use Saved transaction status to inspect or explicitly retry stored bytes." : "";
    setStatus("scan-message", `✗ ${message}${guidance}`, "error");
    $("review-sweep").disabled = false;
  }
});

async function showSavedTransactions() {
  const handle = state.scanHandle;
  if (!handle || state.lastProgress?.phase !== "complete") return;
  const button = $("scan-saved-transactions");
  button.disabled = true;
  setStatus("scan-message", "Checking saved transaction history…", "");
  try {
    const rows = await invoke("reconcile_sweep", { handle });
    if (state.scanHandle?.id !== handle.id) return;
    if (!rows.length) {
      setStatus("scan-message", "No saved transaction receipts were found for this network.", "");
      return;
    }
    const outcome = {
      transactions: rows.map((row) => ({ source_account: null, ...row })),
      skipped_accounts: [], total_donation_zatoshis: 0, donation_note: null,
      error: null, follow_up_review_required: false,
    };
    const completionContext = {
      handle, outcome, statusOnly: true, scanConfig: state.scanConfig,
      lastProgress: state.lastProgress, donationRate: null,
    };
    state.completedScanHandle = handle;
    invalidateSweepReview();
    state.lastProgress = null;
    $("review-sweep").disabled = true;
    await renderCompleteScreen(outcome.transactions, [], 0, null, null, null, completionContext);
    goTo("complete");
  } catch (error) {
    if (state.scanHandle?.id === handle.id) {
      setStatus("scan-message", `Could not check saved transactions: ${error}`, "error");
    }
  } finally {
    button.disabled = state.scanHandle?.id !== handle.id || state.lastProgress?.phase !== "complete";
  }
}

$("scan-saved-transactions").addEventListener("click", showSavedTransactions);

$("sweep-back").addEventListener("click", () => {
  // Re-enable Review & Sweep so the user can navigate back to sweep via the
  // button (or left-hand menu) without having to re-run the scan.
  if (state.lastProgress?.phase === "complete") {
    $("review-sweep").disabled = false;
  }
  goTo("scan");
});

// Client-side per-chip estimate: donation as a % of what you'd net without a
// donation. Only the *selected* rate is ever sent to the backend; the chips
// just preview amounts so we don't fan out three propose_sweep calls.
function estimateDonationZat(pct) {
  const p = state.sweepReview?.proposal;
  if (!p) return null;
  const base = (p.net_received_zatoshis || 0) + (p.total_donation_zatoshis || 0);
  return Math.round((base * pct) / 100);
}

// Reflect a chosen percentage into the source-of-truth fields and re-propose.
function selectDonationPreset(pctValue) {
  const custom = pctValue === "custom";
  $("donate-enabled").checked = true;
  $("donate-form").classList.remove("donate-collapsed");
  $("donate-fields").hidden = !custom;
  if (!custom) $("donate-rate").value = String(pctValue);
  document.querySelectorAll("#donate-presets .preset-chip").forEach((chip) => {
    chip.setAttribute(
      "aria-pressed",
      String(chip.dataset.pct === String(pctValue)),
    );
  });
  invalidateSweepReview();
  maybeRefreshProposal();
}

document.querySelectorAll("#donate-presets .preset-chip").forEach((chip) => {
  chip.addEventListener("click", () => selectDonationPreset(chip.dataset.pct));
});

// Custom field: keep its chip highlighted while typing; re-propose on change.
$("donate-rate").addEventListener("input", () => {
  invalidateSweepReview();
  document.querySelectorAll("#donate-presets .preset-chip").forEach((chip) => {
    chip.setAttribute("aria-pressed", String(chip.dataset.pct === "custom"));
  });
});
$("donate-rate").addEventListener("change", maybeRefreshProposal);

// Skip toggles the donation off (collapse) / back on (default 10%). The
// eyebrow + story copy stay visible either way.
$("donate-skip").addEventListener("click", () => {
  const turningOff = $("donate-enabled").checked;
  if (turningOff) {
    $("donate-enabled").checked = false;
    $("donate-form").classList.add("donate-collapsed");
    document.querySelectorAll("#donate-presets .preset-chip").forEach((chip) => {
      chip.setAttribute("aria-pressed", "false");
    });
    $("donate-skip").textContent = "Changed your mind? Add a donation";
    invalidateSweepReview();
    maybeRefreshProposal();
  } else {
    $("donate-skip").textContent = "No thanks, skip donation";
    selectDonationPreset("10"); // re-enables, un-collapses, and re-proposes
  }
});

for (const id of ["destination-input", "sweep-memo", "max-fee-zec", "donate-email", "donate-enabled"]) {
  $(id).addEventListener("input", () => {
    if (id === "max-fee-zec") {
      state.autoFeeCapZec = null;
      state.maxFeeZec = $(id).value.trim() || null;
    }
    invalidateSweepReview();
  });
  $(id).addEventListener("change", maybeRefreshProposal);
}

// ─── Step 5: Sweep Review ─────────────────────────────────────────────────────

function renderSweepProposal(proposal) {
  const tbody = $("sweep-rows");
  tbody.replaceChildren();

  proposal.transactions.forEach((tx) => {
    const kindLabel = tx.kind === "shield_transparent" ? "Shield" : "Sweep";
    const dest = tx.destination;
    const shortDest =
      dest.length > 26 ? dest.slice(0, 12) + "…" + dest.slice(-10) : dest;
    const tr = document.createElement("tr");
    appendCell(tr, String(tx.source_account));
    appendCell(tr, kindLabel);

    const destCell = document.createElement("td");
    destCell.title = dest;
    destCell.style.cursor = "pointer";
    destCell.dataset.copy = dest;
    destCell.appendChild(document.createTextNode(shortDest + " "));
    const clip = document.createElement("small");
    clip.textContent = "📋";
    destCell.appendChild(clip);
    tr.appendChild(destCell);

    appendCell(tr, fmt(tx.gross_zatoshis));
    appendCell(tr, fmt(tx.fee_zatoshis));
    appendCell(tr, fmt(tx.net_zatoshis));
    appendCell(tr, fmt(tx.donation_zatoshis || 0));
    appendCell(tr, String(tx.memo ?? "—"));
    tbody.appendChild(tr);
  });

  $("sweep-summary").textContent =
    `Net received: ${fmt(proposal.net_received_zatoshis)} after ${fmt(proposal.total_fee_zatoshis)} in fees.` +
    (proposal.warning ? `  ⚠ ${proposal.warning}` : "") +
    (proposal.confirmation_notice ? `  ${proposal.confirmation_notice}` : "");

  const skippedEl = $("sweep-skipped");
  skippedEl.replaceChildren();
  if (proposal.skipped_accounts.length > 0) {
    const heading = document.createElement("p");
    heading.style.margin = "6px 0 4px";
    heading.style.fontWeight = "700";
    heading.style.color = "var(--muted)";
    heading.textContent = "Skipped accounts";
    skippedEl.appendChild(heading);

    const list = document.createElement("ul");
    list.className = "discovery-list";
    proposal.skipped_accounts.forEach((s) => {
      const li = document.createElement("li");
      li.textContent = `Account ${s.account_index}: ${s.reason} (${fmt(s.gross_zatoshis)})`;
      list.appendChild(li);
    });
    skippedEl.appendChild(list);
  }

  $("donate-form").hidden = !state.donationEnabled || state.scanConfig?.network === "testnet";
  // Fill each preset chip's "≈ X ZEC" estimate from the current proposal.
  document.querySelectorAll("#donate-presets .preset-chip").forEach((chip) => {
    if (chip.dataset.pct === "custom") return;
    const est = estimateDonationZat(parseFloat(chip.dataset.pct));
    chip.querySelector(".preset-amt").textContent =
      est == null ? "" : `≈ ${fmt(est)}`;
  });
  const donated = proposal.total_donation_zatoshis || 0;
  const preview = $("donate-amount-preview");
  if (donated > 0) {
    const net = (proposal.net_received_zatoshis || 0) - donated;
    preview.textContent =
      `Estimated donation: ${fmt(donated)} · Net to you: ${fmt(net)}. ` +
      "This is an estimate — the donation is computed per-account at the real network fee when the sweep runs, and may be lower (or 0) if your funds are spread across several small accounts. The actual donated amount is shown when the sweep completes.";
  } else if (proposal.donation_note && state.donationEnabled && $("donate-enabled").checked) {
    // This route can never include a donation, whatever the fee.
    preview.textContent = proposal.donation_note;
  } else if (state.donationEnabled && $("donate-enabled").checked && state.scanConfig?.network !== "testnet") {
    // The proposal estimate uses a fixed ZIP-317 floor; execution uses the
    // real fee. Right at the donation threshold the two can disagree by a
    // few thousand zatoshis, so a "below threshold" preview is only a
    // best-estimate — name that explicitly rather than implying a guarantee.
    preview.textContent =
      "Donation is below the minimum threshold at the estimated fee — may be included or skipped at execution time depending on the real ZIP-317 fee. Funds are never at risk either way.";
  } else {
    preview.textContent = "";
  }

  $("irreversible-check").checked = false;
  $("irreversible-check").disabled = false;
  $("execute-sweep").disabled = true;
}

// Copy-address click handler for sweep table — wired once here so it doesn't
// accumulate duplicates if renderSweepProposal is called more than once.
$("sweep-rows").addEventListener("click", (e) => {
  const cell = e.target.closest("[data-copy]");
  if (!cell) return;
  navigator.clipboard.writeText(cell.dataset.copy).then(() => {
    const orig = cell.cloneNode(true);
    cell.replaceChildren(document.createTextNode("Copied!"));
    setTimeout(() => {
      cell.replaceChildren(...orig.childNodes);
    }, 1200);
  });
});

$("irreversible-check").addEventListener("change", () => {
  $("execute-sweep").disabled = state.sweepExecutionPending || !state.sweepReview || state.proposalPending ||
    state.sweepReview.handleId !== state.scanHandle?.id || !$("irreversible-check").checked;
});

$("execute-sweep").addEventListener("click", async () => {
  const review = state.sweepReview;
  if (state.sweepExecutionPending || !review || state.proposalPending ||
      review.handleId !== state.scanHandle?.id ||
      !$("irreversible-check").checked) return;
  const handle = state.scanHandle;
  const completionContext = {
    handle,
    scanConfig: state.scanConfig,
    lastProgress: state.lastProgress,
  };
  state.sweepExecutionPending = true;
  state.sweepReview = null;
  $("execute-sweep").disabled = true;
  $("irreversible-check").disabled = true;

  try {
    setStatus("sweep-execute-status", "Broadcasting transactions to the Zcash network… this may take up to 2 minutes.", "");
    // `execute_sweep` rejects only when nothing was broadcast. A mid-sequence
    // abort after one or more broadcasts resolves with `{ transactions, error }`
    // so the already-broadcast transaction IDs are still shown (audit Issue E).
    const outcome = await invoke("execute_sweep", { handle, proposalId: review.proposal_id });
    state.completedScanHandle = handle;
    setStatus("sweep-execute-status", "", "");
    await renderCompleteScreen(
      outcome.transactions,
      outcome.skipped_accounts,
      outcome.total_donation_zatoshis || 0,
      review.donationRateForDisplay,
      outcome.error,
      outcome.donation_note,
      { ...completionContext, outcome, donationRate: review.donationRateForDisplay },
    );
    if (state.scanHandle?.id !== handle.id) {
      $("complete-summary").textContent =
        "This result belongs to the sweep started before the scan source changed. " +
        $("complete-summary").textContent;
    }
    goTo("complete");
  } catch (err) {
    invalidateSweepReview();
    setStatus("sweep-execute-status", `✗ Sweep failed: ${err}`, "error");
  } finally {
    clearTransientSecrets();
    state.sweepExecutionPending = false;
  }
});

// ─── Step 6: Complete ─────────────────────────────────────────────────────────

// Older results used "broadcast", "confirmed", and "failed" without the
// current independent evidence. Treat those labels conservatively when shown.
function txStatusKind(status) {
  if (status === "broadcast") return "pending";
  if (status === "confirmed") return "pending";
  if (status === "failed") return "submission_unknown";
  if (["not_submitted", "submission_unknown", "pending", "mined", "mined_single_source", "expired", "rejected"].includes(status)) return status;
  return "submission_unknown";
}


function sweepStatusCounts(results) {
  const counts = { not_submitted: 0, unknown: 0, pending: 0, mined: 0, singleSource: 0, expired: 0, rejected: 0, broadcast: 0, safe: 0 };
  for (const r of results) {
    const kind = txStatusKind(r.status);
    if (kind === "submission_unknown") counts.unknown += 1;
    else if (kind === "mined_single_source") counts.singleSource += 1;
    else counts[kind] += 1;
    // Only corroborated, deep-enough mining may say the source can go.
    if (kind === "mined" && r.safe_to_discard === true) counts.safe += 1;
  }
  counts.broadcast = counts.unknown + counts.pending + counts.mined + counts.singleSource + counts.expired;
  return counts;
}

// The completion text comes from the backend (argos_core::sweep_guidance), the
// same rules the CLI prints, so which state wins over which lives in one place.
// Statuses are normalized first: the backend accepts only current tokens.
function completionGuidanceInput(results, skipped, donated, donationRate, error, donationNote, statusOnly, followUpReviewRequired) {
  return {
    transactions: results.map((r) => ({
      status: txStatusKind(r.status),
      safe_to_discard: r.safe_to_discard === true,
    })),
    skipped_accounts: Array.isArray(skipped) ? skipped.length : 0,
    follow_up_review_required: !!followUpReviewRequired,
    error: error || null,
    status_only: !!statusOnly,
    donation_requested: Number.isFinite(donationRate) && donationRate > 0,
    donated_zatoshis: Number(donated) || 0,
    donation_note: donationNote || null,
  };
}

// A failed lookup must never hide the transaction cards of a sweep that may
// have moved funds, so it falls back to one conservative instruction.
async function loadCompletionGuidance(input) {
  try {
    return await invoke("sweep_completion_guidance", { input });
  } catch (error) {
    return {
      recovery_complete: false,
      summary: "Could not load the completion guidance. Keep the source wallet and recovery workspace; review each transaction status before any new proposal.",
      next_steps: `Guidance error: ${error}`,
      donation: null,
      status_labels: input.transactions.map((tx) => tx.status),
    };
  }
}

async function applyReconciledTransactions(rows) {
  const context = state.completionContext;
  if (!context) return;
  const outcome = context.outcome || { transactions: [] };
  const transactions = [...(outcome.transactions || [])];
  for (const row of rows) {
    const index = transactions.findIndex((item) => item.txid === row.txid);
    if (index >= 0) transactions[index] = { ...transactions[index], ...row };
    else transactions.push({ source_account: null, ...row });
  }
  const updatedOutcome = { ...outcome, transactions };
  const updatedContext = { ...context, outcome: updatedOutcome };
  await renderCompleteScreen(
    transactions, updatedOutcome.skipped_accounts || [],
    updatedOutcome.total_donation_zatoshis || 0,
    updatedContext.donationRate ?? null,
    updatedOutcome.error || null, updatedOutcome.donation_note || null,
    updatedContext,
  );
}

async function refreshSweepStatus() {
  const context = state.completionContext;
  const handle = context?.handle;
  if (!handle || state.reconciliationPending) return;
  state.reconciliationPending = true;
  $("complete-check-status").disabled = true;
  setStatus("complete-reconciliation-status", "Checking saved transactions with independent operators…", "");
  try {
    const rows = await invoke("reconcile_sweep", { handle });
    if (state.completionContext !== context) return;
    const reported = new Set(rows.map((row) => row.txid));
    if (context.outcome?.transactions?.some((row) => row.txid && !reported.has(row.txid))) {
      throw new Error("The journal did not return every displayed transaction; keep the recovery workspace.");
    }
    const newlyFinal = rows.some((row) => {
      const previous = context.outcome?.transactions?.find((item) => item.txid === row.txid);
      return (!previous || txStatusKind(previous.status) !== txStatusKind(row.status)) &&
        ["mined", "mined_single_source", "expired", "rejected"].includes(txStatusKind(row.status));
    });
    await applyReconciledTransactions(rows);
    if (newlyFinal) {
      invalidateSweepReview();
      state.lastProgress = null;
    }
    setStatus("complete-reconciliation-status", newlyFinal
      ? "Transaction status refreshed. Run a fresh scan and review a new quote before another sweep stage."
      : "Transaction status refreshed from independent operators.", "success");
  } catch (error) {
    if (state.completionContext !== context) return;
    // A failed fresh observation cannot support deleting this workspace.
    $("delete-workspace").disabled = true;
    $("delete-workspace-zone").hidden = true;
    setStatus("complete-reconciliation-status", `Could not verify current status: ${error}`, "error");
  } finally {
    state.reconciliationPending = false;
    $("complete-check-status").disabled = false;
  }
}

async function retryStoredSweepTransaction(txid) {
  const context = state.completionContext;
  const handle = context?.handle;
  const current = context?.outcome?.transactions?.find((row) => row.txid === txid);
  if (!handle || !current ||
      !["submission_unknown", "not_submitted"].includes(txStatusKind(current.status)) ||
      state.reconciliationPending) return;
  if (!window.confirm(
    `Retry only the exact saved transaction ${txid}? The app will first check its current status. ` +
    "No new transaction will be built or signed."
  )) return;
  const network = context.scanConfig?.network ?? state.scanConfig?.network ?? "the configured network";
  const dataDir = context.scanConfig?.data_dir ?? state.scanConfig?.data_dir ?? "the configured data directory";
  if (typeof window.prompt !== "function") {
    setStatus("complete-reconciliation-status", "Full txid confirmation is unavailable; transaction was not retried.", "error");
    return;
  }
  const typedTxid = window.prompt(
    `Saved transactions cover ${network} in ${dataDir} and may belong to another wallet. ` +
    `To retry only the exact stored bytes for ${txid}, type the full txid:`,
    "",
  );
  if (typedTxid === null) return;
  if (typedTxid !== txid) {
    setStatus("complete-reconciliation-status", "The full txid did not match; transaction was not retried.", "error");
    return;
  }
  state.reconciliationPending = true;
  $("complete-check-status").disabled = true;
  setStatus("complete-reconciliation-status", "Checking status before retrying saved transaction…", "");
  try {
    const row = await invoke("retry_unknown_sweep", { handle, txid });
    if (state.completionContext !== context) return;
    await applyReconciledTransactions([row]);
    setStatus("complete-reconciliation-status", "Saved transaction retry completed; check status for independent confirmation.", "success");
  } catch (error) {
    if (state.completionContext !== context) return;
    $("delete-workspace").disabled = true;
    $("delete-workspace-zone").hidden = true;
    setStatus("complete-reconciliation-status", `Saved transaction was not retried: ${error}`, "error");
  } finally {
    state.reconciliationPending = false;
    $("complete-check-status").disabled = false;
  }
}

async function renderCompleteScreen(results, skipped, donated, donationRate, error, donationNote, completionContext = null) {
  const render = (state.completionRender = (state.completionRender || 0) + 1);
  state.completionContext = completionContext;
  const statusOnly = !!completionContext?.statusOnly;
  const statusButton = $("complete-check-status");
  statusButton.hidden = !completionContext?.handle;
  statusButton.onclick = () => refreshSweepStatus();
  $("complete-return-address-matches").hidden = !state.retainedAddressSearchId;
  if (state.retainedAddressSearchId) {
    state.addressMatchRecoveryLocked = false;
    document.dispatchEvent(new CustomEvent("address-search-lock-recovery", { detail: { locked: false } }));
  }
  const { unknown, pending, not_submitted: notSubmitted } = sweepStatusCounts(results);
  const followUpReviewRequired = !!(completionContext?.outcome?.follow_up_review_required ?? completionContext?.followUpReviewRequired);
  // Deleting the workspace needs only resolved broadcasts (the service
  // enforces the same rule); it never implies the source can be discarded.
  // A staged sweep still owes its send leg, so the screen keeps the
  // workspace it will rescan.
  const deletable = !statusOnly && !followUpReviewRequired &&
    unknown === 0 && pending === 0 && notSubmitted === 0;
  // Text waits for the backend; the controls and cards below do not.
  $("complete-heading").textContent = statusOnly ? "Saved transaction status" : "Sweep status";
  $("complete-summary").textContent = "";
  $("complete-confirmation-note").textContent = "";
  $("delete-workspace").disabled = !deletable;
  $("delete-workspace-zone").hidden = !deletable;
  $("restart-flow").textContent = statusOnly || followUpReviewRequired ? "Rescan and review" : "Start over";

  const container = $("complete-txids");
  container.innerHTML = "";
  const labels = [];
  results.forEach((r) => {
    const card = document.createElement("div");
    card.className = "txid-card" + (["rejected", "expired", "not_submitted"].includes(txStatusKind(r.status)) ? " txid-card--failed" : "");

    const label = document.createElement("div");
    label.className = "txid-label";
    label.textContent = `${r.source_account == null ? "Journal transaction" : `Account ${r.source_account}`} · ${txStatusKind(r.status)}`;
    labels.push({ label, prefix: r.source_account == null ? "Journal transaction" : `Account ${r.source_account}` });
    card.appendChild(label);

    if (r.txid) {
      const row = document.createElement("div");
      row.className = "txid-row";
      const code = document.createElement("code");
      code.className = "txid-value";
      code.textContent = r.txid;
      const copyBtn = document.createElement("button");
      copyBtn.className = "ghost txid-copy";
      copyBtn.textContent = "Copy";
      copyBtn.addEventListener("click", () => {
        navigator.clipboard.writeText(r.txid).then(() => {
          copyBtn.textContent = "Copied!";
          setTimeout(() => { copyBtn.textContent = "Copy"; }, 1400);
        });
      });
      row.appendChild(code);
      row.appendChild(copyBtn);
      card.appendChild(row);
    }

    if (r.fee_zatoshis != null) {
      const fee = document.createElement("div");
      fee.className = "txid-note";
      fee.textContent = `Fee: ${fmt(r.fee_zatoshis)}`;
      card.appendChild(fee);
    }

    if (txStatusKind(r.status) === "mined" && r.confirmed_height) {
      const note = document.createElement("div");
      note.className = "txid-note";
      note.textContent = `Mined at block ${r.confirmed_height.toLocaleString()}`;
      card.appendChild(note);
    }
    if (r.detail) {
      const note = document.createElement("div");
      note.className = "txid-note";
      note.textContent = r.detail;
      card.appendChild(note);
    }

    if (r.txid && ["submission_unknown", "not_submitted"].includes(txStatusKind(r.status)) && completionContext?.handle) {
      const retry = document.createElement("button");
      retry.className = "secondary";
      retry.textContent = "Retry saved transaction";
      retry.addEventListener("click", () => retryStoredSweepTransaction(r.txid));
      card.appendChild(retry);
    }

    container.appendChild(card);
  });

  // Accounts that held a balance but moved nothing (every spendable note below
  // the ZIP-317 fee floor). Surfaced so the skip is visible rather than silent,
  // mirroring the dry-run proposal's skipped-accounts list.
  const skippedEl = $("complete-skipped");
  skippedEl.replaceChildren();
  if (Array.isArray(skipped) && skipped.length > 0) {
    const heading = document.createElement("p");
    heading.style.margin = "6px 0 4px";
    heading.style.fontWeight = "700";
    heading.style.color = "var(--muted)";
    heading.textContent =
      `${skipped.length} account${skipped.length > 1 ? "s" : ""} skipped — not swept (reasons below)`;
    skippedEl.appendChild(heading);

    const list = document.createElement("ul");
    list.className = "discovery-list";
    skipped.forEach((s) => {
      const li = document.createElement("li");
      li.textContent = `Account ${s.account_index}: ${s.reason} (${fmt(s.gross_zatoshis)})`;
      list.appendChild(li);
    });
    skippedEl.appendChild(list);
  }

  const donationEl = $("complete-donation");
  donationEl.hidden = true;
  donationEl.textContent = "";
  $("save-report").dataset.report = "";

  const guidance = await loadCompletionGuidance(completionGuidanceInput(
    results, skipped, donated, donationRate, error, donationNote, statusOnly, followUpReviewRequired,
  ));
  // A later render (for example after a status refresh) owns the screen.
  if (render !== state.completionRender) return;
  if (!statusOnly && guidance.recovery_complete) $("complete-heading").textContent = "Recovery complete";
  $("complete-summary").textContent = guidance.summary;
  $("complete-confirmation-note").textContent = guidance.next_steps;
  labels.forEach(({ label, prefix }, index) => {
    const text = guidance.status_labels?.[index];
    if (text) label.textContent = `${prefix} · ${text}`;
  });
  // A recorded total is not a donation receipt until every relevant
  // transaction has independent mining evidence; the backend decides.
  donationEl.hidden = !guidance.donation;
  donationEl.textContent = guidance.donation || "";

  const report = buildReport(results, completionContext, guidance);
  $("save-report").dataset.report = report;
  $("report-path").value = buildDefaultReportPath();
}

function buildReport(results, completionContext = null, guidance = null) {
  const outcome = completionContext?.outcome;
  const statusOnly = !!completionContext?.statusOnly;
  const transactions = outcome?.transactions ?? results;
  const skipped = outcome?.skipped_accounts ?? [];
  const error = outcome?.error ?? null;
  const followUpReviewRequired = !!outcome?.follow_up_review_required;
  const status = statusOnly ? "Saved transaction status" : guidance?.recovery_complete ? "Recovery complete" : followUpReviewRequired
    ? "Shielding stage — follow-up review required" : "Incomplete";
  const cfg = completionContext?.scanConfig ?? state.scanConfig;
  const prog = completionContext?.lastProgress ?? state.lastProgress;
  const accountsScanned = prog?.accounts?.length ?? "—";
  const network = cfg?.network ?? "—";
  const birthday = cfg?.birthday != null ? Number(cfg.birthday).toLocaleString() : "—";
  const scanMode = cfg
    ? (cfg.num_accounts != null
        ? `Fixed — ${cfg.num_accounts} accounts`
        : `Gap scan — stop after ${cfg.gap_limit} empty accounts`)
    : "—";
  const workspace = prog?.summary?.workspace_dir ?? "—";

  return [
    "Argos Recovery Report",
    `Date: ${new Date().toISOString()}`,
    "",
    "Scan Summary",
    "────────────",
    `Network:          ${network}`,
    `Wallet birthday:  block ${birthday}`,
    `Accounts scanned: ${accountsScanned}`,
    `Scan mode:        ${scanMode}`,
    `Workspace:        ${workspace}`,
    "",
    `Status: ${status}`,
    `Follow-up review required: ${followUpReviewRequired ? "yes" : "no"}`,
    ...(error ? [`Error: ${error}`] : []),
    `Guidance: ${guidance?.summary ?? "Keep the source wallet and recovery workspace; review each transaction status before any new proposal."}`,
    "",
    "Transaction Results",
    "──────────────────",
    ...transactions.map((r) => {
      let line = `${r.source_account == null ? "Journal transaction" : `Account ${r.source_account}`}: ${txStatusKind(r.status)}`;
      if (r.txid) line += `\n  txid: ${r.txid}`;
      if (r.fee_zatoshis != null) line += `\n  fee: ${fmt(r.fee_zatoshis)}`;
      if (txStatusKind(r.status) === "mined" && r.confirmed_height) line += `\n  mined at block ${r.confirmed_height}`;
      if (r.detail) line += `\n  evidence: ${r.detail}`;
      return line;
    }),
    "",
    "Skipped accounts",
    "────────────────",
    ...(skipped.length ? skipped.map((s) =>
      `Account ${s.account_index}: ${s.reason} (${fmt(s.gross_zatoshis)})`) : ["None"]),
  ].join("\n");
}

function buildDefaultReportPath() {
  // Paths are resolved relative to the recovery workspace by the backend's
  // resolve_report_path, so we just return the bare file name here.
  return "argos-recovery-report.txt";
}

$("save-report").addEventListener("click", async () => {
  const path = $("report-path").value.trim();
  const report = $("save-report").dataset.report ?? "";
  if (!report) {
    setStatus("save-report-status", "Nothing to save yet.", "error");
    return;
  }
  try {
    const saved = await invoke("save_recovery_report", {
      handle: state.completedScanHandle || state.scanHandle,
      path,
      report,
    });
    state.savedReportPath = saved;
    setStatus("save-report-status", `✓ Saved to ${saved}`, "success");
    $("copy-report-path").style.display = "";
  } catch (err) {
    setStatus("save-report-status", `✗ ${err}`, "error");
  }
});

$("copy-report-path").addEventListener("click", () => {
  if (!state.savedReportPath) return;
  navigator.clipboard.writeText(state.savedReportPath).then(() => {
    const btn = $("copy-report-path");
    btn.textContent = "Copied!";
    setTimeout(() => { btn.textContent = "Copy path"; }, 1400);
  });
});

$("delete-workspace").addEventListener("click", async () => {
  if ($("delete-workspace").disabled) return;
  const handle = state.completedScanHandle || state.scanHandle;
  if (!handle) {
    setStatus("delete-workspace-status", "No workspace to delete.", "error");
    return;
  }
  const confirmed = window.confirm(
    "Delete the recovery workspace?\n\n" +
      "This permanently removes the viewing keys and note cache for this seed from disk. " +
      "Make sure you have verified the swept funds in your destination wallet first.\n\n" +
      "Note: on SSDs this is not a cryptographic wipe — the data may persist at the " +
      "block-device level until the cells are overwritten.",
  );
  if (!confirmed) return;

  const btn = $("delete-workspace");
  btn.disabled = true;
  setStatus("delete-workspace-status", "Deleting…", "");
  try {
    const deletedPath = await invoke("delete_workspace", { handle });
    setStatus("delete-workspace-status", `✓ Deleted ${deletedPath}`, "success");
    // The session is gone server-side; further per-handle commands would fail.
    state.scanHandle = null;
    state.completedScanHandle = null;
    state.savedReportPath = null;
    // The recovery report is inside the workspace we just deleted; the
    // "Copy path" affordance now points at nothing.
    $("copy-report-path").style.display = "none";
    $("save-report").disabled = true;
  } catch (err) {
    setStatus("delete-workspace-status", `✗ ${err}`, "error");
    btn.disabled = false;
  }
});

function resetRecoveryFlowState({ destination = "", memo = "", maxFeeZec = "" } = {}) {
  invalidateScanAuthority();
  if (state.retainedAddressSearchId || state.matchedRecovery) {
    const searchId = state.retainedAddressSearchId || state.matchedRecovery?.searchId;
    state.retainedAddressSearchId = null;
    clearMatchedRecoveryUi();
    document.dispatchEvent(new CustomEvent("address-search-release", { detail: { searchId } }));
  }
  furthestStep = 0;
  Object.assign(state, {
    scanHandle: null,
    completedScanHandle: null,
    lastProgress: null,
    sweepReview: null,
    proposalPending: false,
    destination: destination || null,
    memo: memo || null,
    maxFeeZec: maxFeeZec || null,
    autoFeeCapZec: null,
    scanConfig: null,
    savedReportPath: null,
    matchedRecovery: null,
    retainedAddressSearchId: null,
    addressMatchRecoveryLocked: false,
    addressMatchRecoveryStartGeneration: null,
    completionContext: null,
    reconciliationPending: false,
  });
  $("copy-report-path").style.display = "none";
  $("delete-workspace").disabled = false;
  $("delete-workspace-zone").hidden = false;
  $("save-report").disabled = false;
  setStatus("delete-workspace-status", "", "");

  seedInput.value = "";
  forgetLoadedWalletFile();
  $("sapling-scan-keys").value = "";
  $("sapling-key-addresses").replaceChildren();
  forgetSproutScanInputs();
  $("sprout-scan-peers").value = "";
  $("sprout-destination").value = "";
  seedVisibility.checked = false;
  seedInput.classList.add("masked");
  seedNextBtn.disabled = true;
  setStatus("seed-status", "", "");
  setStatus("config-status", "", "");
  $("destination-input").value = destination;
  $("max-fee-zec").value = maxFeeZec;
  $("sweep-memo").value = memo;
  $("memo-byte-count").textContent = `${new TextEncoder().encode(memo).length} / 512 bytes`;
  $("memo-byte-count").style.color = "";
  $("scan-label").value = defaultScanLabel();
  $("scan-label").placeholder = defaultScanLabel();
  $("network-select").value = "mainnet";
  // The starting value again, not a birthday the user chose.
  birthdayTouched = false;
  syncUntouchedBirthdayToNetwork("mainnet");
  $("birthday-date").value = "";
  setStatus("birthday-probe-status", "", "");
  $("accounts-range").value = "20";
  $("accounts-range-value").textContent = "20";
  $("accounts-range-value").style.opacity = "0.4";
  $("auto-gap-limit").checked = true;
  $("accounts-range").disabled = false;
  $("gap-limit").value = "20";
  $("gap-limit-row").style.display = "none";
  $("server-preset").value = "recommended";
  $("lightwalletd-url").value = SERVER_PRESETS.mainnet;
  $("data-dir").value = state.defaultDataDir || "";
  $("transparent-index-start").value = "0";
  $("transparent-index-count").value = "1000";
  $("transparent-include-change").checked = false;
  updateTransparentScanSummary();
  // Reset donation form to its default-on state so a previous run's choices
  // don't silently carry into the next sweep. `state.donationEnabled` itself
  // is feature-availability (whether the backend has a baked address) and is
  // refreshed once at startup via initDonate; it does not need resetting.
  $("donate-enabled").checked = true;
  $("donate-rate").value = "10";
  $("donate-email").value = "";
  $("donate-fields").hidden = true;
  $("donate-form").classList.remove("donate-collapsed");
  $("donate-skip").textContent = "No thanks, skip donation";
  document.querySelectorAll("#donate-presets .preset-chip").forEach((chip) => {
    chip.setAttribute("aria-pressed", String(chip.dataset.pct === "10"));
  });
  setStatus("donate-amount-preview", "", "");
  $("start-scan").disabled = false;
  $("irreversible-check").checked = false;
  $("irreversible-check").disabled = true;
  $("execute-sweep").disabled = true;
  $("sweep-rows").innerHTML = "";
  $("sweep-skipped").innerHTML = "";
  $("sweep-summary").textContent = "";
  $("complete-txids").innerHTML = "";
  $("complete-summary").textContent = "";
  $("complete-skipped").textContent = "";
  $("complete-donation").textContent = "";
  $("complete-report").textContent = "";
  $("complete-report").style.display = "none";
  $("save-report").dataset.report = "";
  setStatus("save-report-status", "", "");

  // Reset scan screen to blank state so stale results aren't visible if the
  // user navigates forward via the sidebar before starting a new scan.
  $("scan-phase").textContent = "Idle";
  $("scan-server").textContent = "Not connected";
  $("scan-progress-text").textContent = "0 / 0";
  $("scan-eta").textContent = "Calculating…";
  $("scan-progress-bar").style.width = "0%";
  $("scan-rows").innerHTML = "";
  $("scan-discoveries").innerHTML = "";
  $("scan-discoveries").style.display = "none";
  $("scan-totals").textContent = "Balance: 0.00000000 ZEC · 0 accounts loaded.";
  $("scan-workspace").textContent = "Workspace: not initialized";
  setStatus("scan-message", "", "");
  $("review-sweep").disabled = true;
  $("scan-saved-transactions").disabled = true;
  $("back-to-config").style.display = "none";
  $("cancel-scan").style.display = "";

}

$("restart-flow").addEventListener("click", () => {
  abandonRecoveryFlow();
  resetRecoveryFlowState();
  goTo("welcome");
});

// ─── Donate ───────────────────────────────────────────────────────────────────

(async function initAppVersion() {
  try {
    const version = await invoke("app_version");
    if (version) {
      $("app-version").textContent = `Version ${version}`;
    }
  } catch (err) {
    // Leave the element empty. A missing version line is strictly better than
    // a wrong one: the whole point is answering "which build am I running".
    console.error("app_version failed:", err);
  }
})();

(async function initDonate() {
  try {
    const addr = await invoke("donation_address");
    state.donationEnabled = !!addr;
    if (addr) {
      $("donate-address").textContent = addr;
      $("copy-donate-address").disabled = false;
    }
    // empty address → keep the existing "Address coming soon" text + disabled copy button
  } catch (err) {
    // leave the placeholder/disabled state on failure
  }
})();

function openDonate() {
  $("donate-overlay").style.display = "";
  document.body.style.overflow = "hidden";
  $("close-donate").focus();
}

function closeDonate() {
  $("donate-overlay").style.display = "none";
  document.body.style.overflow = "";
}

$("open-donate").addEventListener("click", openDonate);
$("complete-open-donate").addEventListener("click", openDonate);
$("close-donate").addEventListener("click", closeDonate);

$("donate-overlay").addEventListener("click", (e) => {
  if (e.target === $("donate-overlay")) closeDonate();
});

$("copy-donate-address").addEventListener("click", () => {
  navigator.clipboard.writeText($("donate-address").textContent).then(() => {
    setStatus("donate-copy-status", "✓ Address copied", "success");
    setTimeout(() => setStatus("donate-copy-status", "", ""), 2500);
  });
});

// ─── User Guide ───────────────────────────────────────────────────────────────

$("open-guide").addEventListener("click", () => {
  $("guide-overlay").style.display = "";
  document.body.style.overflow = "hidden";
  $("close-guide").focus();
});

$("close-guide").addEventListener("click", () => {
  $("guide-overlay").style.display = "none";
  document.body.style.overflow = "";
});

$("guide-overlay").addEventListener("click", (e) => {
  if (e.target === $("guide-overlay")) {
    $("guide-overlay").style.display = "none";
    document.body.style.overflow = "";
  }
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    if ($("donate-overlay").style.display !== "none") closeDonate();
    else if ($("guide-overlay").style.display !== "none") {
      $("guide-overlay").style.display = "none";
      document.body.style.overflow = "";
    }
  }
});

// ─── Sidebar resize ───────────────────────────────────────────────────────────

const SIDEBAR_MIN = 160;
const SIDEBAR_MAX = 420;
const SIDEBAR_KEY = "argos-sidebar-w";

(function initSidebarResize() {
  const handle = $("sidebar-resize-handle");
  const shell = document.querySelector(".app-shell");
  const saved = parseInt(localStorage.getItem(SIDEBAR_KEY), 10);
  if (saved >= SIDEBAR_MIN && saved <= SIDEBAR_MAX) {
    shell.style.setProperty("--sidebar-w", saved + "px");
  }

  let dragging = false;
  let startX = 0;
  let startW = 0;

  handle.addEventListener("mousedown", (e) => {
    dragging = true;
    startX = e.clientX;
    startW = parseInt(getComputedStyle(shell).getPropertyValue("--sidebar-w")) || 220;
    handle.classList.add("dragging");
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
  });

  document.addEventListener("mousemove", (e) => {
    if (!dragging) return;
    const w = Math.min(SIDEBAR_MAX, Math.max(SIDEBAR_MIN, startW + (e.clientX - startX)));
    shell.style.setProperty("--sidebar-w", w + "px");
  });

  document.addEventListener("mouseup", () => {
    if (!dragging) return;
    dragging = false;
    handle.classList.remove("dragging");
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
    const w = parseInt(getComputedStyle(shell).getPropertyValue("--sidebar-w")) || 220;
    localStorage.setItem(SIDEBAR_KEY, w);
  });
})();

// ─── Resume incomplete sessions ───────────────────────────────────────────────

function defaultScanLabel() {
  // Matches the spec default ("Scan started YYYY-MM-DD"). Locale-independent
  // so the label is identical across launches and easy to grep through later.
  const d = new Date();
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  return `Scan started ${yyyy}-${mm}-${dd}`;
}

function fmtRelativeTime(epochSeconds) {
  if (!epochSeconds) return "(no recent run)";
  const diff = Math.max(0, Math.floor(Date.now() / 1000) - Number(epochSeconds));
  if (diff < 60) return "just now";
  if (diff < 3600) {
    const m = Math.floor(diff / 60);
    return `${m} minute${m === 1 ? "" : "s"} ago`;
  }
  if (diff < 86400) {
    const h = Math.floor(diff / 3600);
    return `${h} hour${h === 1 ? "" : "s"} ago`;
  }
  const days = Math.floor(diff / 86400);
  return `${days} day${days === 1 ? "" : "s"} ago`;
}

let pendingResumeRow = null;
let resumeGeneration = 0;
let resumeAttemptPending = false;

const DISMISSED_SESSIONS_KEY = "argos-dismissed-sessions";

// Map of workspace_path -> synced_to_height recorded at dismissal time. A
// dismissed session is hidden only while it stays at that height; if it later
// makes progress it resurfaces (so a stray ✕ can't permanently bury a
// resumable recovery scan). Entries self-heal — paths no longer reported as
// incomplete are pruned on read, bounding localStorage growth.
function getDismissedSessions() {
  try {
    const raw = JSON.parse(localStorage.getItem(DISMISSED_SESSIONS_KEY) || "{}");
    // Ignore the legacy array format (and any non-object) — those entries are
    // dropped, surfacing previously-buried sessions once, which is the safe
    // direction for a recovery tool.
    return raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
  } catch {
    return {};
  }
}

function saveDismissedSessions(map) {
  localStorage.setItem(DISMISSED_SESSIONS_KEY, JSON.stringify(map));
}

function dismissSession(workspacePath, syncedToHeight) {
  const dismissed = getDismissedSessions();
  dismissed[workspacePath] = Number(syncedToHeight) || 0;
  saveDismissedSessions(dismissed);
}

function buildSessionRow(row, onDismiss) {
  const li = document.createElement("li");
  li.className = "session-row";

  const info = document.createElement("div");
  const labelEl = document.createElement("div");
  labelEl.className = "session-label";
  labelEl.textContent = row.legacy_untrusted || row.requires_rescan
    ? "Legacy workspace — rescan required"
    : row.label || "(unlabeled scan)";
  info.appendChild(labelEl);

  if (row.legacy_untrusted || row.requires_rescan) {
    const guidance = document.createElement("div");
    guidance.className = "session-meta";
    guidance.textContent =
      "This workspace is preserved, but it predates private-storage lineage and cannot be safely resumed. " +
      "Keep the original directory and wallet file. Choose a new empty data directory on the recovery settings screen " +
      "(the upgraded default is workspace-v2), then start a new recovery and rescan. " +
      "Reconcile any previously broadcast transactions before recovering those funds again.";
    info.appendChild(guidance);
    li.appendChild(info);

    const actions = document.createElement("div");
    actions.className = "session-actions";
    const dismissBtn = document.createElement("button");
    dismissBtn.className = "ghost";
    dismissBtn.textContent = "Dismiss";
    dismissBtn.title = "Dismiss from list";
    dismissBtn.addEventListener("click", () => {
      dismissSession(row.workspace_path, null);
      onDismiss();
    });
    actions.appendChild(dismissBtn);
    li.appendChild(actions);
    return li;
  }

  const synced = row.synced_to_height
    ? Number(row.synced_to_height).toLocaleString()
    : "0";
  const target = row.target_height ? Number(row.target_height).toLocaleString() : "?";
  const birthday =
    row.birthday != null ? Number(row.birthday).toLocaleString() : "?";
  const meta = document.createElement("div");
  meta.className = "session-meta";
  meta.textContent =
    `${row.network} · birthday ${birthday} · ` +
    `scanned ${synced} of ${target} · ${fmtRelativeTime(row.last_run_at_epoch_seconds)}`;
  info.appendChild(meta);
  if (row.match_coordinates) {
    const matched = document.createElement("div");
    matched.className = "session-meta";
    matched.textContent = `Address-match recovery · ${row.match_coordinates.path || "saved derivation path"}`;
    info.appendChild(matched);
  }
  if (row.transparent_scan) {
    const start = Number(row.transparent_scan.index_start);
    const count = Number(row.transparent_scan.index_count);
    if (Number.isSafeInteger(start) && Number.isSafeInteger(count) && start >= 0 && count > 0 &&
        count <= 10000 && start + count <= 2147483648) {
      const transparent = document.createElement("div");
      transparent.className = "session-meta";
      transparent.textContent = `Additional transparent range: account 0 ${row.transparent_scan.include_change ? "receive + change" : "receive"} indices ${start.toLocaleString()}–${(start + count - 1).toLocaleString()}`;
      info.appendChild(transparent);
    }
  }
  li.appendChild(info);

  const actions = document.createElement("div");
  actions.className = "session-actions";

  const resumeBtn = document.createElement("button");
  resumeBtn.className = "primary";
  resumeBtn.textContent = "Resume";
  resumeBtn.addEventListener("click", () => openResumeModal(row));
  actions.appendChild(resumeBtn);

  const dismissBtn = document.createElement("button");
  dismissBtn.className = "ghost";
  dismissBtn.textContent = "✕";
  dismissBtn.title = "Dismiss from list";
  dismissBtn.addEventListener("click", () => {
    dismissSession(row.workspace_path, row.synced_to_height);
    onDismiss();
  });
  actions.appendChild(dismissBtn);

  li.appendChild(actions);
  return li;
}

async function refreshResumePanel() {
  const dataDir = $("data-dir").value.trim() || null;
  let rows = [];
  let listOk = true;
  try {
    rows = await invoke("list_incomplete_sessions", { dataDir });
  } catch (err) {
    // Non-fatal — the user can still start a new scan from welcome.
    listOk = false;
    console.warn("list_incomplete_sessions failed:", err);
    rows = [];
  }
  const dismissed = getDismissedSessions();
  // Prune dismissals for sessions no longer reported as incomplete (completed
  // or deleted) so the map can't grow unbounded. Only when the listing
  // succeeded: a transient backend error returns an empty list and must not be
  // mistaken for "every session is gone" — that would wipe all dismissals.
  if (listOk) {
    const livePaths = new Set(rows.map((r) => r.workspace_path));
    let pruned = false;
    for (const path of Object.keys(dismissed)) {
      if (!livePaths.has(path)) {
        delete dismissed[path];
        pruned = true;
      }
    }
    if (pruned) saveDismissedSessions(dismissed);
  }
  // Hide a dismissed session only while it has not advanced past the height it
  // was dismissed at; renewed progress brings it back.
  rows = rows.filter(
    (r) =>
      !(r.workspace_path in dismissed) ||
      (Number(r.synced_to_height) || 0) > dismissed[r.workspace_path]
  );
  const panel = $("resume-panel");
  const list = $("resume-sessions");
  list.innerHTML = "";
  if (!rows.length) {
    panel.hidden = true;
    return;
  }
  for (const row of rows) list.appendChild(buildSessionRow(row, refreshResumePanel));
  panel.hidden = false;
}

function openResumeModal(row) {
  ++resumeGeneration;
  pendingResumeRow = row;
  $("resume-confirm").disabled = resumeAttemptPending;
  $("resume-modal-title").textContent = `Resume "${row.label || "(unlabeled scan)"}"`;
  $("resume-source").value = row.match_coordinates ? "seed" : "";
  $("resume-source").disabled = !!row.match_coordinates;
  $("resume-wallet-path").value = "";
  $("resume-wallet-passphrase").value = "";
  $("resume-sapling-keys").value = "";
  syncResumeSourceControls();
  $("resume-seed-input").value = "";
  $("resume-seed-input").classList.add("masked");
  $("resume-seed-visibility").checked = false;
  $("resume-label-input").value = "";
  $("resume-bip39-passphrase").value = "";
  $("resume-destination-input").value = "";
  $("resume-memo-input").value = "";
  $("resume-max-fee-zec").value = "";
  $("resume-confirmation-sources").value = $("confirmation-sources").value;
  $("resume-bip39-passphrase-field").hidden = !row.match_coordinates;
  setStatus("resume-modal-status", "", "");
  $("resume-modal").hidden = false;
  $(row.match_coordinates ? "resume-seed-input" : "resume-source").focus();
}

function closeResumeModal() {
  ++resumeGeneration;
  pendingResumeRow = null;
  $("resume-confirm").disabled = resumeAttemptPending;
  $("resume-modal").hidden = true;
  clearResumeSecrets();
  $("resume-destination-input").value = "";
  $("resume-memo-input").value = "";
  $("resume-max-fee-zec").value = "";
}

function clearResumeSecrets() {
  for (const id of ["resume-seed-input", "resume-bip39-passphrase", "resume-wallet-passphrase", "resume-sapling-keys"]) $(id).value = "";
  $("resume-seed-visibility").checked = false;
  $("resume-seed-input").classList.add("masked");
}

function syncResumeSourceControls() {
  const source = $("resume-source").value;
  $("resume-seed-fields").hidden = source !== "seed";
  $("resume-wallet-fields").hidden = source !== "wallet";
  $("resume-sapling-field").hidden = source !== "wallet" && source !== "sapling";
  $("resume-bip39-passphrase-field").hidden = source !== "seed" || !pendingResumeRow?.match_coordinates;
}

function resumeSourceInput() {
  const source = $("resume-source").value;
  if (source === "seed") {
    const seed = $("resume-seed-input").value.trim().toLowerCase();
    if (!seed) throw new Error("Enter the seed phrase to continue.");
    return { seed, passphrase: passphraseForResumedSession(pendingResumeRow, $("resume-bip39-passphrase").value),
      walletPath: null, walletPassphrase: null, saplingKeys: [] };
  }
  if (source !== "wallet" && source !== "sapling") throw new Error("Choose the original recovery source.");
  const walletPath = source === "wallet" ? $("resume-wallet-path").value.trim() : null;
  if (source === "wallet" && !walletPath) throw new Error("Choose the original wallet file to continue.");
  const saplingKeys = $("resume-sapling-keys").value.split(/\r?\n/).map(line => line.trim()).filter(line => line && !line.startsWith("#"));
  if (source === "sapling" && !saplingKeys.length) throw new Error("Enter the original Sapling spending keys to continue.");
  return { seed: null, passphrase: null, walletPath,
    walletPassphrase: source === "wallet" ? $("resume-wallet-passphrase").value || null : null, saplingKeys };
}

$("resume-source").addEventListener("change", () => {
  ++resumeGeneration;
  clearResumeSecrets();
  syncResumeSourceControls();
  $("resume-confirm").disabled = resumeAttemptPending;
});

function invalidateResumeAttempt() {
  ++resumeGeneration;
  if (pendingResumeRow) $("resume-confirm").disabled = resumeAttemptPending;
}

for (const id of [
  "resume-seed-input", "resume-bip39-passphrase", "resume-wallet-path",
  "resume-wallet-passphrase", "resume-sapling-keys", "resume-destination-input",
  "resume-memo-input", "resume-max-fee-zec", "resume-label-input", "resume-confirmation-sources",
]) {
  for (const event of ["input", "change"]) $(id).addEventListener(event, invalidateResumeAttempt);
}

$("resume-wallet-pick").addEventListener("click", async () => {
  const generation = resumeGeneration;
  try {
    const path = await invoke("pick_wallet_file");
    if (generation !== resumeGeneration || !pendingResumeRow || !path) return;
    $("resume-wallet-path").value = path;
    invalidateResumeAttempt();
  } catch (err) {
    if (generation === resumeGeneration && pendingResumeRow) setStatus("resume-modal-status", `Could not choose wallet file: ${err}`, "error");
  }
});

function passphraseForResumedSession(row, value) {
  return row.match_coordinates ? value : null;
}

$("resume-cancel").addEventListener("click", closeResumeModal);
$("resume-modal").addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    event.stopPropagation();
    closeResumeModal();
  }
});
$("resume-seed-visibility").addEventListener("change", () => {
  $("resume-seed-input").classList.toggle("masked", !$("resume-seed-visibility").checked);
});
$("resume-seed-clear-clipboard").addEventListener("click", () =>
  clearOsClipboard("resume-modal-status")
);

$("resume-confirm").addEventListener("click", async () => {
  if (resumeAttemptPending) return;
  if (state.sweepExecutionPending) {
    setStatus("resume-modal-status", "Wait for the current sweep to finish before resuming a scan.", "error");
    return;
  }
  if (!pendingResumeRow) return;
  const row = pendingResumeRow;
  const generation = resumeGeneration;
  const scanGeneration = state.scanAuthorityGeneration;
  const isCurrent = () => generation === resumeGeneration && pendingResumeRow === row &&
    scanGeneration === state.scanAuthorityGeneration;
  let source;
  try {
    source = resumeSourceInput();
  } catch (err) {
    setStatus("resume-modal-status", err.message, "error");
    return;
  }
  const destination = $("resume-destination-input").value.trim();
  const memo = $("resume-memo-input").value.trim();
  const maxFeeZec = $("resume-max-fee-zec").value.trim();
  if (!destination) {
    setStatus("resume-modal-status", "Enter a destination Unified Address.", "error");
    return;
  }
  if (!/^\d+(?:\.\d{1,8})?$/.test(maxFeeZec) || Number(maxFeeZec) <= 0 || !Number.isFinite(Number(maxFeeZec))) {
    setStatus("resume-modal-status", "Enter a positive maximum fee in ZEC with at most 8 decimal places.", "error");
    return;
  }
  const labelOverride = $("resume-label-input").value.trim();
  const lightwalletdUrl = SERVER_PRESETS[row.network] ?? SERVER_PRESETS.mainnet;
  const confirmationSources = confirmationSourcesFromForm("resume-confirmation-sources");
  // Hold the lock from the first await through stale-handle and review cleanup.
  // Editing or reopening invalidates results, but cannot launch a second worker.
  resumeAttemptPending = true;
  $("resume-confirm").disabled = true;
  let walletReviewId = null;
  try {
    const info = await invoke("validate_address", { address: destination, network: row.network });
    if (!isCurrent()) return;
    if (!info.destination_ok) {
      setStatus("resume-modal-status", "Destination must have an Orchard or Sapling receiver.", "error");
      return;
    }
    setStatus("resume-modal-status", "Verifying recovery source and resuming…", "");
    let walletSummary = null;
    let transparentOnly = false;
    if (source.walletPath) {
      const summary = await invoke("inspect_wallet_file", {
        path: source.walletPath,
        passphrase: source.walletPassphrase,
        network: row.network,
        dataDir: null,
      });
      walletReviewId = summary.review_id || null;
      if (!isCurrent()) return;
      if (summary.needs_passphrase) throw new Error("Enter the correct wallet encryption password to unlock this file.");
      if (!walletReviewId) throw new Error("This wallet file contains no recoverable keys.");
      walletSummary = summary;
      transparentOnly = summary.transparent_only && !source.saplingKeys.length;
    }
    showScanWarning(transparentOnly ? "transparent-only" : "shielded");
    const resumed = await invoke("resume_session", {
      input: {
        workspace_path: row.workspace_path,
        seed: source.seed,
        passphrase: source.passphrase,
        wallet_review_id: walletReviewId,
        wallet_passphrase: source.walletPassphrase,
        sapling_keys: source.saplingKeys,
        destination,
        sweep_memo: memo || null,
        lightwalletd_url: lightwalletdUrl,
        confirmation_sources: confirmationSources,
        label: labelOverride || null,
      },
    });
    if (!isCurrent()) {
      await invoke("release_scan", { handle: resumed.handle }).catch(() => {});
      return;
    }
    resetRecoveryFlowState({ destination, memo, maxFeeZec });
    if (walletSummary) {
      noteUncoveredSproutKeys(walletSummary);
      notePartialImport(walletSummary);
    }
    state.scanConfig = {
      network: resumed.network,
      data_dir: resumed.data_dir,
      lightwalletd_url: resumed.lightwalletd_url,
      confirmation_sources: resumed.confirmation_sources,
    };
    $("network-select").value = resumed.network;
    $("data-dir").value = resumed.data_dir;
    $("lightwalletd-url").value = resumed.lightwalletd_url;
    $("confirmation-sources").value = (resumed.confirmation_sources || []).join("\n");
    try {
      localStorage.setItem(CONFIRMATION_SOURCES_STORAGE_KEY, $("confirmation-sources").value);
    } catch (_) {}
    $("server-preset").value = resumed.lightwalletd_url === SERVER_PRESETS[resumed.network]
      ? "recommended" : "custom";
    state.scanHandle = resumed.handle;
    closeResumeModal();
    furthestStep = steps.indexOf("scan");
    goTo("scan");
    await startProgressListeners(resumed.handle);
  } catch (err) {
    if (isCurrent()) {
      clearResumeSecrets();
      setStatus("resume-modal-status", `✗ ${err}`, "error");
    }
  } finally {
    if (walletReviewId) await invoke("release_wallet_review", { reviewId: walletReviewId }).catch(() => {});
    resumeAttemptPending = false;
    $("resume-confirm").disabled = false;
  }
});

// ─── Init ─────────────────────────────────────────────────────────────────────

$("lightwalletd-url").value = SERVER_PRESETS.mainnet;
try {
  $("confirmation-sources").value = localStorage.getItem(CONFIRMATION_SOURCES_STORAGE_KEY) || "";
} catch (_) {
  // Scans can still use the source input when webview storage is unavailable.
}
$("confirmation-sources").addEventListener("input", () => {
  try {
    localStorage.setItem(CONFIRMATION_SOURCES_STORAGE_KEY, $("confirmation-sources").value);
  } catch (_) {}
});
renderSproutScanPanel();
syncAccountScanControls();
$("scan-label").value = defaultScanLabel();
$("scan-label").placeholder = defaultScanLabel();
goTo("welcome");

invoke("default_data_dir")
  .then((dir) => {
    state.defaultDataDir = dir || null;
    if (dir && !$("data-dir").value.trim()) {
      $("data-dir").value = dir;
      if (/(?:^|[/\\])workspace-v2$/.test(dir)) {
        const notice = document.createElement("small");
        notice.className = "muted";
        notice.textContent = `Your previous default workspace is preserved. Argos now uses ${dir}; ` +
          "rescan from your original seed or wallet file. Reconcile any previously broadcast transactions before recovering those funds again.";
        $("data-dir").insertAdjacentElement("afterend", notice);
      }
    }
  })
  .catch(() => {
    // Non-fatal: user can always type a path manually.
  })
  .finally(() => {
    // Populate resume panel after the data dir is known so we list
    // sessions under the dir the user actually configured.
    refreshResumePanel();
  });

}); // end DOMContentLoaded
