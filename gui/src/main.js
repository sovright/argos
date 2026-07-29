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
  lastProgress: null,
  sweepProposal: null,
  destination: null,
  memo: null,
  maxFeeZec: null,
  unlistenProgress: null,
  unlistenComplete: null,
  unlistenDiscovered: null,
  scanConfig: null,
  savedReportPath: null,
  donationEnabled: false,
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

function goTo(step) {
  const stepIdx = steps.indexOf(step);
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
}

// Make sidebar steps clickable — only allow jumping to already-reached steps
document.querySelectorAll(".step-list li").forEach((li) => {
  li.style.cursor = "pointer";
  li.addEventListener("click", () => {
    const target = li.dataset.stepIndicator;
    const targetIdx = steps.indexOf(target);
    if (targetIdx <= furthestStep) {
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

async function validateSeed() {
  const words = seedInput.value.trim().toLowerCase().split(/\s+/);
  setStatus("seed-status", "Validating…", "");
  seedNextBtn.disabled = true;
  try {
    await invoke("validate_seed", { words });
    setStatus("seed-status", "✓ Seed phrase is valid.", "success");
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

// ─── Step 3: Configuration ────────────────────────────────────────────────────

// Keep in sync with DEFAULT_MAINNET_LIGHTWALLETD / DEFAULT_TESTNET_LIGHTWALLETD
// in crates/zeck-core/src/lightwalletd.rs.
const SERVER_PRESETS = {
  mainnet: "https://zec.rocks:443,https://na.zec.rocks:443",
  testnet: "https://testnet.zec.rocks:443",
};

$("network-select").addEventListener("change", () => {
  if ($("server-preset").value === "recommended") {
    $("lightwalletd-url").value = SERVER_PRESETS[$("network-select").value] ?? SERVER_PRESETS.mainnet;
  }
});

$("server-preset").addEventListener("change", () => {
  const preset = $("server-preset").value;
  if (preset === "custom") return;
  const key = preset === "recommended" ? $("network-select").value : preset;
  $("lightwalletd-url").value = SERVER_PRESETS[key] ?? SERVER_PRESETS.mainnet;
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

$("auto-gap-limit").addEventListener("change", () => {
  const auto = $("auto-gap-limit").checked;
  $("gap-limit-row").style.display = auto ? "none" : "block";
  $("accounts-range").disabled = !auto;
  $("accounts-range-value").style.opacity = auto ? "0.4" : "1";
});

// Approximate mainnet chain tip and scan rate for time estimates
const APPROX_CHAIN_TIP = 2_730_000;
const BLOCKS_PER_MINUTE = 38_000;

function updateScanEstimate() {
  const birthday = parseInt($("birthday-height").value, 10) || 419200;
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

// Piecewise height→date (Sapling 150 s/block until Blossom @ 653,600,
// then 75 s/block). Mirrors crates/argos-core/src/birthday.rs and lets us
// give the user instant round-trip feedback as they type a height.
const SAPLING_ACTIVATION_HEIGHT_JS = 419_200;
const SAPLING_ACTIVATION_DATE_JS = Date.UTC(2018, 9, 28); // Oct 28 2018
const BLOSSOM_ACTIVATION_HEIGHT_JS = 653_600;
const BLOSSOM_ACTIVATION_DATE_JS = Date.UTC(2019, 11, 11); // Dec 11 2019
const PRE_BLOSSOM_BLOCK_SECONDS = 150;
const POST_BLOSSOM_BLOCK_SECONDS = 75;

function approxDateFromHeight(height) {
  if (!Number.isFinite(height) || height <= SAPLING_ACTIVATION_HEIGHT_JS) {
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
  }
  return new Date(anchorMs + (height - anchorHeight) * blockSeconds * 1000);
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
  const approx = formatApproxMonth(approxDateFromHeight(height));
  setBirthdayHint(`Block ${height.toLocaleString()} ≈ ${approx}.`, "");
}

$("birthday-height").addEventListener("input", () => {
  updateScanEstimate();
  updateBirthdayHint();
});
updateScanEstimate();
updateBirthdayHint();

$("birthday-autodetect").addEventListener("click", async () => {
  const seedVal = seedInput.value.trim();
  if (!seedVal) {
    setBirthdayHint("Enter your seed phrase on step 2 first.", "error");
    return;
  }
  $("birthday-autodetect").disabled = true;
  $("birthday-estimate").disabled = true;
  setBirthdayHint("Starting detection…", "");
  setStatus("config-status", "", "");

  const unlistenProbe = await listen("birthday-probe-progress", (event) => {
    setBirthdayHint(event.payload, "");
  });

  try {
    const result = await invoke("detect_birthday", {
      seed: seedVal.toLowerCase(),
      lightwalletdUrl: $("lightwalletd-url").value.trim(),
      network: $("network-select").value,
    });
    $("birthday-height").value = result.birthday;
    updateScanEstimate();
    const approx = formatApproxMonth(approxDateFromHeight(result.birthday));
    setBirthdayHint(
      `✓ Auto-detected birthday: block ${Number(result.birthday).toLocaleString()} (≈ ${approx}).`,
      "success",
    );
  } catch (err) {
    setBirthdayHint(`✗ Auto-detect failed: ${err}`, "error");
  } finally {
    $("birthday-autodetect").disabled = false;
    $("birthday-estimate").disabled = false;
    unlistenProbe();
  }
});

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
      lightwalletdUrl: $("lightwalletd-url").value.trim(),
    });
    $("birthday-height").value = height;
    updateScanEstimate();
    const approx = formatApproxMonth(approxDateFromHeight(height));
    setBirthdayHint(
      `✓ Birthday set to block ${Number(height).toLocaleString()} (≈ ${approx}, with ~1 week safety margin).`,
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

$("start-scan").addEventListener("click", async () => {
  if (!seedInput.value.trim()) {
    setStatus("config-status", "Seed phrase is required — go back and enter it.", "error");
    return;
  }

  const address = $("destination-input").value.trim();
  if (!address) {
    setStatus("config-status", "A destination Unified Address is required.", "error");
    return;
  }

  try {
    const info = await invoke("validate_address", { address, network: $("network-select").value });
    if (!info.destination_ok) {
      setStatus("config-status", "✗ Address must have an Orchard or Sapling receiver.", "error");
      return;
    }
  } catch (err) {
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
      $("data-dir").value = dataDirVal;
    } catch (_) {
      setStatus("config-status", "✗ Could not determine a data directory. Please enter one manually.", "error");
      $("start-scan").disabled = false;
      return;
    }
  }

  const autoGap = $("auto-gap-limit").checked;
  const labelRaw = ($("scan-label")?.value ?? "").trim();
  const config = {
    seed: seedInput.value.trim().toLowerCase(),
    birthday: parseInt($("birthday-height").value, 10) || 419200,
    num_accounts: autoGap ? null : parseInt($("accounts-range").value, 10),
    gap_limit: autoGap ? parseInt($("gap-limit").value, 10) : 20,
    lightwalletd_url: $("lightwalletd-url").value.trim(),
    data_dir: dataDirVal,
    network: $("network-select").value,
    label: labelRaw || defaultScanLabel(),
  };
  // Store a seed-less copy. The seed is passed to `start_scan` below, but
  // must not persist in JS state for the lifetime of the scan→sweep→complete
  // flow (threat model T-S2).
  const { seed: _seed, ...configForState } = config;
  state.scanConfig = configForState;

  setStatus("config-status", "Starting scan…", "");
  $("start-scan").disabled = true;

  try {
    const handle = await invoke("start_scan", { config });
    state.scanHandle = handle;
    goTo("scan");
    await startProgressListeners();
  } catch (err) {
    setStatus("config-status", `✗ ${err}`, "error");
    $("start-scan").disabled = false;
  } finally {
    // Clear the seed phrase from the DOM regardless of whether start_scan
    // succeeded; on failure the user can retype, and a successful scan no
    // longer needs the cleartext phrase visible.
    seedInput.value = "";
  }
});

// ─── Step 4: Scan Progress ────────────────────────────────────────────────────

async function startProgressListeners() {
  $("scan-phase").textContent = "Starting…";
  $("scan-server").textContent = "Connecting…";
  $("scan-progress-text").textContent = "0 / 0";
  $("scan-eta").textContent = "Calculating…";
  $("scan-progress-bar").style.width = "0%";
  $("scan-rows").innerHTML = "";
  setStatus("scan-message", "", "");
  $("review-sweep").disabled = true;
  $("back-to-config").style.display = "none";
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
      if (event.payload.handle?.id !== state.scanHandle?.id) return;
      updateScanUI(event.payload);
    }),
    listen("scan-complete", (event) => {
      if (event.payload.handle?.id !== state.scanHandle?.id) return;
      updateScanUI(event.payload);
      notifyScanComplete(event.payload);
      cleanupListeners();
    }),
    listen("scan-discovery", (event) => {
      const d = event.payload;
      const div = document.createElement("div");
      div.className = "discovery-toast";
      // at_block_height is the scan frontier when first observed, not the
      // mined height of the funding transaction — label it that way.
      const heightHint = d.at_block_height
        ? ` (scanned through block ${d.at_block_height.toLocaleString()})`
        : "";
      div.textContent =
        `Found ${fmt(d.zatoshis)} on account ${d.account_index} — ${d.pool}${heightHint}. Shielded scan still running — Review & Sweep will unlock when complete.`;
      const container = $("scan-discoveries");
      container.appendChild(div);
      container.style.display = "";
    }),
  ]);
  state.unlistenProgress = unlistenProgress;
  state.unlistenComplete = unlistenComplete;
  state.unlistenDiscovered = unlistenDiscovered;
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

function updateScanUI(progress) {
  state.lastProgress = progress;

  $("scan-phase").textContent = phaseLabel(progress.phase);

  if (progress.server?.endpoint) {
    const primary = $("lightwalletd-url").value.split(",")[0].trim();
    const isFallback = progress.server.endpoint !== primary;
    $("scan-server").textContent = progress.server.endpoint + (isFallback ? " (fallback)" : "");
    $("scan-server").title = isFallback
      ? "Connected to a fallback server — a different operator can see your scan activity"
      : "";
  }

  const scanned = Number(progress.blocks_scanned);
  const total = Number(progress.blocks_total);
  $("scan-progress-text").textContent =
    `${scanned.toLocaleString()} / ${total.toLocaleString()}`;

  if (total > 0) {
    $("scan-progress-bar").style.width =
      `${Math.min(100, (scanned / total) * 100).toFixed(1)}%`;
  }

  eta.observe(scanned, total);
  // eraHint expects an absolute Zcash chain height. blocks_scanned is a
  // delta from effective_birthday — passing it directly mislabels the era
  // for any wallet whose birthday is past Sapling activation. Use
  // synced_to_height (set by the backend) when available.
  const era = progress.synced_to_height ? eraHint(Number(progress.synced_to_height)) : null;
  const etaState = eta.estimate();
  let etaText;
  if (etaState.kind === "warmup") {
    etaText = "Calculating…";
  } else if (etaState.kind === "done") {
    etaText = "";
  } else {
    etaText = etaState.text;
  }
  if (era) etaText = etaText ? `${etaText} · scanning ~${era}` : `scanning ~${era}`;
  $("scan-eta").textContent = etaText;

  if (progress.error) {
    setStatus("scan-message", progress.error, "error");
    $("back-to-config").style.display = "";
  } else if (progress.message) {
    setStatus("scan-message", progress.message, "");
  }

  if (progress.summary) {
    const s = progress.summary;
    const acctCount = progress.accounts.length;
    $("scan-totals").textContent =
      `Grand total: ${fmt(s.total_zatoshis)} across ${acctCount} account(s).${s.authoritative_balances ? "" : " (estimates)"}`;
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
    const g = progress.gap_extension;
    $("scan-gap-extension-detail").textContent =
      `Found activity in account ${g.trigger_account_index}, so the search widened to accounts ` +
      `${g.accounts_from}–${g.accounts_to} (extension #${g.pass}). `;
    $("scan-gap-extension-banner").style.display = "";
  } else {
    $("scan-gap-extension-banner").style.display = "none";
  }

  const terminal = ["complete", "cancelled", "error"].includes(progress.phase);
  $("cancel-scan").style.display = terminal ? "none" : "";
  if (progress.phase === "complete") {
    $("review-sweep").disabled = false;
  }
}

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
  cleanupListeners();
  state.scanHandle = null;
  $("back-to-config").style.display = "none";
  $("start-scan").disabled = false;
  goTo("config");
});

$("cancel-scan").addEventListener("click", async () => {
  if (!state.scanHandle) return;
  try {
    await invoke("cancel_scan", { handle: state.scanHandle });
    cleanupListeners();
    setStatus("scan-message", "Scan cancelled. Workspace state preserved on disk.", "");
    $("scan-phase").textContent = "Cancelled";
    $("back-to-config").style.display = "";
    $("start-scan").disabled = false;
  } catch (err) {
    setStatus("scan-message", `Cancel failed: ${err}`, "error");
  }
});

function donationParamsFromForm() {
  if (!state.donationEnabled) return { donationRate: null, donorEmail: null };
  const enabled = $("donate-enabled").checked;
  const pct = parseFloat($("donate-rate").value);
  const donationRate = enabled && Number.isFinite(pct) && pct > 0 ? pct / 100 : null;
  const donorEmail = enabled ? ($("donate-email").value.trim() || null) : null;
  return { donationRate, donorEmail };
}

async function refreshSweepProposal() {
  const { donationRate, donorEmail } = donationParamsFromForm();
  const proposal = await invoke("propose_sweep", {
    handle: state.scanHandle,
    destination: state.destination,
    memo: state.memo,
    maxFeeZec: state.maxFeeZec,
    donationRate,
    donorEmail,
  });
  state.sweepProposal = proposal;
  renderSweepProposal(proposal);
}

async function maybeRefreshProposal() {
  if (!state.sweepProposal) return;
  try {
    await refreshSweepProposal();
  } catch (err) {
    setStatus("sweep-execute-status", `✗ ${err}`, "error");
  }
}

$("review-sweep").addEventListener("click", async () => {
  setStatus("scan-message", "Fetching sweep proposal…", "");
  $("review-sweep").disabled = true;

  try {
    await refreshSweepProposal();
    goTo("sweep");
  } catch (err) {
    setStatus("scan-message", `✗ ${err}`, "error");
    $("review-sweep").disabled = false;
  }
});

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
  const p = state.sweepProposal;
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
  maybeRefreshProposal();
}

document.querySelectorAll("#donate-presets .preset-chip").forEach((chip) => {
  chip.addEventListener("click", () => selectDonationPreset(chip.dataset.pct));
});

// Custom field: keep its chip highlighted while typing; re-propose on change.
$("donate-rate").addEventListener("input", () => {
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
    maybeRefreshProposal();
  } else {
    $("donate-skip").textContent = "No thanks, skip donation";
    selectDonationPreset("10"); // re-enables, un-collapses, and re-proposes
  }
});
// email does not affect amounts; it's read fresh at propose/execute time, no re-propose needed

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
    (proposal.warning ? `  ⚠ ${proposal.warning}` : "");

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
  // Re-enable the checkbox: a prior sweep's execute click disables it (and only
  // the error path re-enables it), so without this a second proposal in the
  // same session leaves the checkbox stuck disabled and the sweep unclickable.
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
  $("execute-sweep").disabled = !$("irreversible-check").checked;
});

$("execute-sweep").addEventListener("click", async () => {
  $("execute-sweep").disabled = true;
  $("irreversible-check").disabled = true;
  setStatus("sweep-execute-status", "Broadcasting transactions to the Zcash network… this may take up to 2 minutes.", "");

  try {
    const { donationRate, donorEmail } = donationParamsFromForm();
    // `execute_sweep` rejects only when nothing was broadcast. A mid-sequence
    // abort after one or more broadcasts resolves with `{ transactions, error }`
    // so the already-broadcast transaction IDs are still shown (audit Issue E).
    const outcome = await invoke("execute_sweep", {
      handle: state.scanHandle,
      destination: state.destination,
      memo: state.memo,
      maxFeeZec: state.maxFeeZec,
      donationRate,
      donorEmail,
    });
    setStatus("sweep-execute-status", "", "");
    renderCompleteScreen(
      outcome.transactions,
      outcome.skipped_accounts,
      outcome.total_donation_zatoshis || 0,
      donationRate,
      outcome.error,
    );
    goTo("complete");
  } catch (err) {
    $("execute-sweep").disabled = false;
    $("irreversible-check").disabled = false;
    setStatus("sweep-execute-status", `✗ Sweep failed: ${err}`, "error");
  }
});

// ─── Step 6: Complete ─────────────────────────────────────────────────────────

function renderCompleteScreen(results, skipped, donated, donationRate, error) {
  const confirmed = results.filter((r) => r.status === "confirmed").length;
  const pending = results.filter((r) => r.status === "pending").length;
  const failed = results.filter((r) => r.status === "failed").length;
  const broadcast = confirmed + pending;

  if (error) {
    // The sweep aborted partway. The transactions below were already
    // broadcast and are irreversible; the remaining accounts were not swept.
    // Surface this so the user does not assume nothing was sent and retry
    // (which would double-broadcast) — audit Issue E.
    $("complete-summary").textContent =
      `The sweep stopped before completing, but ${broadcast} transaction${broadcast === 1 ? " was" : "s were"} already broadcast and cannot be undone (listed below). ` +
      `The remaining accounts were not swept. Rescan or check a block explorer before retrying, so you do not broadcast duplicates. Error: ${error}`;
  } else if (results.length === 0) {
    // Nothing was broadcast because every account with a balance was skipped
    // (below the fee floor, or transparent funds that couldn't be shielded).
    // The reasons are listed below — this is NOT a broadcast failure.
    $("complete-summary").textContent =
      "No funds were swept — every account with a balance was skipped (reasons below).";
  } else if (failed === results.length) {
    $("complete-summary").textContent = "All transactions failed to broadcast. No funds were moved.";
  } else if (confirmed > 0) {
    $("complete-summary").textContent =
      `${confirmed} transaction${confirmed > 1 ? "s" : ""} confirmed on-chain. Your funds are on their way.`;
  } else {
    $("complete-summary").textContent =
      `${broadcast} transaction${broadcast > 1 ? "s" : ""} broadcast to the Zcash network. Confirmation usually takes 1–2 minutes.`;
  }

  const container = $("complete-txids");
  container.innerHTML = "";
  results.forEach((r) => {
    const card = document.createElement("div");
    card.className = "txid-card" + (r.status === "failed" ? " txid-card--failed" : "");

    const label = document.createElement("div");
    label.className = "txid-label";
    const statusTag = r.status === "confirmed" ? "Confirmed" :
                      r.status === "pending"   ? "Broadcast — awaiting confirmation" :
                                                 "Failed";
    label.textContent = `Account ${r.source_account} · ${statusTag}`;
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

    if (r.confirmed_height) {
      const note = document.createElement("div");
      note.className = "txid-note";
      note.textContent = `Mined at block ${r.confirmed_height.toLocaleString()}`;
      card.appendChild(note);
      if (r.detail) {
        const detail = document.createElement("div");
        detail.className = "txid-note";
        detail.textContent = r.detail;
        card.appendChild(detail);
      }
    } else if (r.detail && r.status !== "confirmed") {
      const note = document.createElement("div");
      note.className = "txid-note";
      note.textContent = r.detail;
      card.appendChild(note);
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

  // Actual donated total (the truth, vs the proposal's estimate). Shown whenever
  // a donation was requested — including when it came out to 0, so a proposal
  // estimate that execution couldn't deliver is never silent.
  const donationEl = $("complete-donation");
  const donationRequested = Number.isFinite(donationRate) && donationRate > 0;
  if (donated > 0) {
    donationEl.hidden = false;
    donationEl.textContent = `Donated ${fmt(donated)} to the Argos project — thank you for supporting Zcash recovery.`;
  } else if (donationRequested && broadcast > 0) {
    donationEl.hidden = false;
    donationEl.textContent =
      "No donation was sent: at the real network fee, each account's share fell below the 0.001 ZEC minimum, so your full balance went to your address.";
  } else {
    donationEl.hidden = true;
    donationEl.textContent = "";
  }

  const report = buildReport(results);
  $("save-report").dataset.report = report;
  $("report-path").value = buildDefaultReportPath();
}

function buildReport(results) {
  const cfg = state.scanConfig;
  const prog = state.lastProgress;
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
    "Transaction Results",
    "──────────────────",
    ...results.map((r) => {
      let line = `Account ${r.source_account}: ${r.status}`;
      if (r.txid) line += `\n  txid: ${r.txid}`;
      if (r.confirmed_height) line += `\n  confirmed at block ${r.confirmed_height}`;
      if (r.detail) line += `\n  detail: ${r.detail}`;
      return line;
    }),
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
      handle: state.scanHandle,
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
  if (!state.scanHandle) {
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
    const deletedPath = await invoke("delete_workspace", { handle: state.scanHandle });
    setStatus("delete-workspace-status", `✓ Deleted ${deletedPath}`, "success");
    // The session is gone server-side; further per-handle commands would fail.
    state.scanHandle = null;
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

$("restart-flow").addEventListener("click", () => {
  cleanupListeners();
  furthestStep = 0;
  Object.assign(state, {
    scanHandle: null,
    lastProgress: null,
    sweepProposal: null,
    destination: null,
    memo: null,
    maxFeeZec: null,
    scanConfig: null,
    savedReportPath: null,
  });
  $("copy-report-path").style.display = "none";
  $("delete-workspace").disabled = false;
  $("save-report").disabled = false;
  setStatus("delete-workspace-status", "", "");

  seedInput.value = "";
  seedVisibility.checked = false;
  seedInput.classList.add("masked");
  seedNextBtn.disabled = true;
  setStatus("seed-status", "", "");
  setStatus("config-status", "", "");
  $("destination-input").value = "";
  $("max-fee-zec").value = "";
  $("sweep-memo").value = "";
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
  $("scan-totals").textContent = "Grand total: 0.00000000 ZEC across 0 accounts.";
  $("scan-workspace").textContent = "Workspace: not initialized";
  setStatus("scan-message", "", "");
  $("review-sweep").disabled = true;
  $("back-to-config").style.display = "none";
  $("cancel-scan").style.display = "";

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
  labelEl.textContent = row.label || "(unlabeled scan)";
  info.appendChild(labelEl);

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
  pendingResumeRow = row;
  $("resume-modal-title").textContent = `Resume "${row.label || "(unlabeled scan)"}"`;
  $("resume-seed-input").value = "";
  $("resume-seed-input").classList.add("masked");
  $("resume-seed-visibility").checked = false;
  $("resume-label-input").value = "";
  setStatus("resume-modal-status", "", "");
  $("resume-modal").hidden = false;
  $("resume-seed-input").focus();
}

function closeResumeModal() {
  pendingResumeRow = null;
  $("resume-modal").hidden = true;
  $("resume-seed-input").value = "";
}

$("resume-cancel").addEventListener("click", closeResumeModal);
$("resume-seed-visibility").addEventListener("change", () => {
  $("resume-seed-input").classList.toggle("masked", !$("resume-seed-visibility").checked);
});
$("resume-seed-clear-clipboard").addEventListener("click", () =>
  clearOsClipboard("resume-modal-status")
);

$("resume-confirm").addEventListener("click", async () => {
  if (!pendingResumeRow) return;
  const seed = $("resume-seed-input").value.trim().toLowerCase();
  if (!seed) {
    setStatus("resume-modal-status", "Enter the seed phrase to continue.", "error");
    return;
  }
  const labelOverride = $("resume-label-input").value.trim();
  const lightwalletdUrl =
    $("lightwalletd-url").value.trim() ||
    (pendingResumeRow.network === "testnet"
      ? SERVER_PRESETS.testnet
      : SERVER_PRESETS.mainnet);

  $("resume-confirm").disabled = true;
  setStatus("resume-modal-status", "Verifying seed and resuming…", "");
  try {
    const handle = await invoke("resume_session", {
      input: {
        workspace_path: pendingResumeRow.workspace_path,
        seed,
        lightwalletd_url: lightwalletdUrl,
        label: labelOverride || null,
      },
    });
    state.scanHandle = handle;
    closeResumeModal();
    // Skip the seed/config screens — they don't apply to a resumed scan.
    furthestStep = steps.indexOf("scan");
    goTo("scan");
    await startProgressListeners();
  } catch (err) {
    setStatus("resume-modal-status", `✗ ${err}`, "error");
  } finally {
    $("resume-confirm").disabled = false;
  }
});

// ─── Init ─────────────────────────────────────────────────────────────────────

$("lightwalletd-url").value = SERVER_PRESETS.mainnet;
$("gap-limit-row").style.display = $("auto-gap-limit").checked ? "none" : "block";
$("accounts-range").disabled = !$("auto-gap-limit").checked;
$("scan-label").value = defaultScanLabel();
$("scan-label").placeholder = defaultScanLabel();
goTo("welcome");

invoke("default_data_dir")
  .then((dir) => {
    if (dir && !$("data-dir").value.trim()) $("data-dir").value = dir;
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
