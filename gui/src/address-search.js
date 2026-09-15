// Offline known-address matching. Secret inputs are submitted once, then cleared.
// Poll responses and match records contain public derivation metadata only.
document.addEventListener("DOMContentLoaded", () => {
  const byId = (id) => document.getElementById(id);
  const modal = byId("address-search-modal");
  const form = byId("address-search-form");
  const seedList = byId("address-search-seeds");
  const progress = byId("address-search-progress");
  const results = byId("address-search-results");
  let searchId = null;
  let pollTimer = null;
  let generation = 0;
  let renderedMatchIds = new Set();
  let publicScope = null;
  let startInFlight = null;
  let cleanupInFlight = Promise.resolve();
  let cleanupRunning = false;
  let recoveryLocked = false;

  const invoke = (command, args) => window.__TAURI__.core.invoke(command, args);

  function setFormStatus(message, kind = "") {
    const status = byId("address-search-form-status");
    status.textContent = message;
    status.className = `status-line${kind ? ` ${kind}` : ""}`;
  }

  function addSeedRow() {
    if (seedList.children.length >= 64) {
      setFormStatus("A search can include up to 64 candidate seeds.", "error");
      return;
    }
    const row = document.createElement("div");
    row.className = "candidate-seed";
    const number = seedList.children.length + 1;
    const field = (title, control) => {
      const label = document.createElement("label");
      label.className = "field";
      const caption = document.createElement("span");
      caption.textContent = title;
      label.append(caption, control);
      return label;
    };
    const labelInput = document.createElement("input");
    labelInput.className = "candidate-seed-label";
    labelInput.type = "text";
    labelInput.maxLength = 80;
    labelInput.placeholder = `Backup ${number}`;
    const words = document.createElement("textarea");
    words.className = "candidate-seed-words masked";
    words.rows = 2;
    words.spellcheck = false;
    words.autocapitalize = "off";
    words.required = true;
    const passphrase = document.createElement("input");
    passphrase.className = "candidate-seed-passphrase";
    passphrase.type = "password";
    passphrase.spellcheck = false;
    const remove = document.createElement("button");
    remove.className = "ghost small-button remove-candidate-seed";
    remove.type = "button";
    remove.setAttribute("aria-label", "Remove candidate seed");
    remove.textContent = "Remove";
    row.append(field("Label", labelInput), field("Seed phrase", words), field("BIP39 passphrase (optional)", passphrase), remove);
    remove.addEventListener("click", () => {
      if (seedList.children.length === 1) {
        row.querySelectorAll("input, textarea").forEach((input) => { input.value = ""; });
      } else {
        row.remove();
      }
    });
    seedList.append(row);
  }

  function clearSecrets() {
    seedList.querySelectorAll("input, textarea").forEach((input) => { input.value = ""; });
  }

  function updateProfileScope() {
    const target = byId("address-search-target").value.trim();
    const transparent = !target || /^(t1|tm)/.test(target);
    const fixedAccount = transparent && byId("address-search-profile").value === "zecwallet_lite";
    byId("address-search-account-start").disabled = fixedAccount;
    byId("address-search-account-count").disabled = fixedAccount;
    if (fixedAccount) {
      byId("address-search-account-start").value = "0";
      byId("address-search-account-count").value = "1";
    }
    byId("address-search-profile-note").textContent = fixedAccount
      ? "ZecWallet Lite: search receive-address indices in account 0. Every index in your range is checked, even after unused addresses. Change addresses are optional under Advanced."
      : "Search the selected account and address/diversifier ranges. Every index is checked; unused addresses do not stop the search. Account and change settings are under Advanced.";
  }
  byId("address-search-profile").addEventListener("change", updateProfileScope);
  byId("address-search-target").addEventListener("input", updateProfileScope);

  function resetForm() {
    clearSecrets();
    seedList.replaceChildren();
    addSeedRow();
    form.reset();
    byId("address-search-profile").value = "zecwallet_lite";
    byId("address-search-advanced").open = false;
    byId("address-search-account-start").value = "0";
    byId("address-search-account-count").value = "1";
    byId("address-search-index-start").value = "0";
    byId("address-search-index-count").value = "1000";
    byId("address-search-change").checked = false;
    updateProfileScope();
    setFormStatus("");
  }

  function stopPolling() {
    if (pollTimer != null) window.clearTimeout(pollTimer);
    pollTimer = null;
  }

  async function releaseCurrent(id) {
    if (!id) return true;
    try {
      await invoke("release_address_search", { id });
      document.dispatchEvent(new CustomEvent("address-search-released", { detail: { searchId: id } }));
      return true;
    } catch (error) {
      console.warn("Could not release address search:", error);
      return false;
    }
  }

  async function cancelAndRelease(id) {
    if (!id) return true;
    try { await invoke("cancel_address_search", { id }); } catch (_) { /* already terminal/released */ }
    for (;;) {
      try {
        const snapshot = await invoke("get_address_search", { id });
        if (snapshot.status !== "running") break;
      } catch (_) { break; }
      await new Promise((resolve) => window.setTimeout(resolve, 200));
    }
    return releaseCurrent(id);
  }

  function beginCleanup(id) {
    cleanupRunning = true;
    cleanupInFlight = cancelAndRelease(id).then((released) => {
      if (!released && !searchId) searchId = id;
      return released;
    }).finally(() => {
      cleanupRunning = false;
      if (!modal.hidden && !startInFlight) byId("start-address-search").disabled = false;
    });
    return cleanupInFlight;
  }

  async function close({ preserveSearch = false } = {}) {
    const id = searchId;
    generation++;
    stopPolling();
    if (preserveSearch) {
      clearSecrets();
      modal.hidden = true;
      return;
    }
    if (id) beginCleanup(id);
    searchId = null;
    clearSecrets();
    resetForm();
    progress.hidden = true;
    results.hidden = true;
    modal.hidden = true;
  }

  function numberInRange(id, min, max, label) {
    const value = Number(byId(id).value);
    if (!Number.isSafeInteger(value) || value < min || value > max) {
      throw new Error(`${label} must be a whole number from ${min.toLocaleString()} to ${max.toLocaleString()}.`);
    }
    return value;
  }

  function collectInput() {
    const target = byId("address-search-target").value.trim();
    const network = byId("address-search-network").value;
    const prefixValid = network === "mainnet"
      ? /^(t1|zs|u1)/.test(target)
      : /^(tm|ztestsapling|utest)/.test(target);
    if (!prefixValid) throw new Error(`Enter a complete ${network} transparent, Sapling, or Unified address.`);
    const seeds = [...seedList.children].map((row, seedIndex) => ({
      label: row.querySelector(".candidate-seed-label").value.trim() || `Candidate ${seedIndex + 1}`,
      seed: row.querySelector(".candidate-seed-words").value.trim().split(/\s+/).join(" "),
      passphrase: row.querySelector(".candidate-seed-passphrase").value,
    }));
    if (!seeds.length || seeds.some((candidate) => !candidate.seed)) throw new Error("Enter every candidate seed phrase, or remove its row.");
    const input = {
      target,
      network,
      seeds,
      profile: byId("address-search-profile").value,
      account_start: numberInRange("address-search-account-start", 0, 2147483647, "First account"),
      account_count: numberInRange("address-search-account-count", 1, 1000, "Accounts to check"),
      index_start: numberInRange("address-search-index-start", 0, 2147483647, "First address / diversifier index"),
      index_count: numberInRange("address-search-index-count", 1, 10000, "Indexes per selected scope"),
      include_change: byId("address-search-change").checked,
    };
    const rangeLimit = 2147483648;
    if (input.account_start + input.account_count > rangeLimit) {
      throw new Error("The account range must end at or before 2,147,483,647.");
    }
    if (input.index_start + input.index_count > rangeLimit) {
      throw new Error("The address / diversifier index range must end at or before 2,147,483,647.");
    }
    const scopes = input.include_change ? 2 : 1;
    const work = input.seeds.length * input.account_count * input.index_count * scopes;
    if (work > 10000000) {
      throw new Error("This search exceeds 10,000,000 derivation candidates. Split it into smaller ranges.");
    }
    const directTransparent = network === "mainnet" ? target.startsWith("t1") : target.startsWith("tm");
    if (input.profile === "zecwallet_lite" && directTransparent &&
        (input.account_start !== 0 || input.account_count !== 1)) {
      throw new Error("ZecWallet Lite transparent matching uses account 0 only. Choose account 0 with a count of 1, or use Advanced BIP44 accounts.");
    }
    return input;
  }

  function appendMatch(container, match, id) {
    const card = document.createElement("article");
    card.className = "address-match";
    const detail = document.createElement("div");
    const title = document.createElement("h4");
    title.textContent = `${match.seed_label || `Candidate ${match.seed_index + 1}`} · ${match.pool}`;
    const address = document.createElement("code");
    address.textContent = match.address;
    const path = document.createElement("code");
    path.textContent = match.path;
    const meta = document.createElement("p");
    meta.className = "match-meta";
    meta.textContent = `Account ${match.account} · ${match.scope} · index ${match.index}`;
    detail.append(title, address, path, meta);
    const recover = document.createElement("button");
    recover.className = "primary small-button";
    recover.type = "button";
    recover.textContent = "Recover this match";
    recover.disabled = recoveryLocked;
    recover.addEventListener("click", async () => {
      if (recoveryLocked || recover.disabled) return;
      const event = new CustomEvent("address-match-recovery", {
        detail: { searchId: id, matchId: match.id, match },
        bubbles: true,
      });
      document.dispatchEvent(event);
      await close({ preserveSearch: true });
    });
    card.append(detail, recover);
    container.append(card);
  }

  function renderMatches(snapshot, container) {
    for (const match of snapshot.matches || []) {
      if (renderedMatchIds.has(match.id)) continue;
      renderedMatchIds.add(match.id);
      appendMatch(container, match, snapshot.id);
    }
  }

  function setRecoveryLocked(locked) {
    recoveryLocked = locked;
    for (const container of [byId("address-search-live-matches"), byId("address-search-matches")]) {
      container.querySelectorAll("button").forEach((button) => {
        button.disabled = recoveryLocked;
        button.title = recoveryLocked ? "Finish or stop the current recovery before starting another." : "";
      });
    }
  }

  function scopeDescription(snapshot) {
    const branch = snapshot.include_change ? "external and internal/change scopes" : "external scope";
    const lastAccount = snapshot.account_start + snapshot.account_count - 1;
    const lastIndex = snapshot.index_start + snapshot.index_count - 1;
    return `${snapshot.network} · ${snapshot.profile === "zecwallet_lite" ? "ZecWallet Lite" : "Advanced BIP44 accounts"} · accounts ${snapshot.account_start}–${lastAccount} · address/diversifier indexes ${snapshot.index_start}–${lastIndex}, ${branch}`;
  }

  function renderSnapshot(snapshot) {
    snapshot = { ...publicScope, ...snapshot };
    const checked = Math.max(0, Number(snapshot.checked) || 0);
    const total = Math.max(0, Number(snapshot.total) || 0);
    const percent = total ? Math.min(100, Math.floor(checked / total * 100)) : 0;
    byId("address-search-percent").textContent = `${percent}%`;
    byId("address-search-progress-bar").style.width = `${percent}%`;
    byId("address-search-count").textContent = `${checked.toLocaleString()} of ${total.toLocaleString()} derivation candidates checked · ${scopeDescription(snapshot)}`;
    renderMatches(snapshot, byId("address-search-live-matches"));
    if (snapshot.status === "running") return false;

    progress.hidden = true;
    results.hidden = false;
    const outcome = byId("address-search-outcome");
    outcome.replaceChildren();
    const heading = document.createElement("h3");
    const copy = document.createElement("p");
    const matches = snapshot.matches || [];
    if (snapshot.status === "complete" && matches.length) {
      heading.textContent = matches.length === 1 ? "Exact match found" : `${matches.length} exact matches found`;
      copy.textContent = `The known address, or an individual receiver inside that Unified Address, exactly matches the derivation path shown below. Target: ${snapshot.target}`;
    } else if (snapshot.status === "complete") {
      heading.textContent = "No match in the searched range";
      copy.textContent = `Argos checked ${checked.toLocaleString()} derivation candidates for ${snapshot.target}.`;
    } else if (snapshot.status === "cancelled") {
      heading.textContent = "Search cancelled";
      copy.textContent = `Argos stopped after ${checked.toLocaleString()} of ${total.toLocaleString()} derivation candidates.`;
    } else {
      heading.textContent = "Search could not finish";
      copy.textContent = snapshot.error || "The local matcher returned an error.";
    }
    outcome.append(heading, copy);
    const finalMatches = byId("address-search-matches");
    finalMatches.replaceChildren();
    renderedMatchIds = new Set();
    renderMatches(snapshot, finalMatches);
    byId("address-search-limitation").textContent = matches.length
      ? `This result identifies an exact address or receiver path within ${scopeDescription(snapshot)}. A match to one Unified Address receiver does not prove its other receivers came from the same seed. Recovery will ask for network settings before making any network connection.`
      : `This only rules out ${scopeDescription(snapshot)}. The address may belong to another seed, BIP39 passphrase, wallet derivation, account, index, branch, or imported key.`;
    return true;
  }

  async function poll(id, requestGeneration) {
    if (requestGeneration !== generation || id !== searchId) return;
    try {
      const snapshot = await invoke("get_address_search", { id });
      if (requestGeneration !== generation || id !== searchId) return;
      const terminal = renderSnapshot(snapshot);
      if (terminal) return;
      pollTimer = window.setTimeout(() => poll(id, requestGeneration), 200);
    } catch (error) {
      if (requestGeneration !== generation || id !== searchId) return;
      progress.hidden = true;
      form.hidden = false;
      setFormStatus(`Could not read search progress: ${error}`, "error");
    }
  }

  byId("open-address-search").addEventListener("click", () => {
    if (searchId) {
      document.dispatchEvent(new CustomEvent("address-search-reopen", { detail: { searchId } }));
      return;
    }
    generation++;
    searchId = null;
    resetForm();
    byId("start-address-search").disabled = !!startInFlight || cleanupRunning;
    if (startInFlight || cleanupRunning) setFormStatus("Finishing the previous local search before another can start…");
    form.hidden = false;
    progress.hidden = true;
    results.hidden = true;
    modal.hidden = false;
    byId("address-search-target").focus();
  });
  document.addEventListener("address-search-reopen", async (event) => {
    if (!searchId || (event.detail?.searchId && event.detail.searchId !== searchId)) return;
    const requestGeneration = ++generation;
    stopPolling();
    modal.hidden = false;
    form.hidden = true;
    progress.hidden = false;
    results.hidden = true;
    byId("address-search-progress-title").textContent = "Refreshing retained results…";
    try {
      const snapshot = await invoke("get_address_search", { id: searchId });
      if (requestGeneration !== generation || !searchId) return;
      const terminal = renderSnapshot(snapshot);
      if (event.detail?.error) {
        byId(terminal ? "address-search-limitation" : "address-search-count").textContent = event.detail.error;
      }
      setRecoveryLocked(recoveryLocked);
      if (terminal) {
        byId("address-search-matches").querySelector("button")?.focus();
      } else {
        byId("address-search-progress-title").textContent = "Checking derived addresses…";
        pollTimer = window.setTimeout(() => poll(searchId, requestGeneration), 200);
      }
    } catch (error) {
      if (requestGeneration !== generation || !searchId) return;
      progress.hidden = false;
      results.hidden = true;
      byId("address-search-progress-title").textContent = "Could not refresh retained results";
      byId("address-search-count").textContent = String(error);
    }
  });
  document.addEventListener("address-search-release", (event) => {
    if (!searchId || (event.detail?.searchId && event.detail.searchId !== searchId)) return;
    close();
  });
  document.addEventListener("address-search-lock-recovery", (event) => {
    setRecoveryLocked(!!event.detail?.locked);
  });
  byId("close-address-search").addEventListener("click", () => close());
  byId("address-search-clear").addEventListener("click", resetForm);
  byId("add-address-search-seed").addEventListener("click", addSeedRow);
  byId("address-search-again").addEventListener("click", async () => {
    const id = searchId;
    searchId = null;
    const released = await releaseCurrent(id);
    if (!released) {
      searchId = id;
      results.hidden = false;
      byId("address-search-limitation").textContent = "Argos could not clear the retained results yet. Close the app to release them, or try again.";
      return;
    }
    resetForm();
    form.hidden = false;
    results.hidden = true;
  });
  byId("address-search-new").addEventListener("click", () => byId("address-search-again").click());
  byId("cancel-address-search").addEventListener("click", async () => {
    if (!searchId) return;
    byId("cancel-address-search").disabled = true;
    byId("address-search-progress-title").textContent = "Stopping safely…";
    try { await invoke("cancel_address_search", { id: searchId }); }
    catch (error) { byId("address-search-count").textContent = `Could not cancel: ${error}`; }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (startInFlight) return;
    await cleanupInFlight;
    if (form.hidden || modal.hidden) return;
    let input;
    try { input = collectInput(); }
    catch (error) { setFormStatus(error.message || String(error), "error"); return; }
    const requestGeneration = ++generation;
    setFormStatus("Starting local derivation…");
    byId("start-address-search").disabled = true;
    try {
      const pending = invoke("start_address_search", { input });
      startInFlight = pending;
      clearSecrets();
      const started = await pending;
      if (requestGeneration !== generation) {
        await beginCleanup(started.id);
        return;
      }
      searchId = started.id;
      publicScope = {
        target: input.target, network: input.network, profile: input.profile,
        account_start: input.account_start, account_count: input.account_count,
        index_start: input.index_start, index_count: input.index_count,
        include_change: input.include_change,
      };
      form.hidden = true;
      progress.hidden = false;
      results.hidden = true;
      renderedMatchIds = new Set();
      byId("address-search-live-matches").replaceChildren();
      byId("cancel-address-search").disabled = false;
      byId("address-search-progress-title").textContent = "Checking derived addresses…";
      poll(searchId, requestGeneration);
    } catch (error) {
      if (requestGeneration === generation) setFormStatus(String(error), "error");
    } finally {
      startInFlight = null;
      if (!modal.hidden) byId("start-address-search").disabled = false;
      input.seeds.forEach((candidate) => { candidate.seed = ""; candidate.passphrase = ""; });
      input = null;
    }
  });

  window.addEventListener("beforeunload", () => {
    if (searchId) {
      invoke("cancel_address_search", { id: searchId }).catch(() => {});
      invoke("release_address_search", { id: searchId }).catch(() => {});
    }
    clearSecrets();
  });
});
