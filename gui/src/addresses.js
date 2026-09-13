// Offline public-address inspection. No recovery session, network, or persistence.
document.addEventListener("DOMContentLoaded", () => {
  const el = (id) => document.getElementById(id);
  const dialog = el("addresses-dialog");
  let rows = [];
  let page = 0;
  let generation = 0;
  let busy = false;
  const pageSize = 40;

  function clear() {
    generation++;
    el("addresses-seed").value = "";
    el("addresses-reveal").checked = false;
    el("addresses-seed").classList.add("masked");
    el("addresses-target").value = "";
    rows = [];
    page = 0;
    el("addresses-rows").replaceChildren();
    el("addresses-results").hidden = true;
    el("addresses-status").textContent = "";
    el("addresses-match").textContent = "";
    el("addresses-caption").textContent = "";
    el("addresses-page").textContent = "";
  }

  function render() {
    const target = el("addresses-target").value.trim();
    const visible = target ? rows.filter((row) => row.address === target) : rows;
    const pages = Math.max(1, Math.ceil(visible.length / pageSize));
    page = Math.min(page, pages - 1);
    el("addresses-match").textContent = target
      ? visible.length ? `Found ${visible.length} exact match(es). See the index and path below.`
        : "No match in this seed's requested range. This does not rule out other indexes, seeds, wallet derivation schemes, or imported keys."
      : "Showing public addresses only. Balances have not been checked.";
    const body = el("addresses-rows");
    body.replaceChildren();
    for (const row of visible.slice(page * pageSize, (page + 1) * pageSize)) {
      const tr = document.createElement("tr");
      for (const value of [String(row.index), row.type]) {
        const td = document.createElement("td");
        td.textContent = value;
        tr.append(td);
      }
      const td = document.createElement("td");
      const address = document.createElement("code");
      address.textContent = row.address;
      const path = document.createElement("code");
      path.textContent = row.path;
      td.append(address, path);
      tr.append(td);
      body.append(tr);
    }
    el("addresses-page").textContent = `${visible.length} addresses · Page ${page + 1} of ${pages}`;
    el("addresses-previous").disabled = page === 0;
    el("addresses-next").disabled = page + 1 >= pages;
  }

  el("open-addresses").addEventListener("click", () => {
    clear();
    el("derive-addresses").disabled = busy;
    if (busy) el("addresses-status").textContent = "Waiting for the previous derivation to finish…";
    dialog.showModal();
    el("addresses-seed").focus();
  });
  el("close-addresses").addEventListener("click", () => dialog.close());
  dialog.addEventListener("close", clear);
  el("addresses-reveal").addEventListener("change", () => {
    el("addresses-seed").classList.toggle("masked", !el("addresses-reveal").checked);
  });
  el("addresses-target").addEventListener("input", () => { page = 0; render(); });
  el("addresses-previous").addEventListener("click", () => { page--; render(); });
  el("addresses-next").addEventListener("click", () => { page++; render(); });
  el("addresses-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy) return;
    const start = Number(el("addresses-start").value);
    const count = Number(el("addresses-count").value);
    if (!Number.isInteger(start) || !Number.isInteger(count) || start < 0 || count < 1 || count > 1000 || start + count > 2147483648) {
      el("addresses-status").textContent = "Choose 1–1000 indexes within 0–2147483647.";
      return;
    }
    let seed = el("addresses-seed").value.trim().split(/\s+/).join(" ");
    const network = el("addresses-network").value;
    const target = el("addresses-target").value;
    clear();
    el("addresses-target").value = target;
    const requestGeneration = generation;
    busy = true;
    el("derive-addresses").disabled = true;
    el("addresses-status").textContent = "Deriving addresses locally…";
    try {
      const request = window.__TAURI__.core.invoke("show_addresses", {
        input: { seed, network, start_index: start, count },
      });
      seed = "";
      const accounts = await request;
      if (!dialog.open || requestGeneration !== generation) return;
      rows = accounts.flatMap((account) => [
        { index: account.index, type: "Transparent receive", address: account.transparent_receive_address, path: account.transparent_receive_path },
        { index: account.index, type: "Transparent change", address: account.transparent_change_address, path: account.transparent_change_path },
        { index: account.index, type: "Sapling", address: account.sapling_address, path: account.sapling_path },
        { index: account.index, type: "Unified (Sapling + Orchard)", address: account.unified_address, path: `${account.sapling_path}; ${account.orchard_path}` },
      ]);
      el("addresses-status").textContent = `Derived indexes ${start}–${start + count - 1} on ${network}. Seed field cleared.`;
      el("addresses-caption").textContent = `${network} public addresses · indexes ${start}–${start + count - 1}`;
      el("addresses-results").hidden = false;
      render();
    } catch (error) {
      if (dialog.open && requestGeneration === generation) el("addresses-status").textContent = String(error);
    } finally {
      seed = "";
      busy = false;
      el("derive-addresses").disabled = false;
      if (dialog.open && requestGeneration !== generation) el("addresses-status").textContent = "Ready. Enter a seed to derive addresses.";
    }
  });
});
