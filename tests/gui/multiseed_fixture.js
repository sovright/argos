// Browser-only fixture: never included by production index.html.
const scans = new Map();
function admit() {
  let active = [...scans.values()].filter(s => s.phase === "scanning_shielded").length;
  for (const scan of scans.values()) if (scan.phase === "queued" && active++ < 8) scan.phase = "scanning_shielded";
}
window.__TAURI__ = {
  event: { listen: async () => () => {} },
  core: { invoke: async (command, args = {}) => {
    switch (command) {
      case "tos_status": return { accepted: true };
      case "default_data_dir": return "/tmp/argos-synthetic-fixture";
      case "list_incomplete_sessions": return [];
      case "donation_config": return { enabled: false };
      case "validate_seed": if (args.words.length !== 24) throw new Error("Expected 24 words"); return true;
      case "validate_address": return { destination_ok: true, has_orchard: true, has_sapling: true };
      case "start_seed_batch": {
        if (new Set(args.configs.map(c => c.seed)).size !== args.configs.length) throw new Error("Duplicate seed in batch");
        const handles = args.configs.map((_, index) => ({ id: `synthetic-${index + 1}` }));
        for (const handle of handles) scans.set(handle.id, { handle, phase: "queued", blocks_scanned: 20, blocks_total: 100, accounts: [], discoveries: [], synced_to_height: 419220, elapsed_seconds: 1 });
        admit(); return handles;
      }
      case "get_scan_progress": return scans.get(args.handle.id);
      case "cancel_scan": { const scan = scans.get(args.handle.id); if (!["complete", "error"].includes(scan.phase)) scan.phase = "cancelled"; admit(); return; }
      case "release_session": scans.delete(args.handle.id); return;
      case "retry_seed_scan": {
        const old = scans.get(args.handle.id);
        if (!old || !["cancelled", "error"].includes(old.phase)) throw new Error("Scan cannot be retried");
        if (args.seed.trim().split(/\s+/).length !== 24) throw new Error("Expected 24 words");
        const handle = { id: `${args.handle.id}-retry` };
        scans.delete(args.handle.id);
        scans.set(handle.id, { ...old, handle, phase: "queued" });
        admit(); return handle;
      }
      case "propose_sweep": return { transactions: [], skipped_accounts: [], total_send_zatoshis: 0, total_fee_zatoshis: 0, net_received_zatoshis: 0, total_donation_zatoshis: 0 };
      case "execute_sweep": return { transactions: [{ source_account: 0, status: "pending", txid: `synthetic-receipt-${args.handle.id}`, detail: "UI fixture only" }], skipped_accounts: [], total_donation_zatoshis: 0, error: null };
      default: return null;
    }
  } }
};
document.addEventListener("DOMContentLoaded", () => {
  const banner = document.createElement("div");
  banner.textContent = "SYNTHETIC UI FIXTURE — no real scanning or funds. ";
  const complete = document.createElement("button");
  complete.textContent = "Complete first fixture scan";
  complete.onclick = () => { const s = scans.get("synthetic-1"); if (s) { s.phase = "complete"; s.summary = { total_zatoshis: 100000000, workspace_dir: "/tmp/synthetic-1", authoritative_balances: true }; admit(); } };
  banner.append(complete);
  document.body.prepend(banner);
});
