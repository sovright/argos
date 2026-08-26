#![no_main]

use libfuzzer_sys::fuzz_target;

// The walker consumes attacker-controlled bytes. Any panic, OOM, or hang
// here is a real finding: this is the single highest-value test artifact
// in the import path.
fuzz_target!(|data: &[u8]| {
    let _ = argos_wallet_import::bdb::walk(data);
});
