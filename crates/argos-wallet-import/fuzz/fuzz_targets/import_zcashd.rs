#![no_main]

use libfuzzer_sys::fuzz_target;
use secrecy::SecretString;

/// Passphrase the encrypted golden fixtures were created with. Passing it
/// on every input lets mutations of the encrypted seeds reach decryption and
/// the encrypted-seed path; a plaintext wallet ignores it.
const FIXTURE_PASSPHRASE: &str = "argos-test-passphrase";

// `bdb_walk` covers the page walker; this covers everything above it —
// record parsing, decryption, and the zcashd 5.x seed assessment — on the
// same attacker-controlled bytes. Any panic, OOM, or hang is a real finding.
//
// A mutated `mkey` can ask for up to `MAX_ROUNDS` (10M) SHA-512 rounds, so
// expect occasional slow units; they are bounded by that cap, not hangs.
fuzz_target!(|data: &[u8]| {
    let pass = SecretString::new(FIXTURE_PASSPHRASE.to_owned());
    if let Ok(keys) = argos_wallet_import::zcashd::import_zcashd(data, Some(&pass)) {
        // Exercise every rendering a caller could log: these are hand-written
        // redacting impls, so they run on fuzzer-shaped data too.
        let _ = format!("{keys:?}");
        for d in &keys.diagnostics {
            let _ = format!("{d} {d:?}");
        }
    }
});
