//! What a Sprout scan costs, and the wording that tells the user.
//!
//! A Sprout scan is not a normal scan and should never be presented as one.
//! An ordinary Argos scan talks to lightwalletd and streams compact blocks —
//! a few hundred megabytes, minutes. A Sprout scan cannot use lightwalletd at
//! all (compact blocks carry no JoinSplits), so it downloads **full** blocks
//! straight from the p2p network, from genesis to the chain tip.
//!
//! Presenting that as an ordinary scan would be a straightforward lie about a
//! multi-hour, multi-gigabyte operation, and the person on the other end is
//! typically trying to recover funds they have already had trouble reaching.
//! They deserve to know before it starts, not forty minutes in.
//!
//! # One source of truth
//!
//! The CLI and the GUI both render from here rather than each writing their
//! own copy. Two hand-maintained warnings drift, and the one that drifts is
//! always the one the user reads.
//!
//! # What is exact and what is not
//!
//! Neither figure is exact, and both grow with the chain. ZIP 211 only stops
//! new value entering Sprout at Canopy; JoinSplits after it still spend and
//! create Sprout notes, so the scan reads to the tip and the range is the
//! whole chain.
//!
//! For mainnet both numbers are anchored to one measurement of the real
//! chain rather than a per-block guess: the average block grew roughly
//! tenfold after Canopy, so any single mean is badly wrong somewhere. They
//! are still labelled estimates everywhere they are shown. Callers report
//! real figures as the scan proceeds.

use crate::p2p::wire::P2pNetwork;

/// Mainnet height and total chain size, measured together: blockchair's
/// `/zcash/stats`, 2026-09-27 (`best_block_height`, `blockchain_size`).
const MAINNET_MEASURED_HEIGHT: u32 = 3_497_638;
const MAINNET_MEASURED_BYTES: u64 = 275_761_641_867;

/// Rough average block size, for blocks past the measurement and for
/// networks with no measurement. Deliberately coarse: good enough to tell a
/// coffee break from an overnight job, which is the decision being made.
const APPROX_MEAN_BLOCK_BYTES: u64 = 25_000;

/// What a Sprout scan will cost the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SproutScanCost {
    /// Every block from 1 to the chain tip, as last measured.
    pub blocks: u32,
    /// Approximate total network transfer.
    pub approx_download_bytes: u64,
    /// Approximate persistent disk use.
    ///
    /// Small on purpose: blocks are processed and discarded rather than
    /// stored. Only the commitment tree and a resume checkpoint are kept, so
    /// an interrupted scan resumes without re-downloading, and the user does
    /// not need tens of gigabytes free to recover their own money.
    pub approx_disk_bytes: u64,
}

/// Bytes as a short human string. Powers of ten, because this is quoted to
/// people comparing against an ISP data cap, not to a filesystem.
fn human_bytes(bytes: u64) -> String {
    const GB: u64 = 1_000_000_000;
    const MB: u64 = 1_000_000;
    if bytes >= GB {
        format!("{:.0} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.0} MB", bytes as f64 / MB as f64)
    } else {
        format!("{bytes} bytes")
    }
}

impl SproutScanCost {
    pub fn for_network(network: P2pNetwork) -> Self {
        // Regtest's minimum tip is 0: its chain is whatever the test built,
        // and there is no honest figure to quote for it.
        let (blocks, approx_download_bytes) = match network {
            P2pNetwork::Mainnet => {
                let blocks = network
                    .sprout_scan_minimum_tip()
                    .max(MAINNET_MEASURED_HEIGHT);
                let beyond = u64::from(blocks - MAINNET_MEASURED_HEIGHT);
                (
                    blocks,
                    MAINNET_MEASURED_BYTES + beyond * APPROX_MEAN_BLOCK_BYTES,
                )
            }
            P2pNetwork::Testnet | P2pNetwork::Regtest => {
                let blocks = network.sprout_scan_minimum_tip();
                (blocks, u64::from(blocks) * APPROX_MEAN_BLOCK_BYTES)
            }
        };
        Self {
            blocks,
            approx_download_bytes,
            // The Sprout tree is ~32 bytes per node over a depth-29 tree plus
            // a checkpoint; hundreds of megabytes is a generous ceiling.
            approx_disk_bytes: 500_000_000,
        }
    }

    pub fn download_human(&self) -> String {
        human_bytes(self.approx_download_bytes)
    }

    pub fn disk_human(&self) -> String {
        human_bytes(self.approx_disk_bytes)
    }

    /// The warning, as lines, without any decoration.
    ///
    /// Returned as lines rather than one blob so each surface can frame them
    /// its own way — the CLI indents them, the GUI puts them in a panel —
    /// while the words themselves stay identical.
    pub fn warning_lines(&self) -> Vec<String> {
        vec![
            "A Sprout scan is much slower and heavier than a normal scan.".to_owned(),
            String::new(),
            format!(
                "Sprout notes are invisible to the light-wallet servers Argos normally \
                 uses, so this reads full blocks directly from the Zcash network: every \
                 block from the start of the chain to its tip, at least {} blocks. \
                 Sprout notes can be created and spent after Canopy, so stopping \
                 earlier would miss them.",
                thousands(self.blocks)
            ),
            String::new(),
            format!(
                "  Network transfer   roughly {} (estimate)",
                self.download_human()
            ),
            // Kept short enough to survive a 72-column terminal wrap: these
            // rows align with runs of spaces, and a wrap would collapse them.
            format!(
                "  Disk space         under {} (blocks are not kept)",
                self.disk_human()
            ),
            "  Time               likely days".to_owned(),
            String::new(),
            "The scan saves its progress, so you can stop it and resume later without \
             downloading everything again."
                .to_owned(),
            "You only need this if your Sprout funds cannot be recovered from a wallet \
             file, which Argos checks first."
                .to_owned(),
        ]
    }
}

/// Digit grouping, so a seven-digit block count is readable at a glance.
fn thousands(n: u32) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The scan runs to the tip, not to Canopy: Sprout JoinSplits continue
    /// after it, so the count is the whole chain as last measured.
    #[test]
    fn the_mainnet_block_count_is_the_whole_chain() {
        let cost = SproutScanCost::for_network(P2pNetwork::Mainnet);
        assert!(cost.blocks > 1_046_400, "must not stop at Canopy");
        assert!(cost.blocks >= MAINNET_MEASURED_HEIGHT);
    }

    /// The numbers must be big enough to actually deter a casual click.
    /// If a rounding change ever made this read as "0 GB" the warning would
    /// be worse than none.
    #[test]
    fn the_download_estimate_is_reported_in_gigabytes() {
        let cost = SproutScanCost::for_network(P2pNetwork::Mainnet);
        assert!(
            cost.approx_download_bytes > 200_000_000_000,
            "the whole chain is hundreds of GB, and saying less is the lie this warns against"
        );
        assert!(cost.download_human().ends_with(" GB"));
        assert_ne!(cost.download_human(), "0 GB");
    }

    /// The central promise of the wording: disk stays small because blocks
    /// are streamed. If that ever stopped being true the text would be
    /// misleading, so it is pinned here.
    #[test]
    fn disk_use_is_far_smaller_than_the_download() {
        let cost = SproutScanCost::for_network(P2pNetwork::Mainnet);
        assert!(
            cost.approx_disk_bytes * 10 < cost.approx_download_bytes,
            "blocks are discarded as they are read, so disk must not track download"
        );
    }

    #[test]
    fn the_warning_states_time_disk_and_transfer() {
        let text = SproutScanCost::for_network(P2pNetwork::Mainnet)
            .warning_lines()
            .join("\n");
        assert!(text.contains("days"), "must set a time expectation");
        assert!(
            text.contains("tip"),
            "must say the scan runs to the chain tip"
        );
        assert!(
            !text.contains("to Canopy"),
            "the scan no longer stops at Canopy"
        );
        assert!(text.contains("Disk space"), "must state disk use");
        assert!(text.contains("Network transfer"), "must state transfer");
        assert!(
            text.contains("estimate"),
            "the download figure is not measured and must not look like it is"
        );
        assert!(
            text.contains("resume"),
            "must say progress is saved, or a user will not dare start"
        );
        assert!(
            text.contains("3,497,638"),
            "the measured block count is the most concrete fact available"
        );
    }

    /// The aligned two-column rows are held together by runs of spaces, and
    /// a terminal wrap would collapse them into unreadable prose. The CLI
    /// only passes lines through untouched if they already fit, so those
    /// rows must stay under the wrap width.
    #[test]
    fn the_aligned_rows_fit_in_a_narrow_terminal() {
        const CLI_WRAP_WIDTH: usize = 72;
        for line in SproutScanCost::for_network(P2pNetwork::Mainnet).warning_lines() {
            if line.starts_with("  ") && line.contains("   ") {
                assert!(
                    line.chars().count() <= CLI_WRAP_WIDTH,
                    "aligned row would be wrapped and lose its columns ({} chars): {line:?}",
                    line.chars().count()
                );
            }
        }
    }

    #[test]
    fn digit_grouping_is_readable() {
        assert_eq!(thousands(1_046_400), "1,046,400");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(0), "0");
    }

    #[test]
    fn byte_formatting_picks_sensible_units() {
        assert_eq!(human_bytes(26_160_000_000), "26 GB");
        assert_eq!(human_bytes(500_000_000), "500 MB");
        assert_eq!(human_bytes(512), "512 bytes");
    }
}
