//! What a Sprout scan costs, and the wording that tells the user.
//!
//! A Sprout scan is not a normal scan and should never be presented as one.
//! An ordinary Argos scan talks to lightwalletd and streams compact blocks —
//! a few hundred megabytes, minutes. A Sprout scan cannot use lightwalletd at
//! all (compact blocks carry no JoinSplits), so it downloads **full** blocks
//! straight from the p2p network, from genesis to Canopy.
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
//! The block count is exact and fixed forever: ZIP 211 disables adding value
//! to the Sprout pool at Canopy, so no Sprout note exists at or above that
//! height and the range never grows.
//!
//! The download size is an estimate, and is labelled as one everywhere it is
//! shown. It is not measured here because measuring it would itself require
//! downloading the chain. Callers report real figures as the scan proceeds;
//! this is only what we can honestly say beforehand.

use crate::p2p::wire::P2pNetwork;

/// Rough average size of a mainnet block across the Sprout range.
///
/// Deliberately coarse. Early blocks are tiny and Sapling-era blocks are far
/// larger, so a single average is only good enough to tell someone whether
/// this is a coffee break or an overnight job — which is the actual decision
/// they are making.
const APPROX_MEAN_BLOCK_BYTES: u64 = 25_000;

/// What a Sprout scan will cost the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SproutScanCost {
    /// Exact: every block from 1 up to Canopy activation.
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
        let blocks = network.sprout_scan_end();
        Self {
            blocks,
            approx_download_bytes: u64::from(blocks) * APPROX_MEAN_BLOCK_BYTES,
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
                 uses, so this reads full blocks directly from the Zcash network: all \
                 {} blocks from the start of the chain to Canopy.",
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
            "  Time               hours, not minutes".to_owned(),
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

    #[test]
    fn the_mainnet_block_count_is_the_canopy_bound() {
        let cost = SproutScanCost::for_network(P2pNetwork::Mainnet);
        assert_eq!(cost.blocks, 1_046_400);
    }

    /// The numbers must be big enough to actually deter a casual click.
    /// If a rounding change ever made this read as "0 GB" the warning would
    /// be worse than none.
    #[test]
    fn the_download_estimate_is_reported_in_gigabytes() {
        let cost = SproutScanCost::for_network(P2pNetwork::Mainnet);
        assert!(
            cost.approx_download_bytes > 10_000_000_000,
            "a full-block sweep of the Sprout range is tens of GB"
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
        assert!(text.contains("hours"), "must set a time expectation");
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
            text.contains("1,046,400"),
            "the exact block count is the most concrete fact available"
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
