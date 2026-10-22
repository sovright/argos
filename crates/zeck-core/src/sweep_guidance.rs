//! What the completion screen tells the user after a sweep.
//!
//! The CLI and the GUI both render this text, so which state wins over which
//! (an uncertain submission over an expired one, single-operator mining over
//! "complete", and so on) is decided here and nowhere else. Surface-specific
//! hints (CLI flags, GUI buttons) are appended by each surface.

use serde::{Deserialize, Serialize};

use crate::{broadcast::MIN_DISCARD_CONFIRMATIONS, models::TxLifecycleState};

/// One transaction row as the completion screen sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuidanceTransaction {
    pub status: TxLifecycleState,
    #[serde(default)]
    pub safe_to_discard: bool,
}

/// Everything the completion text depends on.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CompletionGuidanceInput {
    pub transactions: Vec<GuidanceTransaction>,
    /// Accounts that held a balance but were not swept.
    pub skipped_accounts: usize,
    pub follow_up_review_required: bool,
    /// Set when the sweep stopped part-way.
    pub error: Option<String>,
    /// A saved-journal status view rather than a sweep's own result.
    pub status_only: bool,
    pub donation_requested: bool,
    pub donated_zatoshis: u64,
    /// A route that can never donate says why.
    pub donation_note: Option<String>,
}

impl CompletionGuidanceInput {
    /// The input for a sweep's own result. `donation_requested` is whether
    /// the reviewed request asked for a non-zero donation.
    pub fn from_outcome(outcome: &crate::models::SweepOutcome, donation_requested: bool) -> Self {
        Self {
            transactions: outcome
                .transactions
                .iter()
                .map(|tx| GuidanceTransaction {
                    status: tx.status,
                    safe_to_discard: tx.safe_to_discard,
                })
                .collect(),
            skipped_accounts: outcome.skipped_accounts.len(),
            follow_up_review_required: outcome.follow_up_review_required,
            error: outcome.error.clone(),
            status_only: false,
            donation_requested,
            donated_zatoshis: outcome.total_donation_zatoshis,
            donation_note: outcome.donation_note.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletionGuidance {
    /// Every transaction is corroborated, deep enough to discard the source,
    /// and nothing was skipped, stopped, or left for a follow-up review.
    pub recovery_complete: bool,
    /// What happened, with counts.
    pub summary: String,
    /// What the user should do next.
    pub next_steps: String,
    /// The donation line, when a donation was requested or recorded.
    pub donation: Option<String>,
    /// One label per input transaction, in order.
    pub status_labels: Vec<String>,
}

pub fn tx_status_label(status: TxLifecycleState) -> &'static str {
    match status {
        TxLifecycleState::NotSubmitted => "Not submitted.",
        TxLifecycleState::SubmissionUnknown => {
            "Submission uncertain — may already be on the network. Do not retry without a fresh status check."
        }
        TxLifecycleState::Pending => "Broadcast — awaiting independent confirmation.",
        TxLifecycleState::Mined => "Mined — independently confirmed.",
        TxLifecycleState::MinedSingleSource => {
            "Mined — reported by one confirmation operator. Keep your source until an independent source confirms."
        }
        TxLifecycleState::Expired => "Expired — rescan before rebuilding.",
        TxLifecycleState::Rejected => "Rejected by the node.",
    }
}

pub fn completion_guidance(input: &CompletionGuidanceInput) -> CompletionGuidance {
    let counts = Counts::of(&input.transactions);
    let status_labels = input
        .transactions
        .iter()
        .map(|tx| tx_status_label(tx.status).to_owned())
        .collect();
    if input.status_only {
        return CompletionGuidance {
            recovery_complete: false,
            summary: "These are saved transactions in this network data directory, which may include another wallet. Keep the source wallets and recovery workspaces; run a fresh scan and review a new quote before another sweep stage.".to_owned(),
            next_steps: "The status below reflects current independent observations. Verify the txid and source wallet before retrying stored Unknown or Not Submitted bytes.".to_owned(),
            donation: None,
            status_labels,
        };
    }
    let recovery_complete = input.error.is_none()
        && !input.follow_up_review_required
        && input.skipped_accounts == 0
        && counts.total > 0
        && counts.safe == counts.total;
    CompletionGuidance {
        recovery_complete,
        summary: summary(input, &counts),
        next_steps: next_steps(input, &counts),
        donation: donation(input, &counts),
        status_labels,
    }
}

#[derive(Default)]
struct Counts {
    total: usize,
    not_submitted: usize,
    unknown: usize,
    pending: usize,
    mined: usize,
    single_source: usize,
    expired: usize,
    rejected: usize,
    /// Corroborated Mined rows that are deep enough to discard the source.
    safe: usize,
}

impl Counts {
    fn of(transactions: &[GuidanceTransaction]) -> Self {
        let mut counts = Self {
            total: transactions.len(),
            ..Self::default()
        };
        for tx in transactions {
            match tx.status {
                TxLifecycleState::NotSubmitted => counts.not_submitted += 1,
                TxLifecycleState::SubmissionUnknown => counts.unknown += 1,
                TxLifecycleState::Pending => counts.pending += 1,
                TxLifecycleState::Mined => {
                    counts.mined += 1;
                    if tx.safe_to_discard {
                        counts.safe += 1;
                    }
                }
                TxLifecycleState::MinedSingleSource => counts.single_source += 1,
                TxLifecycleState::Expired => counts.expired += 1,
                TxLifecycleState::Rejected => counts.rejected += 1,
            }
        }
        counts
    }

    fn all_mined(&self) -> bool {
        self.total > 0 && self.mined == self.total
    }
}

fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

fn format_zec(zatoshis: u64) -> String {
    format!(
        "{}.{:08} ZEC",
        zatoshis / 100_000_000,
        zatoshis % 100_000_000
    )
}

const WALLET_WARNING: &str = "Keep the source wallet and its recovery workspace while transaction results or remaining balances need review.";

fn summary(input: &CompletionGuidanceInput, c: &Counts) -> String {
    if let Some(error) = &input.error {
        let at_risk = c.unknown + c.pending + c.mined + c.single_source;
        let sent = if at_risk > 0 {
            format!(
                "{} already have moved. ",
                plural(at_risk, "transaction may", "transactions may")
            )
        } else {
            String::new()
        };
        let uncertain = if c.unknown > 0 {
            "A submission may already have moved; do not retry it without a fresh status check. "
        } else {
            ""
        };
        let warning = if at_risk > 0 {
            WALLET_WARNING
        } else {
            "Keep the source wallet and recovery workspace until remaining balances are accounted for."
        };
        return format!(
            "The sweep stopped before completing. {sent}{uncertain}{warning} Rescan and reconcile each txid before any new proposal. Error: {error}"
        );
    }
    if c.total == 0 {
        return if input.skipped_accounts > 0 {
            "No funds were swept — every account with a balance was skipped (reasons below)."
                .to_owned()
        } else {
            "No transaction was submitted. Review the details before trying again.".to_owned()
        };
    }
    if input.follow_up_review_required {
        let uncertain = if c.unknown > 0 {
            "A shielding transaction may already have moved; do not retry it without a fresh status check; reconcile its txid. "
        } else {
            ""
        };
        let mined = if c.mined > 0 {
            format!("{} mined. ", plural(c.mined, "transaction", "transactions"))
        } else {
            String::new()
        };
        let pending = if c.pending > 0 {
            " Reconcile pending txids and wait for independent confirmation."
        } else {
            ""
        };
        let expired = if c.expired > 0 {
            " An expired transaction requires a rescan before rebuilding."
        } else {
            ""
        };
        return format!(
            "Shielding stage requires follow-up. {uncertain}{mined}{WALLET_WARNING}{pending}{expired} Rescan and review a new proposal before sending shielded funds."
        );
    }
    if c.expired > 0 && (c.unknown > 0 || c.pending > 0) {
        let uncertain = if c.unknown > 0 {
            format!(
                "{} uncertain and may already have moved; do not retry without a fresh status check; reconcile the txid. ",
                plural(c.unknown, "submission is", "submissions are")
            )
        } else {
            String::new()
        };
        let awaiting = if c.pending > 0 {
            format!(
                "{} awaiting independent confirmation; reconcile the txid. ",
                plural(c.pending, "transaction is", "transactions are")
            )
        } else {
            String::new()
        };
        return format!(
            "{uncertain}{awaiting}{} expired; rescan before rebuilding. {WALLET_WARNING}",
            plural(c.expired, "transaction has", "transactions have")
        );
    }
    if c.unknown > 0 {
        return format!(
            "{} uncertain — {} already have moved. Do not retry without a fresh status check. {WALLET_WARNING}",
            plural(c.unknown, "submission", "submissions"),
            if c.unknown == 1 { "transaction may" } else { "transactions may" }
        );
    }
    if c.pending > 0 {
        return format!(
            "{} broadcast, awaiting independent confirmation. {WALLET_WARNING}",
            plural(c.pending, "transaction", "transactions")
        );
    }
    if c.expired > 0 {
        return format!(
            "{} expired. Keep the source wallet and recovery workspace; rescan before rebuilding.",
            plural(c.expired, "transaction", "transactions")
        );
    }
    if c.rejected > 0 {
        return format!(
            "{} rejected by the node. Keep the source wallet and recovery workspace; review the details before a new proposal.",
            plural(c.rejected, "transaction was", "transactions were")
        );
    }
    if input.skipped_accounts > 0 {
        let mined = if c.mined > 0 {
            format!(
                "{} mined, but ",
                plural(c.mined, "transaction", "transactions")
            )
        } else {
            String::new()
        };
        return format!(
            "{mined}{} skipped and not swept. Keep the source wallet and recovery workspace; review the remaining balance.",
            plural(input.skipped_accounts, "account was", "accounts were")
        );
    }
    if c.single_source > 0 {
        return format!(
            "{} mined according to one confirmation operator. Keep your source keys or wallet file until an independent source confirms.",
            plural(c.single_source, "transaction", "transactions")
        );
    }
    if c.all_mined() && c.safe == c.total {
        return format!(
            "{} mined and independently confirmed. Recovery complete.",
            plural(c.mined, "transaction", "transactions")
        );
    }
    if c.all_mined() {
        return format!(
            "{} mined and independently confirmed. Keep your source until each has enough confirmations; check status again later.",
            plural(c.mined, "transaction", "transactions")
        );
    }
    if c.mined > 0 {
        return format!(
            "{} mined, but this sweep did not finish. {WALLET_WARNING} Review the remaining results before a new proposal.",
            plural(c.mined, "transaction", "transactions")
        );
    }
    "No transaction was submitted. Review the details before trying again.".to_owned()
}

fn next_steps(input: &CompletionGuidanceInput, c: &Counts) -> String {
    if input.error.is_some() {
        return if c.unknown > 0 {
            "A listed transaction may already have reached the network; do not retry or discard the source wallet. Reconcile its txid before any further sweep."
        } else {
            "Sweep aborted with the transaction results listed above. Keep the source wallet and recovery workspace; verify each txid before a new proposal. Remaining accounts were not swept."
        }
        .to_owned();
    }
    let mut text = next_step_sentence(input, c).to_owned();
    if c.all_mined() && c.safe < c.total {
        text.push_str(&format!(
            " Keep the source until every transaction is {MIN_DISCARD_CONFIRMATIONS} confirmations deep; check status again later."
        ));
    }
    text
}

fn next_step_sentence(input: &CompletionGuidanceInput, c: &Counts) -> &'static str {
    if input.skipped_accounts > 0 && !input.follow_up_review_required && c.all_mined() {
        return "Every listed transaction mined, but at least one account was not swept. Keep the source wallet and recovery workspace; review the skipped balance before a new proposal.";
    }
    if c.single_source > 0 && c.unknown == 0 && c.pending == 0 && c.not_submitted == 0 {
        return if input.follow_up_review_required {
            "Shielding mined according to one confirmation operator. Rescan and review a new proposal for the send; keep your source keys or wallet file until an independent source confirms."
        } else {
            "Mined according to one confirmation operator. Keep your source keys or wallet file until an independent source confirms."
        };
    }
    if input.follow_up_review_required {
        if c.expired > 0 && c.unknown > 0 {
            return "A shielding submission may already have moved; do not retry. Reconcile its txid. Another shielding transaction expired; rescan before rebuilding and review a new proposal before sending shielded funds. Keep the source wallet and recovery workspace.";
        }
        if c.expired > 0 && c.pending > 0 {
            return "A shielding transaction is awaiting independent confirmation; reconcile its txid. Another shielding transaction expired; rescan before rebuilding and review a new proposal before sending shielded funds. Keep the source wallet and recovery workspace.";
        }
        if c.expired > 0 {
            return "A shielding transaction expired. Keep the source wallet and recovery workspace; rescan before rebuilding and review a new proposal before sending shielded funds.";
        }
        if c.unknown > 0 {
            return "Shielding submission may already have moved. Do not retry. Keep the source wallet and recovery workspace; reconcile the txid, then rescan and review a new proposal after mining.";
        }
        if c.pending > 0 {
            return "Shielding transaction awaits independent confirmation. Keep the source wallet and recovery workspace; reconcile its txid, then rescan and review a new proposal after mining.";
        }
        return "Shielding stage submitted. Keep the source wallet and recovery workspace. After every shielding transaction mines, rescan and review a new proposal before sending shielded funds.";
    }
    if c.expired > 0 && c.unknown > 0 {
        return "A submission may already have moved; do not retry. Reconcile its txid. Another transaction expired; rescan before rebuilding. Keep the source wallet and recovery workspace.";
    }
    if c.expired > 0 && c.pending > 0 {
        return "A transaction is awaiting independent confirmation; reconcile its txid. Another transaction expired; rescan before rebuilding. Keep the source wallet and recovery workspace.";
    }
    if c.unknown > 0 {
        return "A transaction may already have moved. Do not retry. Keep the source wallet and recovery workspace; reconcile its txid before a new proposal.";
    }
    if c.pending > 0 {
        return "A transaction is awaiting independent confirmation. Keep the source wallet and recovery workspace until every submitted transaction mines.";
    }
    if c.expired > 0 {
        return "A transaction expired. Keep the source wallet and recovery workspace; rescan before rebuilding.";
    }
    if c.rejected > 0 {
        return "A transaction was rejected by the node. Review the evidence before a new proposal.";
    }
    if c.all_mined() {
        return "Sweep complete. Every submitted transaction was independently confirmed as mined.";
    }
    if c.mined > 0 {
        return "A transaction mined, but this sweep did not finish. Keep the source wallet and recovery workspace; review the remaining results before a new proposal.";
    }
    "No transaction was submitted. Review the details before trying again."
}

fn donation(input: &CompletionGuidanceInput, c: &Counts) -> Option<String> {
    let donated = input.donated_zatoshis;
    if !input.donation_requested && donated == 0 {
        return None;
    }
    if c.unknown > 0 {
        return Some("Donation status and amount are uncertain. A transaction may already have moved; reconcile its txid before reporting a donation total.".to_owned());
    }
    if c.pending > 0 {
        return Some(format!(
            "Proposed donation: {}. Awaiting independent confirmation; reconcile pending txids before reporting a donated amount.{}",
            format_zec(donated),
            if c.expired > 0 { " An expired transaction also requires a rescan." } else { "" }
        ));
    }
    if c.expired > 0 {
        return Some(format!(
            "Planned donation of {} is not confirmed. The transaction expired; rescan before rebuilding.",
            format_zec(donated)
        ));
    }
    if c.rejected > 0 || c.not_submitted > 0 {
        return Some(if c.rejected + c.not_submitted == c.total {
            "No donation was sent or confirmed; the transaction was rejected or not submitted."
        } else {
            "A donation total is not confirmed for this sweep. Review the rejected or unsubmitted transaction before reporting a donated amount."
        }
        .to_owned());
    }
    if donated > 0 {
        return Some(if c.all_mined() {
            format!(
                "Donated {} to the Argos project — thank you for supporting Zcash recovery.",
                format_zec(donated)
            )
        } else {
            "Donation total is not confirmed. Review the transaction results before reporting a donated amount.".to_owned()
        });
    }
    if c.total == 0 {
        return Some("No donation was sent; no transaction was submitted.".to_owned());
    }
    // Every row is mined (corroborated or by one operator) and nothing was
    // donated. A route that never donates says why; otherwise the share fell
    // below the donation floor.
    Some(input.donation_note.clone().unwrap_or_else(|| {
        "No donation was sent: at the real network fee, each account's share fell below the 0.001 ZEC minimum, so your full balance went to your address.".to_owned()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use TxLifecycleState as State;

    fn tx(status: State) -> GuidanceTransaction {
        GuidanceTransaction {
            status,
            safe_to_discard: false,
        }
    }

    fn input(statuses: &[State]) -> CompletionGuidanceInput {
        CompletionGuidanceInput {
            transactions: statuses.iter().copied().map(tx).collect(),
            ..CompletionGuidanceInput::default()
        }
    }

    fn copy(guidance: &CompletionGuidance) -> String {
        format!("{} {}", guidance.summary, guidance.next_steps)
    }

    #[test]
    fn status_labels_preserve_uncertain_and_mined_boundaries() {
        assert_eq!(tx_status_label(State::NotSubmitted), "Not submitted.");
        assert_eq!(
            tx_status_label(State::SubmissionUnknown),
            "Submission uncertain — may already be on the network. Do not retry without a fresh status check."
        );
        assert_eq!(
            tx_status_label(State::Pending),
            "Broadcast — awaiting independent confirmation."
        );
        assert_eq!(
            tx_status_label(State::Mined),
            "Mined — independently confirmed."
        );
        assert!(tx_status_label(State::MinedSingleSource).contains("one confirmation operator"));
        assert_eq!(
            tx_status_label(State::Expired),
            "Expired — rescan before rebuilding."
        );
        assert_eq!(tx_status_label(State::Rejected), "Rejected by the node.");
        let guidance = completion_guidance(&input(&[State::Pending, State::Mined]));
        assert_eq!(
            guidance.status_labels,
            vec![
                tx_status_label(State::Pending).to_owned(),
                tx_status_label(State::Mined).to_owned()
            ]
        );
    }

    #[test]
    fn unknown_submission_may_have_moved_and_is_not_retried() {
        for follow_up in [false, true] {
            let guidance = completion_guidance(&CompletionGuidanceInput {
                follow_up_review_required: follow_up,
                ..input(&[State::SubmissionUnknown])
            });
            let text = copy(&guidance);
            assert!(
                guidance.summary.contains("may already have moved"),
                "{text}"
            );
            assert!(text.to_lowercase().contains("do not retry"), "{text}");
            assert!(text.contains("Keep the source wallet"), "{text}");
            assert!(!text.contains("No funds were moved"), "{text}");
            assert!(!guidance.recovery_complete);
        }
    }

    #[test]
    fn pending_keeps_the_source_wallet() {
        let guidance = completion_guidance(&input(&[State::Pending]));
        assert!(guidance.summary.contains("Keep the source wallet"));
        assert!(guidance.next_steps.contains("Keep the source wallet"));
        assert!(guidance.summary.contains("independent confirmation"));
    }

    #[test]
    fn single_operator_mining_never_reads_as_complete_or_discardable() {
        for follow_up in [false, true] {
            let guidance = completion_guidance(&CompletionGuidanceInput {
                follow_up_review_required: follow_up,
                ..input(&[State::MinedSingleSource])
            });
            let text = copy(&guidance);
            assert!(!guidance.recovery_complete, "{text}");
            assert!(!text.contains("Sweep complete"), "{text}");
            assert!(!text.contains("Recovery complete"), "{text}");
            assert!(!text.contains("independently confirmed"), "{text}");
            assert!(text.contains("independent source"), "{text}");
        }
        let mixed = completion_guidance(&input(&[State::Mined, State::MinedSingleSource]));
        assert!(!copy(&mixed).contains("Sweep complete"));
    }

    #[test]
    fn corroborated_mining_is_complete_only_when_deep_enough() {
        let shallow = completion_guidance(&input(&[State::Mined]));
        assert!(!shallow.recovery_complete);
        assert!(shallow.next_steps.contains("Sweep complete"));
        assert!(shallow.next_steps.contains("confirmations"));
        assert!(shallow.summary.contains("1 transaction mined"));

        let deep = completion_guidance(&CompletionGuidanceInput {
            transactions: vec![GuidanceTransaction {
                status: State::Mined,
                safe_to_discard: true,
            }],
            ..CompletionGuidanceInput::default()
        });
        assert!(deep.recovery_complete);
        assert!(deep.summary.contains("Recovery complete"));
        assert!(!deep.next_steps.contains("confirmations deep"));

        let two = completion_guidance(&input(&[State::Mined, State::Mined]));
        assert!(two.summary.contains("2 transactions mined"));
    }

    #[test]
    fn follow_up_review_never_says_complete() {
        for statuses in [vec![State::Mined], vec![State::Pending]] {
            let guidance = completion_guidance(&CompletionGuidanceInput {
                follow_up_review_required: true,
                ..input(&statuses)
            });
            let text = copy(&guidance).to_lowercase();
            assert!(!guidance.recovery_complete);
            assert!(!text.contains("sweep complete"), "{text}");
            assert!(!text.contains("recovery complete"), "{text}");
            assert!(guidance.summary.to_lowercase().contains("rescan"), "{text}");
            assert!(guidance.summary.to_lowercase().contains("review"), "{text}");
        }
    }

    #[test]
    fn a_partly_mined_sweep_does_not_claim_nothing_was_submitted() {
        let guidance = completion_guidance(&input(&[State::Mined, State::NotSubmitted]));
        assert!(!copy(&guidance).contains("No transaction was submitted"));
        assert!(guidance.summary.contains("1 transaction mined"));
        assert!(guidance.next_steps.contains("mined, but"));
    }

    #[test]
    fn skipped_balances_keep_a_mined_sweep_incomplete() {
        let guidance = completion_guidance(&CompletionGuidanceInput {
            transactions: vec![GuidanceTransaction {
                status: State::Mined,
                safe_to_discard: true,
            }],
            skipped_accounts: 1,
            ..CompletionGuidanceInput::default()
        });
        assert!(!guidance.recovery_complete);
        assert!(!copy(&guidance).contains("Recovery complete"));
        assert!(!copy(&guidance).contains("Sweep complete"));
        assert!(guidance.summary.contains("not swept"));
        assert!(guidance.next_steps.contains("not swept"));
    }

    #[test]
    fn final_failures_do_not_imply_future_mining() {
        for status in [State::Expired, State::Rejected, State::NotSubmitted] {
            let text = copy(&completion_guidance(&input(&[status])));
            for forbidden in ["may still mine", "pending or uncertain", "until every"] {
                assert!(!text.contains(forbidden), "{status:?}: {text}");
            }
        }
    }

    #[test]
    fn mixed_uncertain_and_expired_results_give_both_actions() {
        for first in [State::Pending, State::SubmissionUnknown] {
            for follow_up in [false, true] {
                let guidance = completion_guidance(&CompletionGuidanceInput {
                    follow_up_review_required: follow_up,
                    ..input(&[first, State::Expired])
                });
                for text in [&guidance.summary, &guidance.next_steps] {
                    let lower = text.to_lowercase();
                    assert!(lower.contains("reconcile"), "{first:?}/{follow_up}: {text}");
                    assert!(lower.contains("rescan"), "{first:?}/{follow_up}: {text}");
                    assert!(
                        !lower.contains("every submitted transaction mine"),
                        "{text}"
                    );
                }
            }
        }
    }

    #[test]
    fn an_aborted_sweep_reports_what_may_have_moved() {
        let guidance = completion_guidance(&CompletionGuidanceInput {
            error: Some("later account failed".to_owned()),
            ..input(&[State::SubmissionUnknown, State::Mined])
        });
        assert!(!guidance.recovery_complete);
        assert!(guidance.summary.contains("stopped before completing"));
        assert!(guidance
            .summary
            .contains("2 transactions may already have moved"));
        assert!(guidance.summary.contains("later account failed"));
        assert!(guidance.next_steps.contains("do not retry"));

        let definite = completion_guidance(&CompletionGuidanceInput {
            error: Some("boom".to_owned()),
            ..input(&[State::Mined])
        });
        assert!(!copy(&definite).contains("Sweep complete"));
        assert!(definite
            .next_steps
            .contains("Remaining accounts were not swept"));
    }

    #[test]
    fn saved_journal_status_is_never_a_sweep_result() {
        let guidance = completion_guidance(&CompletionGuidanceInput {
            status_only: true,
            transactions: vec![GuidanceTransaction {
                status: State::Mined,
                safe_to_discard: true,
            }],
            ..CompletionGuidanceInput::default()
        });
        assert!(!guidance.recovery_complete);
        assert!(guidance.summary.contains("may include another wallet"));
        assert!(guidance
            .next_steps
            .contains("current independent observations"));
        assert_eq!(guidance.donation, None);
    }

    #[test]
    fn input_from_an_outcome_carries_every_field_the_text_depends_on() {
        let outcome = crate::models::SweepOutcome {
            transactions: vec![crate::models::TxBroadcastResult {
                source_account: 3,
                txid: Some("ab".to_owned()),
                status: State::Mined,
                fee_zatoshis: 10_000,
                detail: String::new(),
                confirmed_height: Some(100),
                safe_to_discard: true,
            }],
            donation_note: Some("note".to_owned()),
            skipped_accounts: vec![crate::models::SkippedSweepAccount {
                account_index: 4,
                gross_zatoshis: 1,
                reason: "dust".to_owned(),
            }],
            total_donation_zatoshis: 7,
            error: Some("stopped".to_owned()),
            follow_up_review_required: true,
        };
        assert_eq!(
            CompletionGuidanceInput::from_outcome(&outcome, true),
            CompletionGuidanceInput {
                transactions: vec![GuidanceTransaction {
                    status: State::Mined,
                    safe_to_discard: true,
                }],
                skipped_accounts: 1,
                follow_up_review_required: true,
                error: Some("stopped".to_owned()),
                status_only: false,
                donation_requested: true,
                donated_zatoshis: 7,
                donation_note: Some("note".to_owned()),
            }
        );
    }

    fn donation(statuses: &[State], donated: u64, requested: bool) -> Option<String> {
        completion_guidance(&CompletionGuidanceInput {
            donation_requested: requested,
            donated_zatoshis: donated,
            ..input(statuses)
        })
        .donation
    }

    #[test]
    fn donation_receipt_waits_for_certain_mining() {
        let uncertain = donation(&[State::SubmissionUnknown], 0, true).unwrap();
        assert!(uncertain.contains("Donation status and amount are uncertain"));
        assert!(!uncertain.contains("Donated") && !uncertain.contains("No donation"));

        let pending = donation(&[State::Pending], 100_000, true).unwrap();
        assert!(pending
            .to_lowercase()
            .contains("awaiting independent confirmation"));
        assert!(!pending.contains("Donated "));
        let zero_pending = donation(&[State::Pending], 0, true).unwrap();
        assert!(!zero_pending.contains("No donation was sent"));
        assert!(!zero_pending.contains("Donated "));

        let expired = donation(&[State::Expired], 100_000, true).unwrap();
        assert!(expired.contains("not confirmed"));
        assert!(expired.contains("rescan"));
        assert!(!expired.contains("Donated "));

        for status in [State::Rejected, State::NotSubmitted] {
            let text = donation(&[status], 100_000, true).unwrap();
            assert!(text.contains("No donation was sent or confirmed"), "{text}");
        }

        let mined = donation(&[State::Mined], 100_000, true).unwrap();
        assert!(mined.starts_with("Donated 0.00100000 ZEC"), "{mined}");

        let none_sent = donation(&[State::Mined], 0, true).unwrap();
        assert!(none_sent.contains("No donation was sent"));
        assert_eq!(donation(&[State::Mined], 0, false), None);

        let noted = completion_guidance(&CompletionGuidanceInput {
            donation_requested: true,
            donation_note: Some("This route never sends a donation.".to_owned()),
            ..input(&[State::Mined])
        });
        assert_eq!(
            noted.donation.as_deref(),
            Some("This route never sends a donation.")
        );
    }
}
