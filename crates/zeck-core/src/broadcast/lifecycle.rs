use super::{
    observe_transaction, PersistedTransaction, SubmissionDisposition, TxLifecycleState,
    TxObservation, TxObservationState,
};
use crate::{
    error::{ZeckError, ZeckResult},
    models::normalized_confirmation_authority,
};

/// A rejection is final only for bytes that no earlier reply or observation
/// ever placed on the network. Once a node accepted them, or a source saw
/// them, a later rejection (for example of a resend) proves nothing.
pub(super) fn rejection_can_be_definitive(existing: &PersistedTransaction) -> bool {
    !matches!(
        existing.last_submission,
        Some(SubmissionDisposition::Accepted | SubmissionDisposition::AlreadyKnown)
    ) && !existing.observation.as_ref().is_some_and(|item| {
        matches!(
            item.state,
            TxObservationState::Mined
                | TxObservationState::MinedSingleSource
                | TxObservationState::PresentUnmined
        )
    })
}

pub(crate) fn validate_transition(
    existing: &PersistedTransaction,
    state: TxLifecycleState,
    submission: Option<&SubmissionDisposition>,
    observation: Option<&TxObservation>,
    legacy_replay: bool,
) -> ZeckResult<()> {
    let supported = match state {
        TxLifecycleState::NotSubmitted => {
            existing.state == TxLifecycleState::NotSubmitted
                && existing.last_submission.is_none()
                && existing.observation.is_none()
                && submission.is_none()
                && observation.is_none()
        }
        TxLifecycleState::SubmissionUnknown => {
            !matches!(
                existing.state,
                TxLifecycleState::Mined
                    | TxLifecycleState::MinedSingleSource
                    | TxLifecycleState::Rejected
                    | TxLifecycleState::Expired
            ) && observation.is_none()
                && matches!(
                    submission,
                    None | Some(SubmissionDisposition::AmbiguousTransport)
                        | Some(SubmissionDisposition::AlreadyKnown)
                        | Some(SubmissionDisposition::RetryableRejection { .. })
                        | Some(SubmissionDisposition::DeterministicRejection { .. })
                )
        }
        TxLifecycleState::Pending => {
            let effective_observation = observation.or(existing.observation.as_ref());
            let positive_presence = effective_observation.is_some_and(|item| {
                item.state == TxObservationState::PresentUnmined
                    && observe_transaction(item.evidence.clone(), item.expiry_height).state
                        == TxObservationState::PresentUnmined
                    && item.evidence.iter().any(|source| {
                        source.reported_height == Some(0)
                            && normalized_confirmation_authority(&source.endpoint).is_some()
                    })
            });
            let already_pending_nonfinal = existing.state == TxLifecycleState::Pending
                && matches!(
                    effective_observation.map(|item| &item.state),
                    None | Some(
                        TxObservationState::PresentUnmined
                            | TxObservationState::Absent
                            | TxObservationState::Reorged
                            | TxObservationState::Contested
                            | TxObservationState::Unavailable
                    )
                );
            // Only a positive observation demotes a mined record: a reorg
            // sentinel or absence from a source, or the transaction seen back
            // in a mempool. A timeout (Unavailable) or a disagreement
            // (Contested) leaves it mined.
            let mined_reorg = existing.state.is_mined()
                && (matches!(
                    observation.map(|item| &item.state),
                    Some(TxObservationState::Reorged | TxObservationState::Absent)
                ) || (positive_presence
                    && matches!(
                        observation.map(|item| &item.state),
                        Some(TxObservationState::PresentUnmined)
                    )));
            // An earlier acceptance cannot resolve a later Unknown recorded
            // before an exact-byte resend whose outcome has not arrived.
            let accepted = matches!(submission, Some(SubmissionDisposition::Accepted));
            let legacy_nonfinal = legacy_replay
                && matches!(
                    effective_observation.map(|item| &item.state),
                    Some(
                        TxObservationState::PresentUnmined
                            | TxObservationState::Absent
                            | TxObservationState::Reorged
                            | TxObservationState::Contested
                            | TxObservationState::Unavailable
                    )
                );
            // Schema-v1 submitters wrote a retryable response as Pending even
            // without transaction-presence evidence. Preserve replay of that
            // historical identity, but never authorize a new Pending append.
            let legacy_retryable = legacy_replay
                && matches!(
                    submission.or(existing.last_submission.as_ref()),
                    Some(SubmissionDisposition::RetryableRejection { .. })
                );
            (positive_presence
                || accepted
                || already_pending_nonfinal
                || mined_reorg
                || legacy_nonfinal
                || legacy_retryable)
                && !effective_observation.is_some_and(|item| {
                    item.expiry_height == existing.prepared.expiry_height && item.is_expired()
                })
                && !matches!(
                    submission,
                    Some(SubmissionDisposition::DeterministicRejection { .. })
                )
                && !matches!(
                    effective_observation.map(|item| &item.state),
                    Some(TxObservationState::Mined | TxObservationState::MinedSingleSource)
                )
                && (!existing.state.is_mined() || mined_reorg)
                && !matches!(
                    existing.state,
                    TxLifecycleState::Rejected | TxLifecycleState::Expired
                )
        }
        TxLifecycleState::Mined => {
            observation
                .or(existing.observation.as_ref())
                .is_some_and(TxObservation::has_canonical_mined_evidence)
                && !matches!(
                    existing.state,
                    TxLifecycleState::Rejected | TxLifecycleState::Expired
                )
                && !matches!(
                    submission,
                    Some(SubmissionDisposition::DeterministicRejection { .. })
                )
        }
        TxLifecycleState::MinedSingleSource => {
            observation
                .or(existing.observation.as_ref())
                .is_some_and(TxObservation::has_single_source_mined_evidence)
                && !matches!(
                    existing.state,
                    TxLifecycleState::Mined
                        | TxLifecycleState::Rejected
                        | TxLifecycleState::Expired
                )
                && !matches!(
                    submission,
                    Some(SubmissionDisposition::DeterministicRejection { .. })
                )
        }
        TxLifecycleState::Rejected if !legacy_replay => {
            // Only the reply to the submission that just went out, and only
            // when nothing ever showed the bytes reaching the network.
            existing.state == TxLifecycleState::SubmissionUnknown
                && matches!(
                    submission,
                    Some(SubmissionDisposition::DeterministicRejection { .. })
                )
                && observation.is_none()
                && rejection_can_be_definitive(existing)
        }
        TxLifecycleState::Rejected => {
            legacy_replay
                && matches!(
                    submission.or(existing.last_submission.as_ref()),
                    Some(SubmissionDisposition::DeterministicRejection { .. })
                )
                && !matches!(
                    existing.state,
                    TxLifecycleState::Mined
                        | TxLifecycleState::MinedSingleSource
                        | TxLifecycleState::Expired
                )
                && !matches!(
                    observation
                        .or(existing.observation.as_ref())
                        .map(|item| &item.state),
                    Some(TxObservationState::Mined | TxObservationState::MinedSingleSource)
                )
        }
        TxLifecycleState::Expired => {
            let effective_observation = observation.or(existing.observation.as_ref());
            effective_observation.is_some_and(|item| {
                item.expiry_height == existing.prepared.expiry_height && item.is_expired()
            }) && existing.state != TxLifecycleState::Rejected
        }
    };
    if supported {
        Ok(())
    } else {
        Err(ZeckError::Storage(format!(
            "unsupported broadcast state {:?} for {} without matching durable evidence",
            state, existing.prepared.txid
        )))
    }
}
