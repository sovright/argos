//! Backend-owned wallet inspection identities with bounded retention.
//!
//! A review binds recovery to the exact file object and bytes inspected.
//! Changed files revoke their matching review; explicit release and expiry
//! remove abandoned reviews without disturbing other inspections.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const MAX_WALLET_REVIEWS: usize = 16;
pub const WALLET_REVIEW_TTL: Duration = Duration::from_secs(30 * 60);

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WalletReviewId(pub String);

/// Backend-owned authority for the exact file object and bytes inspected.
/// It deliberately exposes neither the digest nor object identity to IPC.
#[derive(PartialEq, Eq)]
pub struct ReviewedWalletSource {
    review_id: WalletReviewId,
    path: PathBuf,
    identity: Arc<argos_core::wallet_file::WalletFileIdentity>,
}

impl ReviewedWalletSource {
    pub fn verify(&self) -> Result<argos_core::wallet_file::WalletFileSnapshot, String> {
        argos_core::wallet_file::verify_wallet_snapshot(&self.path, &self.identity)
            .map_err(|err| err.to_string())
    }
}

struct StoredWalletReview {
    source: Arc<ReviewedWalletSource>,
    created: Instant,
}

struct WalletReviewInner {
    reviews: HashMap<WalletReviewId, StoredWalletReview>,
    ttl: Duration,
}

impl Default for WalletReviewInner {
    fn default() -> Self {
        Self {
            reviews: HashMap::new(),
            ttl: WALLET_REVIEW_TTL,
        }
    }
}

#[derive(Clone, Default)]
pub struct WalletReviewRegistry(Arc<Mutex<WalletReviewInner>>);

impl WalletReviewRegistry {
    #[cfg(test)]
    fn with_ttl(ttl: Duration) -> Self {
        Self(Arc::new(Mutex::new(WalletReviewInner {
            ttl,
            ..WalletReviewInner::default()
        })))
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, WalletReviewInner>, String> {
        self.0
            .lock()
            .map_err(|_| "wallet review registry unavailable".to_owned())
    }

    fn sweep_expired(inner: &mut WalletReviewInner) {
        let now = Instant::now();
        let ttl = inner.ttl;
        inner
            .reviews
            .retain(|_, stored| now.saturating_duration_since(stored.created) < ttl);
    }

    pub fn register(
        &self,
        path: PathBuf,
        identity: Arc<argos_core::wallet_file::WalletFileIdentity>,
    ) -> Result<WalletReviewId, String> {
        let mut inner = self.lock()?;
        Self::sweep_expired(&mut inner);
        if inner.reviews.len() >= MAX_WALLET_REVIEWS {
            return Err(
                "too many wallet reviews; inspect the file again after an older review expires"
                    .into(),
            );
        }
        let review_id = loop {
            let candidate = WalletReviewId(Uuid::new_v4().to_string());
            if !inner.reviews.contains_key(&candidate) {
                break candidate;
            }
        };
        let source = Arc::new(ReviewedWalletSource {
            review_id: review_id.clone(),
            path,
            identity,
        });
        inner.reviews.insert(
            review_id.clone(),
            StoredWalletReview {
                source,
                created: Instant::now(),
            },
        );
        Ok(review_id)
    }

    pub fn resolve(&self, id: &WalletReviewId) -> Result<Arc<ReviewedWalletSource>, String> {
        let mut inner = self.lock()?;
        Self::sweep_expired(&mut inner);
        inner
            .reviews
            .get(id)
            .map(|stored| Arc::clone(&stored.source))
            .ok_or_else(|| "unknown or expired wallet review; inspect the wallet again".to_owned())
    }

    /// Release a finished or abandoned inspection without disturbing other
    /// reviews of the same wallet. Repeated cleanup and expired IDs are harmless.
    pub fn release(&self, id: &WalletReviewId) -> Result<(), String> {
        let mut inner = self.lock()?;
        Self::sweep_expired(&mut inner);
        inner.reviews.remove(id);
        Ok(())
    }

    pub fn verify(
        &self,
        id: &WalletReviewId,
    ) -> Result<
        (
            Arc<ReviewedWalletSource>,
            argos_core::wallet_file::WalletFileSnapshot,
        ),
        String,
    > {
        let source = self.resolve(id)?;
        self.verify_source(&source)
            .map(|snapshot| (source, snapshot))
    }

    pub fn verify_source(
        &self,
        source: &Arc<ReviewedWalletSource>,
    ) -> Result<argos_core::wallet_file::WalletFileSnapshot, String> {
        match source.verify() {
            Ok(snapshot) => Ok(snapshot),
            Err(err) => {
                if let Ok(mut inner) = self.lock() {
                    let is_matching = inner
                        .reviews
                        .get(&source.review_id)
                        .is_some_and(|stored| Arc::ptr_eq(&stored.source, source));
                    if is_matching {
                        inner.reviews.remove(&source.review_id);
                    }
                }
                Err(err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reviewed_wallet(
        registry: &WalletReviewRegistry,
        bytes: &[u8],
    ) -> (PathBuf, PathBuf, WalletReviewId) {
        let dir = std::env::temp_dir().join(format!("argos-wallet-review-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wallet.dat");
        std::fs::write(&path, bytes).unwrap();
        let snapshot = argos_core::wallet_file::read_wallet_snapshot(&path).unwrap();
        let id = registry
            .register(path.clone(), Arc::new(snapshot.identity().clone()))
            .unwrap();
        (dir, path, id)
    }

    #[test]
    fn stale_or_unknown_review_id_is_rejected() {
        let registry = WalletReviewRegistry::with_ttl(Duration::ZERO);
        let (dir, _path, id) = reviewed_wallet(&registry, b"wallet");
        assert!(registry.verify(&id).is_err());
        assert!(registry
            .verify(&WalletReviewId("unknown".to_owned()))
            .is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn wallet_review_release_revokes_only_the_requested_capability() {
        let registry = WalletReviewRegistry::default();
        let (dir, path, released) = reviewed_wallet(&registry, b"wallet");
        let snapshot = argos_core::wallet_file::read_wallet_snapshot(&path).unwrap();
        let retained = registry
            .register(path, Arc::new(snapshot.identity().clone()))
            .unwrap();
        let source = registry.resolve(&released).unwrap();
        let weak = Arc::downgrade(&source);
        drop(source);

        registry.release(&released).unwrap();

        assert!(registry.resolve(&released).is_err());
        assert!(
            weak.upgrade().is_none(),
            "released registry owner was dropped"
        );
        assert!(registry.verify(&retained).is_ok());
        registry.release(&released).unwrap();
        assert!(registry.verify(&retained).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn wallet_review_release_accepts_expired_and_unissued_ids() {
        let registry = WalletReviewRegistry::with_ttl(Duration::ZERO);
        let (dir, _path, id) = reviewed_wallet(&registry, b"wallet");
        registry.release(&id).unwrap();
        registry
            .release(&WalletReviewId("unissued".to_owned()))
            .unwrap();
        assert!(registry.resolve(&id).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn changed_wallet_revokes_matching_review_id() {
        let registry = WalletReviewRegistry::default();
        let (dir, path, id) = reviewed_wallet(&registry, b"wallet-A");
        std::fs::write(&path, b"wallet-B").unwrap();
        assert!(registry.verify(&id).is_err());
        assert!(registry.verify(&id).is_err(), "the rejected ID was revoked");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn retained_source_mismatch_revokes_matching_review_id() {
        let registry = WalletReviewRegistry::default();
        let (dir, path, id) = reviewed_wallet(&registry, b"wallet-A");
        let source = registry.resolve(&id).unwrap();
        std::fs::write(&path, b"wallet-B").unwrap();
        assert!(registry.verify_source(&source).is_err());
        assert!(
            registry.resolve(&id).is_err(),
            "the rejected ID was revoked"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn wallet_review_registry_is_bounded() {
        let registry = WalletReviewRegistry::default();
        let mut roots = Vec::new();
        for marker in 0..MAX_WALLET_REVIEWS {
            let reviewed = reviewed_wallet(&registry, &[marker as u8]);
            roots.push(reviewed);
        }
        let dir = std::env::temp_dir().join(format!("argos-wallet-review-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("overflow.dat");
        std::fs::write(&path, b"overflow").unwrap();
        let snapshot = argos_core::wallet_file::read_wallet_snapshot(&path).unwrap();
        assert!(registry
            .register(path.clone(), Arc::new(snapshot.identity().clone()))
            .is_err());
        registry.release(&roots[0].2).unwrap();
        assert!(
            registry
                .register(path, Arc::new(snapshot.identity().clone()))
                .is_ok(),
            "explicit release reclaims registry capacity"
        );
        for (dir, _, _) in roots {
            std::fs::remove_dir_all(dir).unwrap();
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
