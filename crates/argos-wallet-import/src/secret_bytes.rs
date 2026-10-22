//! A deliberately narrow owner for plaintext wallet bytes.
//!
//! The wrapper exposes immutable borrowing only. In particular, it has no
//! `Clone`, `Debug`, `Serialize`, `DerefMut`, or owned-plaintext getter:
//!
//! ```compile_fail
//! use argos_wallet_import::SecretBytes;
//! let secret = SecretBytes::new(vec![1, 2, 3]);
//! let _copy = secret.clone();
//! ```
//!
//! ```compile_fail
//! use argos_wallet_import::SecretBytes;
//! let secret = SecretBytes::new(vec![1, 2, 3]);
//! println!("{secret:?}");
//! ```
//!
//! ```compile_fail
//! use argos_wallet_import::SecretBytes;
//! fn assert_serialize<T: serde::Serialize>() {}
//! assert_serialize::<SecretBytes>();
//! ```
//!
//! ```compile_fail
//! use argos_wallet_import::SecretBytes;
//! use std::ops::DerefMut;
//! let mut secret = SecretBytes::new(vec![1, 2, 3]);
//! let _ = secret.deref_mut();
//! ```
//!
//! ```compile_fail
//! use argos_wallet_import::SecretBytes;
//! let secret = SecretBytes::new(vec![1, 2, 3]);
//! let _: Vec<u8> = secret.into_inner();
//! ```
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Fixed-size key material erased before leaving its temporary owner.
pub(crate) struct SecretArray<const N: usize> {
    bytes: [u8; N],
    #[cfg(test)]
    drop_probe: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

#[cfg(test)]
thread_local! {
    static SECRET_ARRAY_DROP_PROBE: std::cell::RefCell<Option<std::sync::Arc<std::sync::atomic::AtomicBool>>> =
        const { std::cell::RefCell::new(None) };
}

impl<const N: usize> ZeroizeOnDrop for SecretArray<N> {}

impl<const N: usize> Drop for SecretArray<N> {
    fn drop(&mut self) {
        self.bytes.zeroize();
        #[cfg(test)]
        if let Some(probe) = &self.drop_probe {
            debug_assert!(self.bytes.iter().all(|byte| *byte == 0));
            probe.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

impl<const N: usize> SecretArray<N> {
    pub(crate) fn new(bytes: [u8; N]) -> Self {
        Self {
            bytes,
            #[cfg(test)]
            drop_probe: SECRET_ARRAY_DROP_PROBE.with(|probe| probe.borrow().clone()),
        }
    }

    pub(crate) fn as_array(&self) -> &[u8; N] {
        &self.bytes
    }

    pub(crate) fn as_mut_array(&mut self) -> &mut [u8; N] {
        &mut self.bytes
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn into_secret(mut self) -> secrecy::Secret<[u8; N]> {
        secrecy::Secret::new(std::mem::replace(&mut self.bytes, [0; N]))
    }

    pub(crate) fn into_secret_vec(self) -> secrecy::Secret<Vec<u8>> {
        secrecy::Secret::new(self.bytes.to_vec())
    }

    #[cfg(test)]
    pub(crate) fn with_drop_probe(
        bytes: [u8; N],
        probe: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        let mut secret = Self::new(bytes);
        secret.drop_probe = Some(probe);
        secret
    }

    #[cfg(test)]
    pub(crate) fn test_with_drop_probe<R>(
        probe: std::sync::Arc<std::sync::atomic::AtomicBool>,
        f: impl FnOnce() -> R,
    ) -> R {
        let previous = SECRET_ARRAY_DROP_PROBE.with(|slot| slot.replace(Some(probe)));
        let result = f();
        SECRET_ARRAY_DROP_PROBE.with(|slot| {
            slot.replace(previous);
        });
        result
    }
}

/// Plaintext bytes erased before their allocation is released.
pub struct SecretBytes {
    bytes: Zeroizing<Vec<u8>>,
    #[cfg(test)]
    drop_probe: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl ZeroizeOnDrop for SecretBytes {}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.bytes.zeroize();
        #[cfg(test)]
        if let Some(probe) = &self.drop_probe {
            debug_assert!(self.bytes.iter().all(|byte| *byte == 0));
            probe.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

impl SecretBytes {
    /// Allocate an empty zeroizing buffer for a known final length.
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Zeroizing::new(Vec::with_capacity(capacity)),
            #[cfg(test)]
            drop_probe: None,
        }
    }

    /// Take ownership of an exactly sized plaintext buffer.
    pub fn new(bytes: Vec<u8>) -> Self {
        if bytes.len() == bytes.capacity() {
            return Self {
                bytes: Zeroizing::new(bytes),
                #[cfg(test)]
                drop_probe: None,
            };
        }
        // Growing builders often retain spare capacity. Copy once into the
        // final exact allocation while the builder is already guarded, so
        // dropping its oversized allocation scrubs every initialized byte.
        let bytes = Zeroizing::new(bytes);
        Self::copy_from_slice(bytes.as_slice())
    }

    /// Copy a known-size plaintext slice into one exact-size allocation.
    pub(crate) fn copy_from_slice(bytes: &[u8]) -> Self {
        let mut out = Vec::with_capacity(bytes.len());
        out.extend_from_slice(bytes);
        Self::new(out)
    }

    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        self.bytes.as_mut_slice()
    }

    pub(crate) fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    pub(crate) fn len(&self) -> usize {
        self.bytes.len()
    }

    #[cfg(test)]
    pub(crate) fn test_vec_mut(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }

    #[cfg(test)]
    pub(crate) fn test_capacity(&self) -> usize {
        self.bytes.capacity()
    }

    #[cfg(test)]
    pub(crate) fn with_drop_probe(
        bytes: Vec<u8>,
        probe: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        let mut secret = Self::new(bytes);
        secret.drop_probe = Some(probe);
        secret
    }

    #[cfg(test)]
    pub(crate) fn with_capacity_and_drop_probe(
        capacity: usize,
        probe: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        let mut secret = Self::with_capacity(capacity);
        secret.drop_probe = Some(probe);
        secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::{Zeroize, ZeroizeOnDrop};

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn parser_boundaries_require_secret_buffers() {
        assert_zeroize_on_drop::<SecretBytes>();
        fn assert_zeroize<T: Zeroize>() {}
        assert_zeroize::<x25519_dalek::StaticSecret>();
    }

    #[test]
    fn exact_sized_constructor_does_not_reallocate() {
        let mut exact = Vec::with_capacity(18);
        exact.extend_from_slice(b"spending authority");
        assert_eq!(exact.len(), exact.capacity());
        let allocation = exact.as_ptr();

        let secret = SecretBytes::new(exact);
        assert_eq!(secret.bytes.as_ptr(), allocation);
        assert_eq!(secret.bytes.len(), secret.bytes.capacity());

        let mut oversized = Vec::with_capacity(128);
        oversized.extend_from_slice(b"spending authority");
        let secret = SecretBytes::new(oversized);
        assert_eq!(secret.bytes.len(), secret.bytes.capacity());
    }

    #[test]
    fn fixed_array_owner_zeroizes_before_drop_probe() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };

        let probe = Arc::new(AtomicBool::new(false));
        let secret = SecretArray::with_drop_probe([0xA5; 32], Arc::clone(&probe));
        assert_zeroize_on_drop::<SecretArray<32>>();
        drop(secret);
        assert!(probe.load(Ordering::SeqCst));
    }
}
