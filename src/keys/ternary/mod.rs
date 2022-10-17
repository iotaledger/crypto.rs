// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(deprecated)]

pub mod seed;
#[cfg(feature = "wots_deprecated_do_not_use")]
#[cfg_attr(docsrs, doc(cfg(feature = "wots_deprecated_do_not_use")))]
#[cfg_attr(not(test), deprecated)]
pub mod wots;

use crate::{
    encoding::ternary::{Trits, T1B1},
    keys::ternary::seed::Seed,
    signatures::ternary::PrivateKey,
};

/// Generates a ternary private key.
pub trait PrivateKeyGenerator {
    /// Generated private keys type.
    type PrivateKey: PrivateKey;
    /// Errors occuring while generating private keys.
    type Error;

    /// Deterministically generates and returns a private key from a seed and an index.
    ///
    /// # Arguments
    ///
    /// * `seed`    A seed to deterministically derive a private key from.
    /// * `index`   An index to deterministically derive a private key from.
    fn generate_from_seed(&self, seed: &Seed, index: usize) -> Result<Self::PrivateKey, Self::Error> {
        self.generate_from_entropy(seed.subseed(index).as_trits())
    }

    /// Deterministically generates and returns a private key from ternary entropy.
    ///
    /// # Arguments
    ///
    /// * `entropy` Entropy to deterministically derive a private key from.
    fn generate_from_entropy(&self, entropy: &Trits<T1B1>) -> Result<Self::PrivateKey, Self::Error>;
}
