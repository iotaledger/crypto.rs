// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "sponge")]
#[cfg_attr(docsrs, doc(cfg(feature = "sponge")))]
pub mod sponge;

#[cfg(feature = "blake2b")]
#[cfg_attr(docsrs, doc(cfg(feature = "blake2b")))]
pub mod blake2b;

#[cfg(feature = "sha")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha")))]
pub mod sha;

#[cfg(any(feature = "blake2b", feature = "sha"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "blake2b", feature = "sha"))))]
#[doc(inline)]
pub use digest::{Digest, Output};
