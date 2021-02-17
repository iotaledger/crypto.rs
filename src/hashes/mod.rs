// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "blake2b")]
pub mod blake2b;

#[cfg(feature = "curl-p")]
pub mod curl_p;

#[cfg(feature = "sha")]
pub mod sha;

#[cfg(feature = "digest")]
#[doc(inline)]
pub use digest::{Digest, Output};
