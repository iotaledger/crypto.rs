// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "blake2b")]
#[cfg_attr(docsrs, doc(cfg(feature = "blake2b")))]
pub mod blake2b;

#[cfg(feature = "curl-p")]
#[cfg_attr(docsrs, doc(cfg(feature = "curl-p")))]
pub mod curl_p;

#[cfg(feature = "sha")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha")))]
pub mod sha;

#[cfg(feature = "digest")]
#[cfg_attr(docsrs, doc(cfg(feature = "digest")))]
#[doc(inline)]
pub use digest::{Digest, Output};
