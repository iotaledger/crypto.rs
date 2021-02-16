// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "curl-p")]
pub mod curl_p;

#[cfg(feature = "sha")]
pub mod sha;

#[cfg(feature = "digest")]
#[doc(inline)]
pub use digest::Digest;

#[cfg(feature = "digest")]
#[doc(inline)]
pub use digest::Output;
