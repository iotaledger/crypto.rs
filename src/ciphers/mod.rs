// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(any(feature = "cipher", feature = "chacha"))]
#[macro_use]
mod macros;

#[cfg(feature = "chacha")]
#[cfg_attr(docsrs, doc(cfg(feature = "chacha")))]
pub mod chacha;

#[cfg(feature = "aes-gcm")]
#[cfg_attr(docsrs, doc(cfg(feature = "aes-gcm")))]
pub mod aes_gcm;

#[cfg(feature = "aes-cbc")]
#[cfg_attr(docsrs, doc(cfg(feature = "aes-cbc")))]
pub mod aes_cbc;

#[cfg(feature = "aes-kw")]
#[cfg_attr(docsrs, doc(cfg(feature = "aes-kw")))]
pub mod aes_kw;

#[cfg(feature = "cipher")]
pub mod traits;
