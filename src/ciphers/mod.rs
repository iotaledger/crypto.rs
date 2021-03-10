// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "chacha")]
#[cfg_attr(docsrs, doc(cfg(feature = "chacha")))]
pub mod chacha;

#[cfg(feature = "aes")]
#[cfg_attr(docsrs, doc(cfg(feature = "aes")))]
pub mod aes;

#[cfg(feature = "aes-kw")]
#[cfg_attr(docsrs, doc(cfg(feature = "aes-kw")))]
pub mod aes_kw;
