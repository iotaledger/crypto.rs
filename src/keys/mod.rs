// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "pbkdf")]
#[cfg_attr(docsrs, doc(cfg(feature = "pbkdf")))]
pub mod pbkdf;

#[cfg(feature = "bip39")]
#[cfg_attr(docsrs, doc(cfg(feature = "bip39")))]
pub mod bip39;

#[cfg(feature = "slip10")]
#[cfg_attr(docsrs, doc(cfg(feature = "slip10")))]
pub mod slip10;

#[cfg(feature = "x25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "x25519")))]
pub mod x25519;

#[cfg(feature = "x448")]
#[cfg_attr(docsrs, doc(cfg(feature = "x448")))]
pub mod x448;
