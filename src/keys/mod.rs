// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "ternary_keys")]
#[cfg_attr(docsrs, doc(cfg(feature = "ternary_keys")))]
pub mod ternary;

#[cfg(feature = "pbkdf2")]
#[cfg_attr(docsrs, doc(cfg(feature = "pbkdf2")))]
pub mod pbkdf;

#[cfg(feature = "bip39")]
#[cfg_attr(docsrs, doc(cfg(feature = "bip39")))]
pub mod bip39;

#[cfg(feature = "bip44")]
#[cfg_attr(docsrs, doc(cfg(feature = "bip44")))]
pub mod bip44;

#[cfg(feature = "slip10")]
#[cfg_attr(docsrs, doc(cfg(feature = "slip10")))]
pub mod slip10;

#[cfg(feature = "x25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "x25519")))]
pub mod x25519;

#[cfg(feature = "age")]
#[cfg_attr(docsrs, doc(cfg(feature = "age")))]
pub mod age;
