// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "ternary_signatures")]
#[cfg_attr(docsrs, doc(cfg(feature = "ternary_signatures")))]
pub mod ternary;

#[cfg(feature = "ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
pub mod ed25519;

#[cfg(feature = "sr25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "sr25519")))]
pub mod sr25519;
