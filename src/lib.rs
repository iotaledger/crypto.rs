// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[macro_use]
mod macros;

pub mod ciphers;
pub mod encoding;
pub mod error;
pub mod hashes;
pub mod keys;
pub mod macs;
pub mod signatures;
pub mod utils;

pub use self::error::{Error, Result};

#[macro_use]
#[allow(unused_imports)]
extern crate alloc;
