// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

#[doc(inline)]
pub use tiny_keccak::{Hasher, Keccak};

pub const KECCAK256_LEN: usize = 32;

// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
pub fn keccak256(msg: &[u8], digest: &mut [u8; KECCAK256_LEN]) {
    let mut keccak = Keccak::v256();
    keccak.update(msg);
    keccak.finalize(digest);
}
