// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use sha2::{Digest, Sha256, Sha384, Sha512};

pub const SHA256_LEN: usize = 32;
pub const SHA384_LEN: usize = 48;
pub const SHA512_LEN: usize = 64;

pub fn SHA256(msg: &[u8], digest: &mut [u8; SHA256_LEN]) {
    digest.copy_from_slice(&Sha256::digest(msg))
}

pub fn SHA384(msg: &[u8], digest: &mut [u8; SHA384_LEN]) {
    digest.copy_from_slice(&Sha384::digest(msg))
}

pub fn SHA512(msg: &[u8], digest: &mut [u8; SHA512_LEN]) {
    digest.copy_from_slice(&Sha512::digest(msg))
}
