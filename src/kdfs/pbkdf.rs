// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

#[cfg(all(feature = "hmac", feature = "sha"))]
pub fn PBKDF2_HMAC_SHA512() {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestVector {
        password: &'static str,
        salt: &'static str,
        c: usize,
        dk: &'static str,
    }

    #[test]
    fn test_PBKDF2_HMAC_SHA512() {
    }
}
