// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

fn assert_iteration_count(alg: &'static str, count: usize) -> crate::Result<()> {
    if count == 0 {
        Err(crate::Error::InvalidArgumentError {
            alg,
            expected: "non-zero iteration count",
        })
    } else {
        Ok(())
    }
}

#[cfg(all(feature = "hmac", feature = "sha"))]
pub fn PBKDF2_HMAC_SHA256(password: &[u8], salt: &[u8], count: usize, buffer: &mut [u8]) -> crate::Result<()> {
    assert_iteration_count("PBKDF2-HMAC-SHA256", count).map(|_| {
        pbkdf2::pbkdf2::<hmac_::Hmac<sha2::Sha256>>(password, salt, count as u32, buffer);
    })
}

#[cfg(all(feature = "hmac", feature = "sha"))]
pub fn PBKDF2_HMAC_SHA384(password: &[u8], salt: &[u8], count: usize, buffer: &mut [u8]) -> crate::Result<()> {
    assert_iteration_count("PBKDF2-HMAC-SHA384", count).map(|_| {
        pbkdf2::pbkdf2::<hmac_::Hmac<sha2::Sha384>>(password, salt, count as u32, buffer);
    })
}

#[cfg(all(feature = "hmac", feature = "sha"))]
pub fn PBKDF2_HMAC_SHA512(password: &[u8], salt: &[u8], count: usize, buffer: &mut [u8]) -> crate::Result<()> {
    assert_iteration_count("PBKDF2-HMAC-SHA512", count).map(|_| {
        pbkdf2::pbkdf2::<hmac_::Hmac<sha2::Sha512>>(password, salt, count as u32, buffer);
    })
}
