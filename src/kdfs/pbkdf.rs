// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

#[cfg(all(feature = "hmac", feature = "sha"))]
pub fn PBKDF2_HMAC_SHA512(password: &[u8], salt: &[u8], c: usize, dk: &mut [u8; 64]) -> crate::Result<()> {
    if c == 0 {
        return Err(crate::Error::InvalidArgumentError {
            alg: "PBKDF2-HMAC-SHA512",
            expected: "non-zero iteration count",
        });
    }

    pbkdf2::pbkdf2::<hmac_::Hmac<sha2::Sha512>>(password, salt, c as u32, dk);

    Ok(())
}
