// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

#[cfg(all(feature = "hmac", feature = "sha"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "hmac", feature = "sha"))))]
pub fn PBKDF2_HMAC_SHA256(password: &[u8], salt: &[u8], count: core::num::NonZeroU32, buffer: &mut [u8]) {
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, count.get(), buffer);
}

#[cfg(all(feature = "hmac", feature = "sha"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "hmac", feature = "sha"))))]
pub fn PBKDF2_HMAC_SHA384(password: &[u8], salt: &[u8], count: core::num::NonZeroU32, buffer: &mut [u8]) {
    pbkdf2::pbkdf2_hmac::<sha2::Sha384>(password, salt, count.get(), buffer);
}

#[cfg(all(feature = "hmac", feature = "sha"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "hmac", feature = "sha"))))]
pub fn PBKDF2_HMAC_SHA512(password: &[u8], salt: &[u8], count: core::num::NonZeroU32, buffer: &mut [u8]) {
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(password, salt, count.get(), buffer);
}
