// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

#[cfg(feature = "sha")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha")))]
pub fn HMAC_SHA256(data: &[u8], key: &[u8], mac: &mut [u8; 32]) {
    use hmac_::{Mac, NewMac};
    let mut m = hmac_::Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
    m.update(data);
    mac.copy_from_slice(&m.finalize().into_bytes())
}

#[cfg(feature = "sha")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha")))]
pub fn HMAC_SHA384(data: &[u8], key: &[u8], mac: &mut [u8; 48]) {
    use hmac_::{Mac, NewMac};
    let mut m = hmac_::Hmac::<sha2::Sha384>::new_from_slice(key).unwrap();
    m.update(data);
    mac.copy_from_slice(&m.finalize().into_bytes())
}

#[cfg(feature = "sha")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha")))]
pub fn HMAC_SHA512(data: &[u8], key: &[u8], mac: &mut [u8; 64]) {
    use hmac_::{Mac, NewMac};
    let mut m = hmac_::Hmac::<sha2::Sha512>::new_from_slice(key).unwrap();
    m.update(data);
    mac.copy_from_slice(&m.finalize().into_bytes())
}
