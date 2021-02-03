// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// https://tools.ietf.org/html/rfc7748
// https://cr.yp.to/ecdh/curve25519-20060209.pdf

#![allow(non_snake_case)]

pub const SECRET_KEY_LENGTH: usize = 32;
pub const PUBLIC_KEY_LENGTH: usize = 32;

type SecretKey = [u8; SECRET_KEY_LENGTH];
type PublicKey = [u8; PUBLIC_KEY_LENGTH];

static BASE_POINT: PublicKey = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

// nomenclature compromise:
// RFC7748   Bernstein's 2006 paper
// scalar/u  secret/public
// X25519    Curve25519

/// Perform the X25519 function on the given secret key and public key
///
/// When the public key is omitted the curves base point is used, hence this function can be used
/// to derive the public key of a Curve25519 secret key as well as performing a Diffie-Hellman
/// exchange between a secret key and another public key.
pub fn X25519(s: &SecretKey, u: Option<&PublicKey>) -> PublicKey {
    x25519_dalek::x25519(*s, *u.unwrap_or(&BASE_POINT))
}
