// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::ciphers::traits::consts::{U12, U16, U24, U32};

pub type ChaCha20Poly1305 = chacha20poly1305::ChaCha20Poly1305;
impl_aead!(ChaCha20Poly1305, "CHACHA20-POLY1305", U32, U12, U16);

pub type XChaCha20Poly1305 = chacha20poly1305::XChaCha20Poly1305;
impl_aead!(XChaCha20Poly1305, "XCHACHA20-POLY1305", U32, U24, U16);
