// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::ciphers::traits::consts::{U16, U24, U32};

pub type XChaCha20Poly1305 = chacha20poly1305::XChaCha20Poly1305;
impl_aead!(XChaCha20Poly1305, "XCHACHA20-POLY1305", U32, U24, U16);
