// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::ciphers::traits::consts::{U12, U16, U32};

pub type Aes256Gcm = aes_gcm::Aes256Gcm;
impl_aead!(Aes256Gcm, "AES-256-GCM", U32, U12, U16);
