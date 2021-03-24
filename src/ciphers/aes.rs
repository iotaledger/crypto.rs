// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::ciphers::traits::consts::{U12, U16, U24, U32};

pub type Aes128Gcm = aes_gcm::Aes128Gcm;
impl_aead!(Aes128Gcm, "AES-128-GCM", U16, U12, U16);

pub type Aes192Gcm = aes_gcm::AesGcm<aes_crate::Aes192, U12>;
impl_aead!(Aes192Gcm, "AES-192-GCM", U24, U12, U16);

pub type Aes256Gcm = aes_gcm::Aes256Gcm;
impl_aead!(Aes256Gcm, "AES-256-GCM", U32, U12, U16);
