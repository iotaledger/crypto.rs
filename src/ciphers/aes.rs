// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use crate::Error;

pub mod AES_256_GCM {
    use super::*;
    use aes_gcm::{
        aead::{generic_array::GenericArray, AeadMutInPlace, NewAead},
        Aes256Gcm,
    };

    pub const KEY_LENGTH: usize = 32;
    pub const IV_LENGTH: usize = 12;
    pub const TAG_LENGTH: usize = 16;

    pub fn encrypt(
        key: &[u8; KEY_LENGTH],
        iv: &[u8; IV_LENGTH],
        associated_data: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; TAG_LENGTH],
    ) -> crate::Result<()> {
        if plaintext.len() > ciphertext.len() {
            return Err(Error::BufferSize {
                needs: plaintext.len(),
                has: ciphertext.len(),
            });
        }
        ciphertext.copy_from_slice(plaintext);

        let t = Aes256Gcm::new(GenericArray::from_slice(key))
            .encrypt_in_place_detached(GenericArray::from_slice(iv), associated_data, ciphertext)
            .map_err(|_| Error::CipherError {
                alg: "AES_256_GCM::encrypt",
            })?;

        tag.copy_from_slice(t.as_slice());
        Ok(())
    }

    pub fn decrypt(
        key: &[u8; KEY_LENGTH],
        iv: &[u8; IV_LENGTH],
        associated_data: &[u8],
        tag: &[u8; TAG_LENGTH],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> crate::Result<()> {
        if ciphertext.len() > plaintext.len() {
            return Err(Error::BufferSize {
                needs: ciphertext.len(),
                has: plaintext.len(),
            });
        }
        plaintext.copy_from_slice(ciphertext);

        Aes256Gcm::new(GenericArray::from_slice(key))
            .decrypt_in_place_detached(
                GenericArray::from_slice(iv),
                associated_data,
                plaintext,
                GenericArray::from_slice(tag),
            )
            .map_err(|_| Error::CipherError {
                alg: "AES_256_GCM::decrypt",
            })
    }
}
