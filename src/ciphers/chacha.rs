// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::Error;

use chacha20poly1305::aead::{AeadMutInPlace, NewAead};

pub mod xchacha20poly1305 {
    use super::*;

    pub const XCHACHA20POLY1305_KEY_SIZE: usize = 32;
    pub const XCHACHA20POLY1305_NONCE_SIZE: usize = 24;
    pub const XCHACHA20POLY1305_TAG_SIZE: usize = 16;

    pub fn encrypt(
        ciphertext: &mut [u8],
        tag: &mut [u8; XCHACHA20POLY1305_TAG_SIZE],
        plaintext: &[u8],
        key: &[u8; XCHACHA20POLY1305_KEY_SIZE],
        nonce: &[u8; XCHACHA20POLY1305_NONCE_SIZE],
        associated_data: &[u8],
    ) -> crate::Result<()> {
        if plaintext.len() > ciphertext.len() {
            return Err(Error::BufferSize {
                needs: plaintext.len(),
                has: ciphertext.len(),
            });
        }
        ciphertext.copy_from_slice(plaintext);

        let k = chacha20poly1305::Key::from_slice(key);
        let n = chacha20poly1305::XNonce::from_slice(nonce);
        let mut c = chacha20poly1305::XChaCha20Poly1305::new(k);
        match c.encrypt_in_place_detached(n, associated_data, ciphertext) {
            Ok(t) => {
                tag.copy_from_slice(t.as_slice());
                Ok(())
            }
            Err(_) => Err(Error::CipherError {
                alg: "xchacha20poly1305::encrypt",
            }),
        }
    }

    pub fn decrypt(
        plaintext: &mut [u8],
        ciphertext: &[u8],
        key: &[u8; XCHACHA20POLY1305_KEY_SIZE],
        tag: &[u8; XCHACHA20POLY1305_TAG_SIZE],
        nonce: &[u8; XCHACHA20POLY1305_NONCE_SIZE],
        associated_data: &[u8],
    ) -> crate::Result<()> {
        if ciphertext.len() > plaintext.len() {
            return Err(Error::BufferSize {
                needs: ciphertext.len(),
                has: plaintext.len(),
            });
        }
        plaintext.copy_from_slice(ciphertext);

        let k = chacha20poly1305::Key::from_slice(key);
        let n = chacha20poly1305::XNonce::from_slice(nonce);
        let t = chacha20poly1305::Tag::from_slice(tag);
        let mut c = chacha20poly1305::XChaCha20Poly1305::new(k);
        c.decrypt_in_place_detached(n, associated_data, plaintext, t)
            .map_err(|_| Error::CipherError {
                alg: "xchacha20poly1305::decrypt",
            })
    }
}
