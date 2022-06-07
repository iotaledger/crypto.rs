// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

macro_rules! impl_aead {
    ($impl:ident, $name:expr, $key_len:ident, $nonce_len:ident, $tag_len:ident) => {
        impl $crate::ciphers::traits::Aead for $impl {
            type KeyLength = $key_len;

            type NonceLength = $nonce_len;

            type TagLength = $tag_len;

            const NAME: &'static str = $name;

            /// Warning: type conversions on the tag type can be tricky. instead of `&mut tag.try_into().unwrap()` use
            /// `(&mut tag).try_into().unwrap()`
            fn encrypt(
                key: &$crate::ciphers::traits::Key<Self>,
                nonce: &$crate::ciphers::traits::Nonce<Self>,
                associated_data: &[u8],
                plaintext: &[u8],
                ciphertext: &mut [u8],
                tag: &mut $crate::ciphers::traits::Tag<Self>,
            ) -> crate::Result<()> {
                use aead::{AeadInPlace, NewAead};

                if plaintext.len() > ciphertext.len() {
                    return Err($crate::Error::BufferSize {
                        name: "ciphertext",
                        needs: plaintext.len(),
                        has: ciphertext.len(),
                    });
                }

                ciphertext[..plaintext.len()].copy_from_slice(plaintext);

                let out: $crate::ciphers::traits::Tag<Self> = Self::new(key)
                    .encrypt_in_place_detached(nonce, associated_data, ciphertext)
                    .map_err(|_| $crate::Error::CipherError { alg: Self::NAME })?;

                tag.copy_from_slice(&out);

                Ok(())
            }

            fn decrypt(
                key: &$crate::ciphers::traits::Key<Self>,
                nonce: &$crate::ciphers::traits::Nonce<Self>,
                associated_data: &[u8],
                plaintext: &mut [u8],
                ciphertext: &[u8],
                tag: &$crate::ciphers::traits::Tag<Self>,
            ) -> crate::Result<usize> {
                use aead::{AeadInPlace, NewAead};

                if ciphertext.len() > plaintext.len() {
                    return Err($crate::Error::BufferSize {
                        name: "plaintext",
                        needs: ciphertext.len(),
                        has: plaintext.len(),
                    });
                }

                plaintext[..ciphertext.len()].copy_from_slice(ciphertext);

                Self::new(key)
                    .decrypt_in_place_detached(nonce, associated_data, plaintext, tag)
                    .map_err(|_| $crate::Error::CipherError { alg: Self::NAME })?;

                Ok(ciphertext.len())
            }
        }
    };
}
