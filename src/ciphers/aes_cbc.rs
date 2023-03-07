// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::{
    marker::PhantomData,
    num::NonZeroUsize,
    ops::{Shl, Shr},
};

use aes::{
    cipher::{
        block_padding::{Padding, Pkcs7},
        BlockCipher, BlockDecryptMut, BlockEncryptMut, BlockSizeUser, InnerIvInit, KeyInit, KeySizeUser,
    },
    Aes128, Aes192, Aes256,
};
use cbc::{Decryptor as CbcDecryptor, Encryptor as CbcEncryptor};
use generic_array::{
    typenum::{Unsigned, B1},
    ArrayLength,
};
use hmac::{
    digest::{Digest, FixedOutput, OutputSizeUser, Update},
    SimpleHmac,
};
use sha2::{Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;

use crate::ciphers::traits::{Aead, Key, Nonce, Tag};

/// AES-CBC using 128-bit key and HMAC SHA-256.
pub type Aes128CbcHmac256 = CbcHmac<Aes128, Pkcs7, Sha256>;

/// AES-CBC using 192-bit key and HMAC SHA-384.
pub type Aes192CbcHmac384 = CbcHmac<Aes192, Pkcs7, Sha384>;

/// AES-CBC using 256-bit key and HMAC SHA-512.
pub type Aes256CbcHmac512 = CbcHmac<Aes256, Pkcs7, Sha512>;

/// AES in Cipher Block Chaining mode with PKCS #7 padding and HMAC
///
/// See [RFC7518#Section-5.2](https://tools.ietf.org/html/rfc7518#section-5.2)
#[derive(Clone, Copy, Debug)]
pub struct CbcHmac<Cipher, Pad, Hash> {
    cipher: PhantomData<Cipher>,
    padding: PhantomData<Pad>,
    digest: PhantomData<Hash>,
}

impl<Cipher, Pad, Hash> CbcHmac<Cipher, Pad, Hash>
where
    Cipher: BlockCipher,
{
    const BLOCK_SIZE: usize = <<Cipher as BlockSizeUser>::BlockSize as Unsigned>::USIZE;
}

impl<Cipher, Pad, Hash> Aead for CbcHmac<Cipher, Pad, Hash>
where
    Cipher: BlockCipher + BlockDecryptMut + BlockEncryptMut + KeySizeUser + KeyInit,

    // Key contains both MAC and encryption keys
    // This is the way to double array length
    <Cipher as KeySizeUser>::KeySize: ArrayLength<u8> + Shl<B1>,
    <<Cipher as KeySizeUser>::KeySize as Shl<B1>>::Output: ArrayLength<u8>,

    Pad: Padding<<Cipher as BlockSizeUser>::BlockSize>,

    Hash: BlockSizeUser + Digest + FixedOutput,

    // MAC is the hash output truncated in half
    // This is the way to halve array length
    <Hash as OutputSizeUser>::OutputSize: ArrayLength<u8> + Shr<B1>,
    <<Hash as OutputSizeUser>::OutputSize as Shr<B1>>::Output: ArrayLength<u8>,
{
    type KeyLength = <<Cipher as KeySizeUser>::KeySize as Shl<B1>>::Output;
    type NonceLength = <Cipher as BlockSizeUser>::BlockSize;
    type TagLength = <<Hash as OutputSizeUser>::OutputSize as Shr<B1>>::Output;

    const NAME: &'static str = "AES-CBC";

    fn encrypt(
        key: &Key<Self>,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut Tag<Self>,
    ) -> crate::Result<usize> {
        let length: usize = plaintext.len();
        let padding: usize = Self::padsize(plaintext).map(NonZeroUsize::get).unwrap_or_default();
        let expected: usize = length + padding;

        if expected > ciphertext.len() {
            return Err(crate::Error::BufferSize {
                name: "ciphertext",
                needs: expected,
                has: ciphertext.len(),
            });
        }

        // the second half of the key is the encryption key
        let cipher = CbcEncryptor::<Cipher>::inner_iv_init(
            Cipher::new_from_slice(&key.as_slice()[Self::KEY_LENGTH / 2..]).unwrap(),
            nonce,
        );

        // cbc encryptor does padding
        let cipher_slice = cipher
            .encrypt_padded_b2b_mut::<Pad>(plaintext, ciphertext)
            .map_err(|_| crate::Error::CipherError { alg: Self::NAME })?;
        debug_assert_eq!(expected, cipher_slice.len());

        // the first half of the key is the MAC key
        let mut hmac: SimpleHmac<Hash> =
            <SimpleHmac<Hash> as KeyInit>::new_from_slice(&key.as_slice()[..Self::KEY_LENGTH / 2]).unwrap();

        hmac.update(associated_data);
        hmac.update(nonce);
        hmac.update(ciphertext);
        hmac.update(&((associated_data.len() as u64) * 8).to_be_bytes());
        let hash = hmac.finalize_fixed();
        // the first half of HMAC output is the tag
        tag.copy_from_slice(&hash.as_slice()[..Self::TAG_LENGTH]);

        Ok(expected)
    }

    fn decrypt(
        key: &Key<Self>,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        plaintext: &mut [u8],
        ciphertext: &[u8],
        tag: &Tag<Self>,
    ) -> crate::Result<usize> {
        let length = ciphertext.len();
        if length > plaintext.len() {
            return Err(crate::Error::BufferSize {
                name: "plaintext",
                needs: length,
                has: plaintext.len(),
            });
        }

        // the first half of the key is the MAC key
        let mut hmac: SimpleHmac<Hash> =
            <SimpleHmac<Hash> as KeyInit>::new_from_slice(&key.as_slice()[..Self::KEY_LENGTH / 2]).unwrap();

        hmac.update(associated_data);
        hmac.update(nonce);
        hmac.update(ciphertext);
        hmac.update(&((associated_data.len() as u64) * 8).to_be_bytes());
        let hash = hmac.finalize_fixed();
        let mut computed = Tag::<Self>::default();
        // the first half of HMAC output is the tag
        computed.copy_from_slice(&hash.as_slice()[..Self::TAG_LENGTH]);

        if !bool::from(computed.ct_eq(tag)) {
            return Err(crate::Error::CipherError { alg: Self::NAME });
        }

        // the second half of the key is the encryption key
        let cipher = CbcDecryptor::<Cipher>::inner_iv_init(
            Cipher::new_from_slice(&key.as_slice()[Self::KEY_LENGTH / 2..]).unwrap(),
            nonce,
        );

        // cbc decryptor checks padding
        let plaintext_slice = cipher
            .decrypt_padded_b2b_mut::<Pad>(ciphertext, plaintext)
            .map_err(|_| crate::Error::CipherError { alg: Self::NAME })?;

        Ok(plaintext_slice.len())
    }

    fn padsize(plaintext: &[u8]) -> Option<NonZeroUsize> {
        NonZeroUsize::new(Self::BLOCK_SIZE - (plaintext.len() % Self::BLOCK_SIZE))
    }
}
