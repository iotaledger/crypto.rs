// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use aes_crate::{Aes128, Aes192, Aes256, BlockCipher, NewBlockCipher};
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};

use core::{
    marker::PhantomData,
    num::NonZeroUsize,
    ops::{Shl, Sub},
};
use generic_array::{
    sequence::Split,
    typenum::{Double, Unsigned, B1, U16, U24, U32},
    ArrayLength,
};
use hmac_::{
    digest::{
        block_buffer::Eager,
        core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
        typenum::{IsLess, Le, NonZero, U256},
        FixedOutput, HashMarker, OutputSizeUser, Reset,
    },
    Hmac, Mac,
};
use sha2::{Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;

use crate::ciphers::traits::{Aead, Key, Nonce, Tag};

/// AES-CBC using 128-bit key and HMAC SHA-256.
pub type Aes128CbcHmac256 = AesCbc<Aes128, Sha256, U16, U16>;

/// AES-CBC using 192-bit key and HMAC SHA-384.
pub type Aes192CbcHmac384 = AesCbc<Aes192, Sha384, U24, U24>;

/// AES-CBC using 256-bit key and HMAC SHA-512.
pub type Aes256CbcHmac512 = AesCbc<Aes256, Sha512, U32, U32>;

type AesCbcPkcs7<Cipher> = Cbc<Cipher, Pkcs7>;

type NonceLength = U16;

type DigestOutput<Digest> = <Digest as OutputSizeUser>::OutputSize;

/// AES in Cipher Block Chaining mode with PKCS #7 padding and HMAC
///
/// See [RFC7518#Section-5.2](https://tools.ietf.org/html/rfc7518#section-5.2)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AesCbc<Cipher, Digest, KeyLen, TagLen> {
    cipher: PhantomData<Cipher>,
    digest: PhantomData<Digest>,
    key_len: PhantomData<KeyLen>,
    tag_len: PhantomData<TagLen>,
}

impl<Cipher, Digest, KeyLen, TagLen> AesCbc<Cipher, Digest, KeyLen, TagLen>
where
    Cipher: BlockCipher + NewBlockCipher,
{
    const BLOCK_SIZE: usize = <<Cipher as BlockCipher>::BlockSize as Unsigned>::USIZE;
}

// Trait bounds for [`Digest`] taken from: https://github.com/RustCrypto/MACs/issues/114
impl<Cipher, Digest, KeyLen, TagLen> AesCbc<Cipher, Digest, KeyLen, TagLen>
where
    Cipher: BlockCipher
        + NewBlockCipher
        + block_modes::cipher::BlockCipher
        + block_modes::cipher::NewBlockCipher
        + aes_crate::BlockEncrypt
        + aes_crate::BlockDecrypt,
    Digest: Clone + CoreProxy + Default + FixedOutput + Reset,

    Digest::Core: HashMarker + UpdateCore + FixedOutputCore + BufferKindUser<BufferKind = Eager> + Default + Clone,
    <Digest::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<Digest::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    <Digest::Core as OutputSizeUser>::OutputSize: Sub<TagLen, Output = TagLen>,

    KeyLen: ArrayLength<u8> + Shl<B1>,
    TagLen: ArrayLength<u8>,
    Double<KeyLen>: ArrayLength<u8>,
    DigestOutput<Digest>: ArrayLength<u8> + Sub<TagLen, Output = TagLen>,
{
    fn compute_tag(
        key: &Key<Self>,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> crate::Result<Tag<Self>> {
        // The octet string AL is equal to the number of bits in the Additional
        // Authenticated Data A expressed as a 64-bit unsigned big-endian integer.
        //
        // A message Authentication Tag T is computed by applying HMAC to the
        // following data, in order:
        //
        //    the Additional Authenticated Data A,
        //    the Initialization Vector IV,
        //    the ciphertext E computed in the previous step, and
        //    the octet string AL defined above.
        //
        //  The string MAC_KEY is used as the MAC key. We denote the output
        //  of the MAC computed in this step as M. The first T_LEN octets of
        //  M are used as T.
        let mut hmac: Hmac<Digest> =
            Hmac::new_from_slice(&key[..KeyLen::USIZE]).map_err(|_| crate::Error::CipherError { alg: Self::NAME })?;

        hmac.update(associated_data);
        hmac.update(nonce);
        hmac.update(ciphertext);
        hmac.update(&((associated_data.len() as u64) * 8).to_be_bytes());

        Ok(Split::split(hmac.finalize().into_bytes()).0)
    }

    fn cipher(key: &Key<Self>, nonce: &Nonce<Self>) -> crate::Result<AesCbcPkcs7<Cipher>> {
        AesCbcPkcs7::new_from_slices(&key[KeyLen::USIZE..], nonce)
            .map_err(|_| crate::Error::CipherError { alg: Self::NAME })
    }
}

// Trait bounds for [`Digest`] taken from: https://github.com/RustCrypto/MACs/issues/114
impl<Cipher, Digest, KeyLen, TagLen> Aead for AesCbc<Cipher, Digest, KeyLen, TagLen>
where
    Cipher: BlockCipher + NewBlockCipher + aes_crate::BlockEncrypt + aes_crate::BlockDecrypt,
    Digest: CoreProxy + Clone + Default + FixedOutput + Reset,
    Digest::Core: HashMarker + UpdateCore + FixedOutputCore + BufferKindUser<BufferKind = Eager> + Default + Clone,
    <Digest::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<Digest::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
    <Digest::Core as OutputSizeUser>::OutputSize: Sub<TagLen, Output = TagLen>,
    KeyLen: ArrayLength<u8> + Shl<B1>,
    TagLen: ArrayLength<u8>,
    Double<KeyLen>: ArrayLength<u8>,
    DigestOutput<Digest>: ArrayLength<u8> + Sub<TagLen, Output = TagLen>,
{
    type KeyLength = Double<KeyLen>;
    type NonceLength = NonceLength;
    type TagLength = TagLen;

    const NAME: &'static str = "AES-CBC";

    fn encrypt(
        key: &Key<Self>,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut Tag<Self>,
    ) -> crate::Result<()> {
        let padding: usize = Self::padsize(plaintext).map(NonZeroUsize::get).unwrap_or_default();
        let expected: usize = plaintext.len() + padding;

        if expected > ciphertext.len() {
            return Err(crate::Error::BufferSize {
                name: "ciphertext",
                needs: expected,
                has: ciphertext.len(),
            });
        }

        let cipher: AesCbcPkcs7<Cipher> = Self::cipher(key, nonce)?;
        let length: usize = plaintext.len();

        ciphertext[..length].copy_from_slice(plaintext);

        cipher
            .encrypt(ciphertext, length)
            .map_err(|_| crate::Error::CipherError { alg: Self::NAME })?;

        tag.copy_from_slice(&Self::compute_tag(key, nonce, associated_data, ciphertext)?);

        Ok(())
    }

    fn decrypt(
        key: &Key<Self>,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        plaintext: &mut [u8],
        ciphertext: &[u8],
        tag: &Tag<Self>,
    ) -> crate::Result<usize> {
        if ciphertext.len() > plaintext.len() {
            return Err(crate::Error::BufferSize {
                name: "plaintext",
                needs: ciphertext.len(),
                has: plaintext.len(),
            });
        }

        let cipher: AesCbcPkcs7<Cipher> = Self::cipher(key, nonce)?;
        let computed: Tag<Self> = Self::compute_tag(key, nonce, associated_data, ciphertext)?;

        if !bool::from(computed.ct_eq(tag)) {
            return Err(crate::Error::CipherError { alg: Self::NAME });
        }

        plaintext[..ciphertext.len()].copy_from_slice(ciphertext);

        cipher
            .decrypt(plaintext)
            .map_err(|_| crate::Error::CipherError { alg: Self::NAME })
            .map(|output| output.len())
    }

    fn padsize(plaintext: &[u8]) -> Option<NonZeroUsize> {
        NonZeroUsize::new(Self::BLOCK_SIZE - (plaintext.len() % Self::BLOCK_SIZE))
    }
}
