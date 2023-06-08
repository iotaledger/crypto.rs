// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// https://en.bitcoin.it/wiki/BIP_0039

// https://doc.rust-lang.org/std/primitive.str.html
// "String slices are always valid UTF-8."

use alloc::string::{String, ToString};
use core::convert::TryFrom;
use core::ops::Deref;

use unicode_normalization::{is_nfkd, UnicodeNormalization};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidEntropyCount(usize),
    NoSuchWord(String),
    ChecksumMismatch,
    UnnormalizedMnemonic,
    UnnormalizedPassphrase,
    BadWordlist,
    BadSeparator,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MnemonicRef<'a>(&'a str);

impl<'a> Deref for MnemonicRef<'a> {
    type Target = str;
    fn deref(&self) -> &str {
        self.0
    }
}

impl<'a> TryFrom<&'a str> for MnemonicRef<'a> {
    type Error = Error;
    fn try_from(mnemonic_str: &'a str) -> Result<Self, Error> {
        if is_nfkd(mnemonic_str) {
            Ok(MnemonicRef(mnemonic_str))
        } else {
            Err(Error::UnnormalizedMnemonic)
        }
    }
}

impl<'a> PartialEq<str> for MnemonicRef<'a> {
    fn eq(&self, other: &str) -> bool {
        self.0.eq(other)
    }
}

#[derive(ZeroizeOnDrop)]
pub struct Mnemonic(String);

impl From<&str> for Mnemonic {
    fn from(unnormalized_mnemonic: &str) -> Self {
        Self(unnormalized_mnemonic.chars().nfkd().collect())
    }
}

impl<'a> From<&'a Mnemonic> for MnemonicRef<'a> {
    fn from(mnemonic_ref: &'a Mnemonic) -> Self {
        Self(&mnemonic_ref.0)
    }
}

impl AsRef<str> for Mnemonic {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PassphraseRef<'a>(&'a str);

impl<'a> TryFrom<&'a str> for PassphraseRef<'a> {
    type Error = Error;
    fn try_from(passphrase_str: &'a str) -> Result<Self, Error> {
        if is_nfkd(passphrase_str) {
            Ok(PassphraseRef(passphrase_str))
        } else {
            Err(Error::UnnormalizedPassphrase)
        }
    }
}

#[derive(ZeroizeOnDrop)]
pub struct Passphrase(String);

impl<'a> Deref for PassphraseRef<'a> {
    type Target = str;
    fn deref(&self) -> &str {
        self.0
    }
}

impl From<&str> for Passphrase {
    fn from(unnormalized_passphrase: &str) -> Self {
        Self(unnormalized_passphrase.chars().nfkd().collect())
    }
}

impl<'a> From<&'a Passphrase> for PassphraseRef<'a> {
    fn from(passphrase_ref: &'a Passphrase) -> Self {
        Self(&passphrase_ref.0)
    }
}

#[derive(Clone, ZeroizeOnDrop)]
pub struct Seed([u8; 64]);

impl AsRef<[u8; 64]> for Seed {
    fn as_ref(&self) -> &[u8; 64] {
        &self.0
    }
}

impl Default for Seed {
    fn default() -> Self {
        Self([0_u8; 64])
    }
}

pub fn mnemonic_to_seed(m: MnemonicRef, p: PassphraseRef, s: &mut Seed) {
    let mut salt = String::with_capacity("mnemonic".len() + p.len());
    salt.push_str("mnemonic");
    salt.push_str(p.0);

    const ROUNDS: core::num::NonZeroU32 = unsafe { core::num::NonZeroU32::new_unchecked(2048) };
    crate::keys::pbkdf::PBKDF2_HMAC_SHA512(m.as_bytes(), salt.as_bytes(), ROUNDS, &mut s.0);
    salt.zeroize();
}

pub mod wordlist {
    use alloc::vec::Vec;

    use super::*;

    pub struct Wordlist<'a> {
        words: &'a [&'a str; 2048],
        separator: char,
    }

    #[cfg(feature = "bip39-en")]
    #[cfg_attr(docsrs, doc(cfg(feature = "bip39-en")))]
    include!("bip39.en.rs");

    #[cfg(feature = "bip39-jp")]
    #[cfg_attr(docsrs, doc(cfg(feature = "bip39-jp")))]
    include!("bip39.jp.rs");

    const fn cs(ent: usize) -> usize {
        ent / 32
    }

    impl<'a> Wordlist<'a> {
        // TODO: should it be pub?
        const fn new_unchecked(separator: char, words: &'a [&'a str; 2048]) -> Self {
            Self { words, separator }
        }

        pub fn new(separator: char, words: &'a [&'a str; 2048]) -> Result<Self, Error> {
            // normalize separator char
            let mut s = String::new();
            s.push(separator);
            let s: String = s.nfkd().collect();
            let mut s_chars = s.chars();

            if let Some(separator) = s_chars.next() {
                if s_chars.next().is_none() {
                    // each word is normalized and without separator
                    words.iter().try_for_each(|word| {
                        if is_nfkd(word) && !word.contains(separator) {
                            Ok(())
                        } else {
                            Err(Error::BadWordlist)
                        }
                    })?;
                    Ok(Self { words, separator })
                } else {
                    Err(Error::BadSeparator)
                }
            } else {
                Err(Error::BadSeparator)
            }
        }
    }

    /// Encode the given bytestring as a mnemonic sentence using the specified wordlist.
    /// Only bytestrings of length 128, 160, 192, 224 and 256 bits are accepted, and this is the
    /// only expected error case.
    ///
    /// Currently the Japanese language is not supported, or at least the implementation is not
    /// generating the expected sentences compared to our test vectors. Use at your own risk!
    #[allow(non_snake_case)]
    #[allow(clippy::many_single_char_names)]
    pub fn encode(secret_entropy: &[u8], wordlist: &Wordlist) -> Result<Mnemonic, Error> {
        let ENT = secret_entropy.len() * 8;

        if ENT != 128 && ENT != 160 && ENT != 192 && ENT != 224 && ENT != 256 {
            return Err(Error::InvalidEntropyCount(ENT));
        }

        let mut CS = [0; 32];
        crate::hashes::sha::SHA256(secret_entropy, &mut CS);

        let mut ms = None;

        let b = |i: usize| {
            if i < secret_entropy.len() {
                Some(secret_entropy[i] as usize)
            } else if i - secret_entropy.len() < CS.len() {
                Some(CS[i - secret_entropy.len()] as usize)
            } else {
                None
            }
        };

        let mut i = 0;
        loop {
            if i == ENT + cs(ENT) {
                return Ok(Mnemonic(ms.unwrap()));
            }

            let k = i / 8;
            let r = i % 8;
            let idx = if 16 - r > 11 {
                match (b(k), b(k + 1)) {
                    (Some(b0), Some(b1)) => {
                        let x = 11 - (8 - r);
                        let mut y = (b0 & ((1 << (8 - r)) - 1)) << x;
                        y |= b1 >> (8 - x);
                        y
                    }
                    _ => return Ok(Mnemonic(ms.unwrap())),
                }
            } else {
                match (b(k), b(k + 1), b(k + 2)) {
                    (Some(b0), Some(b1), Some(b2)) => {
                        let x = 11 - 8 - (8 - r);
                        let mut y = (b0 & ((1 << (8 - r)) - 1)) << (8 + x);
                        y |= b1 << x;
                        y |= b2 >> (8 - x);
                        y
                    }
                    _ => return Ok(Mnemonic(ms.unwrap())),
                }
            };

            match ms {
                None => ms = Some(wordlist.words[idx].to_string()),
                Some(ref mut ms) => {
                    ms.push(wordlist.separator);
                    ms.push_str(wordlist.words[idx]);
                }
            }

            i += 11;
        }
    }

    /// Decode and compare the checksum given a mnemonic sentence and the wordlist used in the
    /// generation process.
    ///
    /// Be aware that the error detection has a noticable rate of false positives. Given CS
    /// checksum bits (CS := ENT / 32) the expected rate of false positives are one in 2^CS. For
    /// example given 128 bit entropy that's 1 in 16.
    #[allow(non_snake_case)]
    pub fn decode(mnemonic: MnemonicRef, wordlist: &Wordlist) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut data = Zeroizing::new(Vec::new());
        let mut acc = 0;
        let mut i = 0;

        for ref w in mnemonic.split(wordlist.separator) {
            match wordlist.words.iter().position(|v| v == w) {
                None => return Err(Error::NoSuchWord(w.to_string())),
                Some(idx) => {
                    let r = i % 8;
                    acc <<= 8 - r;
                    acc |= idx >> (11 - (8 - r));
                    data.push(acc as u8);
                    if r + 11 < 16 {
                        acc = idx & ((1 << (11 - (8 - r))) - 1);
                    } else {
                        acc = (idx & ((1 << (11 - (8 - r))) - 1)) >> (11 - 8 - (8 - r));
                        data.push(acc as u8);
                        acc = idx & ((1 << (11 - 8 - (8 - r))) - 1);
                    }

                    i += 11;
                }
            }
        }

        fn sub_whole_byte_case(acc: usize, data: Zeroizing<Vec<u8>>, ent: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
            let mut CS = [0; 32];
            crate::hashes::sha::SHA256(&data, &mut CS);
            if (acc as u8) == CS[0] >> (8 - cs(ent)) {
                Ok(data)
            } else {
                Err(Error::ChecksumMismatch)
            }
        }

        if i == 128 + cs(128) {
            sub_whole_byte_case(acc, data, 128)
        } else if i == 160 + cs(160) {
            sub_whole_byte_case(acc, data, 160)
        } else if i == 192 + cs(192) {
            sub_whole_byte_case(acc, data, 192)
        } else if i == 224 + cs(224) {
            sub_whole_byte_case(acc, data, 224)
        } else if i == 256 + cs(256) {
            let mut CS = [0; 32];
            crate::hashes::sha::SHA256(&data[..32], &mut CS);
            if data[32] == CS[0] {
                data.truncate(32);
                Ok(data)
            } else {
                Err(Error::ChecksumMismatch)
            }
        } else {
            Err(Error::InvalidEntropyCount(i))
        }
    }

    pub fn verify(ms: MnemonicRef, wordlist: &Wordlist) -> Result<(), Error> {
        decode(ms, wordlist).map(|_| ())
    }
}
