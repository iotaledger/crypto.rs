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
    BadWordlistWord(String),
    UnsortedWordlist,
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

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Mnemonic(String);

impl From<String> for Mnemonic {
    fn from(unnormalized_mnemonic: String) -> Self {
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

impl<'a> Deref for PassphraseRef<'a> {
    type Target = str;
    fn deref(&self) -> &str {
        self.0
    }
}

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

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Passphrase(String);

impl From<String> for Passphrase {
    fn from(unnormalized_passphrase: String) -> Self {
        Self(unnormalized_passphrase.chars().nfkd().collect())
    }
}

impl<'a> From<&'a Passphrase> for PassphraseRef<'a> {
    fn from(passphrase_ref: &'a Passphrase) -> Self {
        Self(&passphrase_ref.0)
    }
}

impl AsRef<str> for Passphrase {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Seed([u8; 64]);

impl AsRef<[u8; 64]> for Seed {
    fn as_ref(&self) -> &[u8; 64] {
        &self.0
    }
}

impl Seed {
    pub fn null() -> Self {
        Self([0_u8; 64])
    }
}

pub fn mnemonic_to_seed(m: MnemonicRef, p: PassphraseRef, s: &mut Seed) {
    let mut salt = [b"mnemonic", p.0.as_bytes()].concat();
    const ROUNDS: core::num::NonZeroU32 = unsafe { core::num::NonZeroU32::new_unchecked(2048) };
    crate::keys::pbkdf::PBKDF2_HMAC_SHA512(m.as_bytes(), &salt, ROUNDS, &mut s.0);
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

    impl<'a> Wordlist<'a> {
        const fn new_unchecked(separator: char, words: &'a [&'a str; 2048]) -> Self {
            Self { words, separator }
        }

        pub fn new(separator: char, words: &'a [&'a str; 2048]) -> Result<Self, Error> {
            // normalize separator char
            let s = String::from(separator);
            let mut s_chars = s.nfkd();

            if let Some(separator) = s_chars.next() {
                if s_chars.next().is_none() {
                    // each word is normalized and without separator
                    words.iter().try_for_each(|word| {
                        if is_nfkd(word) && !word.contains(separator) {
                            Ok(())
                        } else {
                            Err(Error::BadWordlistWord(word.to_string()))
                        }
                    })?;

                    // all words are unique, but not necessarily sorted
                    let mut words_set = words.to_vec();
                    words_set.sort();
                    if iterator_sorted::is_unique_sorted(words_set.into_iter()) {
                        Ok(Self { words, separator })
                    } else {
                        Err(Error::UnsortedWordlist)
                    }
                } else {
                    Err(Error::BadSeparator)
                }
            } else {
                Err(Error::BadSeparator)
            }
        }

        pub fn separator(&self) -> char {
            self.separator
        }

        pub fn words(&self) -> &'a [&'a str; 2048] {
            self.words
        }

        pub fn lookup(&self, word: &str) -> Option<usize> {
            self.words.iter().position(|w| *w == word)
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
        match secret_entropy.len() {
            16 | 20 | 24 | 28 | 32 => {}
            _ => return Err(Error::InvalidEntropyCount(secret_entropy.len() * 8)),
        }

        let mut checksum = [0; 32];
        crate::hashes::sha::SHA256(secret_entropy, &mut checksum);

        let (_, leftover_bits, mut capacity, words) = secret_entropy.iter().chain(Some(&checksum[0])).fold(
            (0_u32, 0, 0_usize, Vec::new()),
            |(mut acc, mut bits, mut mnemonic_capacity, mut mnemonic_words), entropy_byte| {
                const MASK: u32 = (1_u32 << 11) - 1;
                acc = (acc << 8) | (*entropy_byte as u32);
                bits += 8;
                if bits >= 11 {
                    debug_assert!(bits <= 18);
                    bits -= 11;
                    let idx = (MASK & (acc >> bits)) as usize;
                    let word = wordlist.words[idx];
                    mnemonic_words.push(word);
                    mnemonic_capacity += word.as_bytes().len();
                }
                debug_assert!(bits <= 10);
                (acc, bits, mnemonic_capacity, mnemonic_words)
            },
        );
        // leftover_bits here represent the number of left-over low bits in checksum byte
        debug_assert_eq!(8, secret_entropy.len() / 4 + leftover_bits as usize);

        if !words.is_empty() {
            capacity += (words.len() - 1) * wordlist.separator.encode_utf8(&mut [0_u8; 4]).len();
        }

        // allocate the exact number of bytes required for secret mnemonic to avoid reallocations and potential secret
        // leakage
        let mut mnemonic = String::with_capacity(capacity);
        words.into_iter().for_each(|word| {
            if !mnemonic.is_empty() {
                mnemonic.push(wordlist.separator);
            }
            mnemonic.push_str(word);
        });
        debug_assert_eq!(capacity, mnemonic.as_bytes().len());

        Ok(Mnemonic(mnemonic))
    }

    /// Decode and compare the checksum given a mnemonic sentence and the wordlist used in the
    /// generation process.
    ///
    /// Be aware that the error detection has a noticable rate of false positives. Given CS
    /// checksum bits (CS := ENT / 32) the expected rate of false positives are one in 2^CS. For
    /// example given 128 bit entropy that's 1 in 16.
    pub fn decode(mnemonic: MnemonicRef, wordlist: &Wordlist) -> Result<Zeroizing<Vec<u8>>, Error> {
        // allocate maximal entropy capacity of 32 bytes to avoid reallocations
        let mut entropy = Zeroizing::new(Vec::with_capacity(32));

        let (checksum_acc, checksum_bits) =
            mnemonic
                .split(wordlist.separator)
                .try_fold((0_u32, 0), |(mut acc, mut bits), word| {
                    let idx = wordlist
                        .lookup(word)
                        .ok_or_else(|| Error::NoSuchWord(word.to_string()))? as u32;

                    acc = (acc << 11) | idx;
                    bits += 11;

                    while bits > 8 {
                        debug_assert!(bits <= 19);
                        if entropy.len() == entropy.capacity() {
                            return Err(Error::InvalidEntropyCount(32));
                        }
                        bits -= 8;
                        entropy.push((acc >> bits) as u8);
                    }

                    debug_assert!(bits <= 8);
                    Ok((acc, bits))
                })?;
        // checksum_bits here represent the number of high bits in checksum byte
        match entropy.len() {
            16 | 20 | 24 | 28 | 32 => {
                debug_assert_eq!(entropy.len() / 4, checksum_bits as usize);
            }
            _ => {
                return Err(Error::InvalidEntropyCount(entropy.len() * 8 + checksum_bits as usize));
            }
        }

        let mut checksum = [0; 32];
        crate::hashes::sha::SHA256(&entropy, &mut checksum);
        if (checksum_acc & ((1 << checksum_bits) - 1)) as u8 != checksum[0] >> (8 - checksum_bits) {
            return Err(Error::ChecksumMismatch);
        }

        Ok(entropy)
    }

    pub fn verify(mnemonic: MnemonicRef, wordlist: &Wordlist) -> Result<(), Error> {
        decode(mnemonic, wordlist).map(|_| ())
    }
}

#[cfg(feature = "bip39-en")]
#[test]
fn test_encode_decode() {
    fn inc(e: u8, i: usize) -> u8 {
        ((e as usize + 0x9b17f203) * (i + 0x4792a0e2) + 7) as u8
    }

    let mut entropy = [0_u8; 32];
    for _ in 0..5 {
        entropy
            .iter_mut()
            .enumerate()
            .for_each(|(i, e)| *e = e.wrapping_add(inc(*e, i)));

        for i in 4..9 {
            let n = 4 * i;

            let mnemonic = wordlist::encode(&entropy[..n], &wordlist::ENGLISH).unwrap();
            let decoded_entropy = wordlist::decode((&mnemonic).into(), &wordlist::ENGLISH).unwrap();
            assert_eq!(&entropy[..n], &decoded_entropy[..]);
        }
    }
}
