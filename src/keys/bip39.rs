// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// https://en.bitcoin.it/wiki/BIP_0039

// https://doc.rust-lang.org/std/primitive.str.html
// "String slices are always valid UTF-8."
type Mnemonic = str;
type Passphrase = str;
type Seed = [u8; 64];

extern crate alloc;
use alloc::string::{String, ToString};

use unicode_normalization::UnicodeNormalization;

pub fn mnemonic_to_seed(m: &Mnemonic, p: &Passphrase, s: &mut Seed) {
    let m = m.chars().nfkd().collect::<String>();

    let mut salt = String::with_capacity("mnemonic".len() + p.len());
    salt.push_str("mnemonic");
    salt.push_str(p);
    let salt = salt.nfkd().collect::<String>();

    // unwrapping here is safe since PBKDF2_HMAC_SHA512 is only expected to fail when iteration
    // count is zero
    crate::keys::pbkdf::PBKDF2_HMAC_SHA512(m.as_bytes(), salt.as_bytes(), 2048, s).unwrap();
}

pub mod wordlist {
    use super::*;
    use alloc::vec::Vec;

    pub struct Wordlist<'a> {
        pub words: &'a [&'a str; 2048],
        pub separator: &'a str,
    }

    #[cfg(feature = "bip39-en")]
    #[cfg_attr(docsrs, doc(cfg(feature = "bip39-en")))]
    include!("bip39.en.rs");

    #[cfg(feature = "bip39-jp")]
    #[cfg_attr(docsrs, doc(cfg(feature = "bip39-jp")))]
    include!("bip39.jp.rs");

    #[derive(Debug, PartialEq)]
    pub enum Error {
        InvalidEntropyCount(usize),
        NoSuchWord(String),
        ChecksumMismatch,
    }

    const fn cs(ent: usize) -> usize {
        ent / 32
    }

    /// Encode the given bytestring as a mnemonic sentence using the specified wordlist.
    /// Only bytestrings of length 128, 160, 192, 224 and 256 bits are accepted, and this is the
    /// only expected error case.
    ///
    /// Currently the Japanese language is not supported, or at least the implementation is not
    /// generating the expected sentences compared to our test vectors. Use at your own risk!
    #[allow(non_snake_case)]
    #[allow(clippy::many_single_char_names)]
    pub fn encode(data: &[u8], wordlist: &Wordlist) -> Result<String, Error> {
        let ENT = data.len() * 8;

        if ENT != 128 && ENT != 160 && ENT != 192 && ENT != 224 && ENT != 256 {
            return Err(Error::InvalidEntropyCount(ENT));
        }

        let mut CS = [0; 32];
        crate::hashes::sha::SHA256(data, &mut CS);

        let mut ms = None;

        let b = |i: usize| {
            if i < data.len() {
                Some(data[i] as usize)
            } else if i - data.len() < CS.len() {
                Some(CS[i - data.len()] as usize)
            } else {
                None
            }
        };

        let mut i = 0;
        loop {
            if i == ENT + cs(ENT) {
                return Ok(ms.unwrap());
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
                    _ => return Ok(ms.unwrap()),
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
                    _ => return Ok(ms.unwrap()),
                }
            };

            match ms {
                None => ms = Some(wordlist.words[idx].to_string()),
                Some(ref mut ms) => {
                    ms.push_str(wordlist.separator);
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
    pub fn decode(ms: &str, wordlist: &Wordlist) -> Result<Vec<u8>, Error> {
        let mut data = Vec::new();
        let mut acc = 0;
        let mut i = 0;
        let ms = ms.chars().nfkd().collect::<String>();
        for ref w in ms.split_whitespace() {
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

        fn sub_whole_byte_case(acc: usize, data: Vec<u8>, ent: usize) -> Result<Vec<u8>, Error> {
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

    pub fn verify(ms: &str, wordlist: &Wordlist) -> Result<(), Error> {
        decode(ms, wordlist).map(|_| ())
    }
}
