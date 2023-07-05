// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "bip39")]

mod utils;

use crypto::keys::bip39::*;
use rand::{rngs::OsRng, RngCore};

struct TestVector {
    wordlist: wordlist::Wordlist<'static>,
    entropy: &'static str,
    mnemonic: &'static str,
    passphrase: &'static str,
    seed: &'static str,
}

#[test]
fn test_separator() {
    use unicode_normalization::{is_nfkd, UnicodeNormalization};
    let s = "　";
    assert!(!is_nfkd(s));
    let s: String = s.nfkd().collect();
    assert_eq!(1, s.chars().count());
    assert_eq!(Some(' '), s.chars().next());
}

#[test]
fn test_vectors() {
    #[cfg(feature = "bip39-en")]
    {
        let tvs_en = include!("fixtures/bip39_en.rs");
        run_test_vectors(&tvs_en);
    }
    #[cfg(feature = "bip39-jp")]
    {
        let tvs_jp = include!("fixtures/bip39_jp.rs");
        run_test_vectors(&tvs_jp);
    }
}

fn run_test_vectors(tvs: &[TestVector]) {
    for tv in tvs.iter() {
        let entropy = hex::decode(tv.entropy).unwrap();
        let mnemonic = hex::decode(tv.mnemonic).unwrap();
        let mnemonic = Mnemonic::from(core::str::from_utf8(&mnemonic).unwrap().to_string());

        assert_eq!(
            wordlist::encode(&entropy, &tv.wordlist).unwrap().as_ref(),
            mnemonic.as_ref()
        );

        assert_eq!(*wordlist::decode(&mnemonic, &tv.wordlist).unwrap(), entropy);

        let passphrase = hex::decode(tv.passphrase).unwrap();
        let passphrase = Passphrase::from(core::str::from_utf8(&passphrase).unwrap().to_string());
        let mut expected_seed = [0; 64];
        hex::decode_to_slice(tv.seed, &mut expected_seed).unwrap();

        let seed = mnemonic_to_seed(&mnemonic, &passphrase);
        assert_eq!(seed.as_ref(), &expected_seed);
    }
}

const ALL_WORDLISTS: &[wordlist::Wordlist<'static>] = &[
    #[cfg(feature = "bip39-en")]
    wordlist::ENGLISH,
    #[cfg(feature = "bip39-jp")]
    wordlist::JAPANESE,
];

#[test]
fn test_wordlist_new() {
    for ws in ALL_WORDLISTS {
        let _ = wordlist::Wordlist::new(ws.separator(), ws.words()).unwrap();
    }
}

#[test]
fn test_from_words() {
    let words = &[
        "sand", "luggage", "rack", "used", "middle", "crater", "deal", "scare", "high", "ring", "swim", "fish",
    ];
    let _: Mnemonic = words.into();
}

#[test]
fn test_wordlist_codec() {
    for _ in 0..1000 {
        let mut data = vec![0; 32 * (4 + rand::random::<usize>() % 5) / 8];
        OsRng.fill_bytes(&mut data);

        for ws in ALL_WORDLISTS {
            let ms = wordlist::encode(&data, ws).unwrap();
            assert_eq!(*wordlist::decode(&ms, ws).unwrap(), data);
            assert_eq!(wordlist::verify(&ms, ws), Ok(()));
        }
    }
}

#[test]
fn test_mnemonic_phrase_additional_whitespace() {
    // additional whitespace at the beginning
    assert_eq!(Error::NoSuchWord("".to_string()),
        wordlist::decode(" sand luggage rack used middle crater deal scare high ring swim fish use then video visa can foot clog base quality all elephant retreat".try_into().unwrap(), &wordlist::ENGLISH).unwrap_err(),
    );
    // additional whitespace in between
    assert_eq!(Error::NoSuchWord("".to_string()),
        wordlist::decode("sand  luggage rack used middle crater deal scare high ring swim fish use then video visa can foot clog base quality all elephant retreat".try_into().unwrap(), &wordlist::ENGLISH).unwrap_err(),
    );
    // additional whitespace inside word
    assert_eq!(Error::NoSuchWord("lug".to_string()),
        wordlist::decode("sand lug gage rack used middle crater deal scare high ring swim fish use then video visa can foot clog base quality all elephant retreat".try_into().unwrap(), &wordlist::ENGLISH).unwrap_err(),
    );
    // additional whitespace at the end
    assert_eq!(Error::NoSuchWord("".to_string()),
        wordlist::decode("sand luggage rack used middle crater deal scare high ring swim fish use then video visa can foot clog base quality all elephant retreat ".try_into().unwrap(), &wordlist::ENGLISH).unwrap_err(),
    );
}
