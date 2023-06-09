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
    let tvs = include!("fixtures/bip39.rs");

    for tv in tvs.iter() {
        let entropy = hex::decode(tv.entropy).unwrap();
        let mnemonic = hex::decode(tv.mnemonic).unwrap();
        let mnemonic = Mnemonic::from(core::str::from_utf8(&mnemonic).unwrap().to_string());
        let mnemonic: MnemonicRef = (&mnemonic).into();

        assert_eq!(wordlist::encode(&entropy, &tv.wordlist).unwrap().as_ref(), &*mnemonic);

        assert_eq!(*wordlist::decode(mnemonic, &tv.wordlist).unwrap(), entropy);

        let passphrase = hex::decode(tv.passphrase).unwrap();
        let passphrase = Passphrase::from(core::str::from_utf8(&passphrase).unwrap().to_string());
        let passphrase: PassphraseRef = (&passphrase).into();
        let mut expected_seed = [0; 64];
        hex::decode_to_slice(tv.seed, &mut expected_seed).unwrap();

        let mut seed = Seed::null();
        mnemonic_to_seed(mnemonic, passphrase, &mut seed);
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
fn test_wordlist_codec() {
    for _ in 0..1000 {
        let mut data = vec![0; 32 * (4 + rand::random::<usize>() % 5) / 8];
        OsRng.fill_bytes(&mut data);

        for ws in ALL_WORDLISTS {
            let ms = wordlist::encode(&data, ws).unwrap();
            assert_eq!(*wordlist::decode((&ms).into(), ws).unwrap(), data);
            assert_eq!(wordlist::verify((&ms).into(), ws), Ok(()));
        }
    }
}

#[test]
fn test_mnemonic_phrase_additional_whitespace() {
    // additional whitespace at the beginning
    assert!(
        wordlist::decode(" sand luggage rack used middle crater deal scare high ring swim fish use then video visa can foot clog base quality all elephant retreat".try_into().unwrap(), &wordlist::ENGLISH).is_err(),
    );
    // additional whitespace in between
    assert!(
        wordlist::decode("sand  luggage rack used middle crater deal scare high ring swim fish use then video visa can foot clog base quality all elephant retreat".try_into().unwrap(), &wordlist::ENGLISH).is_err(),
    );
    // additional whitespace at the end
    assert!(
        wordlist::decode("sand luggage rack used middle crater deal scare high ring swim fish use then video visa can foot clog base quality all elephant retreat ".try_into().unwrap(), &wordlist::ENGLISH).is_err(),
    );
}

// #[test]
// fn test_wordlist_codec_different_data_different_encodings() {
// for _ in 0..1000 {
// let mut data = vec![0; 32 * (4 + rand::random::<usize>() % 5) / 8];
// OsRng.fill_bytes(&mut data);
//
// let mut corrupted_data = data.clone();
// utils::corrupt(&mut corrupted_data);
//
// let ws = choose_wordlist();
// let ms = wordlist::encode(&data, &ws).unwrap();
//
// assert_ne!(ms, wordlist::encode(&corrupted_data, ws).unwrap());
// }
// }
//
// #[test]
// #[allow(non_snake_case)]
// fn test_wordlist_codec_error_detection() {
// for ENT in &[128, 160, 192, 224, 256] {
// let mut false_positives = 0;
// let CS = ENT / 32;
// let N = 1000;
// let acceptable_false_positives = 2 * N / (1 << CS);
// for _ in 0..N {
// let mut data = vec![0; ENT / 8];
// OsRng.fill_bytes(&mut data);
//
// let ws = choose_wordlist();
// let ms = wordlist::encode(&data, ws).unwrap();
//
// let mut wrong_word = ms.clone();
// while wrong_word == ms {
// wrong_word = ms
// .split(ws.separator)
// .map(|w| {
// if rand::random::<usize>() % 8 == 0 {
// ws.words[rand::random::<usize>() % 2048].to_string()
// } else {
// w.to_string()
// }
// })
// .collect::<Vec<String>>()
// .join(ws.separator);
// }
//
// if wordlist::decode(&wrong_word, ws) != Err(wordlist::Error::ChecksumMismatch) {
// false_positives += 1;
// }
// }
//
// assert!(false_positives <= acceptable_false_positives);
// }
// }
