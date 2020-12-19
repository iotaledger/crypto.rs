// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "aes-kw")]

use crypto::aes_kw::{Aes128, Aes192, Aes256, AesKeyWrap, BLOCK};

static AES_128_TVS: &'static [TestVector] = &include!("fixtures/aes_128_kw.rs");
static AES_192_TVS: &'static [TestVector] = &include!("fixtures/aes_192_kw.rs");
static AES_256_TVS: &'static [TestVector] = &include!("fixtures/aes_256_kw.rs");

#[derive(Debug)]
struct TestVector {
    encryption_key: &'static str,
    plaintext: &'static str,
    ciphertext: &'static str,
}

fn test_aes_kw<T: AesKeyWrap>(tvs: &[TestVector]) {
    for tv in tvs {
        let kek: Vec<u8> = hex::decode(tv.encryption_key).unwrap();
        let ptx: Vec<u8> = hex::decode(tv.plaintext).unwrap();
        let ctx: Vec<u8> = hex::decode(tv.ciphertext).unwrap();

        let mut ciphertext: Vec<u8> = vec![0; BLOCK + ptx.len()];
        T::wrap_key(&kek, &ptx, &mut ciphertext).unwrap();
        assert_eq!(ciphertext, ctx);

        let mut plaintext: Vec<u8> = vec![0; ctx.len() - BLOCK];
        T::unwrap_key(&kek, &ciphertext, &mut plaintext).unwrap();
        assert_eq!(plaintext, ptx);
    }
}

#[test]
fn test_aes_128_kw() {
    test_aes_kw::<Aes128>(AES_128_TVS);
}

#[test]
fn test_aes_192_kw() {
    test_aes_kw::<Aes192>(AES_192_TVS);
}

#[test]
fn test_aes_256_kw() {
    test_aes_kw::<Aes256>(AES_256_TVS);
}
