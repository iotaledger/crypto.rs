// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "aes-kw")]

use crypto::aes_kw::{Aes128Kw, Aes192Kw, Aes256Kw, BLOCK};

#[derive(Debug)]
struct TestVector {
    encryption_key: &'static str,
    plaintext: &'static str,
    ciphertext: &'static str,
}

macro_rules! test_aes_kw {
    ($impl:ident, $tvs:expr) => {{
        for tv in $tvs {
            let kek: Vec<u8> = hex::decode(tv.encryption_key).unwrap();
            let ptx: Vec<u8> = hex::decode(tv.plaintext).unwrap();
            let ctx: Vec<u8> = hex::decode(tv.ciphertext).unwrap();

            let mut output: Vec<u8> = vec![0; ptx.len() + BLOCK];
            $impl::new(&kek).wrap_key(&ptx, &mut output).unwrap();
            assert_eq!(output, ctx);

            let mut output: Vec<u8> = vec![0; ctx.len() - BLOCK];
            $impl::new(&kek).unwrap_key(&ctx, &mut output).unwrap();
            assert_eq!(output, ptx);
        }
    }};
}

#[test]
fn test_aes_128_kw() {
    test_aes_kw!(Aes128Kw, &include!("fixtures/aes_128_kw.rs"));
}

#[test]
fn test_aes_192_kw() {
    test_aes_kw!(Aes192Kw, &include!("fixtures/aes_192_kw.rs"));
}

#[test]
fn test_aes_256_kw() {
    test_aes_kw!(Aes256Kw, &include!("fixtures/aes_256_kw.rs"));
}
