// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "aes")]

use crypto::ciphers::aes::AES_256_GCM;

struct TestVector {
    key: &'static str,
    iv: &'static str,
    associated_data: &'static str,
    plaintext: &'static str,
    ciphertext: &'static str,
    tag: &'static str,
}

#[test]
fn test_vectors_aes_256_gcm() -> crypto::Result<()> {
    let tvs = include!("fixtures/aes_256_gcm.rs");

    for tv in tvs.iter() {
        let mut key = [0; AES_256_GCM::KEY_LENGTH];
        hex::decode_to_slice(tv.key, &mut key as &mut [u8]).unwrap();

        let mut iv = [0; AES_256_GCM::IV_LENGTH];
        hex::decode_to_slice(tv.iv, &mut iv as &mut [u8]).unwrap();

        let ad = hex::decode(tv.associated_data).unwrap();
        let pt = hex::decode(tv.plaintext).unwrap();
        let expected_ct = hex::decode(tv.ciphertext).unwrap();

        let mut expected_tag = [0; AES_256_GCM::TAG_LENGTH];
        hex::decode_to_slice(tv.tag, &mut expected_tag as &mut [u8]).unwrap();

        let mut ct = vec![0; pt.len()];
        let mut tag = [0; AES_256_GCM::TAG_LENGTH];
        AES_256_GCM::encrypt(&key, &iv, &ad, &pt, &mut ct, &mut tag)?;
        assert_eq!(ct, expected_ct);
        assert_eq!(tag, expected_tag);

        let mut decrypted_plain_text = vec![0; ct.len()];
        AES_256_GCM::decrypt(&key, &iv, &ad, &tag, &ct, &mut decrypted_plain_text)?;
        assert_eq!(decrypted_plain_text, pt);
    }

    Ok(())
}
