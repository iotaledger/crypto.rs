// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "chacha")]

mod utils;

use crypto::ciphers::chacha::xchacha20poly1305::*;

struct TestVector {
    plaintext: &'static str,
    associated_data: &'static str,
    key: &'static str,
    nonce: &'static str,
    ciphertext: &'static str,
    tag: &'static str,
}

#[test]
fn test_vectors() -> crypto::Result<()> {
    let tvs = &include!("fixtures/xchacha20_poly1305.rs");

    for tv in tvs.iter() {
        let plaintext = hex::decode(tv.plaintext).unwrap();
        let associated_data = hex::decode(tv.associated_data).unwrap();

        let mut key = [0; XCHACHA20POLY1305_KEY_SIZE];
        hex::decode_to_slice(tv.key, &mut key as &mut [u8]).unwrap();
        let mut nonce = [0; XCHACHA20POLY1305_NONCE_SIZE];
        hex::decode_to_slice(tv.nonce, &mut nonce as &mut [u8]).unwrap();

        let expected_ciphertext = hex::decode(tv.ciphertext).unwrap();
        let expected_tag = hex::decode(tv.tag).unwrap();

        let mut ciphertext = vec![0; plaintext.len()];
        let mut tag = [0; XCHACHA20POLY1305_TAG_SIZE];

        encrypt(&mut ciphertext, &mut tag, &plaintext, &key, &nonce, &associated_data)?;
        assert_eq!(expected_ciphertext, ciphertext);
        assert_eq!(expected_tag, tag);

        let mut decrypted_plain_text = vec![0; ciphertext.len()];
        decrypt(
            &mut decrypted_plain_text,
            &ciphertext,
            &key,
            &tag,
            &nonce,
            &associated_data,
        )?;
        assert_eq!(decrypted_plain_text, plaintext);

        let mut corrupted_tag = tag;
        utils::corrupt(&mut corrupted_tag);
        assert!(decrypt(
            &mut decrypted_plain_text,
            &ciphertext,
            &key,
            &corrupted_tag,
            &nonce,
            &associated_data
        )
        .is_err());

        let mut corrupted_nonce = nonce;
        utils::corrupt(&mut corrupted_nonce);
        assert!(decrypt(
            &mut decrypted_plain_text,
            &ciphertext,
            &key,
            &tag,
            &corrupted_nonce,
            &associated_data
        )
        .is_err());

        if !associated_data.is_empty() {
            let mut corrupted_associated_data = associated_data.clone();
            utils::corrupt(&mut corrupted_associated_data);
            assert!(decrypt(
                &mut decrypted_plain_text,
                &ciphertext,
                &key,
                &tag,
                &nonce,
                &corrupted_associated_data
            )
            .is_err());
            assert!(decrypt(
                &mut decrypted_plain_text,
                &ciphertext,
                &key,
                &tag,
                &nonce,
                &utils::fresh::bytestring()
            )
            .is_err());
        } else {
            assert!(decrypt(
                &mut decrypted_plain_text,
                &ciphertext,
                &key,
                &tag,
                &nonce,
                &utils::fresh::non_empty_bytestring()
            )
            .is_err());
        }
    }

    Ok(())
}
