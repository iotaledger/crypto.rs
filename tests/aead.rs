// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(any(feature = "aes", feature = "chacha"))]

mod utils;

use crypto::ciphers::traits::Aead;

struct TestVector {
    key: &'static str,
    nonce: &'static str,
    associated_data: &'static str,
    plaintext: &'static str,
    ciphertext: &'static str,
    tag: &'static str,
}

fn test_aead_one<A: Aead>(tv: &TestVector) -> crypto::Result<()> {
    let key = hex::decode(tv.key).unwrap();
    let nonce = hex::decode(tv.nonce).unwrap();
    let aad = hex::decode(tv.associated_data).unwrap();
    let ptx = hex::decode(tv.plaintext).unwrap();
    let mut tag = vec![0u8; A::TAG_LENGTH];

    let expected_ctx = hex::decode(tv.ciphertext).unwrap();
    let expected_tag = hex::decode(tv.tag).unwrap();

    let mut ctx = vec![0; ptx.len()];
    A::try_encrypt(&key, &nonce, &aad, &ptx, &mut ctx, &mut tag)?;

    assert_eq!(&ctx[..], &expected_ctx[..]);
    assert_eq!(&tag[..], &expected_tag[..]);

    let mut out = vec![0; ctx.len()];
    let len = A::try_decrypt(&key, &nonce, &aad, &mut out, &ctx, &tag)?;

    assert_eq!(&out[..len], &ptx[..]);

    let mut corrupted_tag = tag.clone();
    utils::corrupt(&mut corrupted_tag);
    assert!(A::try_decrypt(&key, &nonce, &aad, &mut out, &ctx, &corrupted_tag).is_err());

    let mut corrupted_nonce = nonce.clone();
    utils::corrupt(&mut corrupted_nonce);
    assert!(A::try_decrypt(&key, &corrupted_nonce, &aad, &mut out, &ctx, &tag).is_err());

    if aad.is_empty() {
        assert!(A::try_decrypt(
            &key,
            &nonce,
            &utils::fresh::non_empty_bytestring(),
            &mut out,
            &ctx,
            &tag,
        )
        .is_err());
    } else {
        let mut corrupted_associated_data = aad;
        utils::corrupt(&mut corrupted_associated_data);
        assert!(A::try_decrypt(&key, &nonce, &corrupted_associated_data, &mut out, &ctx, &tag).is_err());
        assert!(A::try_decrypt(&key, &nonce, &utils::fresh::bytestring(), &mut out, &ctx, &tag).is_err());
    }

    Ok(())
}

fn test_aead_all<A: Aead>(tvs: &[TestVector]) -> crypto::Result<()> {
    for tv in tvs {
        test_aead_one::<A>(tv)?;
    }

    Ok(())
}

#[cfg(feature = "aes")]
mod aes {
    use super::{test_aead_all, TestVector};
    use crypto::ciphers::aes::Aes256Gcm;

    #[test]
    fn test_vectors_aes_256_gcm() {
        test_aead_all::<Aes256Gcm>(&include!("fixtures/aes_256_gcm.rs")).unwrap();
    }
}

#[cfg(feature = "chacha")]
mod chacha {
    use super::{test_aead_all, TestVector};
    use crypto::ciphers::chacha::XChaCha20Poly1305;

    #[test]
    fn test_vectors_xchacha20_poly1305() {
        test_aead_all::<XChaCha20Poly1305>(&include!("fixtures/xchacha20_poly1305.rs")).unwrap();
    }
}
