// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "wots_deprecated_do_not_use")]
#![allow(deprecated)]

use crypto::{
    hashes::sponge::kerl::Kerl,
    keys::ternary::{
        seed::Seed,
        wots::{sponge::WotsSpongePrivateKeyGeneratorBuilder, WotsSecurityLevel},
        PrivateKeyGenerator,
    },
    signatures::ternary::{
        wots::{normalize, WotsPrivateKey},
        PrivateKey, PublicKey, RecoverableSignature, Signature,
    },
};

use bee_ternary::{T1B1Buf, TryteBuf};

use std::{
    fs::File,
    io::{prelude::*, BufReader},
    str::FromStr,
};

#[test]
fn wots_generate_n_addresses_for_seed() {
    let reader = BufReader::new(File::open("tests/fixtures/wots/generateNAddressesForSeed.txt").unwrap());

    for line in reader.lines() {
        let hashes = line.unwrap().split(",").map(|s| s.to_string()).collect::<Vec<String>>();
        let seed = Seed::from_str(&hashes[0]).unwrap();

        for i in 1..5 {
            let private_key_generator = WotsSpongePrivateKeyGeneratorBuilder::<Kerl>::default()
                .with_security_level(WotsSecurityLevel::Medium)
                .build()
                .unwrap();
            let private_key = private_key_generator.generate_from_seed(&seed, i - 1).unwrap();
            let public_key = private_key
                .generate_public_key()
                .unwrap()
                .as_trits()
                .iter_trytes()
                .map(|trit| char::from(trit))
                .collect::<String>();

            assert_eq!(hashes[i], public_key);
        }
    }
}

#[test]
fn wots_iota_go_json() {
    let mut reader = BufReader::new(File::open("tests/fixtures/wots/wots.json").unwrap());
    let mut data = String::new();

    reader.read_to_string(&mut data).unwrap();

    let json: serde_json::Value = serde_json::from_str(&data).unwrap();
    let cases = json.as_array().unwrap();

    for case in cases.iter() {
        let object = case.as_object().unwrap();

        let mut private_key = WotsPrivateKey::<Kerl>::from_trits(
            TryteBuf::try_from_str(object["key"].as_str().unwrap())
                .unwrap()
                .as_trits()
                .encode::<T1B1Buf>(),
        )
        .unwrap();
        let public_key = private_key.generate_public_key().unwrap();

        assert_eq!(
            object["address"].as_str().unwrap(),
            public_key
                .as_trits()
                .iter_trytes()
                .map(|trit| char::from(trit))
                .collect::<String>()
        );

        let hash = normalize(
            &TryteBuf::try_from_str(object["hash"].as_str().unwrap())
                .unwrap()
                .as_trits()
                .encode::<T1B1Buf>(),
        )
        .unwrap();

        let signature = private_key.sign(&hash).unwrap();

        assert_eq!(
            object["signature"].as_str().unwrap(),
            signature
                .as_trits()
                .iter_trytes()
                .map(|trit| char::from(trit))
                .collect::<String>()
        );

        let recovered_publick_key = signature.recover_public_key(&hash).unwrap();

        assert_eq!(
            object["address"].as_str().unwrap(),
            recovered_publick_key
                .as_trits()
                .iter_trytes()
                .map(|trit| char::from(trit))
                .collect::<String>()
        );

        assert!(public_key.verify(&hash, &signature).unwrap());
    }
}
