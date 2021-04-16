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
    signatures::ternary::{PrivateKey, PublicKey},
};

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
            let publick_key = private_key
                .generate_public_key()
                .unwrap()
                .as_trits()
                .iter_trytes()
                .map(|trit| char::from(trit))
                .collect::<String>();

            assert_eq!(hashes[i], publick_key);
        }
    }
}
