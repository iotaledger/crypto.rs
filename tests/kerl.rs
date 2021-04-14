// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "kerl")]

use crypto::hashes::sponge::{kerl::Kerl, Sponge};

use bee_ternary::{T1B1Buf, T3B1Buf, TritBuf, TryteBuf};

use std::{
    fs::File,
    io::{prelude::*, BufReader},
};

fn digest(input: &str, output: &str) {
    let mut kerl = Kerl::new();

    let input_trit_buf = TryteBuf::try_from_str(input).unwrap().as_trits().encode::<T1B1Buf>();
    let expected_hash = TryteBuf::try_from_str(output).unwrap();
    let calculated_hash = kerl.digest(input_trit_buf.as_slice()).unwrap().encode::<T3B1Buf>();

    assert_eq!(calculated_hash.as_slice(), expected_hash.as_trits());
}

fn digest_into(input: &str, output: &str) {
    let mut kerl = Kerl::new();

    let input_trit_buf = TryteBuf::try_from_str(input).unwrap().as_trits().encode::<T1B1Buf>();
    let expected_hash = TryteBuf::try_from_str(output).unwrap();

    let output_len = expected_hash.as_trits().len();
    let mut calculated_hash = TritBuf::<T1B1Buf>::zeros(output_len);

    kerl.digest_into(input_trit_buf.as_slice(), &mut calculated_hash.as_slice_mut())
        .unwrap();

    let calculated_hash = calculated_hash.encode::<T3B1Buf>();

    assert_eq!(calculated_hash.as_slice(), expected_hash.as_trits());
}

#[test]
fn kerl_generate_trytes_and_hashes() {
    let reader = BufReader::new(File::open("tests/fixtures/kerl/generateTrytesAndHashes.txt").unwrap());

    for line in reader.lines() {
        let hashes = line.unwrap().split(",").map(|s| s.to_string()).collect::<Vec<String>>();
        digest(&hashes[0], &hashes[1]);
    }
}

#[test]
fn kerl_generate_multi_trytes_and_hash() {
    let reader = BufReader::new(File::open("tests/fixtures/kerl/generateMultiTrytesAndHash.txt").unwrap());

    for line in reader.lines() {
        let hashes = line.unwrap().split(",").map(|s| s.to_string()).collect::<Vec<String>>();
        digest_into(&hashes[0], &hashes[1]);
    }
}

#[test]
fn kerl_generate_trytes_and_multi_squeeze() {
    let mut kerl = Kerl::new();
    let reader = BufReader::new(File::open("tests/fixtures/kerl/generateTrytesAndMultiSqueeze.txt").unwrap());

    for line in reader.lines() {
        let hashes = line.unwrap().split(",").map(|s| s.to_string()).collect::<Vec<String>>();
        let input = TryteBuf::try_from_str(&hashes[0])
            .unwrap()
            .as_trits()
            .encode::<T1B1Buf>();
        kerl.absorb(&input).unwrap();

        for i in 0..3 {
            let expected = TryteBuf::try_from_str(&hashes[i + 1]).unwrap();
            let digest = kerl.squeeze().unwrap().encode::<T3B1Buf>();
            assert_eq!(expected.as_trits(), digest.as_slice());
        }

        kerl.reset();
    }
}
