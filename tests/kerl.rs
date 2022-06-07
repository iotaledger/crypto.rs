// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "kerl_deprecated_do_not_use")]
#![allow(deprecated)]

use crypto::{
    hashes::ternary::{kerl::Kerl, Sponge},
    keys::ternary::seed::{Error as SeedError, Seed},
};

use bee_ternary::{T1B1Buf, T3B1Buf, TritBuf, TryteBuf};

use std::{
    fs::File,
    io::{prelude::*, BufReader},
    str::FromStr,
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
        let hashes = line.unwrap().split(',').map(|s| s.to_string()).collect::<Vec<String>>();
        digest(&hashes[0], &hashes[1]);
    }
}

#[test]
fn kerl_generate_multi_trytes_and_hash() {
    let reader = BufReader::new(File::open("tests/fixtures/kerl/generateMultiTrytesAndHash.txt").unwrap());

    for line in reader.lines() {
        let hashes = line.unwrap().split(',').map(|s| s.to_string()).collect::<Vec<String>>();
        digest_into(&hashes[0], &hashes[1]);
    }
}

#[test]
fn kerl_generate_trytes_and_multi_squeeze() {
    let mut kerl = Kerl::new();
    let reader = BufReader::new(File::open("tests/fixtures/kerl/generateTrytesAndMultiSqueeze.txt").unwrap());

    for line in reader.lines() {
        let hashes = line.unwrap().split(',').map(|s| s.to_string()).collect::<Vec<String>>();
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

fn subseed_generic<S: Sponge + Default>(seed_string: &str, subseed_strings: &[&str]) {
    let seed = Seed::from_str(seed_string).unwrap();

    for (i, subseed_string) in subseed_strings.iter().enumerate() {
        let subseed = seed.subseed(i);
        let subseed_trits = TryteBuf::try_from_str(subseed_string)
            .unwrap()
            .as_trits()
            .encode::<T1B1Buf>();

        assert_eq!(subseed.as_trits(), subseed_trits.as_slice());
    }
}

#[test]
fn subseed_kerl() {
    const SEED: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9";

    subseed_generic::<Kerl>(
        SEED,
        &[
            "APSNZAPLANAGSXGZMZYCSXROJ9KUX9HVOPODQHMWNJOCGBKRIOOQKYGPFAIQBYNIODMIWMFKJGKRWFFPY",
            "PXQMW9VMXGYTEPYPIASGPQ9CAQUQWNSUIIVHFIEAB9C9DHNNCWSNJKSBEAKYIBCYOZDDTQANEKPGJPVIY",
            "ZUJWIFUVFGOGDNMTFDVZGTWVCBVIK9XQQDQEKJSKBXNGLFLLIPTVUHHPCPKNMBFMATPYJVOH9QTEVOYTW",
            "OCHUZGFIX9VXXMBJXPKAPZHXIOCLAEKREMCKQIYQPXQQLRTOEUQRCZIYVSLUTJQGISGDRDSCERBOEEI9C",
            "GWTMVQWHHCYFXVHGUYYZHUNXICJLMSOZVBAZOIZIWGBRAXMFDUBLP9NVIFEFFRARYIHNGPEBLNUECABKW",
            "XWIYCHCVZEXOPXCQEJUGPMGVAIYBULVHWDD9YWMAZNJQEISHOBMYFHZKCBT9GWCSRQSFURKF9I9ITWEUC",
            "XRBHXHE9IVEDFHQPNNMYOPXOLPXRBSYCGQNMRFKYENRJZLZAVMFLUCWWCNBFPKOSHF9UPMFFEWAWAHJP9",
            "IP9DGBVAPNHHDP9CXOBYRLTYVJCQYUUWNWGNFUSDRKFIIAVPYPQDASDULPJBBEBOQATDHV9PVXYIJFQTA",
            "XSGWTBAECBMTKEHXNYAVSYRPLASPJSHPIWROHRLDFUEKISEMCMXYGRZMPZCEAKZ9UKQBA9LEQFXWEMZPD",
            "JXCAHDZVVCMGIGWJFFVDRFCHKBVAWTSLWIPZYGBECFXJQPDNDYJTEYCBHSRPDMPFEPWZUMDEIPIBW9SI9",
        ],
    );
}

#[test]
fn from_str_invalid_length() {
    let trytes = "VBAZOIZIWGBRAXMFDUBLP";

    assert_eq!(
        Seed::from_str(trytes).err(),
        Some(SeedError::InvalidLength(trytes.len() * 3))
    );
}

#[test]
fn from_str_invalid_trytes() {
    let trytes = "APSNZAPL@NAGSXGZMZYCSXROJ9KUX9HVOPODQHMWNJOCGBKRIOOQKYGPFAIQBYNIODMIWMFKJGKRWFFPY";

    assert_eq!(Seed::from_str(trytes).err(), Some(SeedError::InvalidTrytes));
}

#[test]
fn from_trits_invalid_length() {
    let trits = TritBuf::zeros(42);

    assert_eq!(
        Seed::from_trits(trits.clone()).err(),
        Some(SeedError::InvalidLength(trits.len()))
    );
}

// #[test]
// fn to_trits_from_trits() {
//     for _ in 0..10 {
//         let seed_1 = Seed::rand();
//         let seed_2 = Seed::from_trits(seed_1.as_trits().to_buf()).unwrap();
//
//         assert_eq!(seed_1.as_trits(), seed_2.as_trits());
//     }
// }
