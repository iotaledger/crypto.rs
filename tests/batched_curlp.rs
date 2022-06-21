// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "curl-p")]

use crypto::hashes::ternary::{
    curl_p::{CurlPBatchHasher, BATCH_SIZE},
    HASH_LENGTH,
};

use bee_ternary::{
    raw::{RawEncoding, RawEncodingBuf},
    Btrit, T1B1Buf, T5B1Buf, TryteBuf, T1B1, T5B1,
};

use std::{
    fs::File,
    io::{prelude::*, BufReader},
};

/// Repeats the input and hashes it `BATCH_SIZE` times.
fn batched_curlp_broadcasted<B, S>(input: &str, output: &str)
where
    B: RawEncodingBuf<Slice = S> + Clone,
    S: RawEncoding<Trit = Btrit, Buf = B> + ?Sized,
{
    let input_trit_buf = TryteBuf::try_from_str(input).unwrap().as_trits().encode::<B>();
    let expected_hash = TryteBuf::try_from_str(output).unwrap().as_trits().encode::<T1B1Buf>();

    assert_eq!(expected_hash.len(), HASH_LENGTH);

    let mut batch_hasher = CurlPBatchHasher::new(input_trit_buf.len());

    for _ in 0..BATCH_SIZE {
        batch_hasher.add(input_trit_buf.clone());
    }

    for (index, hash) in batch_hasher.hash().enumerate() {
        assert_eq!(expected_hash, hash, "input {} failed", index);
    }
}

/// Hashes `BATCH_SIZE` items at once.
fn batched_curlp<B, S>(cases: &[(String, String)])
where
    B: RawEncodingBuf<Slice = S> + Clone,
    S: RawEncoding<Trit = Btrit, Buf = B> + ?Sized,
{
    let mut batch_hasher = CurlPBatchHasher::new(8019);

    let mut expected_hashes = vec![];

    for (input, output) in cases.iter() {
        let input_trit_buf = TryteBuf::try_from_str(input).unwrap().as_trits().encode::<B>();

        let expected_hash = TryteBuf::try_from_str(output).unwrap().as_trits().encode::<T1B1Buf>();

        assert_eq!(expected_hash.len(), HASH_LENGTH);

        batch_hasher.add(input_trit_buf);
        expected_hashes.push(expected_hash);
    }

    for (index, hash) in batch_hasher.hash().enumerate() {
        assert_eq!(expected_hashes[index], hash, "input {} failed", index);
    }
}

fn json_to_vec(path: &str) -> Vec<(String, String)> {
    let mut reader = BufReader::new(File::open(path).unwrap());
    let mut data = String::new();

    reader.read_to_string(&mut data).unwrap();

    let json: serde_json::Value = serde_json::from_str(&data).unwrap();
    let cases = json
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            let object = case.as_object().unwrap();
            let input = object["in"].as_str().unwrap().into();
            let output = object["hash"].as_str().unwrap().into();
            (input, output)
        })
        .collect();

    cases
}

#[test]
fn batched_curl_p_broadcasted_t1b1_input_243() {
    let tests = include!("fixtures/curl_p/input_243_output_243.rs");

    for test in tests.iter() {
        batched_curlp_broadcasted::<T1B1Buf, T1B1>(test.0, test.1);
    }
}

#[test]
fn batched_curl_p_broadcasted_t5b1_input_243() {
    let tests = include!("fixtures/curl_p/input_243_output_243.rs");

    for test in tests.iter() {
        batched_curlp_broadcasted::<T5B1Buf, T5B1>(test.0, test.1);
    }
}

#[test]
fn batched_curl_p_broadcasted_t1b1_input_6561() {
    let tests = include!("fixtures/curl_p/input_6561_output_243.rs");

    for test in tests.iter() {
        batched_curlp_broadcasted::<T1B1Buf, T1B1>(test.0, test.1);
    }
}

#[test]
fn batched_curl_p_broadcasted_t5b1_input_6561() {
    let tests = include!("fixtures/curl_p/input_6561_output_243.rs");

    for test in tests.iter() {
        batched_curlp_broadcasted::<T5B1Buf, T5B1>(test.0, test.1);
    }
}

#[test]
fn batched_curl_p_broadcasted_t1b1_input_8019() {
    let tests = include!("fixtures/curl_p/input_8019_output_243.rs");

    for test in tests.iter() {
        batched_curlp_broadcasted::<T1B1Buf, T1B1>(test.0, test.1);
    }
}

#[test]
fn batched_curl_p_broadcasted_t5b1_input_8019() {
    let tests = include!("fixtures/curl_p/input_8019_output_243.rs");

    for test in tests.iter() {
        batched_curlp_broadcasted::<T5B1Buf, T5B1>(test.0, test.1);
    }
}

#[test]
fn batched_curl_p_broadcasted_t1b1_iota_go() {
    let cases = json_to_vec("tests/fixtures/curl_p/curlp81-iota-go.json");
    let mut counter = 0;
    for (input, output) in cases.iter() {
        // We filter the outputs that do not have the required length
        if TryteBuf::try_from_str(output).unwrap().as_trits().len() == HASH_LENGTH {
            batched_curlp_broadcasted::<T1B1Buf, T1B1>(input, output);
            counter += 1;
        }
        assert!(counter != 0) // We should at least run one test case
    }
}

#[test]
fn batched_curl_p_broadcasted_t5b1_iota_go() {
    let cases = json_to_vec("tests/fixtures/curl_p/curlp81-iota-go.json");
    let mut counter = 0;
    for (input, output) in cases.iter() {
        // We filter the outputs that do not have the required length
        if TryteBuf::try_from_str(output).unwrap().as_trits().len() == HASH_LENGTH {
            batched_curlp_broadcasted::<T5B1Buf, T5B1>(input, output);
            counter += 1;
        }
        assert!(counter != 0) // We should at least run one test case
    }
}

#[test]
fn batched_curl_p_t1b1_input_8019() {
    let cases = include!("fixtures/curl_p/input_8019_output_243.rs")
        .iter()
        .map(|(input, output)| (input.to_string(), output.to_string()))
        .collect::<Vec<_>>();

    batched_curlp::<T1B1Buf, T1B1>(&cases);
}

#[test]
fn batched_curl_p_t5b1_input_8019() {
    let cases = include!("fixtures/curl_p/input_8019_output_243.rs")
        .iter()
        .map(|(input, output)| (input.to_string(), output.to_string()))
        .collect::<Vec<_>>();

    batched_curlp::<T5B1Buf, T5B1>(&cases);
}
