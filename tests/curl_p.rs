// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "curl-p")]

use crypto::hashes::curl_p::CurlP;

use bee_ternary::{T1B1Buf, T3B1Buf, TritBuf, TryteBuf};

fn digest(input: &str, output: &str) {
    let mut curl = CurlP::new();

    let input_trit_buf = TryteBuf::try_from_str(input).unwrap().as_trits().encode::<T1B1Buf>();
    let expected_hash = TryteBuf::try_from_str(output).unwrap();
    let calculated_hash = curl.digest(input_trit_buf.as_slice()).encode::<T3B1Buf>();

    assert_eq!(calculated_hash.as_slice(), expected_hash.as_trits());
}

fn digest_into(input: &str, output: &str) {
    let mut curl = CurlP::new();

    let input_trit_buf = TryteBuf::try_from_str(input).unwrap().as_trits().encode::<T1B1Buf>();
    let expected_hash = TryteBuf::try_from_str(output).unwrap();

    let output_len = expected_hash.as_trits().len();
    let mut calculated_hash = TritBuf::<T1B1Buf>::zeros(output_len);

    curl.digest_into(input_trit_buf.as_slice(), &mut calculated_hash.as_slice_mut());

    let calculated_hash = calculated_hash.encode::<T3B1Buf>();

    assert_eq!(calculated_hash.as_slice(), expected_hash.as_trits());
}

// In the following tests, fields are (input, output).

#[test]
fn curl_p_input_243_output_243() {
    let tests = include!("fixtures/curl_p/input_243_output_243.rs");

    for test in tests.iter() {
        digest(test.0, test.1);
    }
}

#[test]
fn curl_p_input_243_output_486() {
    let tests = include!("fixtures/curl_p/input_243_output_486.rs");

    for test in tests.iter() {
        digest_into(test.0, test.1);
    }
}

#[test]
fn curl_p_input_243_output_6561() {
    let tests = include!("fixtures/curl_p/input_243_output_6561.rs");

    for test in tests.iter() {
        digest_into(test.0, test.1);
    }
}

#[test]
fn curl_p_input_486_output_486() {
    let tests = include!("fixtures/curl_p/input_486_output_486.rs");

    for test in tests.iter() {
        digest_into(test.0, test.1);
    }
}

#[test]
fn curl_p_input_6561_output_6561() {
    let tests = include!("fixtures/curl_p/input_6561_output_6561.rs");

    for test in tests.iter() {
        digest_into(test.0, test.1);
    }
}

#[test]
fn curl_p_input_6561_output_243() {
    let tests = include!("fixtures/curl_p/input_6561_output_243.rs");

    for test in tests.iter() {
        digest_into(test.0, test.1);
    }
}
