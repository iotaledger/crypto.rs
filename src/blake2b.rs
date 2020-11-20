// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use blake2b_simd::Params;

pub fn hash(data: &[u8], output_buffer: &mut [u8]) {
    let hash = Params::new().hash_length(output_buffer.len()).hash(data);
    let hash_bytes = hash.as_bytes();
    output_buffer[..hash_bytes.len()].clone_from_slice(&hash_bytes[..]);
}
