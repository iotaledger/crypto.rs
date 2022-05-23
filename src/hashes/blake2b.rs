// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use blake2::{Blake2b, Digest};
use digest::{
    FixedOutput,
    generic_array::typenum::{U20, U32},
    HashMarker, Reset, Update, Output, OutputSizeUser
};

// blake2 has [`Blake2s256`] instance but not for 160 bits.
/// Blake2b instance with a 256-bit output.
#[derive(Clone)]
pub struct Blake2b256(Blake2b<U32>);

impl Blake2b256 {
    /// Creates a new [`Blake2b256`] instance.
    pub fn new() -> Self {
        Self(Blake2b::new())
    }
}

impl Default for Blake2b256 {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputSizeUser for Blake2b256 {
    type OutputSize = U32;
}

impl FixedOutput for Blake2b256 {
    fn finalize_into(self, out: &mut Output<Self>) {
        FixedOutput::finalize_into(self.0, out);
    }
}

impl Reset for Blake2b256 {
    fn reset(&mut self) {
        Reset::reset(&mut self.0);
    }
}

impl Update for Blake2b256 {
    fn update(&mut self, data: &[u8]) {
        Update::update(&mut self.0, data);
    }
}

impl HashMarker for Blake2b256 {}

/// Blake2b instance with a 160-bit output.
#[derive(Clone)]
pub struct Blake2b160(Blake2b<U20>);

impl Blake2b160 {
    /// Creates a new [`Blake2b160`] instance.
    pub fn new() -> Self {
        Self(Blake2b::new())
    }
}

impl Default for Blake2b160 {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputSizeUser for Blake2b160 {
    type OutputSize = U20;
}

impl FixedOutput for Blake2b160 {
    fn finalize_into(self, out: &mut Output<Self>) {
        FixedOutput::finalize_into(self.0, out);
    }
}

impl Reset for Blake2b160 {
    fn reset(&mut self) {
        Reset::reset(&mut self.0);
    }
}

impl Update for Blake2b160 {
    fn update(&mut self, data: &[u8]) {
        Update::update(&mut self.0, data);
    }
}

impl HashMarker for Blake2b160 {}
