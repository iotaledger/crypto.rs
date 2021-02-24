// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use blake2::VarBlake2b;
use digest::{
    generic_array::{
        typenum::{Unsigned, U32},
        GenericArray,
    },
    FixedOutput, Reset, Update, VariableOutput,
};

/// Blake2b instance with a 256-bit output.
#[derive(Clone)]
pub struct Blake2b256(VarBlake2b);

impl Blake2b256 {
    /// Creates a new [`Blake2b256`] instance.
    pub fn new() -> Self {
        Self(VarBlake2b::new_keyed(&[], U32::USIZE))
    }
}

impl Default for Blake2b256 {
    fn default() -> Self {
        Self::new()
    }
}

impl FixedOutput for Blake2b256 {
    type OutputSize = U32;

    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
        self.0.finalize_variable(|output| out.copy_from_slice(output));
    }

    fn finalize_into_reset(&mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
        self.0.finalize_variable_reset(|output| out.copy_from_slice(output));
    }
}

impl Reset for Blake2b256 {
    fn reset(&mut self) {
        self.0.reset();
    }
}

impl Update for Blake2b256 {
    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.0.update(data);
    }
}
