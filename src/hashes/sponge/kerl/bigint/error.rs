// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Big integer errors.

/// Errors related to big integers.
#[derive(Clone, Debug)]
pub enum Error {
    /// Error when converting and binary representation exceeds ternary range.
    BinaryExceedsTernaryRange,
    /// Error when converting and ternary representation exceeds binary range.
    TernaryExceedsBinaryRange,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::BinaryExceedsTernaryRange => write!(f, "Binary representation exceeds ternary range."),
            Error::TernaryExceedsBinaryRange => write!(f, "Ternary representation exceeds binary range."),
        }
    }
}
