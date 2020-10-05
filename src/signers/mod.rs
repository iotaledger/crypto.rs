// Copyright 2020 IOTA Stiftung
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.
//! Binary signing scheme primitives.

pub mod ed25519;

use core::fmt;

/// Errors occuring during signing operations.
#[derive(Debug)]
pub enum Error {
    /// Convertion Error
    ConvertError,
    /// Invalid seed length.
    InvalidLength(usize),
    /// Private Key Error
    PrivateKeyError,
    /// Last trit of the entropy is not null.
    NonNullEntropyLastTrit,
    /// Failed sponge operation.
    FailedSpongeOperation,
    /// Invalid signature length.
    InvalidSignatureLength(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ConvertError => write!(f, "Failed to convert bytes to target primitives."),
            Error::InvalidLength(l) => write!(f, "Invalid seed length, should be 243 trits, was {}", l),
            Error::PrivateKeyError => write!(f, "Failed to generate private key."),
            Error::NonNullEntropyLastTrit => write!(f, "Last trit of the entropy is not null."),
            Error::FailedSpongeOperation => write!(f, "Failed sponge operation."),
            Error::InvalidSignatureLength(l) => write!(
                f,
                "Invalid signature length, should be a multiple of 6561 trits, was {}",
                l
            ),
        }
    }
}
