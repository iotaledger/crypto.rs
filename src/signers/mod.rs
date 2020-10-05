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
use thiserror::Error;

pub mod ed25519;

/// Errors occuring during signing operations.
#[derive(Debug, Error)]
pub enum Error {
    /// Convertion Error
    #[error("Failed to convert bytes to target primitives.")]
    ConvertError,
    /// Invalid seed length.
    #[error("Invalid seed length, should be 243 trits, was {0}.")]
    InvalidLength(usize),
    /// Private Key Error
    #[error("Failed to generate private key.")]
    PrivateKeyError,
    /// Last trit of the entropy is not null.
    #[error("Last trit of the entropy is not null.")]
    NonNullEntropyLastTrit,
    /// Failed sponge operation.
    #[error("Failed sponge operation.")]
    FailedSpongeOperation,
    /// Invalid signature length.
    #[error("Invalid signature length, should be a multiple of 6561 trits, was {0}.")]
    InvalidSignatureLength(usize),
}
