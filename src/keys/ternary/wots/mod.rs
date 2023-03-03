// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub mod shake;
pub mod sponge;

/// Errors occurring during WOTS operations.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Missing security level in generator.
    MissingSecurityLevel,
    /// Failed sponge operation.
    FailedSpongeOperation,
    /// Invalid entropy length.
    InvalidEntropyLength(usize),
    /// Last trit of the entropy is not null.
    NonNullEntropyLastTrit,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::MissingSecurityLevel => write!(f, "Missing security level in generator."),
            Error::FailedSpongeOperation => write!(f, "Failed sponge operation."),
            Error::InvalidEntropyLength(length) => {
                write!(f, "Invalid entropy length, should be 243 trits, was {0}.", length)
            }
            Error::NonNullEntropyLastTrit => write!(f, "Last trit of the entropy is not null."),
        }
    }
}

/// Available WOTS security levels.
#[derive(Clone, Copy, Default)]
#[repr(u8)]
pub enum WotsSecurityLevel {
    /// Low security.
    Low = 1,
    /// Medium security.
    #[default]
    Medium = 2,
    /// High security.
    High = 3,
}
