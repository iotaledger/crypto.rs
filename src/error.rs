// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::fmt::{Display, Formatter, Result as FmtResult};

pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Error type of crypto.rs
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Buffer Error
    BufferSize {
        name: &'static str,
        needs: usize,
        has: usize,
    },
    ///  Cipher Error
    CipherError { alg: &'static str },
    /// Convertion Error
    ConvertError { from: &'static str, to: &'static str },
    /// Private Key Error
    PrivateKeyError,
    /// InvalidArgumentError
    InvalidArgumentError { alg: &'static str, expected: &'static str },
    /// System Error
    SystemError {
        call: &'static str,
        raw_os_error: Option<i32>,
    },
    #[cfg(feature = "digest")]
    InvalidLength,
}

#[cfg(feature = "digest")]
impl From<digest::InvalidLength> for Error {
    fn from(_: digest::InvalidLength) -> Self {
        Error::InvalidLength
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Error::BufferSize { name, needs, has } => {
                write!(f, "{} buffer needs {} bytes, but it only has {}", name, needs, has)
            }
            Error::CipherError { alg } => write!(f, "error in algorithm {}", alg),
            Error::ConvertError { from, to } => write!(f, "failed to convert {} to {}", from, to),
            Error::PrivateKeyError => write!(f, "Failed to generate private key."),
            Error::InvalidArgumentError { alg, expected } => write!(f, "{} expects {}", alg, expected),
            Error::SystemError {
                call,
                raw_os_error: None,
            } => write!(f, "system error when calling {}", call),
            Error::SystemError {
                call,
                raw_os_error: Some(errno),
            } => write!(f, "system error when calling {}: {}", call, errno),
            #[cfg(feature = "digest")]
            Error::InvalidLength => write!(f, "digest invalid length"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
