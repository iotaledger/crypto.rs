// Copyright 2020 IOTA Stiftung
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#![no_std]

pub mod ciphers;

#[cfg(feature = "ed25519")]
pub mod ed25519;

use core::fmt;

/// Error type of crypto.rs
#[derive(Debug)]
pub enum Error {
    /// Buffer Error
    BufferSize { needs: usize, has: usize },
    ///  Cipher Error
    CipherError { alg: &'static str },
    /// Convertion Error
    ConvertError { from: &'static str, to: &'static str },
    /// Private Key Error
    PrivateKeyError
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BufferSize { needs, has } =>
                write!(f, "buffer needs {} bytes, but it only has {}", needs, has),
            Error::CipherError { alg } => write!(f, "error in algorithm {}", alg),
            Error::ConvertError { from, to } =>
                write!(f, "failed to convert {} to {}", from, to),
            Error::PrivateKeyError => write!(f, "Failed to generate private key."),
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;
