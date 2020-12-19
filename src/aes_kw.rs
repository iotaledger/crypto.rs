// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use aes_crate::{cipher::generic_array::typenum::Unsigned as _, BlockCipher, NewBlockCipher};
pub use aes_crate::{Aes128, Aes192, Aes256};
use core::{array, convert::TryInto as _, mem};

use crate::Result;

impl AesKeyWrap for Aes128 {}

impl AesKeyWrap for Aes192 {}

impl AesKeyWrap for Aes256 {}

/// AES Key Wrap operates on 64-bit block sizes
pub const BLOCK: usize = mem::size_of::<u64>();

/// The default initial value (IV)
///
/// See [RFC3394#Section-2.2.3.1](https://tools.ietf.org/html/rfc3394#section-2.2.3.1).
pub const DIV: u64 = 0xA6A6A6A6A6A6A6A6;

/// The AES Key Wrap Algorithm as defined in [RFC3394](https://tools.ietf.org/html/rfc3394)
pub trait AesKeyWrap: NewBlockCipher + BlockCipher {
    /// Wraps a key using the AES Key Wrap algorithm.
    ///
    /// See [RFC3394](https://tools.ietf.org/html/rfc3394).
    #[allow(non_snake_case)]
    fn wrap_key(kek: &[u8], plaintext: &[u8], ciphertext: &mut [u8]) -> Result<()> {
        if kek.len() != <Self as NewBlockCipher>::KeySize::to_usize() {
            todo!("Error: InvalidKeyLength")
        }

        if ciphertext.len() < BLOCK + plaintext.len() {
            todo!("Error: InvalidBufferLength")
        }

        if plaintext.len() % BLOCK != 0 {
            todo!("Error: InvalidContentLength")
        }

        // Inputs:  Plaintext, n 64-bit values {P1, P2, ..., Pn}, and Key, K (the KEK).
        // Outputs: Ciphertext, (n+1) 64-bit values {C0, C1, ..., Cn}.

        let cipher: Self = Self::new(kek.into());
        let N: usize = plaintext.len() / BLOCK;
        let R: &mut [u8] = &mut ciphertext[BLOCK..];

        // 1) Initialize variables.

        // Set A = IV, an initial value (see 2.2.3)
        let mut A: u64 = DIV;

        // For i = 1 to n
        //   R[i] = P[i]
        R.copy_from_slice(plaintext);

        // 2) Calculate intermediate values.

        let mut B: [u8; BLOCK << 1] = [0; BLOCK << 1];

        // For j = 0 to 5
        for j in 0..=5 {
            // For i=1 to n
            for i in 1..=N {
                // B = AES(K, A | R[i])
                B[..BLOCK].copy_from_slice(&A.to_be_bytes());
                B[BLOCK..].copy_from_slice(&R[BLOCK * (i - 1)..BLOCK * i]);

                cipher.encrypt_block((&mut B[..]).into());

                // A = MSB(64, B) ^ t where t = (n*j)+i
                A = Self::__read_u64(&B[..BLOCK]).unwrap() ^ ((N * j) + i) as u64;

                // R[i] = LSB(64, B)
                R[BLOCK * (i - 1)..BLOCK * i].copy_from_slice(&B[BLOCK..]);
            }
        }

        // 3) Output the results.

        // Set C[0] = A
        ciphertext[..BLOCK].copy_from_slice(&A.to_be_bytes());

        // We skip the following step because `R` is a mutable reference
        // to a subslice of `C` and there is no need to copy.

        // For i = 1 to n
        //   C[i] = R[i]

        Ok(())
    }

    /// Unwraps an encrypted key using the AES Key Wrap algorithm.
    ///
    /// See [RFC3394](https://tools.ietf.org/html/rfc3394).
    #[allow(non_snake_case)]
    fn unwrap_key(kek: &[u8], ciphertext: &[u8], plaintext: &mut [u8]) -> Result<()> {
        if kek.len() != <Self as NewBlockCipher>::KeySize::to_usize() {
            todo!("Error: InvalidKeyLength")
        }

        if plaintext.len() < ciphertext.len() - BLOCK {
            todo!("Error: InvalidBufferLength")
        }

        if ciphertext.len() % BLOCK != 0 {
            todo!("Error: InvalidContentLength")
        }

        // Inputs:  Ciphertext, (n+1) 64-bit values {C0, C1, ..., Cn}, and Key, K (the KEK).
        // Outputs: Plaintext, n 64-bit values {P0, P1, K, Pn}.

        let cipher: Self = Self::new(kek.into());
        let N: usize = (ciphertext.len() / BLOCK) - 1;
        let R: &mut [u8] = plaintext;

        // 1) Initialize variables.

        // Set A = C[0]
        let mut A: u64 = Self::__read_u64(&ciphertext[..BLOCK]).unwrap();

        // For i = 1 to n
        //   R[i] = C[i]
        R.copy_from_slice(&ciphertext[BLOCK..]);

        // 2) Compute intermediate values.

        let mut B: [u8; BLOCK << 1] = [0; BLOCK << 1];

        // For j = 5 to 0
        for j in (0..=5).rev() {
            // For i = n to 1
            for i in (1..=N).rev() {
                // B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
                B[..BLOCK].copy_from_slice(&(A ^ ((N * j) + i) as u64).to_be_bytes());
                B[BLOCK..].copy_from_slice(&R[BLOCK * (i - 1)..BLOCK * i]);

                cipher.decrypt_block((&mut B[..]).into());

                // A = MSB(64, B)
                A = Self::__read_u64(&B[..BLOCK]).unwrap();

                // R[i] = LSB(64, B)
                R[BLOCK * (i - 1)..BLOCK * i].copy_from_slice(&B[BLOCK..]);
            }
        }

        // 3) Output results.

        // If A is an appropriate initial value (see 2.2.3),
        // Then
        //   For i = 1 to n
        //     P[i] = R[i]
        // Else
        //   Return an error
        if A == DIV {
            Ok(())
        } else {
            todo!("Error: FailedIntegrityCheck")
        }
    }

    #[doc(hidden)]
    fn __read_u64(slice: &[u8]) -> Result<u64, array::TryFromSliceError> {
        slice.try_into().map(u64::from_be_bytes)
    }
}
