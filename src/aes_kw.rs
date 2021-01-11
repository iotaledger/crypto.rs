// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use aes_crate::{cipher::generic_array::typenum::Unsigned as _, Aes128, Aes192, Aes256, BlockCipher, NewBlockCipher};
use core::{convert::TryInto as _, marker::PhantomData, mem};

use crate::{Error, Result};

/// AES Key Wrap using AES-128 block cipher.
pub type Aes128Kw<'a> = AesKeyWrap<'a, Aes128>;

/// AES Key Wrap using AES-192 block cipher.
pub type Aes192Kw<'a> = AesKeyWrap<'a, Aes192>;

/// AES Key Wrap using AES-256 block cipher.
pub type Aes256Kw<'a> = AesKeyWrap<'a, Aes256>;

/// AES Key Wrap operates on 64-bit block sizes
pub const BLOCK: usize = mem::size_of::<u64>();

/// The default initial value (IV)
///
/// See [RFC3394#Section-2.2.3.1](https://tools.ietf.org/html/rfc3394#section-2.2.3.1).
pub const DIV: u64 = 0xA6A6A6A6A6A6A6A6;

/// The AES Key Wrap Algorithm as defined in [RFC3394](https://tools.ietf.org/html/rfc3394)
#[derive(Clone, Copy, Debug)]
pub struct AesKeyWrap<'a, T> {
    key: &'a [u8],
    cipher: PhantomData<T>,
}

impl<'a, T> AesKeyWrap<'a, T> {
    pub const BLOCK: usize = BLOCK;

    pub fn new(key: &'a [u8]) -> Self {
        Self {
            key,
            cipher: PhantomData,
        }
    }
}

impl<'a, T> AesKeyWrap<'a, T>
where
    T: NewBlockCipher,
{
    pub const KEY_LENGTH: usize = <T as NewBlockCipher>::KeySize::USIZE;
}

impl<'a, T> AesKeyWrap<'a, T>
where
    T: BlockCipher + NewBlockCipher,
{
    /// Wraps a key using the AES Key Wrap algorithm.
    ///
    /// See [RFC3394](https://tools.ietf.org/html/rfc3394).
    #[allow(non_snake_case)]
    pub fn wrap_key(&self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<()> {
        assert_buffer_gte!(ciphertext.len(), plaintext.len() + BLOCK);

        if plaintext.len() % BLOCK != 0 {
            return Err(Error::CipherError { alg: "AES Key Wrap" });
        }

        // Inputs:  Plaintext, n 64-bit values {P1, P2, ..., Pn}, and Key, K (the KEK).
        // Outputs: Ciphertext, (n+1) 64-bit values {C0, C1, ..., Cn}.

        let cipher: T = T::new_varkey(self.key).unwrap();
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
                A = Self::__read_u64(&B[..BLOCK]) ^ ((N * j) + i) as u64;

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
    pub fn unwrap_key(&self, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<()> {
        assert_buffer_gte!(ciphertext.len(), BLOCK);
        assert_buffer_gte!(plaintext.len(), ciphertext.len() - BLOCK);

        if ciphertext.len() % BLOCK != 0 {
            return Err(Error::CipherError { alg: "AES Key Wrap" });
        }

        // Inputs:  Ciphertext, (n+1) 64-bit values {C0, C1, ..., Cn}, and Key, K (the KEK).
        // Outputs: Plaintext, n 64-bit values {P0, P1, K, Pn}.

        let cipher: T = T::new_varkey(self.key).unwrap();
        let N: usize = (ciphertext.len() / BLOCK) - 1;
        let R: &mut [u8] = plaintext;

        // 1) Initialize variables.

        // Set A = C[0]
        let mut A: u64 = Self::__read_u64(&ciphertext[..BLOCK]);

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
                A = Self::__read_u64(&B[..BLOCK]);

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
            Err(Error::CipherError { alg: "AES Key Wrap" })
        }
    }

    fn __read_u64(slice: &[u8]) -> u64 {
        assert_eq!(slice.len(), BLOCK);
        u64::from_be_bytes(slice.try_into().unwrap())
    }
}
