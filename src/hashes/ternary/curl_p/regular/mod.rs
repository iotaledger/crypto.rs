// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod transform;
mod u256;

use u256::U256;

use crate::hashes::ternary::{curl_p::SpongeDirection, HASH_LENGTH};

use bee_ternary::{Btrit, TritBuf, Trits};

/// State of the ternary cryptographic function `CurlP`.
pub struct CurlP {
    p: [U256; 3],
    n: [U256; 3],
    direction: SpongeDirection,
}

impl Default for CurlP {
    fn default() -> Self {
        Self {
            p: Default::default(),
            n: Default::default(),
            direction: SpongeDirection::Absorb,
        }
    }
}

impl CurlP {
    fn squeeze_aux(&mut self, hash: &mut Trits) {
        if let SpongeDirection::Squeeze = self.direction {
            self.transform();
        }

        self.direction = SpongeDirection::Squeeze;

        for i in 0..HASH_LENGTH {
            // SAFETY: `U256::bit` returns an `i8` between `0` and `1`.
            // Substracting two bits will produce an `i8` between `-1` and `1` and matches the `repr` of `Btrit`.
            let trit = unsafe { core::mem::transmute::<i8, Btrit>(self.p[0].bit(i) - self.n[0].bit(i)) };
            hash.set(i, trit);
        }
    }

    fn transform(&mut self) {
        transform::transform(&mut self.p, &mut self.n)
    }

    /// Creates a new [`CurlP`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Resets the internal state by overwriting it with zeros.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Absorbs `input` into the sponge by copying `HASH_LENGTH` chunks of it into its internal state and transforming
    /// the state before moving on to the next chunk.
    ///
    /// If `input` is not a multiple of `HASH_LENGTH` with the last chunk having `n < HASH_LENGTH` trits, the last chunk
    /// will be copied to the first `n` slots of the internal state. The remaining data in the internal state is then
    /// just the result of the last transformation before the data was copied, and will be reused for the next
    /// transformation.
    pub fn absorb(&mut self, input: &Trits) {
        assert!(
            !(input.is_empty() || input.len() % HASH_LENGTH != 0),
            "trits slice length must be multiple of {}",
            HASH_LENGTH
        );

        if let SpongeDirection::Squeeze = self.direction {
            panic!("absorb after squeeze");
        }

        for chunk in input.chunks(HASH_LENGTH) {
            let mut p = U256::default();
            let mut n = U256::default();

            for (i, trit) in chunk.iter().enumerate() {
                match trit {
                    Btrit::PlusOne => p.set_bit(i),
                    Btrit::Zero => (),
                    Btrit::NegOne => n.set_bit(i),
                }
            }

            self.p[0] = p;
            self.n[0] = n;
            self.transform();
        }
    }

    /// Squeezes the sponge by copying the state into the provided `buf`. This will fill the buffer in chunks of
    /// `HASH_LENGTH` at a time.
    ///
    /// If the last chunk is smaller than `HASH_LENGTH`, then only the fraction that fits is written into it.
    fn squeeze_into(&mut self, buf: &mut Trits) {
        assert_eq!(buf.len() % HASH_LENGTH, 0, "Invalid squeeze length");

        for chunk in buf.chunks_mut(HASH_LENGTH) {
            self.squeeze_aux(chunk);
        }
    }

    /// Convenience function using `squeeze_into` to return an owned output.
    pub fn squeeze(&mut self) -> TritBuf {
        let mut output = TritBuf::zeros(HASH_LENGTH);
        self.squeeze_into(&mut output);

        output
    }

    /// Convenience function to absorb `input`, squeeze the sponge into `buf`, and reset the sponge.
    pub fn digest_into(&mut self, input: &Trits, buf: &mut Trits) {
        self.absorb(input);
        self.squeeze_into(buf);
        self.reset();
    }

    /// Convenience function to absorb `input`, squeeze the sponge, reset the sponge and return an owned output.
    pub fn digest(&mut self, input: &Trits) -> TritBuf {
        self.absorb(input);
        let output = self.squeeze();
        self.reset();

        output
    }
}
