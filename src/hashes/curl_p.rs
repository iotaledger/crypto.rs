// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use bee_ternary::{Btrit, TritBuf, Trits};

const HASH_LENGTH: usize = 243;
const STATE_LENGTH: usize = HASH_LENGTH * 3;
const HALF_STATE_LENGTH: usize = STATE_LENGTH / 2;
const CURL_P_ROUNDS: usize = 81;

const TRUTH_TABLE: [Btrit; 9] = [
    Btrit::PlusOne,
    Btrit::Zero,
    Btrit::NegOne,
    Btrit::PlusOne,
    Btrit::NegOne,
    Btrit::Zero,
    Btrit::NegOne,
    Btrit::PlusOne,
    Btrit::Zero,
];

/// State of the ternary cryptographic function `CurlP`.
pub struct CurlP {
    /// The internal state.
    state: TritBuf,
    /// Workspace for performing transformations.
    work_state: TritBuf,
}

impl Default for CurlP {
    fn default() -> Self {
        Self {
            state: TritBuf::zeros(STATE_LENGTH),
            work_state: TritBuf::zeros(STATE_LENGTH),
        }
    }
}

impl CurlP {
    /// Create a new `CurlP`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Transforms the internal state of the `CurlP` sponge after the input was copied into the internal state.
    /// The essence of this transformation is the application of a substitution box to the internal state.
    fn transform(&mut self) {
        /// # Safety
        ///
        /// For performance reasons, this method is unsafe.
        /// It is however fine since:
        /// - It is not publicly exposed.
        /// - `state` is indexed with `p` and `q` that come from iteration on `state`.
        /// - `TRUTH_TABLE`, of size 9, is indexed with a value that is in [0, 8].
        #[inline]
        unsafe fn truth_table_get(state: &Trits, p: usize, q: usize) -> Btrit {
            // Reason: `BTrit`'s repr is between `-1` and `1`.
            #[allow(clippy::cast_sign_loss)]
            *TRUTH_TABLE
                .get_unchecked((3 * (state.get_unchecked(q) as i8 + 1) + (state.get_unchecked(p) as i8 + 1)) as usize)
        }

        /// # Safety
        ///
        /// For performance reasons, this method is unsafe.
        /// It is however fine since:
        /// - It is not publicly exposed.
        /// - `input` and `output` have the same known sizes.
        #[inline]
        unsafe fn substitution_box(input: &Trits, output: &mut Trits) {
            output.set_unchecked(0, truth_table_get(input, 0, HALF_STATE_LENGTH));

            for state_index in 0..HALF_STATE_LENGTH {
                let left_idx = HALF_STATE_LENGTH - state_index;
                let right_idx = STATE_LENGTH - state_index - 1;
                let state_index_2 = 2 * state_index;

                output.set_unchecked(state_index_2 + 1, truth_table_get(input, left_idx, right_idx));
                output.set_unchecked(state_index_2 + 2, truth_table_get(input, right_idx, left_idx - 1));
            }
        }

        let (lhs, rhs) = (&mut self.state, &mut self.work_state);

        for _ in 0..CURL_P_ROUNDS as usize {
            unsafe {
                substitution_box(lhs, rhs);
            }
            core::mem::swap(lhs, rhs);
        }
    }

    /// Resets the internal state by overwriting it with zeros.
    pub fn reset(&mut self) {
        self.state.fill(Btrit::Zero);
    }

    /// Absorbs `input` into the sponge by copying `HASH_LENGTH` chunks of it into its internal state and transforming
    /// the state before moving on to the next chunk.
    ///
    /// If `input` is not a multiple of `HASH_LENGTH` with the last chunk having `n < HASH_LENGTH` trits, the last chunk
    /// will be copied to the first `n` slots of the internal state. The remaining data in the internal state is then
    /// just the result of the last transformation before the data was copied, and will be reused for the next
    /// transformation.
    pub fn absorb(&mut self, input: &Trits) {
        for chunk in input.chunks(HASH_LENGTH) {
            self.state[0..chunk.len()].copy_from(chunk);
            self.transform();
        }
    }

    /// Squeezes the sponge by copying the state into the provided `buf`. This will fill the buffer in chunks of
    /// `HASH_LENGTH` at a time.
    ///
    /// If the last chunk is smaller than `HASH_LENGTH`, then only the fraction that fits is written into it.
    pub fn squeeze_into(&mut self, buf: &mut Trits) {
        for chunk in buf.chunks_mut(HASH_LENGTH) {
            chunk.copy_from(&self.state[0..chunk.len()]);
            self.transform()
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
