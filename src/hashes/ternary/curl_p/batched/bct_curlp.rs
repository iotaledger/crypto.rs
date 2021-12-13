// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::hashes::ternary::{
    curl_p::{
        batched::{
            bct::{BcTrit, BcTritArr, BcTrits},
            HIGH_BITS, NUM_ROUNDS,
        },
        SpongeDirection,
    },
    HASH_LENGTH,
};

pub(crate) struct BctCurlP {
    state: BcTritArr<{ 3 * HASH_LENGTH }>,
    state_copy: BcTritArr<{ 3 * HASH_LENGTH }>,
    direction: SpongeDirection,
}

impl BctCurlP {
    #[allow(clippy::assertions_on_constants)]
    pub(crate) fn new() -> Self {
        // Ensure that changing the hash length will not cause undefined behaviour.
        assert!(3 * HASH_LENGTH > 728);
        Self {
            state: BcTritArr::filled(HIGH_BITS),
            state_copy: BcTritArr::filled(HIGH_BITS),
            direction: SpongeDirection::Absorb,
        }
    }

    pub(crate) fn reset(&mut self) {
        self.state.fill(HIGH_BITS);
        self.direction = SpongeDirection::Absorb;
    }

    pub(crate) fn transform(&mut self) {
        #[inline(always)]
        pub(crate) fn sbox(x_lo: usize, x_hi: usize, y_lo: usize, y_hi: usize) -> BcTrit {
            let d = x_hi ^ y_lo;
            BcTrit(!(d & x_lo), d | (x_lo ^ y_hi))
        }

        let mut scratch_pad_index = 0;

        // All the unchecked accesses here are guaranteed to be safe by the assertion inside `new`.
        for _round in 0..NUM_ROUNDS as usize {
            core::mem::swap(&mut self.state, &mut self.state_copy);

            let BcTrit(mut lo, mut hi) = unsafe { *self.state_copy.get_unchecked(scratch_pad_index) };

            scratch_pad_index += 364;

            let mut temp = unsafe { *self.state_copy.get_unchecked(scratch_pad_index) };

            *unsafe { self.state.get_unchecked_mut(0) } = sbox(lo, hi, temp.lo(), temp.hi());

            let mut state_index = 1;

            while state_index < self.state.len() {
                scratch_pad_index += 364;

                lo = temp.lo();
                hi = temp.hi();
                temp = unsafe { *self.state_copy.get_unchecked(scratch_pad_index) };

                *unsafe { self.state.get_unchecked_mut(state_index) } = sbox(lo, hi, temp.lo(), temp.hi());

                state_index += 1;

                scratch_pad_index -= 365;

                lo = temp.lo();
                hi = temp.hi();
                temp = unsafe { *self.state_copy.get_unchecked(scratch_pad_index) };

                *unsafe { self.state.get_unchecked_mut(state_index) } = sbox(lo, hi, temp.lo(), temp.hi());

                state_index += 1;
            }
        }
    }

    pub(crate) fn absorb(&mut self, bc_trits: &BcTrits) {
        let mut length = bc_trits.len();

        assert!(
            length % HASH_LENGTH == 0,
            "trits slice length must be multiple of {}",
            HASH_LENGTH
        );

        let mut offset = 0;

        if let SpongeDirection::Squeeze = self.direction {
            panic!("absorb after squeeze");
        }

        loop {
            let length_to_copy = length.min(HASH_LENGTH);
            // This is safe as `length_to_copy <= HASH_LENGTH`.
            unsafe { self.state.get_unchecked_mut(0..length_to_copy) }
                .copy_from_slice(unsafe { bc_trits.get_unchecked(offset..offset + length_to_copy) });

            self.transform();

            if length <= length_to_copy {
                break;
            } else {
                offset += length_to_copy;
                length -= length_to_copy;
            }
        }
    }

    fn squeeze_aux(&mut self, chunk: &mut BcTrits) {
        if let SpongeDirection::Squeeze = self.direction {
            self.transform();
        }

        self.direction = SpongeDirection::Squeeze;

        chunk.copy_from_slice(unsafe { self.state.get_unchecked(0..HASH_LENGTH) });
    }

    // This method shouldn't assume that `result` has any particular content, just that it has an
    // adequate size.
    pub(crate) fn squeeze_into(&mut self, result: &mut BcTrits) {
        let trit_count = result.len();

        assert!(
            trit_count % HASH_LENGTH == 0,
            "trits slice length must be multiple of {}",
            HASH_LENGTH
        );

        let hash_count = trit_count / HASH_LENGTH;

        for i in 0..hash_count {
            self.squeeze_aux(unsafe { result.get_unchecked_mut(i * HASH_LENGTH..(i + 1) * HASH_LENGTH) });
        }
    }
}
