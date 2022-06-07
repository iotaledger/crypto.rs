// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Transform operations for the CurlP hasher.
//!
//! The documentation found here was copied from <https://github.com/iotaledger/iota.go/blob/legacy/curl/transform.go>.
use super::{u256::U256, HASH_LENGTH};

const NUM_ROUNDS: usize = 81;
const ROTATION_OFFSET: usize = 364;
const STATE_SIZE: usize = HASH_LENGTH * 3;

/// Type to store the chunk offset and the bit shift of the state after each round.
///
/// Since the modulo operations are rather costly, they are pre-computed in [`STATE_ROTATIONS`].
#[derive(Clone, Copy)]
struct StateRotation {
    offset: usize,
    shift: u8,
}

const STATE_ROTATIONS: [StateRotation; NUM_ROUNDS] = {
    let mut rotation = ROTATION_OFFSET;

    let mut state_rotations = [StateRotation { offset: 0, shift: 0 }; NUM_ROUNDS];

    let mut i = 0;

    while i < NUM_ROUNDS {
        state_rotations[i].offset = rotation / HASH_LENGTH;
        state_rotations[i].shift = {
            let shift = rotation % HASH_LENGTH;

            if shift > 255 {
                panic!("shift is too large");
            } else {
                shift as u8
            }
        };

        rotation = (rotation * ROTATION_OFFSET) % STATE_SIZE;

        i += 1;
    }

    state_rotations
};

/// Performs the Curl transformation.
///
/// According to the specification, one Curl round performs the following transformation:
///   for i ← 1 to 729
///     x ← S[1]
///     S ← rot(S)
///     y ← S[1]
///     N[i] ← g(x,y)
///   S ← N
/// Each element of the state S is combined with its rotated counterpart using the S-box g.  This is
/// equivalent to rotating just once and applying the S-box on the entire state:
///   N ← rot(S)
///   S ← g(S,N)
/// The only difference then is, that the trits are at the wrong position. Successive trits are now
/// an opposite rotation apart. This rotation offset adds up over the rounds and needs to be
/// reverted in the end.
pub(super) fn transform(p: &mut [U256; 3], n: &mut [U256; 3]) {
    for state_rotation in STATE_ROTATIONS.iter() {
        let (p2, n2) = rotate_state(p, n, state_rotation.offset, state_rotation.shift);

        for i in 0..3 {
            for j in 0..4 {
                let tmp = batch_box(p[i][j], n[i][j], p2[i][j], n2[i][j]);
                p[i][j] = tmp.0;
                n[i][j] = tmp.1;
            }
        }

        for i in 0..3 {
            p[i].clear_after_243();
            n[i].clear_after_243();
        }
    }

    reorder(p, n);
}

/// Rotates the Curl state by `offset * 243 + shift`.
///
/// It performs a left rotation of the state elements towards lower indices.
fn rotate_state(p: &[U256; 3], n: &[U256; 3], offset: usize, shift: u8) -> ([U256; 3], [U256; 3]) {
    let mut p2 = <[U256; 3]>::default();
    let mut n2 = <[U256; 3]>::default();

    macro_rules! rotate {
        ($p:expr, $p2:expr, $i:expr) => {
            $p2[$i]
                .shr_into(&$p[($i + offset) % 3], shift)
                .shl_into(&$p[(($i + 1) + offset) % 3], 243 - shift);
        };
    }

    for i in 0..3 {
        rotate!(p, p2, i);
        rotate!(n, n2, i);
    }

    (p2, n2)
}

/// Applies the Curl S-box on `64` trits encoded as positive and negative bits.
fn batch_box(x_p: u64, x_n: u64, y_p: u64, y_n: u64) -> (u64, u64) {
    let tmp = x_n ^ y_p;
    (tmp & !x_p, !tmp & !(x_p ^ y_n))
}

/// Arranges the state so that the trit at index `(244 * k) % 729` becomes the trit at index `k`.
///
/// Since the state is organized as `3` chunks of `243` trits each, the 1st output trit lies at
/// index `(0, 0)`, 2nd at `(1, 1)`, 3rd at `(2, 2)`, 4th at `(0, 3)`, 5th at `(1, 4)`...  Thus, in
/// order to rearrange the 1st chunk, copy trits 3*k from the 1st chunk, trits `3*  k + 1` from the
/// 2nd chunk and trits `3 * k + 2` from the 3rd chunk.
fn reorder(p: &mut [U256; 3], n: &mut [U256; 3]) {
    const M0: u64 = 0x9249249249249249;
    const M1: u64 = M0 << 1;
    const M2: u64 = M0 << 2;

    let mut p2 = <[U256; 3]>::default();
    let mut n2 = <[U256; 3]>::default();

    for i in 0..3 {
        macro_rules! compute {
            ($p:expr, $p2:expr, $j:expr, $m0:expr, $m1:expr, $m2:expr) => {
                $p2[i][$j] = ($p[i][$j] & $m0) | ($p[(1 + i) % 3][$j] & $m1) | ($p[(2 + i) % 3][$j] & $m2);
            };
        }

        compute!(p, p2, 0, M0, M1, M2);
        compute!(p, p2, 1, M2, M0, M1);
        compute!(p, p2, 2, M1, M2, M0);
        compute!(p, p2, 3, M0, M1, M2);

        compute!(n, n2, 0, M0, M1, M2);
        compute!(n, n2, 1, M2, M0, M1);
        compute!(n, n2, 2, M1, M2, M0);
        compute!(n, n2, 3, M0, M1, M2);
    }

    *p = p2;
    *n = n2;
}
