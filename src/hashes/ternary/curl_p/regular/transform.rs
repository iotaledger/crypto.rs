// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
use super::{u256::U256, HASH_LENGTH};

use lazy_static::lazy_static;

use core::convert::TryInto;

const NUM_ROUNDS: usize = 81;
const ROTATION_OFFSET: usize = 364;
const STATE_SIZE: usize = HASH_LENGTH * 3;

#[derive(Clone, Copy)]
struct StateRotation {
    offset: usize,
    shift: u8,
}

lazy_static! {
    static ref STATE_ROTATIONS: [StateRotation; NUM_ROUNDS] = {
        let mut rotation = ROTATION_OFFSET;

        let mut state_rotations = [StateRotation { offset: 0, shift: 0 }; NUM_ROUNDS];

        for state_rotation in &mut state_rotations {
            state_rotation.offset = rotation / HASH_LENGTH;
            // This is fine since `HASH_LENGTH <= u8::MAX`.
            state_rotation.shift = (rotation % HASH_LENGTH).try_into().unwrap();
            rotation = (rotation * ROTATION_OFFSET) % STATE_SIZE;
        }

        state_rotations
    };
}

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

fn batch_box(x_p: u64, x_n: u64, y_p: u64, y_n: u64) -> (u64, u64) {
    let tmp = x_n ^ y_p;
    (tmp & !x_p, !tmp & !(x_p ^ y_n))
}

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
