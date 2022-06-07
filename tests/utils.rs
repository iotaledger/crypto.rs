// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

pub mod fresh {
    use super::*;

    pub fn bytestring() -> Vec<u8> {
        let s = if rand::random::<u8>() % 4 == 0 {
            0
        } else {
            rand::random::<usize>() % 4096
        };

        let mut bs = Vec::with_capacity(s);
        for _ in 1..s {
            bs.push(rand::random());
        }
        bs
    }

    pub fn non_empty_bytestring() -> Vec<u8> {
        let s = (rand::random::<usize>() % 4096) + 1;
        let mut bs = Vec::with_capacity(s);
        for _ in 1..s {
            bs.push(rand::random());
        }
        bs
    }
}

pub fn corrupt(bs: &mut [u8]) {
    if bs.is_empty() {
        return;
    }
    loop {
        let i = rand::random::<usize>() % bs.len();
        let b = bs[i];
        bs[i] = rand::random();
        if b != bs[i] && rand::random() {
            break;
        }
    }
}
