// Copyright 2020 IOTA Stiftung
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
    loop {
        let i = rand::random::<usize>() % bs.len();
        let b = bs[i];
        bs[i] = rand::random();
        if b != bs[i] && rand::random() {
            break;
        }
    }
}
