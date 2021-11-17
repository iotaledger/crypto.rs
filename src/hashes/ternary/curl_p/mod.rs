// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod batched;
mod regular;

pub use batched::{BatchHasher, BATCH_SIZE};
pub use regular::CurlP;
