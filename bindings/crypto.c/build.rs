// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use cbindgen;
use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    // use cbindgen.toml instead of Builder
    cbindgen::generate(&crate_dir)
        .unwrap()
        .write_to_file("iota_crypto.h");
    
    // classic style
    /*
    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("bindings.h");
    */
}
