// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// https://en.bitcoin.it/wiki/BIP_0039
// https://raw.githubusercontent.com/bip32JP/bip32JP.github.io/master/test_JP_BIP39.json

// https://doc.rust-lang.org/std/primitive.str.html
// "String slices are always valid UTF-8."
type Mnemonic = str;
type Passphrase = str;
type Seed = [u8; 64];

pub fn mnemonic_to_seed(_m: &Mnemonic, _p: &Passphrase, _s: &mut Seed) -> crate::Result<()> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestVector {
        mnemonic: &'static str,
        passphrase: &'static str,
        seed: &'static str,
    }

    #[test]
    fn test_vectors() -> crate::Result<()> {
        Ok(())
    }
}
