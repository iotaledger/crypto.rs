#![cfg(feature = "sr25519")]

use crypto::signatures::sr25519::{DeriveJunction, KeyPair};
use hex_literal::hex;

#[test]
fn from_string() {
    let mnemonics = include!("fixtures/sr25519.rs");
    let message = b"crypto.rs";

    for mnemonic in mnemonics.iter() {
        let k = KeyPair::from_string(mnemonic, None).unwrap();
        let o = KeyPair::from_seed(&k.seed());
        assert_eq!(k.public_key(), o.public_key());
        let public_key = k.public_key();
        let signature = k.sign(&message[..]);
        assert!(public_key.verify(&signature, &message[..]));
    }
}

// taken from https://github.com/paritytech/substrate/blob/master/primitives/core/src/sr25519.rs
#[test]
fn derive_soft_should_work() {
    let pair = KeyPair::from_seed(&hex!(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    ));
    let derive_1 = pair.derive(Some(DeriveJunction::soft(1)).into_iter(), None).unwrap();
    let derive_1b = pair.derive(Some(DeriveJunction::soft(1)).into_iter(), None).unwrap();
    let derive_2 = pair.derive(Some(DeriveJunction::soft(2)).into_iter(), None).unwrap();
    assert_eq!(derive_1.public_key(), derive_1b.public_key());
    assert_ne!(derive_1.public_key(), derive_2.public_key());

    assert_eq!(derive_1.public_key(), KeyPair::from_seed(&derive_1.seed()).public_key());
    assert_eq!(
        derive_1b.public_key(),
        KeyPair::from_seed(&derive_1b.seed()).public_key()
    );
    assert_eq!(derive_2.public_key(), KeyPair::from_seed(&derive_2.seed()).public_key());
}

// taken from https://github.com/paritytech/substrate/blob/master/primitives/core/src/sr25519.rs
#[test]
fn derive_hard_should_work() {
    let pair = KeyPair::from_seed(&hex!(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    ));
    let derive_1 = pair.derive(Some(DeriveJunction::hard(1)).into_iter(), None).unwrap();
    let derive_1b = pair.derive(Some(DeriveJunction::hard(1)).into_iter(), None).unwrap();
    let derive_2 = pair.derive(Some(DeriveJunction::hard(2)).into_iter(), None).unwrap();
    assert_eq!(derive_1.public_key(), derive_1b.public_key());
    assert_ne!(derive_1.public_key(), derive_2.public_key());

    assert_eq!(derive_1.public_key(), KeyPair::from_seed(&derive_1.seed()).public_key());
    assert_eq!(
        derive_1b.public_key(),
        KeyPair::from_seed(&derive_1b.seed()).public_key()
    );
    assert_eq!(derive_2.public_key(), KeyPair::from_seed(&derive_2.seed()).public_key());
}

// taken from https://github.com/paritytech/substrate/blob/master/primitives/core/src/sr25519.rs
#[test]
fn derive_soft_public_should_work() {
    let pair = KeyPair::from_seed(&hex!(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    ));
    let path = Some(DeriveJunction::soft(1));
    let pair_1 = pair.derive(path.into_iter(), None).unwrap();
    let public_1 = pair.public_key().derive(path.into_iter()).unwrap();
    assert_eq!(pair_1.public_key(), public_1);
}

// taken from https://github.com/paritytech/substrate/blob/master/primitives/core/src/sr25519.rs
#[test]
fn derive_hard_public_should_fail() {
    let pair = KeyPair::from_seed(&hex!(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    ));
    let path = Some(DeriveJunction::hard(1));
    assert!(pair.public_key().derive(path.into_iter()).is_none());
}
