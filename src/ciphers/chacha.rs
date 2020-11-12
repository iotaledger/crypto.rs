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

use crate::Error;

use chacha20poly1305::aead::{AeadMutInPlace, NewAead};

pub const XCHACHA20POLY1305_KEY_SIZE: usize = 32;
pub const XCHACHA20POLY1305_NONCE_SIZE: usize = 24;
pub const XCHACHA20POLY1305_TAG_SIZE: usize = 16;

pub fn xchacha20poly1305_encrypt(
    ciphertext: &mut [u8],
    tag: &mut [u8; XCHACHA20POLY1305_TAG_SIZE],
    plain: &[u8],
    key: &[u8; XCHACHA20POLY1305_KEY_SIZE],
    nonce: &[u8; XCHACHA20POLY1305_NONCE_SIZE],
    associated_data: &[u8],
) -> crate::Result<()> {
    if plain.len() > ciphertext.len() {
        return Err(Error::BufferSize{ needs:plain.len(), has: ciphertext.len()});
    }
    ciphertext.copy_from_slice(plain);

    let k = chacha20poly1305::Key::from_slice(key);
    let n = chacha20poly1305::XNonce::from_slice(nonce);
    let mut c = chacha20poly1305::XChaCha20Poly1305::new(k);
    match c.encrypt_in_place_detached(n, associated_data, ciphertext) {
        Ok(t) => {
            tag.copy_from_slice(t.as_slice());
            Ok(())
        }
        Err(_) => Err(Error::CipherError { alg: "xchacha20poly1305_encrypt" })
    }
}
