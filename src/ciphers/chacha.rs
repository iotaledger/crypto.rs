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

pub mod xchacha20poly1305 {
    use super::*;

    pub const XCHACHA20POLY1305_KEY_SIZE: usize = 32;
    pub const XCHACHA20POLY1305_NONCE_SIZE: usize = 24;
    pub const XCHACHA20POLY1305_TAG_SIZE: usize = 16;

    pub fn encrypt(
        ciphertext: &mut [u8],
        tag: &mut [u8; XCHACHA20POLY1305_TAG_SIZE],
        plaintext: &[u8],
        key: &[u8; XCHACHA20POLY1305_KEY_SIZE],
        nonce: &[u8; XCHACHA20POLY1305_NONCE_SIZE],
        associated_data: &[u8],
    ) -> crate::Result<()> {
        if plaintext.len() > ciphertext.len() {
            return Err(Error::BufferSize{ needs: plaintext.len(), has: ciphertext.len() });
        }
        ciphertext.copy_from_slice(plaintext);

        let k = chacha20poly1305::Key::from_slice(key);
        let n = chacha20poly1305::XNonce::from_slice(nonce);
        let mut c = chacha20poly1305::XChaCha20Poly1305::new(k);
        match c.encrypt_in_place_detached(n, associated_data, ciphertext) {
            Ok(t) => {
                tag.copy_from_slice(t.as_slice());
                Ok(())
            }
            Err(_) => Err(Error::CipherError { alg: "xchacha20poly1305::encrypt" })
        }
    }

    pub fn decrypt(
        plaintext: &mut [u8],
        ciphertext: &[u8],
        key: &[u8; XCHACHA20POLY1305_KEY_SIZE],
        tag: &[u8; XCHACHA20POLY1305_TAG_SIZE],
        nonce: &[u8; XCHACHA20POLY1305_NONCE_SIZE],
        associated_data: &[u8],
    ) -> crate::Result<()> {
        if ciphertext.len() > plaintext.len() {
            return Err(Error::BufferSize{ needs: ciphertext.len(), has: plaintext.len()});
        }
        plaintext.copy_from_slice(ciphertext);

        let k = chacha20poly1305::Key::from_slice(key);
        let n = chacha20poly1305::XNonce::from_slice(nonce);
        let t = chacha20poly1305::Tag::from_slice(tag);
        let mut c = chacha20poly1305::XChaCha20Poly1305::new(k);
        c.decrypt_in_place_detached(n, associated_data, plaintext, t).map_err(|_| {
            Error::CipherError { alg: "xchacha20poly1305::decrypt" }
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        // https://tools.ietf.org/html/draft-arciszewski-xchacha-03#appendix-A.3
        #[test]
        fn test_vector_ietf_draft() -> crate::Result<()> {
            let plaintext = hex::decode("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e").unwrap();
            let associated_data = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();

            let mut key = [0; XCHACHA20POLY1305_KEY_SIZE];
            hex::decode_to_slice("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", &mut key as &mut [u8]).unwrap();
            let mut nonce = [0; XCHACHA20POLY1305_NONCE_SIZE];
            hex::decode_to_slice("404142434445464748494a4b4c4d4e4f5051525354555657", &mut nonce as &mut [u8]).unwrap();

            let expected_ciphertext = hex::decode("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e").unwrap();
            let _expected_poly1305_key = hex::decode("7b191f80f361f099094f6f4b8fb97df847cc6873a8f2b190dd73807183f907d5").unwrap();
            let expected_tag = hex::decode("c0875924c1c7987947deafd8780acf49").unwrap();

            let mut ciphertext = vec![0; plaintext.len()];
            let mut tag = [0; XCHACHA20POLY1305_TAG_SIZE];

            encrypt(&mut ciphertext, &mut tag, &plaintext, &key, &nonce, &associated_data)?;
            assert_eq!(expected_ciphertext, ciphertext);
            assert_eq!(expected_tag, tag);

            let mut decrypted_plain_text = vec![0; ciphertext.len()];
            decrypt(&mut decrypted_plain_text, &ciphertext, &key, &tag, &nonce, &associated_data)?;
            assert_eq!(decrypted_plain_text, plaintext);

            Ok(())
        }
    }
}
