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

#[cfg(feature = "blake2b")]
mod test {
    use crypto::blake2b;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct TestVector {
        hash: String,
        #[serde(rename = "in")]
        input: String,
        key: String,
        out: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        out_256: Option<String>,
    }

    #[test]
    fn blake2b_simd_lib() {
        // uses blake2b testvectors from the official testvectors at https://github.com/BLAKE2/BLAKE2/tree/master/testvectors
        // out_256 was generated with b2sum on inputs without key
        let test_vectors: Vec<TestVector> = serde_json::from_str(include_str!("blake2b.json")).unwrap();
        let mut test_num = 0u64;
        for vector in test_vectors.iter() {
            test_num += 1;
            let input = hex::decode(&vector.input).unwrap();
            let mut params = blake2b_simd::Params::new();

            if !vector.key.is_empty() {
                params.key(&hex::decode(&vector.key).unwrap());
            }

            let hash = params.hash(&input);
            assert_eq!(hex::decode(vector.out.clone()).unwrap(), hash.as_bytes());

            if vector.key.is_empty() && vector.out_256.is_some() {
                let hash_256 = params.hash_length(32).hash(&input);
                assert_eq!(
                    hex::decode(vector.out_256.as_ref().unwrap()).unwrap(),
                    hash_256.as_bytes()
                );
            }
        }
        assert_eq!(512, test_num);
    }

    #[test]
    fn iota_cypto_blake2b_256() {
        let test_vectors: Vec<TestVector> = serde_json::from_str(include_str!("blake2b.json")).unwrap();
        let mut test_num = 0u64;
        for vector in test_vectors.iter().filter(|v| v.key.is_empty() && v.out_256.is_some()) {
            test_num += 1;
            let input = hex::decode(&vector.input).unwrap();
            let mut output_256: [u8; 32] = [0; 32];
            blake2b::hash(&input, &mut output_256);
            assert_eq!(hex::decode(vector.out_256.as_ref().unwrap()).unwrap(), output_256);
        }
        assert_eq!(256, test_num);
    }
}
