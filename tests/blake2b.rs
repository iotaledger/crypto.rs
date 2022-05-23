// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "blake2b")]
mod test {
    use blake2::Blake2bVar;
    use crypto::hashes::blake2b;
    use digest::{Digest, Update, VariableOutput};
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
        #[serde(skip_serializing_if = "Option::is_none")]
        out_160: Option<String>,
    }

    fn variable_blake2b(input: &[u8], key: &str, size: usize) -> Option<Vec<u8>> {
        let mut digest: Blake2bVar = if key.is_empty() {
            Blake2bVar::new(size).unwrap()
        } else {
            // We don't handle test cases with a key.
            // Currently there does not seem to exist an easy solution to create
            // [`Blake2bVar`] with a key. See:
            // https://github.com/RustCrypto/hashes/issues/360
            return None;
        };
        let mut output: Vec<u8> = vec![0; size];
        digest.update(input);
        digest.finalize_variable(&mut output).unwrap();
        Some(output)
    }

    #[test]
    fn blake2b_lib() {
        // uses blake2b testvectors from the official testvectors at https://github.com/BLAKE2/BLAKE2/tree/master/testvectors
        // out_256 and out_160 was generated with b2sum on inputs without key
        let test_vectors: Vec<TestVector> = serde_json::from_str(include_str!("fixtures/blake2b.json")).unwrap();
        let mut test_num = 0u64;
        for vector in test_vectors.iter() {
            test_num += 1;
            let input = hex::decode(&vector.input).unwrap();
            if let Some(test_vec) = variable_blake2b(&input, &vector.key, 64) {
                assert_eq!(hex::decode(vector.out.clone()).unwrap(), test_vec,);
            }
            if vector.key.is_empty() && vector.out_256.is_some() {
                if let Some(test_vec) = variable_blake2b(&input, &vector.key, 32) {
                    assert_eq!(hex::decode(vector.out_256.as_ref().unwrap()).unwrap(), test_vec,);
                }
            }
            if vector.key.is_empty() && vector.out_160.is_some() {
                if let Some(test_vec) = variable_blake2b(&input, &vector.key, 20) {
                    assert_eq!(hex::decode(vector.out_160.as_ref().unwrap()).unwrap(), test_vec,);
                }
            }
        }
        assert_eq!(512, test_num);
    }

    #[test]
    fn iota_cypto_blake2b_256() {
        let test_vectors: Vec<TestVector> = serde_json::from_str(include_str!("fixtures/blake2b.json")).unwrap();
        let mut test_num = 0u64;
        for vector in test_vectors.iter().filter(|v| v.key.is_empty() && v.out_256.is_some()) {
            test_num += 1;
            let input = hex::decode(&vector.input).unwrap();
            assert_eq!(
                hex::decode(vector.out_256.as_ref().unwrap()).unwrap(),
                blake2b::Blake2b256::digest(&input).to_vec(),
            );
        }
        assert_eq!(256, test_num);
    }

    #[test]
    fn iota_cypto_blake2b_160() {
        let test_vectors: Vec<TestVector> = serde_json::from_str(include_str!("fixtures/blake2b.json")).unwrap();
        let mut test_num = 0u64;
        for vector in test_vectors.iter().filter(|v| v.key.is_empty() && v.out_160.is_some()) {
            test_num += 1;
            let input = hex::decode(&vector.input).unwrap();
            assert_eq!(
                hex::decode(vector.out_160.as_ref().unwrap()).unwrap(),
                blake2b::Blake2b160::digest(&input).to_vec(),
            );
        }
        assert_eq!(256, test_num);
    }
}
