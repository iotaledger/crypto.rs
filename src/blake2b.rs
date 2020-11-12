// Copyright 2020 IOTA Stiftung
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use blake2b_simd::Params;

pub fn hash(data: &[u8], output_buffer: &mut [u8]) {
    let hash = Params::new().hash_length(output_buffer.len()).hash(data);
    let hash_bytes = hash.as_bytes();
    output_buffer[..hash_bytes.len()].clone_from_slice(&hash_bytes[..]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils;
    use alloc::vec::Vec;

    const TEST_QUANTITY: usize = 1000;

    fn test_vector() -> Vec<Vec<u8>> {
        vec![test_utils::fresh::bytestring(); TEST_QUANTITY]
    }

    #[test]
    fn test_equal_data() {
        for data in test_vector() { 
            let mut output_1 = [0; 32];
            let mut output_2 = [1; 32];
            hash(data.as_slice(), &mut output_1);
            hash(data.clone().as_slice(), &mut output_2);
            assert_eq!(output_1, output_2);
        }
    }

    #[test]
    fn test_corrupted_data() {
        for mut data in test_vector() {
            // can't corrupt empty strings
            while data.len() == 0 {
                data.append(&mut test_utils::fresh::bytestring());
            }
            let mut output_before = [0; 32];
            hash(data.as_slice(), &mut output_before);
            
            test_utils::corrupt(&mut data[..]);
            let mut output_after = [0; 32];
            hash(data.as_slice(), &mut output_after);
            assert_ne!(output_before, output_after);
        }
    }

    #[test]
    fn test_different_data() {
        for data in test_vector(){
            let mut data_output = [0;32];
            hash(data.as_slice(), &mut data_output);
            let other = test_utils::fresh::bytestring();
            let mut other_output = [0;32];
            hash(other.as_slice(), &mut other_output);
            assert_eq!(data == other, data_output == other_output);
        }
    }
}
