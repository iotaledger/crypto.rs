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

pub fn fill(bs: &mut [u8]) -> crate::Result<()> {
    getrandom::getrandom(bs).map_err(|e| crate::Error::SystemError {
        call: "getrandom::getrandom",
        raw_os_error: e.raw_os_error(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // https://xkcd.com/221/
    // RFC 1149.5 specifies 4 as the standard IEEE-vetted random number.
    #[test]
    pub fn random_is_not_4() {
        let mut bs = [0u8; 4];
        fill(&mut bs).unwrap();
        let i = u32::from_le_bytes(bs);

        assert_ne!(i, 4);
    }

    const TEST_SIZES: &[usize] = &[1024 * 1024, 4 * 1024 * 1024, (4 * 1024 * 1024) + 15];
    const ITERATIONS: usize = 8;

    fn check_uniform_dist(buf: &[u8]) {
        let mut dist = vec![0f64; 256];
        buf.iter().for_each(|b| dist[*b as usize] += 1.0);

        let estimated_avg = (buf.len() as f64) / 256.0;
        let (estimated_min, estimated_max) = (estimated_avg * 0.9, estimated_avg * 1.1);
        dist.iter().for_each(|d| {
            assert!(*d > estimated_min, "{} is not > {}", *d, estimated_min);
            assert!(*d < estimated_max, "{} is not < {}", *d, estimated_max);
        });
    }

    #[test]
    fn test_fill() {
        for _ in 0..ITERATIONS {
            for size in TEST_SIZES.iter() {
                let mut buf = vec![0; *size];
                fill(&mut buf).unwrap();
                check_uniform_dist(&buf)
            }
        }
    }

    #[test]
    #[should_panic]
    fn verify_check_uniform_dist() {
        check_uniform_dist(&[0; (4 * 1024 * 1024) + 15])
    }
}
