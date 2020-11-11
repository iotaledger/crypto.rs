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
