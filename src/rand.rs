// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub fn fill(bs: &mut [u8]) -> crate::Result<()> {
    getrandom::getrandom(bs).map_err(|e| crate::Error::SystemError {
        call: "getrandom::getrandom",
        raw_os_error: e.raw_os_error(),
    })
}

pub unsafe fn gen<T>() -> crate::Result<T> {
    let mut t = core::mem::MaybeUninit::uninit();
    fill(core::slice::from_raw_parts_mut(t.as_mut_ptr() as *mut u8, core::mem::size_of::<T>()))?;
    Ok(t.assume_init())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    #[should_panic]
    fn verify_check_uniform_dist() {
        check_uniform_dist(&[0; (4 * 1024 * 1024) + 15])
    }
}
