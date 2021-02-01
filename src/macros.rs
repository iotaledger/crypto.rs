// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(unused_macros)]

macro_rules! assert_buffer {
    ($has:expr, $needs:expr, $expr:expr) => {{
        if !($expr) {
            return Err($crate::Error::BufferSize {
                needs: $needs,
                has: $has,
            });
        }
    }};
}

macro_rules! assert_buffer_lte {
    ($length:expr, $maximum:expr) => {{
        assert_buffer!($length, $maximum, $length <= $maximum)
    }};
}

macro_rules! assert_buffer_gte {
    ($length:expr, $minimum:expr) => {{
        assert_buffer!($length, $minimum, $length >= $minimum)
    }};
}

#[cfg(test)]
mod tests {
    fn test_assert_lte(length: usize, minimum: usize) -> crate::Result<()> {
        assert_buffer_lte!(length, minimum);
        Ok(())
    }

    fn test_assert_gte(length: usize, maximum: usize) -> crate::Result<()> {
        assert_buffer_gte!(length, maximum);
        Ok(())
    }

    #[test]
    fn test_assert_buffer_lte() {
        assert!(test_assert_lte(0, 16).is_ok());
        assert!(test_assert_lte(15, 16).is_ok());
        assert!(test_assert_lte(16, 16).is_ok());
        assert!(test_assert_lte(17, 16).is_err());
        assert!(test_assert_lte(255, 16).is_err());
    }

    #[test]
    fn test_assert_buffer_gte() {
        assert!(test_assert_gte(0, 16).is_err());
        assert!(test_assert_gte(15, 16).is_err());
        assert!(test_assert_gte(16, 16).is_ok());
        assert!(test_assert_gte(17, 16).is_ok());
        assert!(test_assert_gte(255, 16).is_ok());
    }
}
