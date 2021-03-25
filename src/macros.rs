// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(unused_macros)]

macro_rules! assert_buffer {
    ($has:expr, $needs:expr, $expr:expr, $name:expr) => {{
        if !($expr) {
            return Err($crate::Error::BufferSize {
                name: $name,
                needs: $needs,
                has: $has,
            });
        }
    }};
}

macro_rules! assert_buffer_eq {
    ($length:expr, $target:expr, $name:expr) => {{
        assert_buffer!($length, $target, $length == $target, $name)
    }};
}

macro_rules! assert_buffer_lte {
    ($length:expr, $maximum:expr, $name:expr) => {{
        assert_buffer!($length, $maximum, $length <= $maximum, $name)
    }};
}

macro_rules! assert_buffer_gte {
    ($length:expr, $minimum:expr, $name:expr) => {{
        assert_buffer!($length, $minimum, $length >= $minimum, $name)
    }};
}

#[cfg(test)]
mod tests {
    fn test_assert_eq(length: usize, target: usize) -> crate::Result<()> {
        assert_buffer_eq!(length, target, "buffer");
        Ok(())
    }

    fn test_assert_lte(length: usize, minimum: usize) -> crate::Result<()> {
        assert_buffer_lte!(length, minimum, "buffer");
        Ok(())
    }

    fn test_assert_gte(length: usize, maximum: usize) -> crate::Result<()> {
        assert_buffer_gte!(length, maximum, "buffer");
        Ok(())
    }

    #[test]
    fn test_assert_buffer_eq() {
        assert!(test_assert_eq(0, 16).is_err());
        assert!(test_assert_eq(15, 16).is_err());
        assert!(test_assert_eq(16, 16).is_ok());
        assert!(test_assert_eq(17, 16).is_err());
        assert!(test_assert_eq(255, 16).is_err());
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
