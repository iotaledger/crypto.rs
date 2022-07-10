extern crate alloc;

use serde::{Deserialize, Serialize};

use alloc::vec::Vec;
use core::default::Default;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Segment {
    pub hardened: bool,
    pub i: u32,
}

impl Segment {
    pub fn from_u32(i: u32) -> Self {
        Self {
            hardened: i >= Self::HARDEN_MASK,
            i, // ser32(i)
        }
    }

    pub fn hardened(&self) -> bool {
        self.hardened
    }

    pub(crate) fn is_normal(&self) -> bool {
        self.i & Self::HARDEN_MASK == 0
    }

    pub fn bs(&self) -> [u8; 4] {
        self.i.to_be_bytes()
    }

    pub const HARDEN_MASK: u32 = 1 << 31;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chain(pub Vec<Segment>);

impl Chain {
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn from_u32<I: IntoIterator<Item = u32>>(is: I) -> Self {
        Self(is.into_iter().map(Segment::from_u32).collect())
    }

    pub fn from_u32_hardened<I: IntoIterator<Item = u32>>(is: I) -> Self {
        Self::from_u32(is.into_iter().map(|i| Segment::HARDEN_MASK | i))
    }

    pub fn join<O: AsRef<Chain>>(&self, o: O) -> Self {
        let mut ss = self.0.clone();
        ss.extend_from_slice(&o.as_ref().0);
        Self(ss)
    }

    pub fn segments(&self) -> Vec<Segment> {
        self.0.clone()
    }
}

impl Default for Chain {
    fn default() -> Self {
        Chain::empty()
    }
}

impl AsRef<Chain> for Chain {
    fn as_ref(&self) -> &Self {
        self
    }
}
