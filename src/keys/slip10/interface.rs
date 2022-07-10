use super::{Chain, Key, Segment};

pub trait PrivateKey<T> {
    type SecretKey;

    fn secret_key(&self) -> crate::Result<Self::SecretKey>;

    fn child_key(&self, segment: Segment) -> crate::Result<Key>;

    fn derive(&self, chain: &Chain) -> crate::Result<Key>;
}
