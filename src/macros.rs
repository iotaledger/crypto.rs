#[macro_export]
macro_rules! impl_secret_debug {
    ($ty:ty) => {
        impl ::core::fmt::Debug for $ty {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                f.write_fmt(format_args!("{}(*Secret*)", stringify!($ty)))
            }
        }
    };
}
