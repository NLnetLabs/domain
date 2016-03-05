
#[macro_export]
macro_rules! dname {
    ( $( $x:expr ),* ) => {
        {
            let mut res = $crate::name::DomainNameBuf::new();
            $(
                res.push_normal($x).unwrap();
            )*
            res
        }
    };
}



