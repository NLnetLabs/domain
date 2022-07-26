//! Path scoped macros.

/// Shortcircuits a `Result<Option<T>, E>` into a `T`.
#[macro_export]
macro_rules! try_opt {
    ($expr:expr $(,)?) => {
        match $expr {
            core::result::Result::Ok(core::option::Option::Some(val)) => val,
            core::result::Result::Ok(core::option::Option::None) => {
                return core::result::Result::Ok(core::option::Option::None);
            }
            core::result::Result::Err(err) => {
                return core::result::Result::Err(
                    core::convert::From::from(err)
                );
            }
        }
    };
}

