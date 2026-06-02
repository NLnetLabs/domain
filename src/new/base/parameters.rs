use alloc::string::{String, ToString};
use core::fmt;

/// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
pub(crate) trait DNSParameter
where
    Self: Sized,
{
    /// Integer type used by the DNSParameter type
    type INT: Sized + fmt::Debug + fmt::Display;

    /// returns associated integer
    fn get_integer(&self) -> Self::INT;

    /// returns associated mnemonic if possible
    fn get_mnemonic(&self) -> Option<&'static str>;

    /// converts integer into Self
    fn from_integer(value: Self::INT) -> Self;
    /// converts mnemonic str into Self if it exists
    fn from_mnemonic(value: &str) -> Option<Self>;

    /// representation of self used for fmt::Debug
    fn debug_impl(&self) -> String;

    /// redirects to the desired fmt::Display implementation function
    fn display_impl(&self) -> String;

    //--- Default implementations --------------------------------------------

    /// displays the DNSParameter as an integer
    fn display_integer(&self) -> String {
        format!("{}", self.get_integer())
    }

    /// displays the DNSParameter as mnemonic otherwise integer
    fn display_mnemonic_fallback_integer(&self) -> String {
        match Self::get_mnemonic(self) {
            Some(m) => m.to_string(),
            None => self.display_integer(),
        }
    }
}

/// Macro which replaces the boilerplate implementation for all the IANA
/// macros
macro_rules! dns_parameter_impl {
    ( $(#[$attr:meta])* =>
      $struct_name:ident, $int_type:ident; ) => {
        //--- Conversion to and from 'u8'
        impl From<u8> for $struct_name {
            fn from(value: $int_type) -> Self {
                Self::from_integer(value)
            }
        }

        impl From<$struct_name> for $int_type {
            fn from(value: $struct_name) -> Self {
                $struct_name::get_integer(&value)
            }
        }

        //--- fmt::Debug implementation
        impl fmt::Debug for $struct_name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.debug_impl())
            }
        }

        //--- fmt::Display implementation
        impl fmt::Display for $struct_name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.display_impl())
            }
        }
    };
}

//----------- OpCode ---------------------------------------------------------
/// The type of a record.
///
/// Operation Code (OpCode)
///
/// IANA Assignments can be found under [DNS OpCodes].
///
/// [DNS OpCodes]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
#[derive(Copy, Clone, PartialEq)]
pub struct OpCode {
    /// The operation code
    pub code: u8,
}

impl OpCode {
    /// Create a new [`OpCode`].
    pub const fn new(value: u8) -> Self {
        Self { code: value }
    }

    /// Query [RFC1035](https://www.iana.org/go/rfc1035)
    pub const QUERY: Self = Self::new(0);

    /// IQuery (Inverse Query, OBSOLETE)
    /// [RFC3425](https://www.iana.org/go/rfc3425)
    pub const IQUERY: Self = Self::new(1);

    /// Status [RFC1035](https://www.iana.org/go/rfc1035)
    pub const STATUS: Self = Self::new(2);

    /// Notify [RFC1996](https://www.iana.org/go/rfc1996)
    pub const NOTIFY: Self = Self::new(4);

    /// Update [RFC2136](https://www.iana.org/go/rfc2136)
    pub const UPDATE: Self = Self::new(5);

    /// DNS Stateful Operations (DSO)
    /// [RFC8490](https://www.iana.org/go/rfc8490)
    pub const DSO: Self = Self::new(6);

    /// Contains all Constants in a tuple (<NAME>, <VALUE>).
    /// Should be generated automatically
    const MAGIC_LIST: [(&'static str, u8); 6] = [
        ("QUERY", 0),
        ("IQUERY", 1),
        ("STATUS", 2),
        ("NOTIFY", 4),
        ("UPDATE", 5),
        ("DSO", 6),
    ];
}

//--- DNSParameter
impl DNSParameter for OpCode {
    type INT = u8;
    fn from_integer(value: Self::INT) -> Self {
        OpCode { code: value }
    }
    fn from_mnemonic(_: &str) -> Option<Self> {
        // `OpCode`s do not have mnemonics
        None
    }
    fn get_integer(&self) -> Self::INT {
        self.code
    }
    fn get_mnemonic(&self) -> Option<&'static str> {
        // `OpCode`s do not have mnemonics
        None
    }
    fn debug_impl(&self) -> String {
        match Self::MAGIC_LIST.iter().find(|e| e.1 == self.get_integer()) {
            Some(r) => format!("OpCode::{}", r.0),
            _ => format!("OpCode({})", self.get_integer()),
        }
    }
    fn display_impl(&self) -> String {
        self.display_integer()
    }
}

dns_parameter_impl! {=> OpCode, u8;}
