use std::fmt::{Debug, Display};
use std::string::{String, ToString};

/// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
pub(crate) trait DNSParameter
where
    Self: Sized,
{
    /// Integer type used by the DNSParameter type
    type INT: Sized + Debug + Display;

    /// returns associated integer
    fn get_integer(&self) -> Self::INT;

    /// returns associated mnemonic if possible
    fn get_mnemonic(&self) -> Option<&'static str>;

    /// converts integer into Self
    fn from_integer(value: Self::INT) -> Self;
    /// converts mnemonic str into Self if it exists
    fn from_mnemonic(value: &str) -> Option<Self>;

    /// representation of self used for fmt::Debug
    fn get_representation(&self) -> String;

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
