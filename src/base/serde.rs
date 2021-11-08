//! Traits, types, and functions helping with implementing serialization.
#![cfg(feature = "serde")]

/*
use super::octets::DeserializeOctets;
use core::marker::PhantomData;
use core::fmt;
use serde::de::{Deserializer, Visitor};


//------------ OctetsNewtypeVisitor ------------------------------------------

pub struct OctetsNewtypeVisitor<Octets>(PhantomData<Octets>);

impl<Octets> OctetsNewtypeVisitor<Octets> {
    pub fn new() -> Self {
        OctetsNewtypeVisitor(PhantomData)
    }
}

impl<'de, Octets> Visitor<'de> for OctetsNewtypeVisitor<Octets>
where
    Octets: DeserializeOctets<'de>,
{
    type Value = Octets;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("an octets sequence")
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(
        self,
        deserializer: D
    ) -> Result<Self::Value, D::Error> {
        Octets::deserialize_octets(deserializer)
    }
}
*/
