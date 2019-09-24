//! Assembling wire-format DNS data.

#[cfg(feature = "std")] use std::vec::Vec;
#[cfg(feature = "bytes")] use bytes::BytesMut;
use crate::name::ToDname;
use crate::net::{Ipv4Addr, Ipv6Addr};
use crate::octets::OctetsBuilder;

//------------ Re-exported for your convenience ------------------------------

pub use crate::parse::ShortBuf;


//------------ ComposeTarget -------------------------------------------------

pub trait ComposeTarget: OctetsBuilder {
}

impl<T: OctetsBuilder> ComposeTarget for T { }


//------------ Compose -------------------------------------------------------

/// A type that knows how to compose itself.
///
/// The term ‘composing’ refers to the process of creating a DNS wire-format
/// representation of a value’s data.
pub trait Compose {
    fn compose<T: ComposeTarget + ?Sized>(&self, target: &mut T);

    fn compose_canonical<T: ComposeTarget + ?Sized>(&self, target: &mut T) {
        self.compose(target)
    }
}

impl<'a, C: Compose + ?Sized> Compose for &'a C {
    fn compose<T: ComposeTarget + ?Sized>(&self, target: &mut T) {
        (*self).compose(target)
    }

    fn compose_canonical<T: ComposeTarget + ?Sized>(&self, target: &mut T) {
        (*self).compose_canonical(target)
    }
}

impl Compose for i8 {
    fn compose<T: ComposeTarget + ?Sized>(&self, target: &mut T) {
        target.append_slice(&[*self as u8])
    }
}

impl Compose for u8 {
    fn compose<T: ComposeTarget + ?Sized>(&self, target: &mut T) {
        target.append_slice(&[*self])
    }
}

impl Compose for i16 {
    fn compose<T: ComposeTarget + ?Sized>(&self, target: &mut T) {
        target.append_slice(&self.to_be_bytes())
    }
}

impl Compose for u16 {
    fn compose<T: ComposeTarget + ?Sized>(&self, target: &mut T) {
        target.append_slice(&self.to_be_bytes())
    }
}

impl Compose for i32 {
    fn compose<T: ComposeTarget + ?Sized>(&self, target: &mut T) {
        target.append_slice(&self.to_be_bytes())
    }
}

impl Compose for u32 {
    fn compose<T: ComposeTarget + ?Sized>(&self, target: &mut T) {
        target.append_slice(&self.to_be_bytes())
    }
}

impl Compose for Ipv4Addr {
    fn compose<T: ComposeTarget + ?Sized>(&self, target: &mut T) {
        target.append_slice(&self.octets())
    }
}

impl Compose for Ipv6Addr {
    fn compose<T: ComposeTarget + ?Sized>(&self, target: &mut T) {
        target.append_slice(&self.octets())
    }
}

