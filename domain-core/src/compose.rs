//! Assembling wire-format DNS data.

use std::net::{Ipv4Addr, Ipv6Addr};
use bytes::BytesMut;
use crate::name::ToDname;

//------------ Re-exported for your convenience ------------------------------

pub use crate::parse::ShortBuf;


//------------ ComposeTarget -------------------------------------------------

pub trait ComposeTarget: AsRef<[u8]> + AsMut<[u8]> {
    type LenTarget: ComposeTarget;

    fn append_slice(&mut self, slice: &[u8]);

    fn truncate(&mut self, len: usize);

    fn append_compressed_dname<N: ToDname>(&mut self, name: &N) {
        if let Some(slice) = name.as_flat_slice() {
            self.append_slice(slice)
        }
        else {
            for label in name.iter_labels() {
                label.compose(self)
            }
        }
    }

    fn len_prefixed<F: FnOnce(&mut Self::LenTarget)>(&mut self, op: F);
}

impl ComposeTarget for Vec<u8> {
    type LenTarget = Self;

    fn append_slice(&mut self, slice: &[u8]) {
        self.extend_from_slice(slice);
    }

    fn truncate(&mut self, len: usize) {
        Vec::truncate(self, len)
    }

    fn len_prefixed<F: FnOnce(&mut Self)>(&mut self, op: F) {
        let pos = self.len();
        self.extend_from_slice(&[0; 2]);
        op(self);
        let len = (self.len() - pos) as u16;
        self[pos..pos + 2].copy_from_slice(&len.to_be_bytes());
    }
}

impl ComposeTarget for BytesMut {
    type LenTarget = Self;

    fn append_slice(&mut self, slice: &[u8]) {
        self.extend_from_slice(slice);
    }

    fn truncate(&mut self, len: usize) {
        BytesMut::truncate(self, len)
    }

    fn len_prefixed<F: FnOnce(&mut Self)>(&mut self, op: F) {
        let pos = self.len();
        self.extend_from_slice(&[0; 2]);
        op(self);
        let len = (self.len() - pos) as u16;
        self[pos..pos + 2].copy_from_slice(&len.to_be_bytes());
    }
}



//------------ TryCompose ----------------------------------------------------

pub trait TryCompose {
    type Target: ComposeTarget;

    fn try_compose<F>(&mut self, op: F) -> Result<(), ShortBuf>
    where F: FnOnce(&mut Self::Target);
}

impl TryCompose for Vec<u8> {
    type Target = Self;

    fn try_compose<F>(&mut self, op: F) -> Result<(), ShortBuf>
    where F: FnOnce(&mut Self::Target) {
        op(self);
        Ok(())
    }
}

impl TryCompose for BytesMut {
    type Target = Self;

    fn try_compose<F>(&mut self, op: F) -> Result<(), ShortBuf>
    where F: FnOnce(&mut Self::Target) {
        op(self);
        Ok(())
    }
}


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

