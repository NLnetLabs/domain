// Trust anchor

use super::types::Error;
use crate::base::name::Chain;
use crate::base::name::Name;
use crate::base::name::ToName;
use crate::base::Record;
use crate::base::RelativeName;
use crate::rdata::ZoneRecordData;
use crate::zonefile::inplace::Entry;
use crate::zonefile::inplace::Zonefile;
use bytes::Bytes;
use std::fmt::Debug;
use std::io::Read;
use std::slice::Iter;
use std::sync::Arc;
use std::vec::Vec;

// Type of Record we get from Zonefile.

type RrType = Record<
    Chain<RelativeName<Bytes>, Name<Bytes>>,
    ZoneRecordData<Bytes, Chain<RelativeName<Bytes>, Name<Bytes>>>,
>;

#[derive(Clone, Debug)]
pub(crate) struct TrustAnchor {
    rrs: Vec<RrType>,
    owner: Name<Bytes>,
    label_count: usize,
}

impl TrustAnchor {
    fn new(rr: RrType) -> Self {
        let owner = rr.owner().to_name::<Bytes>();
        let label_count = owner.label_count();
        Self {
            rrs: vec![rr],
            owner,
            label_count,
        }
    }

    fn add(&mut self, rr: &RrType) -> Result<(), ()> {
        // Only the owner names need to match. We assume !self.0.is_empty().
        if self.rrs[0].owner().name_eq(rr.owner()) {
            self.rrs.push(rr.clone());
            return Ok(());
        }

        // No match.
        Err(())
    }

    pub fn owner(&self) -> Name<Bytes> {
        self.owner.clone()
    }

    pub fn iter(&mut self) -> Iter<RrType> {
        self.rrs.iter()
    }
}

pub struct TrustAnchors(Vec<TrustAnchor>);

impl TrustAnchors {
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn from_reader<R>(mut reader: R) -> Result<Self, Error>
    where
        R: Read,
    {
        let mut new_self = Self(Vec::new());

        let mut buf = Vec::new();
        match reader.read_to_end(&mut buf) {
            Ok(_) => (), // continue,
            Err(error) => return Err(Error::ReadError(Arc::new(error))),
        }
        let mut zonefile = Zonefile::new();
        zonefile.extend_from_slice(&buf);
        for e in zonefile {
            let e = e?;
            match e {
                Entry::Record(r) => {
                    new_self.add(r);
                }
                Entry::Include { path: _, origin: _ } => continue, // Just ignore include
            }
        }
        Ok(new_self)
    }

    pub fn from_u8(str: &[u8]) -> Result<Self, Error> {
        let mut new_self = Self(Vec::new());

        let mut zonefile = Zonefile::new();
        zonefile.extend_from_slice(str);
        zonefile.extend_from_slice("\n".as_bytes());
        for e in zonefile {
            let e = e?;
            match e {
                Entry::Record(r) => {
                    new_self.add(r);
                }
                Entry::Include { path: _, origin: _ } => continue, // Just ignore include
            }
        }
        Ok(new_self)
    }

    pub fn add_u8(&mut self, str: &[u8]) -> Result<(), Error> {
        let mut zonefile = Zonefile::new();
        zonefile.extend_from_slice(str);
        zonefile.extend_from_slice("\n".as_bytes());
        for e in zonefile {
            let e = e?;
            match e {
                Entry::Record(r) => {
                    self.add(r);
                }
                Entry::Include { path: _, origin: _ } => continue, // Just ignore include
            }
        }
        Ok(())
    }

    fn add(&mut self, rr: RrType) {
        // Very simplistic implementation of add. If this O(n^2) algorithm is
        // not enough, then we should use a small hash table or sort first.
        if self.0.is_empty() {
            self.0.push(TrustAnchor::new(rr));
            return;
        }

        // Try all existing anchors.
        for a in &mut self.0 {
            let res = a.add(&rr);
            if res.is_ok() {
                return;
            }
        }

        // Add a new anchor.
        self.0.push(TrustAnchor::new(rr));
    }

    pub(crate) fn find<TDN: Debug + ToName>(
        &self,
        name: TDN,
    ) -> Option<&TrustAnchor> {
        let mut best: Option<&TrustAnchor> = None;
        let mut best_labels = 0;

        for ta in &self.0 {
            if !name.ends_with(ta.rrs[0].owner()) {
                continue;
            }
            if best.is_none() {
                best = Some(ta);
                best_labels = ta.label_count;
                continue;
            }
            if ta.label_count > best_labels {
                best = Some(ta);
                best_labels = ta.label_count;
            }
        }

        best
    }
}
