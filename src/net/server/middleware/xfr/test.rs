//------------ SortingBatcher -------------------------------------------------

// Conditionally use HashMap or BTreeMap in order to guarantee the order of
// tree walking when in test mode so that Stelline tests that need to know
// which response RRs will be in which response of a multi-part response have
// a predictable tree walking order compared to the usual unordered tree
// walking results. This will be make tree inserts slower, but one shouldn't
// be doing performance tests against a test build anyway so that shouldn't
// matter.
use core::marker::PhantomData;

use std::vec::Vec;

use octseq::Octets;

use crate::base::record::ComposeRecord;
use crate::base::wire::Composer;
use crate::net::server::batcher::PushResult;
use crate::net::server::batcher::ResourceRecordBatcher;

pub struct PredictablyOrderedBatcher<RequestOctets, Target, Batcher>
where
    Target: Composer + Default,
    RequestOctets: Octets,
    Batcher: ResourceRecordBatcher<RequestOctets, Target>,
{
    composed: Vec<Vec<u8>>,
    batcher: Batcher,
    _phantom: PhantomData<(RequestOctets, Target)>,
}

impl<RequestOctets, Target, Batcher>
    PredictablyOrderedBatcher<RequestOctets, Target, Batcher>
where
    Target: Composer + Default,
    RequestOctets: Octets,
    Batcher: ResourceRecordBatcher<RequestOctets, Target>,
{
    pub fn new(batcher: Batcher) -> Self {
        Self {
            composed: vec![],
            batcher,
            _phantom: PhantomData,
        }
    }
}

impl<RequestOctets, Target, Batcher>
    ResourceRecordBatcher<RequestOctets, Target>
    for PredictablyOrderedBatcher<RequestOctets, Target, Batcher>
where
    RequestOctets: Octets,
    Target: Composer + Default,
    Batcher: ResourceRecordBatcher<RequestOctets, Target>,
{
    fn push(
        &mut self,
        record: impl ComposeRecord,
    ) -> Result<PushResult<Target>, ()> {
        let mut new_vec = vec![];
        record.compose_record(&mut new_vec).map_err(|_| ())?;
        self.composed.push(new_vec);
        Ok(PushResult::PushedAndReadyForMore)
    }

    fn finish(&mut self) -> Result<(), ()> {
        let len = self.composed.len();
        self.composed[1..len - 1].sort();
        for v in self.composed.iter().as_ref() {
            self.batcher.push(v).unwrap();
        }
        self.batcher.finish().unwrap();
        Ok(())
    }
}

impl ComposeRecord for Vec<u8> {
    fn compose_record<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_slice(self.as_slice())
    }
}
