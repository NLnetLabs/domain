use std::vec::Vec;

use bytes::Bytes;
use futures_util::{pin_mut, StreamExt};
use tokio::sync::mpsc::Sender;
use tracing::error;

use crate::base::iana::OptRcode;
use crate::base::{Name, Rtype};
use crate::zonetree::{SharedRrset, StoredName, ZoneDiff, ZoneDiffItem};

//------------ DiffFunneler ----------------------------------------------------

pub struct DiffFunneler<Diff> {
    qname: StoredName,
    zone_soa_rrset: SharedRrset,
    diffs: Vec<Diff>,
    batcher_tx: Sender<(Name<Bytes>, SharedRrset)>,
}

impl<Diff> DiffFunneler<Diff>
where
    Diff: ZoneDiff,
{
    pub fn new(
        qname: StoredName,
        zone_soa_rrset: SharedRrset,
        diffs: Vec<Diff>,
        batcher_tx: Sender<(Name<Bytes>, SharedRrset)>,
    ) -> Self {
        Self {
            qname,
            zone_soa_rrset,
            diffs,
            batcher_tx,
        }
    }

    pub async fn run(self) -> Result<(), OptRcode> {
        // https://datatracker.ietf.org/doc/html/rfc1995#section-4
        // 4. Response Format
        //    ...
        //   "If incremental zone transfer is available, one or more
        //    difference sequences is returned.  The list of difference
        //    sequences is preceded and followed by a copy of the server's
        //    current version of the SOA.
        //
        //    Each difference sequence represents one update to the zone
        //    (one SOA serial change) consisting of deleted RRs and added
        //    RRs.  The first RR of the deleted RRs is the older SOA RR
        //    and the first RR of the added RRs is the newer SOA RR.
        //
        //    Modification of an RR is performed first by removing the
        //    original RR and then adding the modified one.
        //
        //    The sequences of differential information are ordered oldest
        //    first newest last.  Thus, the differential sequences are the
        //    history of changes made since the version known by the IXFR
        //    client up to the server's current version.
        //
        //    RRs in the incremental transfer messages may be partial. That
        //    is, if a single RR of multiple RRs of the same RR type changes,
        //    only the changed RR is transferred."

        if let Err(err) = self
            .batcher_tx
            .send((self.qname.clone(), self.zone_soa_rrset.clone()))
            .await
        {
            error!("Internal error: Failed to send initial IXFR SOA to batcher: {err}");
            return Err(OptRcode::SERVFAIL);
        }

        let qname = self.qname.clone();

        for diff in self.diffs {
            // 4. Response Format
            //    "Each difference sequence represents one update to the
            //    zone (one SOA serial change) consisting of deleted RRs
            //    and added RRs.  The first RR of the deleted RRs is the
            //    older SOA RR and the first RR of the added RRs is the
            //    newer SOA RR.

            let added_soa =
                diff.get_added(qname.clone(), Rtype::SOA).await.unwrap(); // The diff MUST have a SOA record
            Self::send_diff_section(
                &qname,
                &self.batcher_tx,
                added_soa,
                diff.added(),
            )
            .await?;

            let removed_soa =
                diff.get_removed(qname.clone(), Rtype::SOA).await.unwrap(); // The diff MUST have a SOA record
            Self::send_diff_section(
                &qname,
                &self.batcher_tx,
                removed_soa,
                diff.removed(),
            )
            .await?;
        }

        if let Err(err) = self
            .batcher_tx
            .send((qname.clone(), self.zone_soa_rrset))
            .await
        {
            error!("Internal error: Failed to send final IXFR SOA to batcher: {err}");
            return Err(OptRcode::SERVFAIL);
        }

        Ok(())
    }

    async fn send_diff_section(
        qname: &StoredName,
        batcher_tx: &Sender<(Name<Bytes>, SharedRrset)>,
        soa: &SharedRrset,
        diff_stream: <Diff as ZoneDiff>::Stream<'_>,
    ) -> Result<(), OptRcode> {
        if let Err(err) = batcher_tx.send((qname.clone(), soa.clone())).await
        {
            error!("Internal error: Failed to send SOA to batcher: {err}");
            return Err(OptRcode::SERVFAIL);
        }

        pin_mut!(diff_stream);

        while let Some(item) = diff_stream.next().await {
            let (owner, rtype) = item.key();
            if *rtype != Rtype::SOA {
                let rrset = item.value();
                if let Err(err) =
                    batcher_tx.send((owner.clone(), rrset.clone())).await
                {
                    error!("Internal error: Failed to send RRSET to batcher: {err}");
                    return Err(OptRcode::SERVFAIL);
                }
            }
        }

        Ok(())
    }
}
