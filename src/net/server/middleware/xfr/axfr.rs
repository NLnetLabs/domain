use std::boxed::Box;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::mpsc::Sender;
use tokio::sync::Semaphore;
use tracing::error;

use crate::base::iana::OptRcode;
use crate::base::{Name, Rtype};
use crate::zonetree::{ReadableZone, SharedRrset, StoredName};

//------------ ZoneFunneler ---------------------------------------------------

pub struct ZoneFunneler {
    read: Box<dyn ReadableZone>,
    qname: StoredName,
    zone_soa_rrset: SharedRrset,
    batcher_tx: Sender<(Name<Bytes>, SharedRrset)>,
    zone_walk_semaphore: Arc<Semaphore>,
}

impl ZoneFunneler {
    pub fn new(
        read: Box<dyn ReadableZone>,
        qname: StoredName,
        zone_soa_rrset: SharedRrset,
        batcher_tx: Sender<(Name<Bytes>, SharedRrset)>,
        zone_walk_semaphore: Arc<Semaphore>,
    ) -> Self {
        Self {
            read,
            qname,
            zone_soa_rrset,
            batcher_tx,
            zone_walk_semaphore,
        }
    }

    pub async fn run(self) -> Result<(), OptRcode> {
        // Limit the number of concurrently running XFR related zone walking
        // operations.
        if self.zone_walk_semaphore.acquire().await.is_err() {
            error!("Internal error: Failed to acquire XFR zone walking semaphore");
            return Err(OptRcode::SERVFAIL);
        }

        let cloned_batcher_tx = self.batcher_tx.clone();
        let op = Box::new(move |owner: StoredName, rrset: &SharedRrset| {
            if rrset.rtype() != Rtype::SOA {
                let _ = cloned_batcher_tx
                    .blocking_send((owner.clone(), rrset.clone()));
                // If the blocking send fails it means that the
                // batcher is no longer available. This can happen if
                // it was no longer able to pass messages back to the
                // underlying transport, which can happen if the
                // client closed the connection. We don't log this
                // because we can't stop the tree walk and so will
                // keep hitting this error until the tree walk is
                // complete, causing a lot of noise if we were to log
                // this.
            }
        });

        // Walk the zone tree, invoking our operation for each leaf.
        match self.read.is_async() {
            true => {
                self.read.walk_async(op).await;
                if let Err(err) = self
                    .batcher_tx
                    .send((self.qname, self.zone_soa_rrset))
                    .await
                {
                    error!("Internal error: Failed to send final AXFR SOA to batcher: {err}");
                    return Err(OptRcode::SERVFAIL);
                }
            }
            false => {
                tokio::task::spawn_blocking(move || {
                    self.read.walk(op);
                    if let Err(err) = self
                        .batcher_tx
                        .blocking_send((self.qname, self.zone_soa_rrset))
                    {
                        error!("Internal error: Failed to send final AXFR SOA to batcher: {err}");
                        // Note: The lack of the final SOA will be detected by the batcher.
                    }
                });
            }
        }

        Ok(())
    }
}
