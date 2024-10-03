use std::boxed::Box;

use bytes::Bytes;
use tokio::sync::mpsc::UnboundedSender;
use tracing::error;

use crate::base::{Name, Rtype};
use crate::net::server::service::{CallResult, ServiceResult};
use crate::zonetree::error::OutOfZone;
use crate::zonetree::{Answer, ReadableZone};

//------------ read_soa() -----------------------------------------------------

#[allow(clippy::borrowed_box)]
pub async fn read_soa(
    read: &Box<dyn ReadableZone>,
    qname: Name<Bytes>,
) -> Result<Answer, OutOfZone> {
    match read.is_async() {
        true => read.query_async(qname, Rtype::SOA).await,
        false => read.query(qname, Rtype::SOA),
    }
}

//------------ add_to_stream() ------------------------------------------------

pub fn add_to_stream<Target, T: Into<CallResult<Target>>>(
    call_result: T,
    response_tx: &UnboundedSender<ServiceResult<Target>>,
) {
    if response_tx.send(Ok(call_result.into())).is_err() {
        // We failed to write the message into the response stream. This
        // shouldn't happen. We can't now return an error to the client
        // because that would require writing to the response stream as well.
        // We don't want to panic and take down the entire application, so
        // instead just log.
        error!("Failed to send DNS message to the internal response stream");
    }
}
