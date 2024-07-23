use core::future::Ready;

use futures::stream::Once;
use tokio_stream::wrappers::UnboundedReceiverStream;

use crate::base::iana::OptRcode;
use crate::net::server::middleware::stream::MiddlewareStream;

//------------ XfrMapStream ---------------------------------------------------

pub type XfrResultStream<StreamItem> = UnboundedReceiverStream<StreamItem>;

//------------ XfrMiddlewareStream --------------------------------------------

pub type XfrMiddlewareStream<Future, Stream, StreamItem> = MiddlewareStream<
    Future,
    Stream,
    Once<Ready<StreamItem>>,
    XfrResultStream<StreamItem>,
    StreamItem,
>;

//------------ XfrMode --------------------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum XfrMode {
    AxfrAndIxfr,
    AxfrOnly,
}

//------------ IxfrResult -----------------------------------------------------

pub enum IxfrResult<Stream> {
    Ok(Stream),
    FallbackToAxfr,
    Err(OptRcode),
}
