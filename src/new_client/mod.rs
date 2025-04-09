use core::{future::Future, pin::Pin};
use std::boxed::Box;
use std::io;
use std::vec::Vec;

use crate::new_base::build::MessageBuilder;
use crate::new_base::name::RevName;
use crate::new_base::wire::{SizePrefixed, TruncationError, U16};
use crate::new_base::{Message, Record};
use crate::new_edns::{EdnsFlags, EdnsOption, EdnsRecord};
use crate::new_rdata::{Opt, RecordData};

// pub mod redundant;
pub mod multi_tcp;
pub mod tcp;
pub mod udp;

pub trait Client {
    #[allow(async_fn_in_trait)]
    async fn request(
        &self,
        request: ExtendedMessageBuilder<'_, '_>,
    ) -> Result<Box<Message>, ClientError>;
}

pub trait BoxClient {
    fn dyn_request<'a, 'b: 'a, 'c: 'a>(
        &'a self,
        request: ExtendedMessageBuilder<'b, 'c>,
    ) -> Pin<Box<dyn Future<Output = Result<Box<Message>, ClientError>> + 'a>>;
}

impl<T: Client> BoxClient for T {
    fn dyn_request<'a, 'b: 'a, 'c: 'a>(
        &'a self,
        request: ExtendedMessageBuilder<'b, 'c>,
    ) -> Pin<Box<dyn Future<Output = Result<Box<Message>, ClientError>> + 'a>>
    {
        Box::pin(self.request(request))
    }
}

#[derive(Clone, Debug, Default)]
pub struct EdnsRecordBuilder<'a> {
    pub header: EdnsHeader,
    pub options: Vec<EdnsOption<'a>>,
}

#[derive(Clone, Debug, Default)]
pub struct EdnsHeader {
    pub max_udp_payload_size: U16,
    pub ext_rcode: u8,
    pub version: u8,
    pub flags: EdnsFlags,
}

/// A message with the OPT data kept separately for easy access and modification.
pub struct ExtendedMessageBuilder<'b, 'c> {
    pub builder: MessageBuilder<'b, 'c>,
    pub edns_record: Option<EdnsRecordBuilder<'b>>,
}

impl<'b, 'c> ExtendedMessageBuilder<'b, 'c> {
    pub fn build(self) -> Result<&'b mut Message, TruncationError> {
        let Self {
            mut builder,
            edns_record,
        } = self;
        if let Some(edns_record) = edns_record {
            let h = edns_record.header;
            let record = EdnsRecord {
                max_udp_payload: h.max_udp_payload_size,
                ext_rcode: h.ext_rcode,
                version: h.version,
                flags: h.flags,
                options: SizePrefixed::new(&Opt::EMPTY),
            };
            let record: Record<&RevName, RecordData<'_, &RevName>> =
                record.into();
            let mut builder = builder.build_additional(&record)?;
            let mut delegate = builder.delegate();
            delegate.append_built_bytes(&&*edns_record.options)?;
            delegate.commit();
            builder.commit();
        }
        Ok(builder.finish())
    }

    pub fn set_id(&mut self, id: u16) {
        self.builder.header_mut().id.set(id);
    }

    pub fn set_udp_max_payload_size(&mut self, size: u16) {
        self.get_edns_mut().header.max_udp_payload_size.set(size);
    }

    pub fn get_edns_mut(&mut self) -> &mut EdnsRecordBuilder<'b> {
        self.edns_record.get_or_insert_default()
    }
}

#[derive(Clone, Debug)]
pub enum SocketError {
    Bind(io::ErrorKind),
    Connect(io::ErrorKind),
    Send(io::ErrorKind),
    Receive(io::ErrorKind),
    Timeout,
}

/// Error type for client transports.
#[derive(Clone, Debug)]
pub enum ClientError {
    TruncatedRequest,

    GarbageResponse,

    /// An error happened in the datagram transport.
    Socket(SocketError),

    TooManyRequests,

    Bug,

    Broken,

    Closed,

    TimedOut,

    NoTransportAvailable,
}

impl From<SocketError> for ClientError {
    fn from(value: SocketError) -> Self {
        ClientError::Socket(value)
    }
}
