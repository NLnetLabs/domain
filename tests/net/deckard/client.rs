use crate::net::deckard::matches::match_msg;
use crate::net::deckard::parse_deckard::{Deckard, Entry, Reply, StepType};
use crate::net::deckard::parse_query;
use bytes::Bytes;

use domain::base::opt::{ComposeOptData, OptData};
use domain::base::{Message, MessageBuilder};
use domain::net::client::request::{
    ComposeRequest, RequestMessage, SendRequest,
};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Mutex;
use tracing::{debug, info_span, trace};

#[derive(Debug)]
pub struct DeckardError<'a> {
    _deckard: &'a Deckard,
    step_value: &'a CurrStepValue,
    cause: DeckardErrorCause,
}

impl<'a> std::fmt::Display for DeckardError<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "Deckard test failed at step {} with error: {}",
            self.step_value, self.cause
        ))
    }
}

impl<'a> DeckardError<'a> {
    pub fn from_cause(
        deckard: &'a Deckard,
        step_value: &'a CurrStepValue,
        cause: DeckardErrorCause,
    ) -> Self {
        Self {
            _deckard: deckard,
            step_value,
            cause,
        }
    }
}

#[derive(Debug)]
pub enum DeckardErrorCause {
    ClientError(domain::net::client::request::Error),
    MismatchedAnswer,
    MissingResponse,
    MissingStepEntry,
    MissingClientFactory,
}

impl From<domain::net::client::request::Error> for DeckardErrorCause {
    fn from(err: domain::net::client::request::Error) -> Self {
        Self::ClientError(err)
    }
}

impl std::fmt::Display for DeckardErrorCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeckardErrorCause::ClientError(err) => {
                f.write_fmt(format_args!("Client error: {err}"))
            }
            DeckardErrorCause::MismatchedAnswer => {
                f.write_str("Mismatched answer")
            }
            DeckardErrorCause::MissingClientFactory => {
                f.write_str("Missing client factory")
            }
            DeckardErrorCause::MissingResponse => {
                f.write_str("Missing response")
            }
            DeckardErrorCause::MissingStepEntry => {
                f.write_str("Missing step entry")
            }
        }
    }
}

pub enum Dispatcher<Dgram, Stream> {
    Dgram(Option<Dgram>),
    Stream(Option<Stream>),
}

impl<Dgram, Stream> Dispatcher<Dgram, Stream>
where
    Dgram: SendRequest<RequestMessage<Vec<u8>>>,
    Stream: SendRequest<RequestMessage<Vec<u8>>>,
{
    pub async fn dispatch(
        &self,
        entry: &Entry,
    ) -> Result<Option<Message<Bytes>>, DeckardErrorCause> {
        let reqmsg = entry2reqmsg(entry);
        trace!(?reqmsg);
        match self {
            Self::Dgram(Some(conn)) => {
                let mut req = conn.send_request(reqmsg);
                Ok(Some(req.get_response().await?))
            }
            Self::Stream(Some(conn)) => {
                let mut req = conn.send_request(reqmsg);
                Ok(Some(req.get_response().await?))
            }
            _ => Err(DeckardErrorCause::MissingClientFactory),
        }
    }
}

pub async fn do_client<'a, F, Dgram, Stream>(
    deckard: &'a Deckard,
    client_factory: F,
    step_value: &'a CurrStepValue,
) where
    F: Fn(&Entry) -> Pin<Box<dyn Future<Output = Dispatcher<Dgram, Stream>>>>,
    Dgram: SendRequest<RequestMessage<Vec<u8>>>,
    Stream: SendRequest<RequestMessage<Vec<u8>>>,
{
    async fn inner<F, Dgram, Stream>(
        deckard: &Deckard,
        step_value: &CurrStepValue,
        dispatcher: F,
    ) -> Result<(), DeckardErrorCause>
    where
        F: Fn(
            &Entry,
        )
            -> Pin<Box<dyn Future<Output = Dispatcher<Dgram, Stream>>>>,
        Dgram: SendRequest<RequestMessage<Vec<u8>>>,
        Stream: SendRequest<RequestMessage<Vec<u8>>>,
    {
        let mut resp: Option<Message<Bytes>> = None;

        // Assume steps are in order. Maybe we need to define that.
        for step in &deckard.scenario.steps {
            let span = info_span!(
                "deckard",
                "{}:{}",
                step.step_value,
                step.step_type
            );
            let _guard = span.enter();

            debug!("Processing step");
            step_value.set(step.step_value);
            match step.step_type {
                StepType::Query => {
                    let entry = step
                        .entry
                        .as_ref()
                        .ok_or(DeckardErrorCause::MissingStepEntry)?;
                    resp = dispatcher(entry).await.dispatch(entry).await?;
                    trace!(?resp);
                }
                StepType::CheckAnswer => {
                    let answer = resp
                        .take()
                        .ok_or(DeckardErrorCause::MissingResponse)?;
                    let entry = step
                        .entry
                        .as_ref()
                        .ok_or(DeckardErrorCause::MissingStepEntry)?;
                    if !match_msg(entry, &answer, true) {
                        return Err(DeckardErrorCause::MismatchedAnswer);
                    }
                }
                StepType::TimePasses
                | StepType::Traffic
                | StepType::CheckTempfile
                | StepType::Assign => todo!(),
            }
        }

        Ok(())
    }

    if let Err(cause) = inner(deckard, step_value, client_factory).await {
        panic!("{}", DeckardError::from_cause(deckard, step_value, cause));
    }
}

struct RawOptData<'a> {
    bytes: &'a [u8],
}

impl<'a> OptData for RawOptData<'a> {
    fn code(&self) -> domain::base::iana::OptionCode {
        u16::from_be_bytes(self.bytes[0..2].try_into().unwrap()).into()
    }
}

impl<'a> ComposeOptData for RawOptData<'a> {
    fn compose_len(&self) -> u16 {
        u16::from_be_bytes(self.bytes[2..4].try_into().unwrap())
    }

    fn compose_option<Target: octseq::OctetsBuilder + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_slice(&self.bytes[4..])
    }
}

fn entry2reqmsg(entry: &Entry) -> RequestMessage<Vec<u8>> {
    let sections = entry.sections.as_ref().unwrap();
    let mut msg = MessageBuilder::new_vec().question();
    for q in &sections.question {
        let question = match q {
            parse_query::Entry::QueryRecord(question) => question,
            _ => todo!(),
        };
        msg.push(question).unwrap();
    }
    let msg = msg.answer();
    for _a in &sections.answer {
        todo!();
    }
    let msg = msg.authority();
    for _a in &sections.authority {
        todo!();
    }
    let mut msg = msg.additional();
    for _a in &sections.additional.zone_entries {
        todo!();
    }
    let reply: Reply = match &entry.reply {
        Some(reply) => reply.clone(),
        None => Default::default(),
    };
    if reply.rd {
        msg.header_mut().set_rd(true);
    }
    let msg = msg.into_message();

    let mut reqmsg = RequestMessage::new(msg);

    let edns_bytes = &sections.additional.edns_bytes;
    if !edns_bytes.is_empty() {
        let raw_opt = RawOptData { bytes: edns_bytes };
        reqmsg.add_opt(&raw_opt).unwrap();
    }

    if let Some(client_addr) = entry.client_addr {
        reqmsg.set_source_address(SocketAddr::new(client_addr, 0));
    }

    reqmsg
}

#[derive(Debug)]
pub struct CurrStepValue {
    v: Mutex<u64>,
}

impl CurrStepValue {
    pub fn new() -> Self {
        Self { v: 0.into() }
    }
    fn set(&self, v: u64) {
        let mut self_v = self.v.lock().unwrap();
        *self_v = v;
    }
    pub fn get(&self) -> u64 {
        *(self.v.lock().unwrap())
    }
}

impl std::fmt::Display for CurrStepValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", self.get()))
    }
}
