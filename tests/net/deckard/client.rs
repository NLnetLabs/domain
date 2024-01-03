use crate::net::deckard::matches::match_msg;
use crate::net::deckard::parse_deckard::{Deckard, Entry, Reply, StepType};
use crate::net::deckard::parse_query;
use bytes::Bytes;

use domain::base::{Message, MessageBuilder};
use domain::net::client::request::{Error, RequestMessage, SendRequest};
use std::future::Future;
use std::sync::Mutex;

pub async fn closure_do_client<F, Fut>(
    deckard: &Deckard,
    step_value: &CurrStepValue,
    request: F,
) where
    F: Fn(RequestMessage<Vec<u8>>) -> Fut,
    Fut: Future<Output = Result<Message<Bytes>, Error>>,
{
    let mut resp: Option<Message<Bytes>> = None;

    // Assume steps are in order. Maybe we need to define that.
    for step in &deckard.scenario.steps {
        step_value.set(step.step_value);
        match step.step_type {
            StepType::Query => {
                let reqmsg = entry2reqmsg(step.entry.as_ref().unwrap());
                resp = Some(request(reqmsg).await.unwrap());
            }
            StepType::CheckAnswer => {
                let answer = resp.take().unwrap();
                if !match_msg(step.entry.as_ref().unwrap(), &answer, true) {
                    panic!("reply failed");
                }
            }
            StepType::TimePasses
            | StepType::Traffic
            | StepType::CheckTempfile
            | StepType::Assign => todo!(),
        }
    }
    println!("Done");
}

pub async fn do_client<R: SendRequest<RequestMessage<Vec<u8>>>>(
    deckard: &Deckard,
    request: R,
    step_value: &CurrStepValue,
) {
    let mut resp: Option<Message<Bytes>> = None;

    // Assume steps are in order. Maybe we need to define that.
    for step in &deckard.scenario.steps {
        step_value.set(step.step_value);
        match step.step_type {
            StepType::Query => {
                let reqmsg = entry2reqmsg(step.entry.as_ref().unwrap());
                let mut req = request.send_request(&reqmsg).await.unwrap();
                resp = Some(req.get_response().await.unwrap());
            }
            StepType::CheckAnswer => {
                let answer = resp.take().unwrap();
                if !match_msg(step.entry.as_ref().unwrap(), &answer, true) {
                    panic!("reply failed");
                }
            }
            StepType::TimePasses
            | StepType::Traffic
            | StepType::CheckTempfile
            | StepType::Assign => todo!(),
        }
    }
    println!("Done");
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
    for _a in &sections.additional {
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
    RequestMessage::new(msg)
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
