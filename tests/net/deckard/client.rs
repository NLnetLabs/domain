use crate::net::deckard::matches::match_msg;
use crate::net::deckard::parse_deckard::{Deckard, Entry, Reply, StepType};
use crate::net::deckard::parse_query;
use bytes::Bytes;

use domain::base::iana::Opcode;
use domain::base::{Message, MessageBuilder};
use domain::net::client::request::{
    ComposeRequest, RequestMessage, SendRequest,
};
use domain::net::client::time::FakeTime;
use std::sync::Mutex;
use std::time::Duration;

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
                let mut req = request.send_request(reqmsg);
                resp = Some(req.get_response().await.unwrap());
            }
            StepType::CheckAnswer => {
                let answer = resp.take().unwrap();
                if !match_msg(step.entry.as_ref().unwrap(), &answer, true) {
                    println!(
                        "Reply message does not match at step {}",
                        step_value.get()
                    );
                    panic!("reply failed");
                }
            }
            StepType::TimePasses => {
                FakeTime::adjust_time(Duration::from_secs(
                    step.time_passes.unwrap(),
                ));
            }
            StepType::Traffic
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
    if reply.ad {
        msg.header_mut().set_ad(true);
    }
    if reply.cd {
        msg.header_mut().set_cd(true);
    }
    let msg = msg.into_message();
    let mut msg = RequestMessage::new(msg);
    if reply.fl_do {
        msg.set_dnssec_ok(true);
    }
    if reply.notify {
        msg.header_mut().set_opcode(Opcode::Notify);
    }
    msg
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
