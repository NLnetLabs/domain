use crate::net::deckard::client::CurrStepValue;
use crate::net::deckard::matches::match_msg;
use crate::net::deckard::parse_deckard;
use crate::net::deckard::parse_deckard::{Adjust, Deckard, Reply};
use crate::net::deckard::parse_query;
use domain::base::iana::rcode::Rcode;
use domain::base::iana::Opcode;
use domain::base::{Message, MessageBuilder};
use domain::dep::octseq::Octets;
use domain::zonefile::inplace::Entry as ZonefileEntry;

pub fn do_server<'a, Oct: Clone + Octets + 'a>(
    msg: &'a Message<Oct>,
    deckard: &Deckard,
    step_value: &CurrStepValue,
) -> Option<Message<Vec<u8>>>
where
    <Oct as Octets>::Range<'a>: Clone,
{
    let ranges = &deckard.scenario.ranges;
    let step = step_value.get();
    for range in ranges {
        if step < range.start_value || step > range.end_value {
            continue;
        }
        for entry in &range.entry {
            if !match_msg(entry, msg, false) {
                continue;
            }
            let reply = do_adjust(entry, msg);
            return Some(reply);
        }
    }
    println!("do_server: no reply at step value {step}");
    todo!();
}

fn do_adjust<Octs: Octets>(
    entry: &parse_deckard::Entry,
    reqmsg: &Message<Octs>,
) -> Message<Vec<u8>> {
    let sections = entry.sections.as_ref().unwrap();
    let adjust: Adjust = match &entry.adjust {
        Some(adjust) => adjust.clone(),
        None => Default::default(),
    };
    let mut msg = MessageBuilder::new_vec().question();
    if adjust.copy_query {
        for q in reqmsg.question() {
            msg.push(q.unwrap()).unwrap();
        }
    } else {
        for q in &sections.question {
            let question = match q {
                parse_query::Entry::QueryRecord(question) => question,
                _ => todo!(),
            };
            msg.push(question).unwrap();
        }
    }
    let mut msg = msg.answer();
    for a in &sections.answer {
        let rec = if let ZonefileEntry::Record(record) = a {
            record
        } else {
            panic!("include not expected")
        };
        msg.push(rec).unwrap();
    }
    let mut msg = msg.authority();
    for a in &sections.authority {
        let rec = if let ZonefileEntry::Record(record) = a {
            record
        } else {
            panic!("include not expected")
        };
        msg.push(rec).unwrap();
    }
    let mut msg = msg.additional();
    for a in &sections.additional {
        let rec = if let ZonefileEntry::Record(record) = a {
            record
        } else {
            panic!("include not expected")
        };
        msg.push(rec).unwrap();
    }
    let reply: Reply = match &entry.reply {
        Some(reply) => reply.clone(),
        None => Default::default(),
    };
    if reply.aa {
        msg.header_mut().set_aa(true);
    }
    if reply.ad {
        msg.header_mut().set_ad(true);
    }
    if reply.cd {
        msg.header_mut().set_cd(true);
    }
    if reply.fl_do {
        todo!()
    }
    if reply.formerr {
        msg.header_mut().set_rcode(Rcode::FormErr);
    }
    if reply.noerror {
        msg.header_mut().set_rcode(Rcode::NoError);
    }
    if reply.notimp {
        msg.header_mut().set_rcode(Rcode::NotImp);
    }
    if reply.nxdomain {
        msg.header_mut().set_rcode(Rcode::NXDomain);
    }
    if reply.qr {
        msg.header_mut().set_qr(true);
    }
    if reply.ra {
        msg.header_mut().set_ra(true);
    }
    if reply.rd {
        msg.header_mut().set_rd(true);
    }
    if reply.refused {
        msg.header_mut().set_rcode(Rcode::Refused);
    }
    if reply.servfail {
        todo!()
    }
    if reply.tc {
        todo!()
    }
    if reply.yxdomain {
        todo!()
    }
    if reply.notify {
        msg.header_mut().set_opcode(Opcode::Notify);
    }
    if adjust.copy_id {
        msg.header_mut().set_id(reqmsg.header().id());
    } else {
        todo!();
    }
    msg.into_message()
}
