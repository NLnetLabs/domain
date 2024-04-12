use std::fmt::Debug;

use octseq::{OctetsBuilder, Truncate};

use domain::base::iana::rcode::Rcode;
use domain::base::iana::Opcode;
use domain::base::message_builder::AdditionalBuilder;
use domain::base::wire::Composer;
use domain::base::{Message, MessageBuilder};
use domain::dep::octseq::Octets;
use domain::zonefile::inplace::Entry as ZonefileEntry;

use crate::net::stelline::client::CurrStepValue;
use crate::net::stelline::matches::match_msg;
use crate::net::stelline::parse_query;
use crate::net::stelline::parse_stelline;
use crate::net::stelline::parse_stelline::{Adjust, Reply, Stelline};

pub fn do_server<'a, Oct, Target>(
    msg: &'a Message<Oct>,
    stelline: &Stelline,
    step_value: &CurrStepValue,
) -> Option<AdditionalBuilder<Target>>
where
    <Oct as Octets>::Range<'a>: Clone,
    Oct: Clone + Octets + 'a,
    Target: Composer + Default + OctetsBuilder + Truncate,
    <Target as OctetsBuilder>::AppendError: Debug,
{
    let ranges = &stelline.scenario.ranges;
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

fn do_adjust<Octs, Target>(
    entry: &parse_stelline::Entry,
    reqmsg: &Message<Octs>,
) -> AdditionalBuilder<Target>
where
    Octs: Octets,
    Target: Composer + Default + OctetsBuilder + Truncate,
    <Target as OctetsBuilder>::AppendError: Debug,
{
    let sections = entry.sections.as_ref().unwrap();
    let adjust: Adjust = match &entry.adjust {
        Some(adjust) => adjust.clone(),
        None => Default::default(),
    };
    let mut msg = MessageBuilder::from_target(Target::default())
        .unwrap()
        .question();
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
    for a in &sections.additional.zone_entries {
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
    let header = msg.header_mut();
    header.set_aa(reply.aa);
    header.set_ad(reply.ad);
    header.set_cd(reply.cd);
    if reply.fl_do {
        todo!()
    }
    if reply.formerr {
        header.set_rcode(Rcode::FORMERR);
    }
    if reply.noerror {
        header.set_rcode(Rcode::NOERROR);
    }
    if reply.notimp {
        header.set_rcode(Rcode::NOTIMP);
    }
    if reply.nxdomain {
        header.set_rcode(Rcode::NXDOMAIN);
    }
    header.set_qr(reply.qr);
    header.set_ra(reply.ra);
    header.set_rd(reply.rd);
    if reply.refused {
        header.set_rcode(Rcode::REFUSED);
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
        header.set_opcode(Opcode::NOTIFY);
    }
    if adjust.copy_id {
        header.set_id(reqmsg.header().id());
    } else {
        todo!();
    }
    msg
}
