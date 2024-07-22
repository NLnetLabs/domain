use std::fmt::Debug;

use octseq::{OctetsBuilder, Truncate};

use crate::base::iana::Opcode;
use crate::base::message_builder::AdditionalBuilder;
use crate::base::wire::Composer;
use crate::base::{Message, MessageBuilder};
use crate::dep::octseq::Octets;
use crate::zonefile::inplace::Entry as ZonefileEntry;

use super::client::CurrStepValue;
use super::matches::match_msg;
use super::parse_stelline;
use super::parse_stelline::{Adjust, Reply, Stelline};

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
    let mut opt_entry = None;

    // Take the last entry. That works better if the RPL is written with
    // a recursive resolver in mind.
    for range in ranges {
        if step < range.start_value || step > range.end_value {
            continue;
        }
        for entry in &range.entry {
            if match_msg(entry, msg, false) {
                opt_entry = Some(entry);
            }
        }
    }

    match opt_entry {
        Some(entry) => {
            let reply = do_adjust(entry, msg);
            Some(reply)
        }
        None => {
            println!("do_server: no reply at step value {step}");
            todo!();
        }
    }
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
            msg.push(q).unwrap();
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
    header.set_qr(reply.qr);
    header.set_ra(reply.ra);
    header.set_rd(reply.rd);
    if reply.tc {
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

    // Assume there is no existing Opt record.
    if reply.fl_do {
        msg.opt(|o| {
            o.set_dnssec_ok(reply.fl_do);
            if let Some(rcode) = reply.rcode {
                o.set_rcode(rcode);
            }
            Ok(())
        })
        .unwrap()
    } else if let Some(rcode) = reply.rcode {
        if rcode.is_ext() {
            msg.opt(|o| {
                o.set_rcode(rcode);
                Ok(())
            })
            .unwrap();
        } else {
            header.set_rcode(rcode.rcode());
        }
    }
    msg
}
