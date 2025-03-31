use std::fmt::Debug;

use octseq::{OctetsBuilder, Truncate};
use tracing::trace;

use crate::base::iana::Opcode;
use crate::base::message_builder::AdditionalBuilder;
use crate::base::wire::Composer;
use crate::base::{Message, MessageBuilder};
use crate::dep::octseq::Octets;
use crate::net::server::message::Request;
use crate::zonefile::inplace::Entry as ZonefileEntry;

use super::client::CurrStepValue;
use super::matches::match_msg;
use super::parse_stelline;
use super::parse_stelline::{Adjust, Reply, Stelline};

/// Gets a matching Stelline range entry.
/// 
/// Entries inside a RANGE_BEGIN/RANGE_END block within a Stelline file define
/// queries to match and if matched the response to serve to that query.
/// 
/// The _last_ matching entry is returned, as apparently that "works better if
/// the (Stelline) RPL is written with a recursive resolver in mind", along
/// with the zero based index of the range the entry was found in, and the
/// zero based index of the entry within that range.
pub fn do_server<'a, Oct, Target>(
    req: &'a Request<Oct>,
    stelline: &Stelline,
    step_value: &CurrStepValue,
) -> Option<(AdditionalBuilder<Target>, (usize, usize))>
where
    <Oct as Octets>::Range<'a>: Clone,
    Oct: Clone + Octets + 'a + Send + Sync,
    Target: Composer + Default + OctetsBuilder + Truncate,
    <Target as OctetsBuilder>::AppendError: Debug,
{
    let ranges = &stelline.scenario.ranges;
    let step = step_value.get();
    let mut opt_entry = None;
    let mut last_found_indices: Option<(usize, usize)> = None;
    let msg = req.message();

    // Take the last entry. That works better if the RPL is written with
    // a recursive resolver in mind.
    trace!(
        "Looking for matching Stelline range response for opcode {} qtype {}",
        msg.header().opcode(),
        msg.first_question().unwrap().qtype()
    );
    for (range_idx, range) in ranges.iter().enumerate() {
        trace!(
            "Checking against range {} <= {}",
            range.start_value,
            range.end_value
        );
        if step < range.start_value || step > range.end_value {
            continue;
        }
        for (entry_idx, entry) in range.entry.iter().enumerate() {
            if match_msg(entry, req, true) {
                trace!("Match found");
                opt_entry = Some(entry);
                last_found_indices = Some((range_idx, entry_idx))
            }
        }
    }

    match opt_entry {
        Some(entry) => {
            let reply = do_adjust(entry, msg);
            Some((reply, last_found_indices.unwrap()))
        }
        None => {
            trace!("No matching reply found");
            println!("do_server: no reply at step value {step}");
            None
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
    for a in &sections.answer[0] {
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
