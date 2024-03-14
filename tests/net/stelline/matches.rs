use crate::net::stelline::parse_stelline::{Entry, Matches, Reply};
use crate::net::stelline::parse_query;
use domain::base::iana::Opcode;
use domain::base::iana::OptRcode;
use domain::base::iana::Rtype;
use domain::base::opt::{Opt, OptRecord};
use domain::base::Message;
use domain::base::ParsedDname;
use domain::base::QuestionSection;
use domain::base::RecordSection;
use domain::dep::octseq::Octets;
use domain::rdata::ZoneRecordData;
use domain::zonefile::inplace::Entry as ZonefileEntry;
//use std::fmt::Debug;

pub fn match_msg<'a, Octs: AsRef<[u8]> + Clone + Octets + 'a>(
    entry: &Entry,
    msg: &'a Message<Octs>,
    verbose: bool,
) -> bool
where
    <Octs as Octets>::Range<'a>: Clone,
{
    let sections = entry.sections.as_ref().unwrap();

    let mut matches: Matches = match &entry.matches {
        Some(matches) => matches.clone(),
        None => Default::default(),
    };

    let reply: Reply = match &entry.reply {
        Some(reply) => reply.clone(),
        None => Default::default(),
    };

    if matches.all {
        matches.opcode = true;
        matches.qtype = true;
        matches.qname = true;
        matches.flags = true;
        matches.rcode = true;
        matches.answer = true;
        matches.authority = true;
        matches.additional = true;
    }

    if matches.question {
        matches.qtype = true;
        matches.qname = true;
    }

    if matches.edns_data {
        matches.additional = true;
    }

    if matches.additional {
        let mut arcount = msg.header_counts().arcount();
        if msg.opt().is_some() {
            arcount -= 1;
        }
        let match_edns_bytes = if matches.edns_data {
            Some(sections.additional.edns_bytes.as_ref())
        } else {
            None
        };
        if !match_section(
            sections.additional.zone_entries.clone(),
            match_edns_bytes,
            msg.additional().unwrap(),
            arcount,
            matches.ttl,
            verbose,
        ) {
            if verbose {
                println!("match_msg: additional section does not match");
            }
            return false;
        }
    }
    if matches.answer
        && !match_section(
            sections.answer.clone(),
            None,
            msg.answer().unwrap(),
            msg.header_counts().ancount(),
            matches.ttl,
            verbose,
        )
    {
        if verbose {
            println!("match_msg: answer section does not match");
        }
        return false;
    }
    if matches.authority
        && !match_section(
            sections.authority.clone(),
            None,
            msg.authority().unwrap(),
            msg.header_counts().nscount(),
            matches.ttl,
            verbose,
        )
    {
        if verbose {
            println!("match_msg: authority section does not match");
        }
        return false;
    }

    if matches.ad && !msg.header().ad() {
        if verbose {
            println!("match_msg: AD not in message",);
        }
        return false;
    }
    if matches.cd && !msg.header().cd() {
        if verbose {
            println!("match_msg: CD not in message",);
        }
        return false;
    }
    if matches.fl_do {
        if let Some(opt) = msg.opt() {
            if !opt.dnssec_ok() {
                if verbose {
                    println!("match_msg: DO not in message",);
                }
                return false;
            }
        } else {
            if verbose {
                println!("match_msg: DO not in message (not opt record)",);
            }
            return false;
        }
    }
    if matches.rd && !msg.header().rd() {
        if verbose {
            println!("match_msg: RD not in message",);
        }
        return false;
    }
    if matches.flags {
        let header = msg.header();
        if reply.qr != header.qr() {
            if verbose {
                todo!();
            }
            return false;
        }
        if reply.aa != header.aa() {
            if verbose {
                println!(
                    "match_msg: AA does not match, got {}, expected {}",
                    header.aa(),
                    reply.aa
                );
            }
            return false;
        }
        if reply.tc != header.tc() {
            if verbose {
                println!(
                    "match_msg: TC does not match, got {}, expected {}",
                    header.tc(),
                    reply.tc
                );
            }
            return false;
        }
        if reply.ra != header.ra() {
            if verbose {
                println!(
                    "match_msg: RA does not match, got {}, expected {}",
                    header.ra(),
                    reply.ra
                );
            }
            return false;
        }
        if reply.rd != header.rd() {
            if verbose {
                println!(
                    "match_msg: RD does not match, got {}, expected {}",
                    header.rd(),
                    reply.rd
                );
            }
            return false;
        }
        if reply.ad != header.ad() {
            if verbose {
                println!(
                    "match_msg: AD does not match, got {}, expected {}",
                    header.ad(),
                    reply.ad
                );
            }
            return false;
        }
        if reply.cd != header.cd() {
            if verbose {
                println!(
                    "match_msg: CD does not match, got {}, expected {}",
                    header.cd(),
                    reply.cd
                );
            }
            return false;
        }
    }
    if matches.opcode {
        let expected_opcode = if reply.notify {
            Opcode::Notify
        } else {
            Opcode::Query
        };
        if msg.header().opcode() != expected_opcode {
            if verbose {
                println!(
                    "Opcode does not match, got {} expected {}",
                    msg.header().opcode(),
                    expected_opcode
                );
            }
            return false;
        }
    }
    if (matches.qname || matches.qtype)
        && !match_question(
            sections.question.clone(),
            msg.question(),
            matches.qname,
            matches.qtype,
        )
    {
        if verbose {
            println!("match_msg: question section does not match");
        }
        return false;
    }
    if matches.rcode {
        let msg_rcode =
            get_opt_rcode(&Message::from_octets(msg.as_slice()).unwrap());
        if reply.noerror {
            if let OptRcode::NoError = msg_rcode {
                // Okay
            } else {
                if verbose {
                    println!(
                        "Wrong Rcode, expected NOERROR, got {msg_rcode}"
                    );
                }
                return false;
            }
        } else if reply.formerr {
            if let OptRcode::FormErr = msg_rcode {
                // Okay
            } else {
                if verbose {
                    println!(
                        "Wrong Rcode, expected FORMERR, got {msg_rcode}"
                    );
                }
                return false;
            }
        } else if reply.notimp {
            if let OptRcode::NotImp = msg_rcode {
                // Okay
            } else {
                if verbose {
                    println!("Wrong Rcode, expected NOTIMP, got {msg_rcode}");
                }
                return false;
            }
        } else if reply.nxdomain {
            if let OptRcode::NXDomain = msg_rcode {
                // Okay
            } else {
                if verbose {
                    println!(
                        "Wrong Rcode, expected NXDOMAIN, got {msg_rcode}"
                    );
                }
                return false;
            }
        } else if reply.refused {
            if let OptRcode::Refused = msg_rcode {
                // Okay
            } else {
                if verbose {
                    println!(
                        "Wrong Rcode, expected REFUSED, got {msg_rcode}"
                    );
                }
                return false;
            }
        } else if "BADCOOKIE" == reply.yxrrset.as_str() {
            if !matches!(msg_rcode, OptRcode::BadCookie) {
                if verbose {
                    println!(
                        "Wrong Rcode, expected BADCOOKIE, got {msg_rcode}"
                    );
                }
                return false;
            }
        } else {
            if verbose {
                println!("Unexpected Rcode: {msg_rcode}");
            }
            return false;
        }
    }
    if matches.subdomain {
        todo!()
    }
    if matches.tcp {
        // Note: Creation of a TCP client is handled by the client factory passed to do_client().
        // TODO: Verify that the client is actually a TCP client.
    }
    if matches.ttl {
        // Nothing to do. TTLs are checked in the relevant sections.
    }
    if matches.udp {
        // Note: Creation of a UDP client is handled by the client factory passed to do_client().
        // TODO: Verify that the client is actually a UDP client.
    }

    // All checks passed!
    true
}

fn match_section<
    'a,
    Octs: Clone + Octets<Range<'a> = Octs2> + 'a,
    Octs2: AsRef<[u8]> + Clone,
>(
    mut match_section: Vec<ZonefileEntry>,
    match_edns_bytes: Option<&[u8]>,
    msg_section: RecordSection<'a, Octs>,
    msg_count: u16,
    match_ttl: bool,
    verbose: bool,
) -> bool {
    let mat_opt =
        match_edns_bytes.map(|bytes| Opt::from_slice(bytes).unwrap());

    if match_section.len() != msg_count.into() {
        if verbose {
            println!("match_section: expected section length {} doesn't match message count {}", match_section.len(), msg_count);
            if !match_section.is_empty() {
                println!("expected sections:");
                for section in match_section {
                    println!("  {section:?}");
                }
            }
        }
        return false;
    }
    'outer: for msg_rr in msg_section {
        let msg_rr = msg_rr.unwrap();
        if msg_rr.rtype() == Rtype::Opt {
            if let Some(mat_opt) = mat_opt {
                let record =
                    msg_rr.clone().into_record::<Opt<_>>().unwrap().unwrap();
                let record = OptRecord::from_record(record);
                println!("matching {:?} with {:?}", record.opt(), mat_opt);
                if record.opt() == mat_opt {
                    continue;
                }
            } else {
                continue;
            }
        }
        for (index, mat_rr) in match_section.iter().enumerate() {
            // Remove outer Record
            let mat_rr = if let ZonefileEntry::Record(record) = mat_rr {
                record
            } else {
                panic!("include not expected");
            };
            println!(
                "matching {:?} with {:?}",
                msg_rr.owner(),
                mat_rr.owner()
            );
            if msg_rr.owner() != mat_rr.owner() {
                continue;
            }
            println!(
                "matching {:?} with {:?}",
                msg_rr.class(),
                mat_rr.class()
            );
            if msg_rr.class() != mat_rr.class() {
                continue;
            }
            println!(
                "matching {:?} with {:?}",
                msg_rr.rtype(),
                mat_rr.rtype()
            );
            if msg_rr.rtype() != mat_rr.rtype() {
                continue;
            }
            let msg_rdata = msg_rr
                .clone()
                .into_record::<ZoneRecordData<Octs2, ParsedDname<Octs2>>>()
                .unwrap()
                .unwrap();
            println!(
                "matching {:?} with {:?}",
                msg_rdata.data(),
                mat_rr.data()
            );
            if msg_rdata.data() != mat_rr.data() {
                continue;
            }

            // Found one. Check TTL
            if match_ttl && msg_rr.ttl() != mat_rr.ttl() {
                if verbose {
                    println!("match_section: TTL does not match for {} {} {}: got {:?} expected {:?}",
			msg_rr.owner(), msg_rr.class(), msg_rr.rtype(),
			msg_rr.ttl(), mat_rr.ttl());
                }
                return false;
            }
            // Delete this entry
            match_section.swap_remove(index);
            continue 'outer;
        }
        // Nothing matches
        if verbose {
            println!(
                "no match for record {} {} {}",
                msg_rr.owner(),
                msg_rr.class(),
                msg_rr.rtype()
            );
        }
        return false;
    }

    // All entries in the reply were matched.
    true
}

fn match_question<Octs: Octets>(
    match_section: Vec<parse_query::Entry>,
    msg_section: QuestionSection<'_, Octs>,
    match_qname: bool,
    match_qtype: bool,
) -> bool {
    if match_section.is_empty() {
        // Nothing to match.
        return true;
    }
    for msg_rr in msg_section {
        let msg_rr = msg_rr.unwrap();
        let mat_rr = if let parse_query::Entry::QueryRecord(record) =
            &match_section[0]
        {
            record
        } else {
            panic!("include not expected");
        };
        if match_qname && msg_rr.qname() != mat_rr.qname() {
            return false;
        }
        if match_qtype && msg_rr.qtype() != mat_rr.qtype() {
            return false;
        }
    }
    // All entries in the reply were matched.
    true
}

fn get_opt_rcode<Octs: Octets>(msg: &Message<Octs>) -> OptRcode {
    let opt = msg.opt();
    match opt {
        Some(opt) => opt.rcode(msg.header()),
        None => {
            // Convert Rcode to OptRcode, this should be part of
            // OptRcode
            OptRcode::from_int(msg.header().rcode().to_int() as u16)
        }
    }
}
