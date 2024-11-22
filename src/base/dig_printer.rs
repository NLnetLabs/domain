use core::fmt;

use crate::rdata::AllRecordData;

use super::zonefile_fmt::ZonefileFmt;
use super::ParsedRecord;
use super::{opt::AllOptData, Message, Rtype};

/// Interal type for printing a message in dig style
///
/// This is only exposed to users of this library as `impl fmt::Display`.
pub(super) struct DigPrinter<'a, Octs> {
    pub msg: &'a Message<Octs>,
}

impl<'a, Octs: AsRef<[u8]>> fmt::Display for DigPrinter<'a, Octs> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = self.msg.for_slice_ref();

        // Header
        let header = msg.header();
        let counts = msg.header_counts();

        writeln!(
            f,
            ";; ->>HEADER<<- opcode: {}, rcode: {}, id: {}",
            header.opcode().display_zonefile(false, false),
            header.rcode(),
            header.id()
        )?;
        write!(f, ";; flags: {}", header.flags())?;
        writeln!(
            f,
            "; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}",
            counts.qdcount(),
            counts.ancount(),
            counts.nscount(),
            counts.arcount()
        )?;

        // We need this later
        let opt = msg.opt();

        if let Some(opt) = opt.as_ref() {
            writeln!(f, "\n;; OPT PSEUDOSECTION:")?;
            writeln!(
                f,
                "; EDNS: version {}; flags: {}; udp: {}",
                opt.version(),
                opt.dnssec_ok(),
                opt.udp_payload_size()
            )?;
            for option in opt.opt().iter::<AllOptData<_, _>>() {
                use AllOptData::*;

                match option {
                    Ok(opt) => match opt {
                        Nsid(nsid) => writeln!(f, "; NSID: {}", nsid)?,
                        Dau(dau) => writeln!(f, "; DAU: {}", dau)?,
                        Dhu(dhu) => writeln!(f, "; DHU: {}", dhu)?,
                        N3u(n3u) => writeln!(f, "; N3U: {}", n3u)?,
                        Expire(expire) => {
                            writeln!(f, "; EXPIRE: {}", expire)?
                        }
                        TcpKeepalive(opt) => {
                            writeln!(f, "; TCPKEEPALIVE: {}", opt)?
                        }
                        Padding(padding) => {
                            writeln!(f, "; PADDING: {}", padding)?
                        }
                        ClientSubnet(opt) => {
                            writeln!(f, "; CLIENTSUBNET: {}", opt)?
                        }
                        Cookie(cookie) => {
                            writeln!(f, "; COOKIE: {}", cookie)?
                        }
                        Chain(chain) => writeln!(f, "; CHAIN: {}", chain)?,
                        KeyTag(keytag) => {
                            writeln!(f, "; KEYTAG: {}", keytag)?
                        }
                        ExtendedError(extendederror) => {
                            writeln!(f, "; EDE: {}", extendederror)?
                        }
                        Other(other) => {
                            writeln!(f, "; {}", other.code())?;
                        }
                    },
                    Err(err) => {
                        writeln!(f, "; ERROR: bad option: {}.", err)?;
                    }
                }
            }
        }

        // Question
        let questions = msg.question();
        if counts.qdcount() > 0 {
            writeln!(f, ";; QUESTION SECTION:")?;
            for item in questions {
                if let Ok(item) = item {
                    writeln!(f, "; {}", item)?;
                } else {
                    writeln!(f, "; <invalid message>")?;
                    return Ok(());
                };
            }
        }

        // Answer
        let section = questions.answer().unwrap();
        if counts.ancount() > 0 {
            writeln!(f, "\n;; ANSWER SECTION:")?;
            for item in section {
                if let Ok(item) = item {
                    write_record_item(f, &item)?;
                } else {
                    writeln!(f, "; <invalid message>")?;
                    return Ok(());
                };
            }
        }

        // Authority
        let section = section.next_section().unwrap().unwrap();
        if counts.nscount() > 0 {
            writeln!(f, "\n;; AUTHORITY SECTION:")?;
            for item in section {
                if let Ok(item) = item {
                    write_record_item(f, &item)?;
                } else {
                    writeln!(f, "; <invalid message>")?;
                    return Ok(());
                };
            }
        }

        // Additional
        let section = section.next_section().unwrap().unwrap();
        if counts.arcount() > 1 || (opt.is_none() && counts.arcount() > 0) {
            writeln!(f, "\n;; ADDITIONAL SECTION:")?;
            for item in section {
                if let Ok(item) = item {
                    if item.rtype() != Rtype::OPT {
                        write_record_item(f, &item)?;
                    }
                } else {
                    writeln!(f, "; <invalid message>")?;
                    return Ok(());
                };
            }
        }

        Ok(())
    }
}

fn write_record_item(
    f: &mut impl fmt::Write,
    item: &ParsedRecord<&[u8]>,
) -> Result<(), fmt::Error> {
    let parsed = item.to_any_record::<AllRecordData<_, _>>();

    match parsed {
        Ok(item) => writeln!(f, "{}", item.display_zonefile(false, false)),
        Err(_) => writeln!(
            f,
            "; {} {} {} {} <invalid data>",
            item.owner(),
            item.ttl().as_secs(),
            item.class(),
            item.rtype()
        ),
    }
}
