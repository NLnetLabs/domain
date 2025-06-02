use tracing::trace;

use super::parse_stelline::{Entry, Matches};
use crate::base::iana::{Opcode, Rtype};
use crate::base::opt::Opt;
use crate::base::{Message, ParsedName, ParsedRecord, RecordSection};
use crate::dep::octseq::Octets;
use crate::rdata::ZoneRecordData;
use crate::zonefile::inplace::Entry as ZonefileEntry;

impl Matches {
    pub fn set_all(&mut self) {
        self.opcode = true;
        self.qtype = true;
        self.qname = true;
        self.flags = true;
        self.rcode = true;
        self.answer = true;
        self.authority = true;
        self.additional = true;
    }

    pub fn set_question(&mut self) {
        self.qtype = true;
        self.qname = true;
    }
}

pub struct DidNotMatch;

impl Entry {
    pub fn match_multi_msg_ordered(&self) -> OrderedMultiMatcher {
        OrderedMultiMatcher {
            entry: self,
            answer_idx: 0,
        }
    }

    pub fn match_multi_msg_unordered(&self) -> UnorderedMultiMatcher {
        let all_answers =
            self.sections.answer.iter().flatten().cloned().collect();
        UnorderedMultiMatcher {
            entry: self,
            answers: all_answers,
        }
    }

    pub fn match_msg<Octs: Octets>(
        &self,
        msg: &Message<Octs>,
    ) -> Result<(), DidNotMatch> {
        self.match_flags(msg)?;
        self.match_edns_data(msg)?;
        self.match_opcode(msg)?;
        self.match_question(msg)?;
        self.match_rcode(msg)?;

        if self.matches.answer {
            if self.matches.any_answer {
                self.match_any_answer(msg)?;
            } else {
                self.match_answer(0, msg)?;
            }
        }

        self.match_authority(msg)?;
        self.match_additional(msg)?;

        if self.matches.tcp {
            // Note: Creation of a TCP client is handled by the client factory passed to do_client().
            // TODO: Verify that the client is actually a TCP client.
        }
        if self.matches.udp {
            // Note: Creation of a UDP client is handled by the client factory passed to do_client().
            // TODO: Verify that the client is actually a UDP client.
        }

        // All checks passed!
        Ok(())
    }

    /// Match the ENDS data in the OPT record
    fn match_edns_data<Octs: Octets>(
        &self,
        msg: &Message<Octs>,
    ) -> Result<(), DidNotMatch> {
        if self.matches.edns_data {
            let data = &self.sections.additional.edns_bytes;
            let opt = Opt::from_slice(data).unwrap();

            let Some(msg_opt) = msg.opt() else {
                trace!("match_msg: an OPT record must be present");
                return Err(DidNotMatch);
            };

            trace!("matching {:?} with {:?}", msg_opt.opt(), opt);
            if msg_opt.opt() != opt {
                return Err(DidNotMatch);
            }
        }
        Ok(())
    }

    /// Match the value of the OPCODE
    fn match_opcode<Octs: Octets>(
        &self,
        msg: &Message<Octs>,
    ) -> Result<(), DidNotMatch> {
        if !self.matches.opcode {
            return Ok(());
        }

        let expected_opcode = if self.reply.notify {
            Opcode::NOTIFY
        } else if let Some(opcode) = self.opcode {
            opcode
        } else {
            Opcode::QUERY
        };

        if msg.header().opcode() == expected_opcode {
            Ok(())
        } else {
            trace!(
                "Opcode does not match, got {} expected {}",
                msg.header().opcode(),
                expected_opcode
            );
            Err(DidNotMatch)
        }
    }

    /// Match the value of the RCODE
    fn match_rcode<Octs: Octets>(
        &self,
        msg: &Message<Octs>,
    ) -> Result<(), DidNotMatch> {
        if self.matches.rcode {
            let msg_rcode = msg.opt_rcode();
            match self.reply.rcode {
                Some(reply_rcode) if reply_rcode != msg_rcode => {
                    trace!(
                        "Wrong Rcode, expected {reply_rcode}, got {msg_rcode}"
                    );
                    return Err(DidNotMatch);
                }
                _ => { /* Okay */ }
            }
        }
        Ok(())
    }

    /// Match the question section
    ///
    /// This checks the qname, qtype and subdomain of the records in the section
    /// (if the relevant fields of `Matches` are set).
    fn match_question<Octs: Octets>(
        &self,
        msg: &Message<Octs>,
    ) -> Result<(), DidNotMatch> {
        let match_section = &self.sections.question;
        let msg_section = msg.question();

        if !self.matches.qname
            && !self.matches.qtype
            && !self.matches.subdomain
        {
            // small optimization: nothing to check!
            return Ok(());
        }

        for msg_rr in msg_section {
            let msg_rr = msg_rr.unwrap();
            let mat_rr = &match_section[0];
            if self.matches.qname && msg_rr.qname() != mat_rr.qname() {
                return Err(DidNotMatch);
            }
            if self.matches.subdomain
                && !msg_rr.qname().ends_with(mat_rr.qname())
            {
                return Err(DidNotMatch);
            }
            if self.matches.qtype && msg_rr.qtype() != mat_rr.qtype() {
                return Err(DidNotMatch);
            }
        }

        // All checks passed!
        Ok(())
    }

    fn match_section<Octs: Octets>(
        &self,
        match_section: &[ZonefileEntry],
        msg_section: RecordSection<'_, Octs>,
        msg_count: u16,
        allow_partial_match: bool,
    ) -> Result<(), DidNotMatch> {
        if !allow_partial_match && match_section.len() != msg_count as usize {
            trace!("match_section: expected section length {} doesn't match message count {}", match_section.len(), msg_count);
            if !match_section.is_empty() {
                trace!("expected sections:");
                for section in match_section {
                    trace!("  {section:?}");
                }
            }
            return Err(DidNotMatch);
        }

        // We delete the matched sections to track which ones we've seen, so we
        // clone the vec.
        let mut match_section = match_section.to_vec();

        for msg_rr in msg_section {
            let msg_rr = msg_rr.unwrap();
            if msg_rr.rtype() == Rtype::OPT {
                continue;
            }

            if let Some(idx) =
                self.find_matching_record(&match_section, &msg_rr)
            {
                // Delete the entry because only one record should match it
                match_section.swap_remove(idx);
            } else {
                // Nothing matches
                trace!(
                    "no match for record '{} {} {}'",
                    msg_rr.owner(),
                    msg_rr.class(),
                    msg_rr.rtype(),
                );
                return Err(DidNotMatch);
            }
        }

        // All entries in the reply were matched.
        Ok(())
    }

    fn find_matching_record<Octs: Octets>(
        &self,
        entries: &[ZonefileEntry],
        msg_rr: &ParsedRecord<'_, Octs>,
    ) -> Option<usize> {
        let msg_rdata = msg_rr
            .to_record::<ZoneRecordData<_, ParsedName<_>>>()
            .unwrap()
            .unwrap();

        entries.iter().position(|mat_rr| {
            // Remove outer Record
            let ZonefileEntry::Record(mat_rr) = mat_rr else {
                panic!("include not expected");
            };

            let owner = msg_rr.owner() == mat_rr.owner();
            let class = msg_rr.class() == mat_rr.class();
            let rtype = msg_rr.rtype() == mat_rr.rtype();
            let rdata = msg_rdata.data() == mat_rr.data();

            if !(owner && class && rtype && rdata) {
                return false;
            }

            // Found one. Check TTL
            if self.matches.ttl && msg_rr.ttl() != mat_rr.ttl() {
                trace!("match_section: TTL does not match for {} {} {}: got {:?} expected {:?}",
                msg_rr.owner(), msg_rr.class(), msg_rr.rtype(),
                msg_rr.ttl(), mat_rr.ttl());
                return false;
            }

            true
        })
    }

    /// Match the specified answer
    fn match_answer<Octs: Octets>(
        &self,
        answer_idx: usize,
        msg: &Message<Octs>,
    ) -> Result<(), DidNotMatch> {
        if !self.matches.answer {
            return Ok(());
        }

        let Some(answer) = self.sections.answer.get(answer_idx) else {
            trace!("match_msg: answer section {answer_idx} missing");
            return Err(DidNotMatch);
        };

        self.match_section(
            answer,
            msg.answer().unwrap(),
            msg.header_counts().ancount(),
            self.matches.extra_packets,
        )
    }

    /// Match any one of the available answers (additional answers can
    /// be provided using the EXTRA_PACKET Stelline directive).
    fn match_any_answer<Octs: Octets>(
        &self,
        msg: &Message<Octs>,
    ) -> Result<(), DidNotMatch> {
        for answer_idx in 0..self.sections.answer.len() {
            if let Ok(()) = self.match_answer(answer_idx, msg) {
                return Ok(());
            }
        }
        Err(DidNotMatch)
    }

    /// Match the authority section if `matches.authority` is set
    fn match_authority<Octs: Octets>(
        &self,
        msg: &Message<Octs>,
    ) -> Result<(), DidNotMatch> {
        if self.matches.authority {
            self.match_section(
                &self.sections.authority,
                msg.authority().unwrap(),
                msg.header_counts().nscount(),
                false,
            )?;
        }
        Ok(())
    }

    /// Match the additional section if `matches.additional` is set
    fn match_additional<Octs: Octets>(
        &self,
        msg: &Message<Octs>,
    ) -> Result<(), DidNotMatch> {
        if !self.matches.additional {
            return Ok(());
        }

        let mut arcount = msg.header_counts().arcount();
        if msg.opt().is_some() {
            arcount -= 1;
        }

        self.match_section(
            &self.sections.additional.zone_entries,
            msg.additional().unwrap(),
            arcount,
            false,
        )
    }

    /// Match the flags of the incoming message including `DO`
    fn match_flags<Octs: Octets>(
        &self,
        msg: &Message<Octs>,
    ) -> Result<(), DidNotMatch> {
        let r = &self.reply;
        let h = msg.header();

        // These flags must be set if the value for self is true
        let flags = [
            ("AD", self.matches.ad, h.ad()),
            ("CD", self.matches.cd, h.cd()),
            ("RD", self.matches.rd, h.rd()),
        ];
        for (name, m, h) in flags {
            if m && !h {
                trace!("match_msg: {name} not in message",);
                return Err(DidNotMatch);
            }
        }

        if self.matches.fl_do {
            let do_set = msg.opt().is_some_and(|o| o.dnssec_ok());
            if !do_set {
                trace!("match_msg: DO not set");
                return Err(DidNotMatch);
            }
        }

        // If we don't check the other flags, we return early
        if !self.matches.flags {
            return Ok(());
        }

        // These flags must match the reply
        let flags = [
            ("QR", r.qr, h.qr()),
            ("AA", r.aa, h.aa()),
            ("TC", r.tc, h.tc()),
            ("RA", r.ra, h.ra()),
            ("RA", r.rd, h.rd()),
            ("AD", r.ad, h.ad()),
            ("CD", r.cd, h.cd()),
        ];

        for (name, r, h) in flags {
            if r != h {
                trace!("match_msg: {name} does not match, got {r:?}, expected {h:?}");
                return Err(DidNotMatch);
            }
        }

        Ok(())
    }
}

pub struct OrderedMultiMatcher<'a> {
    answer_idx: usize,
    entry: &'a Entry,
}

impl OrderedMultiMatcher<'_> {
    pub fn match_msg<Octs: Octets>(
        &mut self,
        msg: &Message<Octs>,
    ) -> Result<(), DidNotMatch> {
        let e = &self.entry;

        e.match_flags(msg)?;
        e.match_edns_data(msg)?;
        e.match_opcode(msg)?;
        e.match_question(msg)?;
        e.match_rcode(msg)?;

        if e.matches.answer {
            e.match_answer(self.answer_idx, msg)?;
        }

        e.match_authority(msg)?;
        e.match_additional(msg)?;

        self.answer_idx += 1;
        Ok(())
    }

    pub fn finish(self) -> Result<(), DidNotMatch> {
        let answer = &self.entry.sections.answer;

        // Special case for when we don't have to check anything
        if self.answer_idx == 0 && answer.len() == 1 && answer[0].is_empty() {
            Ok(())
        } else if self.answer_idx < answer.len() {
            Err(DidNotMatch)
        } else {
            Ok(())
        }
    }
}

pub struct UnorderedMultiMatcher<'a> {
    entry: &'a Entry,
    answers: std::vec::Vec<ZonefileEntry>,
}

impl UnorderedMultiMatcher<'_> {
    pub fn answer_records_left(&self) -> usize {
        self.answers.len()
    }

    pub fn match_msg<Octs: Octets>(
        &mut self,
        msg: &Message<Octs>,
    ) -> Result<(), DidNotMatch> {
        let e = &self.entry;

        e.match_flags(msg)?;
        e.match_edns_data(msg)?;
        e.match_opcode(msg)?;
        e.match_question(msg)?;
        e.match_rcode(msg)?;

        for msg_rr in msg.answer().unwrap() {
            let msg_rr = msg_rr.unwrap();
            if msg_rr.rtype() == Rtype::OPT {
                continue;
            }

            if let Some(idx) =
                self.entry.find_matching_record(&self.answers, &msg_rr)
            {
                // Delete the entry because only one record should match it
                self.answers.swap_remove(idx);
            } else {
                // Nothing matches
                trace!(
                    "no match for record {} {} {}",
                    msg_rr.owner(),
                    msg_rr.class(),
                    msg_rr.rtype(),
                );
                return Err(DidNotMatch);
            }
        }

        e.match_authority(msg)?;
        e.match_additional(msg)?;

        Ok(())
    }

    pub fn finish(self) -> Result<(), DidNotMatch> {
        if self.answers.is_empty() {
            Ok(())
        } else {
            Err(DidNotMatch)
        }
    }
}
