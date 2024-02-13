use std::default::Default;
use std::fmt::Debug;
use std::io::{self, BufRead, Read};
use std::net::IpAddr;

use crate::net::deckard::parse_query;
use crate::net::deckard::parse_query::Zonefile as QueryZonefile;
use domain::zonefile::inplace::Entry as ZonefileEntry;
use domain::zonefile::inplace::Zonefile;

const CONFIG_END: &str = "CONFIG_END";
const SCENARIO_BEGIN: &str = "SCENARIO_BEGIN";
const SCENARIO_END: &str = "SCENARIO_END";
const RANGE_BEGIN: &str = "RANGE_BEGIN";
const RANGE_END: &str = "RANGE_END";
const ADDRESS: &str = "ADDRESS";
const ENTRY_BEGIN: &str = "ENTRY_BEGIN";
const ENTRY_END: &str = "ENTRY_END";
const MATCH: &str = "MATCH";
const ADJUST: &str = "ADJUST";
const REPLY: &str = "REPLY";
const SECTION: &str = "SECTION";
const QUESTION: &str = "QUESTION";
const ANSWER: &str = "ANSWER";
const AUTHORITY: &str = "AUTHORITY";
const ADDITIONAL: &str = "ADDITIONAL";
const STEP: &str = "STEP";
const STEP_TYPE_QUERY: &str = "QUERY";
const STEP_TYPE_CHECK_ANSWER: &str = "CHECK_ANSWER";
const STEP_TYPE_TIME_PASSES: &str = "TIME_PASSES";
const STEP_TYPE_TRAFFIC: &str = "TRAFFIC";
const STEP_TYPE_CHECK_TEMPFILE: &str = "CHECK_TEMPFILE";
const STEP_TYPE_ASSIGN: &str = "ASSIGN";
const HEX_EDNSDATA_BEGIN: &str = "HEX_EDNSDATA_BEGIN";
const HEX_EDNSDATA_END: &str = "HEX_EDNSDATA_END";

enum Section {
    Question,
    Answer,
    Authority,
    Additional,
}

#[derive(Clone, Debug)]
pub enum StepType {
    Query,
    CheckAnswer,
    TimePasses,
    Traffic,
    CheckTempfile,
    Assign,
}

impl std::fmt::Display for StepType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StepType::Query => f.write_str("Query"),
            StepType::CheckAnswer => f.write_str("CheckAnswer"),
            StepType::TimePasses => f.write_str("TimePasses"),
            StepType::Traffic => f.write_str("Traffic"),
            StepType::CheckTempfile => f.write_str("CheckTempfile"),
            StepType::Assign => f.write_str("Assign"),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Config {
    lines: Vec<String>,
}

impl Config {
    #[allow(dead_code)]
    pub fn lines(&self) -> &[String] {
        self.lines.as_ref()
    }
}

#[derive(Clone, Debug)]
pub struct Deckard {
    pub config: Config,
    pub scenario: Scenario,
}

pub fn parse_file<F: Debug + Read>(file: F) -> Deckard {
    let mut lines = io::BufReader::new(file).lines();
    Deckard {
        config: parse_config(&mut lines),
        scenario: parse_scenario(&mut lines),
    }
}

fn parse_config<Lines: Iterator<Item = Result<String, std::io::Error>>>(
    l: &mut Lines,
) -> Config {
    let mut config: Config = Default::default();
    loop {
        let line = l.next().unwrap().unwrap();
        let clean_line = get_clean_line(line.as_ref());
        if clean_line.is_none() {
            continue;
        }
        let clean_line = clean_line.unwrap();
        if clean_line == CONFIG_END {
            break;
        }
        config.lines.push(line.to_string());
    }
    config
}

#[derive(Clone, Debug, Default)]
pub struct Scenario {
    pub ranges: Vec<Range>,
    pub steps: Vec<Step>,
}

pub fn parse_scenario<
    Lines: Iterator<Item = Result<String, std::io::Error>>,
>(
    l: &mut Lines,
) -> Scenario {
    let mut scenario: Scenario = Default::default();
    // Find SCENARIO_BEGIN
    loop {
        let line = l.next().unwrap().unwrap();
        let clean_line = get_clean_line(line.as_ref());
        if clean_line.is_none() {
            continue;
        }
        let clean_line = clean_line.unwrap();
        let mut tokens = LineTokens::new(clean_line);
        let token = tokens.next().unwrap();
        if token == SCENARIO_BEGIN {
            break;
        }
        println!("parse_scenario: garbage line {clean_line:?}");
        panic!("bad line");
    }

    // Find RANGE_BEGIN, STEP, or SCENARIO_END
    loop {
        let line = l.next().unwrap().unwrap();
        let clean_line = get_clean_line(line.as_ref());
        if clean_line.is_none() {
            continue;
        }
        let clean_line = clean_line.unwrap();
        let mut tokens = LineTokens::new(clean_line);
        let token = tokens.next().unwrap();
        if token == RANGE_BEGIN {
            scenario.ranges.push(parse_range(tokens, l));
            continue;
        }
        if token == STEP {
            scenario.steps.push(parse_step(tokens, l));
            continue;
        }
        if token == SCENARIO_END {
            break;
        }
        todo!();
    }
    scenario
}

#[derive(Clone, Debug, Default)]
pub struct Range {
    pub start_value: u64,
    pub end_value: u64,
    addr: Option<IpAddr>,
    pub entry: Vec<Entry>,
}

fn parse_range<Lines: Iterator<Item = Result<String, std::io::Error>>>(
    mut tokens: LineTokens<'_>,
    l: &mut Lines,
) -> Range {
    let mut range: Range = Range {
        start_value: tokens.next().unwrap().parse::<u64>().unwrap(),
        end_value: tokens.next().unwrap().parse::<u64>().unwrap(),
        ..Default::default()
    };
    loop {
        let line = l.next().unwrap().unwrap();
        let clean_line = get_clean_line(line.as_ref());
        if clean_line.is_none() {
            continue;
        }
        let clean_line = clean_line.unwrap();
        let mut tokens = LineTokens::new(clean_line);
        let token = tokens.next().unwrap();
        if token == ADDRESS {
            let addr_str = tokens.next().unwrap();
            range.addr = Some(addr_str.parse().unwrap());
            continue;
        }
        if token == ENTRY_BEGIN {
            range.entry.push(parse_entry(l));
            continue;
        }
        if token == RANGE_END {
            break;
        }
        todo!();
    }
    //println!("parse_range: {:?}", range);
    range
}

#[derive(Clone, Debug)]
pub struct Step {
    pub step_value: u64,
    pub step_type: StepType,
    pub entry: Option<Entry>,
}

fn parse_step<Lines: Iterator<Item = Result<String, std::io::Error>>>(
    mut tokens: LineTokens<'_>,
    l: &mut Lines,
) -> Step {
    let mut step_client_address = None;
    let step_value = tokens.next().unwrap().parse::<u64>().unwrap();
    let step_type_str = tokens.next().unwrap();
    let step_type = if step_type_str == STEP_TYPE_QUERY {
        StepType::Query
    } else if step_type_str == STEP_TYPE_CHECK_ANSWER {
        StepType::CheckAnswer
    } else if step_type_str == STEP_TYPE_TIME_PASSES {
        StepType::TimePasses
    } else if step_type_str == STEP_TYPE_TRAFFIC {
        StepType::Traffic
    } else if step_type_str == STEP_TYPE_CHECK_TEMPFILE {
        StepType::CheckTempfile
    } else if step_type_str == STEP_TYPE_ASSIGN {
        StepType::Assign
    } else {
        todo!();
    };
    let mut step = Step {
        step_value,
        step_type,
        entry: None,
    };

    match step.step_type {
        StepType::Query => {
            // Extract possible query settings
            loop {
                let (param, value) = (tokens.next(), tokens.next());
                match (param, value) {
                    (Some(ADDRESS), Some(addr)) => {
                        step_client_address = Some(addr.parse().unwrap());
                    }
                    (Some(param), Some(value)) => {
                        eprintln!("Ignoring unknown query parameter '{param}' with value '{value}'");
                    }
                    (Some(param), None) => {
                        eprintln!(
                            "Ignoring unknown query parameter '{param}'"
                        );
                    }
                    (None, _) => {
                        // No additional settings specified
                        break;
                    }
                }
            }

            // Continue with entry
        }
        StepType::CheckAnswer => (), // Continue with entry
        StepType::TimePasses => {
            println!("parse_step: should handle TIME_PASSES");
            return step;
        }
        StepType::Traffic => {
            println!("parse_step: should handle TRAFFIC");
            return step;
        }
        StepType::CheckTempfile => {
            println!("parse_step: should handle CHECK_TEMPFILE");
            return step;
        }
        StepType::Assign => {
            println!("parse_step: should handle ASSIGN");
            return step;
        }
    }

    loop {
        let line = l.next().unwrap().unwrap();
        let clean_line = get_clean_line(line.as_ref());
        if clean_line.is_none() {
            continue;
        }
        let clean_line = clean_line.unwrap();
        let mut tokens = LineTokens::new(clean_line);
        let token = tokens.next().unwrap();
        if token == ENTRY_BEGIN {
            step.entry = Some(parse_entry(l));
            step.entry.as_mut().unwrap().client_addr = step_client_address;
            //println!("parse_step: {:?}", step);
            return step;
        }
        todo!();
    }
}

#[derive(Clone, Debug, Default)]
pub struct Entry {
    pub client_addr: Option<IpAddr>,
    pub matches: Option<Matches>,
    pub adjust: Option<Adjust>,
    pub reply: Option<Reply>,
    pub sections: Option<Sections>,
}

fn parse_entry<Lines: Iterator<Item = Result<String, std::io::Error>>>(
    l: &mut Lines,
) -> Entry {
    let mut entry = Entry {
        client_addr: None,
        matches: None,
        adjust: None,
        reply: None,
        sections: None,
    };
    loop {
        let line = l.next().unwrap().unwrap();
        let clean_line = get_clean_line(line.as_ref());
        if clean_line.is_none() {
            continue;
        }
        let clean_line = clean_line.unwrap();
        let mut tokens = LineTokens::new(clean_line);
        let token = tokens.next().unwrap();
        if token == MATCH {
            entry.matches = Some(parse_match(tokens));
            continue;
        }
        if token == ADJUST {
            entry.adjust = Some(parse_adjust(tokens));
            continue;
        }
        if token == REPLY {
            entry.reply = Some(parse_reply(tokens));
            continue;
        }
        if token == SECTION {
            let (sections, line) = parse_section(tokens, l);
            //println!("parse_entry: sections {:?}", sections);
            entry.sections = Some(sections);
            let clean_line = get_clean_line(line.as_ref());
            let clean_line = clean_line.unwrap();
            let mut tokens = LineTokens::new(clean_line);
            let token = tokens.next().unwrap();
            if token == ENTRY_END {
                break;
            }
            todo!();
        }
        if token == ENTRY_END {
            break;
        }
        todo!();
    }
    entry
}

#[derive(Clone, Debug, Default)]
pub struct AdditionalSection {
    pub zone_entries: Vec<ZonefileEntry>,
    pub edns_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct Sections {
    pub question: Vec<parse_query::Entry>,
    pub answer: Vec<ZonefileEntry>,
    pub authority: Vec<ZonefileEntry>,
    pub additional: AdditionalSection,
}

fn parse_section<Lines: Iterator<Item = Result<String, std::io::Error>>>(
    mut tokens: LineTokens<'_>,
    l: &mut Lines,
) -> (Sections, String) {
    let mut sections = Sections::default();
    let next = tokens.next().unwrap();
    let mut section = if next == QUESTION {
        Section::Question
    } else {
        panic!("Bad section {next}");
    };
    // Should extract which section
    loop {
        let line = l.next().unwrap().unwrap();
        let clean_line = get_clean_line(line.as_ref());
        if clean_line.is_none() {
            continue;
        }
        let clean_line = clean_line.unwrap();
        let mut tokens = LineTokens::new(clean_line);
        let token = tokens.next().unwrap();
        if token == SECTION {
            let next = tokens.next().unwrap();
            section = if next == QUESTION {
                Section::Question
            } else if next == ANSWER {
                Section::Answer
            } else if next == AUTHORITY {
                Section::Authority
            } else if next == ADDITIONAL {
                Section::Additional
            } else {
                panic!("Bad section {next}");
            };
            continue;
        }
        if token == ENTRY_END {
            return (sections, line);
        }

        match section {
            Section::Question => {
                let mut zonefile = QueryZonefile::new();
                zonefile.extend_from_slice(clean_line.as_ref());
                zonefile.extend_from_slice(b"\n");
                let e = zonefile.next_entry().unwrap();
                sections.question.push(e.unwrap());
            }
            Section::Answer | Section::Authority | Section::Additional => {
                if matches!(section, Section::Additional)
                    && clean_line == HEX_EDNSDATA_BEGIN
                {
                    loop {
                        let line = l.next().unwrap().unwrap();
                        let clean_line = get_clean_line(line.as_ref());
                        if clean_line.is_none() {
                            continue;
                        }
                        let clean_line = clean_line.unwrap();
                        if clean_line == HEX_EDNSDATA_END {
                            break;
                        }
                        let clean_line = clean_line
                            .replace(|c: char| c.is_whitespace(), "");
                        let edns_line_bytes = hex::decode(&clean_line)
                            .map_err(|err| format!("Hex decoding failure of HEX_EDNSDATA line '{clean_line}': {err}"))
                            .unwrap();
                        sections
                            .additional
                            .edns_bytes
                            .extend(edns_line_bytes);
                    }
                } else {
                    let mut zonefile = Zonefile::new();
                    zonefile.extend_from_slice(b"$ORIGIN .\n");
                    zonefile.extend_from_slice(b"ignore 3600 in ns ignore\n");
                    zonefile.extend_from_slice(clean_line.as_ref());
                    zonefile.extend_from_slice(b"\n");
                    let _e = zonefile.next_entry().unwrap();
                    let e = zonefile.next_entry().unwrap();

                    let e = e.unwrap();
                    match section {
                        Section::Question => unreachable!(),
                        Section::Answer => sections.answer.push(e),
                        Section::Authority => sections.authority.push(e),
                        Section::Additional => {
                            sections.additional.zone_entries.push(e)
                        }
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Matches {
    pub additional: bool,
    pub all: bool,
    pub answer: bool,
    pub authority: bool,
    pub fl_do: bool,
    pub flags: bool,
    pub opcode: bool,
    pub qname: bool,
    pub qtype: bool,
    pub question: bool,
    pub rcode: bool,
    pub subdomain: bool,
    pub tcp: bool,
    pub ttl: bool,
    pub udp: bool,
    pub server_cookie: bool,
}

fn parse_match(mut tokens: LineTokens<'_>) -> Matches {
    let mut matches: Matches = Default::default();

    loop {
        let token = match tokens.next() {
            None => return matches,
            Some(token) => token,
        };

        if token == "all" {
            matches.all = true;
        } else if token == "DO" {
            matches.fl_do = true;
        } else if token == "opcode" {
            matches.opcode = true;
        } else if token == "qname" {
            matches.qname = true;
        } else if token == "question" {
            matches.question = true;
        } else if token == "qtype" {
            matches.qtype = true;
        } else if token == "subdomain" {
            matches.subdomain = true;
        } else if token == "TCP" {
            matches.tcp = true;
        } else if token == "ttl" {
            matches.ttl = true;
        } else if token == "UDP" {
            matches.tcp = true;
        } else if token == "server_cookie" {
            matches.server_cookie = true;
        } else {
            println!("should handle match {token:?}");
            todo!();
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Adjust {
    pub copy_id: bool,
    pub copy_query: bool,
}

fn parse_adjust(mut tokens: LineTokens<'_>) -> Adjust {
    let mut adjust: Adjust = Default::default();

    loop {
        let token = match tokens.next() {
            None => return adjust,
            Some(token) => token,
        };

        if token == "copy_id" {
            adjust.copy_id = true;
        } else if token == "copy_query" {
            adjust.copy_query = true;
        } else {
            println!("should handle adjust {token:?}");
            todo!();
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Reply {
    pub aa: bool,
    pub ad: bool,
    pub cd: bool,
    pub fl_do: bool,
    pub formerr: bool,
    pub noerror: bool,
    pub nxdomain: bool,
    pub qr: bool,
    pub ra: bool,
    pub rd: bool,
    pub refused: bool,
    pub servfail: bool,
    pub tc: bool,
    pub yxdomain: bool,
    pub yxrrset: String,
}

fn parse_reply(mut tokens: LineTokens<'_>) -> Reply {
    let mut reply: Reply = Default::default();

    loop {
        let token = match tokens.next() {
            None => return reply,
            Some(token) => token,
        };

        if token == "AA" {
            reply.aa = true;
        } else if token == "AD" {
            reply.ad = true;
        } else if token == "CD" {
            reply.cd = true;
        } else if token == "DO" {
            reply.fl_do = true;
        } else if token == "FORMERR" {
            reply.formerr = true;
        } else if token == "NOERROR" {
            reply.noerror = true;
        } else if token == "NXDOMAIN" {
            reply.nxdomain = true;
        } else if token == "QR" {
            reply.qr = true;
        } else if token == "RA" {
            reply.ra = true;
        } else if token == "RD" {
            reply.rd = true;
        } else if token == "REFUSED" {
            reply.refused = true;
        } else if token == "SERVFAIL" {
            reply.servfail = true;
        } else if token == "TC" {
            reply.tc = true;
        } else if token == "YXDOMAIN" {
            reply.yxdomain = true;
        } else if token.starts_with("YXRRSET=") {
            reply.yxrrset = token.split_once('=').unwrap().1.to_string();
        } else {
            println!("should handle reply {token:?}");
            todo!();
        }
    }
}

fn get_clean_line(line: &str) -> Option<&str> {
    //println!("get clean line for {:?}", line);
    let opt_comment = line.find(';');
    let line = if let Some(index) = opt_comment {
        &line[0..index]
    } else {
        line
    };
    let trimmed = line.trim();

    //println!("line after trim() {:?}", trimmed);

    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

struct LineTokens<'a> {
    str: &'a str,
    curr_index: usize,
}

impl<'a> LineTokens<'a> {
    fn new(str: &'a str) -> Self {
        Self { str, curr_index: 0 }
    }
}

impl<'a> Iterator for LineTokens<'a> {
    type Item = &'a str;
    fn next(&mut self) -> Option<Self::Item> {
        let cur_str = &self.str[self.curr_index..];

        if cur_str.is_empty() {
            return None;
        }

        // Assume cur_str starts with a token
        for (index, char) in cur_str.char_indices() {
            if !char.is_whitespace() {
                continue;
            }
            let start_index = self.curr_index;
            let end_index = start_index + index;

            let space_str = &self.str[end_index..];

            for (index, char) in space_str.char_indices() {
                if char.is_whitespace() {
                    continue;
                }

                self.curr_index = end_index + index;
                return Some(&self.str[start_index..end_index]);
            }

            todo!();
        }
        self.curr_index = self.str.len();
        Some(cur_str)
    }
}
