// Validator

use crate::base::Dname;
use crate::base::Message;
use bytes::Bytes;
//use crate::base::ParseRecordData;
//use crate::base::ParsedDname;
use crate::base::iana::Class;
use crate::base::iana::OptRcode::NoError;
use crate::base::name::ToDname;
use crate::base::Rtype;
use crate::dep::octseq::Octets;
//use crate::dep::octseq::OctetsInto;
//use crate::dep::octseq::OctetsFrom;
//use crate::dep::octseq::OctetsInto;
use crate::net::client::request::RequestMessage;
use crate::net::client::request::SendRequest;
//use crate::rdata::AllRecordData;
use context::ValidationContext;
//use group::Group;
use group::GroupList;
use std::fmt::Debug;
use types::Error;
use types::ValidationState;

pub async fn validate_msg<'a, Octs, Upstream>(
    msg: &'a Message<Octs>,
    vc: &ValidationContext<Upstream>,
) -> Result<ValidationState, Error>
where
    Octs: Clone + Debug + Octets + 'a,
    <Octs as Octets>::Range<'a>: Debug,
    Upstream: Clone + SendRequest<RequestMessage<Bytes>>,
{
    // Convert to Bytes.
    let bytes = Bytes::copy_from_slice(msg.as_slice());
    let msg = Message::from_octets(bytes).unwrap();

    // First convert the Answer and Authority sections to lists of RR groups
    let mut answers = GroupList::new();
    for rr in msg.answer().unwrap() {
        answers.add(rr.unwrap());
    }
    let mut authorities = GroupList::new();
    for rr in msg.authority().unwrap() {
        authorities.add(rr.unwrap());
    }

    //println!("Answer groups: {answers:?}");
    //println!("Authority groups: {authorities:?}");

    // Get rid of redundant unsigned CNAMEs
    answers.remove_redundant_cnames();

    // Validate each group. We cannot use iter_mut because it requires a
    // reference with a lifetime that is too long.
    // Group can handle this by hiding the state behind a Mutex.
    match validate_groups(&mut answers, vc).await {
        Some(state) => return Ok(state),
        None => (),
    }
    match validate_groups(&mut authorities, vc).await {
        Some(state) => return Ok(state),
        None => (),
    }

    // Go through the answers and use CNAME and DNAME records to update 'SNAME'
    // (see RFC 1034, Section 5.3.2) to the final name that results in an
    // answer, NODATA, or NXDOMAIN. First extract QNAME/QCLASS/QTYPE. Require
    // that the question section has only one entry. Return FormError if that
    // is not the case (following draft-bellis-dnsop-qdcount-is-one-00)

    // Extract Qname, Qclass, Qtype
    let mut question_section = msg.question();
    let question = match question_section.next() {
        None => {
            return Err(Error::FormError);
        }
        Some(question) => question?,
    };
    if question_section.next().is_some() {
        return Err(Error::FormError);
    }
    let qname: Dname<Bytes> = question.qname().to_dname().unwrap();
    let qclass = question.qclass();
    let qtype = question.qtype();

    let sname = do_cname_dname(qname, qclass, qtype, &mut answers);

    // For NOERROR, check if the answer is positive. Then extract the status
    // of the group and be done.
    // For NODATA first get the SOA, this determines if the proof of a
    // negative result is signed or not.
    if let NoError = msg.opt_rcode() {
        let opt_state = get_answer_state(&sname, qclass, qtype, &mut answers);
        if let Some(state) = opt_state {
            return Ok(state);
        }
    }

    // For both NOERROR/NODATA and for NXDOMAIN we can first look at the SOA
    // record in the authority section. If there is no SOA, return bogus. If
    // there is one and the state is not secure, then return the state of the
    // SOA record.
    match get_soa_state(sname, qclass, &mut authorities) {
        None => return Ok(ValidationState::Bogus), // No SOA, assume the worst.
        Some(state) => match state {
            ValidationState::Secure => (), // Continue validation.
            ValidationState::Insecure
            | ValidationState::Bogus
            | ValidationState::Indeterminate => return Ok(state),
        },
    }

    todo!();
}

fn do_cname_dname(
    qname: Dname<Bytes>,
    qclass: Class,
    _qtype: Rtype,
    groups: &mut GroupList,
) -> Dname<Bytes> {
    for g in groups.iter() {
        if g.class() != qclass {
            continue;
        }
        let rtype = g.rtype();
        if rtype != Rtype::Cname && rtype != Rtype::Dname {
            continue;
        }
        todo!();
    }

    qname
}

fn get_answer_state(
    qname: &Dname<Bytes>,
    qclass: Class,
    qtype: Rtype,
    groups: &mut GroupList,
) -> Option<ValidationState> {
    for g in groups.iter() {
        if g.class() != qclass {
            continue;
        }
        if g.rtype() != qtype {
            continue;
        }
        if g.name() != qname {
            continue;
        }
        return Some(g.get_state().unwrap());
    }
    None
}

fn get_soa_state(
    qname: Dname<Bytes>,
    qclass: Class,
    groups: &mut GroupList,
) -> Option<ValidationState> {
    for g in groups.iter() {
        println!("get_soa_state: trying {g:?} for {qname:?}");
        if g.class() != qclass {
            println!("get_soa_state: wrong class");
            continue;
        }
        if g.rtype() != Rtype::Soa {
            println!("get_soa_state: wrong type");
            continue;
        }
        if !qname.ends_with(&g.name()) {
            println!(
                "get_soa_state: wrong name {qname:?} should end with {:?}",
                g.name()
            );
            println!(
                "{:?}.ends_with({:?}): {:?}",
                qname,
                g.name(),
                qname.ends_with(&g.name())
            );
            println!(
                "{:?}.ends_with({:?}): {:?}",
                g.name(),
                qname,
                g.name().ends_with(&qname)
            );
            continue;
        }
        return Some(g.get_state().unwrap());
    }
    None
}

async fn validate_groups<Upstream>(
    groups: &mut GroupList,
    vc: &ValidationContext<Upstream>,
) -> Option<ValidationState>
where
    Upstream: Clone + SendRequest<RequestMessage<Bytes>>,
{
    for g in groups.iter() {
        //println!("Validating group {g:?}");
        let state = g.validate_with_vc(vc).await;
        if let ValidationState::Bogus = state {
            return Some(state);
        }
        g.set_state(state);
    }
    None
}

pub mod anchor;
pub mod context;
mod group;
pub mod types;
