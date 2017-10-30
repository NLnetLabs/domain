use bytes::BufMut;
use ::iana::{Class, Rtype};
use super::name::{ParsedFqdn, ParsedFqdnError, ToFqdn};
use super::parse::{Parser};


//------------ Question ------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Question<N> {
    qname: N,
    qtype: Rtype,
    qclass: Class,
}

/// # Creation and Conversion
///
impl<N> Question<N> {
    pub fn new(qname: N, qtype: Rtype, qclass: Class) -> Self {
        Question { qname, qtype, qclass }
    }

    pub fn new_in(qname: N, qtype: Rtype) -> Self {
        Question { qname, qtype, qclass: Class::In }
    }
}

impl Question<ParsedFqdn> {
    pub fn parse(parser: &mut Parser) -> Result<Self, ParsedFqdnError> {
        Ok(Question::new(ParsedFqdn::parse(parser)?,
                         Rtype::parse(parser)?,
                         Class::parse(parser)?))
    }
}

impl<N: ToFqdn> Question<N> {
    pub fn compose_len(&self) -> usize {
        self.qname.len() + self.qtype.compose_len()
            + self.qclass.compose_len()
    }

    pub fn compose<B: BufMut>(&self, buf: &mut B) {
        self.qname.compose(buf);
        self.qtype.compose(buf);
        self.qclass.compose(buf);
    }
}


/// # Field Access
///
impl<N> Question<N> {
    pub fn qname(&self) -> &N {
        &self.qname
    }

    pub fn qtype(&self) -> Rtype {
        self.qtype
    }

    pub fn qclass(&self) -> Class {
        self.qclass
    }

}
