//! Rendering individul records or entire Zonefiles.
//! ```txt
//! struct RenderContext {
//!   origin: Option<&RevName>
//!   last_owner: Option<&RevName>
//!   last_ttl: Option<TTL>
//! }
//! struct RenderConfiguration {
//!   comment_verbose: usize
//!   separator: &str
//!   multiline: bool
//!   class_ttl_order: TTL_Class | Class_TTL
//!   owner_handle: OMIT | RELATIVE | DIRECTIVE
//!   ttl_handle: OMIT | DIRECTIVE
//! }
//! ```

use alloc::string::String;
use core::net::Ipv4Addr;
use std::string::ToString;

use crate::new::base::Record;
use crate::new::base::{RClass, RType, TTL};
use crate::new::rdata::{A, Mx};
use alloc::vec::Vec;

#[allow(dead_code)]
#[derive(Debug)]
enum Token<'a, N> {
    Owner(&'a N),
    Name(&'a N),
    Class(&'a RClass),
    TTL(TTL),

    RData(Vec<Token<'a, N>>),
    Type(&'a RType),
    Number(u32),
    Text(&'a str),
    IP(String),
    // had to add Vec because of inifinite size problem
    Annotation(Vec<Token<'a, N>>, String),
}

#[allow(dead_code)]
trait Projection<'a, N> {
    fn project(&'a self) -> Vec<Token<'a, N>>;
}

impl<'a, N> Projection<'a, N> for A {
    fn project(&'a self) -> Vec<Token<'a, N>> {
        vec![Token::IP(Ipv4Addr::from_octets(self.octets).to_string())]
    }
}
impl<'a, N> Projection<'a, N> for Mx<N> {
    fn project(&'a self) -> Vec<Token<'a, N>> {
        vec![
            Token::Annotation(
                vec![Token::Number(self.preference.get().into())],
                "preference".to_string(),
            ),
            Token::Annotation(
                vec![Token::Name(&self.exchange)],
                "exchange".to_string(),
            ),
        ]
    }
}

impl<'a, N, D: Projection<'a, N>> Projection<'a, N> for Record<N, D> {
    fn project(&'a self) -> Vec<Token<'a, N>> {
        vec![
            Token::Owner(&self.rname),
            Token::Class(&self.rclass),
            Token::TTL(self.ttl),
            Token::RData(self.rdata.project()),
        ]
    }
}

#[cfg(test)]
mod test {
    use crate::new::base::Record;
    use crate::new::base::name::RevNameBuf;
    use crate::new::base::wire::U16;
    use crate::new::base::{RClass, RType, TTL};
    use crate::new::rdata;
    use crate::new::render::Projection;

    #[test]
    fn projection_example() {
        let a_record = Record {
            rname: "example.com".parse::<RevNameBuf>().unwrap(),
            rtype: RType::A,
            rclass: RClass::IN,
            ttl: TTL::from(3600),
            rdata: rdata::A {
                octets: [1, 1, 1, 1],
            },
        };
        let mx_record = Record {
            rname: "example.com".parse::<RevNameBuf>().unwrap(),
            rtype: RType::MX,
            rclass: RClass::IN,
            ttl: TTL::from(3600),
            rdata: rdata::Mx {
                preference: U16::from(10),
                exchange: "example.com".parse::<RevNameBuf>().unwrap(),
            },
        };
        println!("{:?}", a_record.project());
        println!("{:?}", mx_record.project());
        for i in a_record.project() {
            print!("{:?} ", i);
        }
        println!("");
    }
}
