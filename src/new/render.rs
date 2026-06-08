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

use alloc::fmt::Display;
use alloc::string::String;
use core::fmt::Debug;
use core::net::Ipv4Addr;
use std::rc::Rc;
use std::str;
use std::string::ToString;

use crate::new::base::Record;
use crate::new::base::{RClass, RType, TTL};
use crate::new::rdata::RecordData;
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
    Annotation(Rc<Token<'a, N>>, String),
}

#[allow(dead_code)]
trait Projection<N> {
    fn project<'a>(&'a self) -> Vec<Token<'a, N>>;
}

fn write_token<'a, N: Display>(token: &Token<'a, N>, mut is_first: bool) {
    if !is_first {
        match token {
            Token::RData(_) => (),
            Token::Annotation(_, _) => (),
            _ => print!(" "),
        }
    }
    is_first = false;
    match token {
        Token::Owner(owner) => print!("{}", owner),
        Token::Name(name) => print!("{}", name),
        Token::Class(rclass) => print!("{}", rclass),
        Token::TTL(ttl) => print!("{}", ttl),
        Token::RData(rdata) => {
            for t in rdata {
                write_token(&t, is_first);
                is_first = false;
            }
        }
        Token::Type(rtype) => print!("{}", rtype),
        Token::Number(number) => print!("{}", number),
        Token::Text(text) => print!("{}", text),
        Token::IP(ip) => print!("{}", ip),
        Token::Annotation(t, _) => {
            write_token(&t, is_first);
        }
    }
}
fn write_projection<N: Display, R: Projection<N>>(records: Vec<R>) {
    for rr in records {
        let mut is_first = true;
        for token in rr.project() {
            write_token(&token, is_first);
            is_first = false;
        }
        println!();
    }
}

impl<N> Projection<N> for A {
    fn project<'a>(&'a self) -> Vec<Token<'a, N>> {
        vec![Token::IP(Ipv4Addr::from_octets(self.octets).to_string())]
    }
}
impl<N> Projection<N> for Mx<N> {
    fn project<'a>(&'a self) -> Vec<Token<'a, N>> {
        vec![
            Token::Annotation(
                Rc::new(Token::Number(self.preference.get().into())),
                "preference".to_string(),
            ),
            Token::Annotation(
                Rc::new(Token::Name(&self.exchange)),
                "exchange".to_string(),
            ),
        ]
    }
}

impl<'b, N> Projection<N> for RecordData<'b, N> {
    fn project<'a>(&'a self) -> Vec<Token<'a, N>> {
        match self {
            Self::A(a) => a.project(),
            Self::Mx(mx) => mx.project(),
            _ => unimplemented!(),
        }
    }
}

impl<N, D: Projection<N>> Projection<N> for Record<N, D> {
    fn project<'a>(&'a self) -> Vec<Token<'a, N>> {
        vec![
            Token::Owner(&self.rname),
            Token::Class(&self.rclass),
            Token::Type(&self.rtype),
            Token::TTL(self.ttl),
            Token::RData(self.rdata.project()),
        ]
    }
}

#[cfg(test)]
mod test {
    use crate::new::base::Record;
    use crate::new::base::name::{NameBuf, RevNameBuf};
    use crate::new::base::wire::U16;
    use crate::new::base::{RClass, RType, TTL};
    use crate::new::rdata;
    use crate::new::render::write_projection;

    fn reverse_labels(buf: &mut [u8]) {
        buf.reverse();

        let mut i = buf.len();

        while i > 0 {
            i -= 1;
            let len = buf[i] as usize;
            buf[i - len..=i].reverse();
            i -= len;
        }
    }
    #[test]
    fn projection_example() {
        // 2ab 3abc 5abcde
        // 2ab 3abc 5abcde
        // edcba5 cba3 ba2
        // 5abcde 3abc 2ab
        let n: RevNameBuf = "ns1.ams.example.com".parse().unwrap();
        let mut n_bytes = n.as_bytes().to_vec();
        reverse_labels(&mut n_bytes);
        println!("{:?}", std::str::from_utf8(&n.as_bytes()));
        println!("{:?}", std::str::from_utf8(&n_bytes));

        let a_record = Record {
            rname: "example.com".parse::<NameBuf>().unwrap(),
            rtype: RType::A,
            rclass: RClass::IN,
            ttl: TTL::from(3600),
            rdata: rdata::RecordData::A(rdata::A {
                octets: [1, 1, 1, 1],
            }),
        };
        let mx_record = Record {
            rname: "example.com".parse::<NameBuf>().unwrap(),
            rtype: RType::MX,
            rclass: RClass::IN,
            ttl: TTL::from(3600),
            rdata: rdata::RecordData::Mx(rdata::Mx {
                preference: U16::from(10),
                exchange: "example.com".parse::<NameBuf>().unwrap(),
            }),
        };
        write_projection(vec![a_record, mx_record]);
    }
}
