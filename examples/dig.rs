extern crate argparse;
extern crate domain;
extern crate rotor;

use std::convert;
use std::error;
use std::fmt;
use std::io;
use std::result;
use std::str::FromStr;
use domain::bits::{ComposeError, FromStrError, ParseError};
use domain::bits::message::{MessageBuf, RecordIter};
use domain::bits::name::{DName, DNameBuf, DNameSlice};
use domain::bits::rdata::GenericRecordData;
use domain::iana::{Class, RRType};
use domain::resolv::{ResolvConf, Resolver, Query};


//------------ Options ------------------------------------------------------

struct Options {
    // @server
    // -b address
    // -c class             Class as string
    // -f filename
    // -k filename
    // -m
    // -p port#
    // -q name
    // -t type
    // -x addr
    // -y [hmac:name:key]
    // -4
    // -6
    name: String,   // name
    qtype: String,  // type                 Type as string
    qclass: String, // class
    // queryopt...

    conf: ResolvConf,
}

impl Options {
    fn new() -> Options {
        let mut conf = ResolvConf::new();
        let _ = conf.parse_file("/etc/resolv.conf");
        conf.finalize();
        Options {
            name: String::new(),
            qtype: String::new(), // default depends on name.
            qclass: "IN".to_string(),
            conf: conf,
        }
    }

    fn from_args() -> Options {
        let mut res = Options::new();
        res.parse();
        res
    }

    fn parse(&mut self) {
        use argparse::{ArgumentParser, Store};

        let mut parser = ArgumentParser::new();

        parser.refer(&mut self.name)
              .add_argument("name", Store, "name of the resource record");
        parser.refer(&mut self.qtype)
              .add_argument("type", Store, "query type");
        parser.refer(&mut self.qclass)
              .add_argument("class", Store, "query class");

        parser.parse_args_or_exit();
    }
}

impl Options {
    fn name(&self) -> Result<DName> {
        if self.name.is_empty() {
            Ok(DNameSlice::root().into())
        }
        else {
            let mut res = try!(DNameBuf::from_str(&self.name));
            res.append_root();
            Ok(res.into())
        }
    }

    fn qtype(&self) -> Result<RRType> {
        if self.qtype.is_empty() {
            Ok((if self.name.is_empty() { RRType::Ns } else { RRType::A }))
        }
        else {
            Ok(try!(RRType::from_str(&self.qtype)))
        }
    }

    fn qclass(&self) -> Result<Class> {
        Ok((Class::In))
    }
    
    fn conf(&self) -> &ResolvConf { &self.conf }
}


//------------ Error and Result ---------------------------------------------

#[derive(Debug)]
struct Error {
    inner: Box<error::Error>
}

impl error::Error for Error {
    fn description(&self) -> &str {
        self.inner.description()
    }
}

impl convert::From<ComposeError> for Error {
    fn from(error: ComposeError) -> Error {
        Error { inner: Box::new(error) }
    }
}

impl convert::From<FromStrError> for Error {
    fn from(error: FromStrError) -> Error {
        Error { inner: Box::new(error) }
    }
}

impl convert::From<ParseError> for Error {
    fn from(error: ParseError) -> Error {
        Error { inner: Box::new(error) }
    }
}

impl convert::From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Error { inner: Box::new(error) }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.inner.fmt(f)
    }
}

type Result<T> = result::Result<T, Error>;


//------------ Processing Steps ---------------------------------------------

fn print_result(response: MessageBuf) {
    println!(";; Got answer:");
    println!(";; ->>HEADER<<- opcode: {}, status: {}, id: {}",
             response.header().opcode(), response.header().rcode(),
             response.header().id());
    print!(";; flags:");
    if response.header().qr() { print!(" qr"); }
    if response.header().aa() { print!(" aa"); }
    if response.header().tc() { print!(" tc"); }
    if response.header().rd() { print!(" rd"); }
    if response.header().ra() { print!(" ra"); }
    if response.header().ad() { print!(" ad"); }
    if response.header().cd() { print!(" cd"); }
    println!("; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}",
             response.counts().qdcount(), response.counts().ancount(),
             response.counts().nscount(), response.counts().arcount());
    println!("");

    let mut question = response.question();
    if response.counts().qdcount() > 0 {
        println!(";; QUESTION SECTION");
        for item in question.iter() {
            let item = item.unwrap();
            println!("; {}\t\t{}\t{}", item.qname(),
                     item.qclass(), item.qtype());
        }
        println!("");
    }

    let answer = question.answer().unwrap();
    if response.counts().ancount() > 0 {
        println!(";; ANSWER SECTION");
        print_records(answer.iter());
        println!("");
    }

    let authority = answer.next_section().unwrap().unwrap();
    if response.counts().nscount() > 0 {
        println!(";; AUTHORITY SECTION");
        print_records(authority.iter());
        println!("");
    }

    let additional = authority.next_section().unwrap().unwrap();
    if response.counts().arcount() > 0 {
        println!(";; ADDITIONAL SECTION");
        print_records(additional.iter());
        println!("");
    }
}

fn print_records<'a>(iter: RecordIter<'a, GenericRecordData<'a>>) {
    for record in iter {
        println!("{}", record.unwrap());
    }
}


//------------ Main Function ------------------------------------------------

fn main() {
    let options = Options::from_args();
    let (join, resolver) = Resolver::spawn(options.conf().clone()).unwrap();
    let query = Query::new(options.name().unwrap(), options.qtype().unwrap(),
                           options.qclass().unwrap());
    let response = resolver.sync_task(query).unwrap();
    let len = response.len();
    print_result(response);
    println!(";; Query time: not yet available.");
    println!(";; SERVER: we don't currently know.");
    println!(";; WHEN: not yet available.");
    println!(";; MSG SIZE  rcvd: {} bytes", len);
    println!("");
    drop(resolver);
    join.join().unwrap();
}
