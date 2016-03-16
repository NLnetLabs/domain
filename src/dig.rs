extern crate argparse;
extern crate domain;

use std::convert;
use std::error;
use std::fmt;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::result;
use std::str::FromStr;
use domain::iana::{rrtype, Class, RRType};
use domain::message::{self, MessageBuf, MessageBuilder, RecordSection};
use domain::rdata::generic::CompactGenericRecordData;
use domain::resolver::conf::ResolvConf;
use domain::name::{self, DomainNameBuf};


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
    fn name(&self) -> Result<DomainNameBuf> {
        if self.name.is_empty() {
            Ok(DomainNameBuf::root())
        }
        else {
            let mut res = try!(DomainNameBuf::from_str(&self.name));
            res.append(DomainNameBuf::root());
            Ok(res)
        }
    }

    fn qtype(&self) -> Result<RRType> {
        if self.qtype.is_empty() {
            Ok((if self.name.is_empty() { RRType::NS } else { RRType::A }))
        }
        else {
            Ok(try!(RRType::from_str(&self.qtype)))
        }
    }

    fn qclass(&self) -> Result<Class> {
        Ok((Class::IN))
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
        use ::std::error::Error;

        self.inner.description()
    }
}

impl convert::From<name::ParseError> for Error {
    fn from(error: name::ParseError) -> Error {
        Error { inner: Box::new(error) }
    }
}

impl convert::From<rrtype::ParseError> for Error {
    fn from(error: rrtype::ParseError) -> Error {
        Error { inner: Box::new(error) }
    }
}

impl convert::From<message::Error> for Error {
    fn from(error: message::Error) -> Error {
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

fn create_query(options: &Options) -> Result<MessageBuf> {
    let mut msg = MessageBuilder::new(::std::u16::MAX as usize, 2, true);

    // XXX make a header
    msg.header_mut().set_id(17);

    let mut question = msg.question();
    try!(question.push_question(try!(options.name()), try!(options.qtype()),
                                try!(options.qclass())));

    // XXX set prefix
    Ok(question.finish())
}

fn send_query(options: &Options, query: &MessageBuf)
              -> Result<(MessageBuf, SocketAddr)> {
    send_query_udp(options, query)
}

fn send_query_udp(options: &Options, query: &MessageBuf)
                  -> Result<(MessageBuf, SocketAddr)> {
    let sock = try!(UdpSocket::bind("0.0.0.0:0"));
    try!(sock.set_read_timeout(Some(options.conf().timeout)));
    for server in options.conf().servers.iter() {
        try!(sock.send_to(query.message_bytes(), server));
        let mut buf = Vec::new();
        buf.resize(2000, 0);
        let (len, from) = try!(sock.recv_from(&mut buf));
        buf.truncate(len);
        let msg = try!(MessageBuf::from_vec(buf, 0));
        return Ok((msg, from));
    }
    Err(io::Error::new(io::ErrorKind::Other, "No more servers").into())
}

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

    let mut answer = question.answer().unwrap();
    if response.counts().ancount() > 0 {
        println!(";; ANSWER SECTION");
        print_section(&mut answer);
        println!("");
    }

    let mut authority = answer.authority().unwrap();
    if response.counts().nscount() > 0 {
        println!(";; AUTHORITY SECTION");
        print_section(&mut authority);
        println!("");
    }

    let mut additional = authority.additional().unwrap();
    if response.counts().arcount() > 0 {
        println!(";; ADDITIONAL SECTION");
        print_section(&mut additional);
        println!("");
    }
}

fn print_section<'a>(section: &mut RecordSection<'a, CompactGenericRecordData<'a>>) {
    for record in section.iter() {
        let record = record.unwrap();
        println!("{}\t{}\t{}\t{}\t{}", record.name(), record.ttl(),
                 record.rclass(), record.rtype(), record.rdata())
    }
}


//------------ Main Function ------------------------------------------------

fn main() {
    let options = Options::from_args();
    let query = create_query(&options).unwrap();    
    let (response, server) = send_query(&options, &query).unwrap();
    let len = response.message_bytes().len();
    print_result(response);
    println!(";; Query time: not yet available.");
    println!(";; SERVER: {}", server);
    println!(";; WHEN: not yet available.");
    println!(";; MSG SIZE  rcvd: {} bytes", len);
    println!("");
}
