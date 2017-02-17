extern crate argparse;
extern crate domain;
extern crate tokio_core;

use std::error;
use std::result;
use std::str::FromStr;
use domain::bits::message::{MessageBuf, RecordSection};
use domain::bits::name::{DNameBuf, DNameSlice};
use domain::iana::{Class, Rtype};
use domain::resolv::{ResolvConf, Resolver};


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
        conf.options.use_vc = true;
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
    fn name(&self) -> Result<DNameBuf> {
        if self.name.is_empty() {
            Ok(DNameSlice::root().to_owned())
        }
        else {
            let mut res = try!(DNameBuf::from_str(&self.name));
            res.append_root().unwrap();
            Ok(res)
        }
    }

    fn qtype(&self) -> Result<Rtype> {
        if self.qtype.is_empty() {
            Ok((if self.name.is_empty() { Rtype::Ns } else { Rtype::A }))
        }
        else {
            Ok(try!(Rtype::from_str(&self.qtype)))
        }
    }

    fn qclass(&self) -> Result<Class> {
        Ok((Class::In))
    }
    
    fn conf(&self) -> &ResolvConf { &self.conf }
}


//------------ Error and Result ---------------------------------------------

type Error = Box<error::Error>;

type Result<T> = result::Result<T, Error>;


//------------ Processing Steps ---------------------------------------------

fn query(options: Options) -> MessageBuf {
    Resolver::run_with_conf(options.conf().clone(), |resolv| {
        resolv.query((options.name().unwrap(), options.qtype().unwrap(),
                           options.qclass().unwrap()))
    }).unwrap()
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
        for item in &mut question {
            let item = item.unwrap();
            println!("; {}\t\t{}\t{}", item.qname(),
                     item.qclass(), item.qtype());
        }
        println!("");
    }

    let mut answer = question.answer().unwrap();
    if response.counts().ancount() > 0 {
        println!(";; ANSWER SECTION");
        print_records(&mut answer);
        println!("");
    }

    let mut authority = answer.next_section().unwrap().unwrap();
    if response.counts().nscount() > 0 {
        println!(";; AUTHORITY SECTION");
        print_records(&mut authority);
        println!("");
    }

    let mut additional = authority.next_section().unwrap().unwrap();
    if response.counts().arcount() > 0 {
        println!(";; ADDITIONAL SECTION");
        print_records(&mut additional);
        println!("");
    }
}

fn print_records(section: &mut RecordSection) {
    for record in section {
        println!("{}", record.unwrap());
    }
}


//------------ Main Function ------------------------------------------------

fn main() {
    let options = Options::from_args();
    let response = query(options);
    let len = response.len();
    print_result(response);
    println!(";; Query time: not yet available.");
    println!(";; SERVER: we don't currently know.");
    println!(";; WHEN: not yet available.");
    println!(";; MSG SIZE  rcvd: {} bytes", len);
    println!("");
}
