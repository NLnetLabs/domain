extern crate bytes;
extern crate chrono;
extern crate domain;
extern crate failure;

use std::{env, io};
use std::net::{SocketAddr, UdpSocket};
use std::process::exit;
use std::str::FromStr;
use std::time::{Duration, Instant};
use bytes::BytesMut;
use chrono::{DateTime, Local};
use failure::Error;
use domain::bits::{Dname, Message, MessageBuilder, ParsedDname, RecordSection};
use domain::iana::{Class, Rtype};
use domain::rdata::AllRecordData;
use domain::resolv::ResolvConf;


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
    name: Dname,
    qtype: Rtype,
    qclass: Class,
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
            name: Dname::root(),
            qtype: Rtype::A,
            qclass: Class::In,
            conf: conf,
        }
    }

    fn from_args() -> Result<Options, Error> {
        let mut res = Options::new();
        res.parse()?;
        Ok(res)
    }

    fn parse(&mut self) -> Result<(), Error> {
        let mut args = env::args();
        args.next();

        match args.next() {
            Some(name) => self.name = Dname::from_str(&name)?,
            None => {
                println!("Usage: dig qname [qtype [qclass]]");
                exit(1);
            }
        };
        match args.next() {
            Some(qtype) => self.qtype = Rtype::from_str(&qtype)?,
            None => return Ok(()),
        }
        if let Some(qclass) = args.next() {
            self.qclass = Class::from_str(&qclass)?
        }
        Ok(())
    }
}

impl Options {
}


impl Options {
    fn create_request(&self) -> Result<Message, Error> {
        let mut msg = MessageBuilder::new_udp();
        msg.header_mut().set_random_id();
        msg.header_mut().set_rd(true);
        msg.push((&self.name, self.qtype, self.qclass))?;
        let mut msg = msg.opt()?;
        msg.set_udp_payload_size(4096);
        Ok(msg.freeze())
    }

    fn query(&self, request: Message) -> Result<Response, Error> {
        let start = Local::now();
        for server in &self.conf.servers {
            let now = Instant::now();
            if let Some(message) = self.query_udp(&request, server.addr)? {
                let duration = Instant::now().duration_since(now);
                return Ok(Response { message, server: server.addr,start,
                                     duration })
            }
        }
        Err(io::Error::new(io::ErrorKind::TimedOut,
                           "no servers could be reached").into())
    }

    fn query_udp(&self, request: &Message, addr: SocketAddr)
                 -> Result<Option<Message>, Error> {
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        sock.send_to(request.as_slice(), addr)?;
        let done = Instant::now() + self.conf.timeout;
        while Instant::now() < done {
            sock.set_read_timeout(Some(done - Instant::now()))?;
            let mut buf = BytesMut::with_capacity(4096);
            unsafe { buf.set_len(4096) };
            let (size, raddr) = match sock.recv_from(buf.as_mut()) {
                Ok(res) => res,
                Err(err) => {
                    if err.kind() == io::ErrorKind::TimedOut {
                        return Ok(None)
                    }
                    else {
                        return Err(err.into())
                    }
                }
            };
            if raddr != addr {
                // XXX This may actually be wrong ...
                continue
            }
            unsafe { buf.set_len(size) };
            if let Ok(res) = Message::from_bytes(buf.freeze()) {
                if res.is_answer(request) {
                    return Ok(Some(res))
                }
            }
        }
        Ok(None)
    }

    fn print_result(&self, response: Response) -> Result<(), Error> {
        println!(";; Got answer:");
        println!(";; ->>HEADER<<- opcode: {}, status: {}, id: {}",
                 response.message.header().opcode(),
                 response.message.header().rcode(),
                 response.message.header().id());
        print!(";; flags:");
        if response.message.header().qr() { print!(" qr"); }
        if response.message.header().aa() { print!(" aa"); }
        if response.message.header().tc() { print!(" tc"); }
        if response.message.header().rd() { print!(" rd"); }
        if response.message.header().ra() { print!(" ra"); }
        if response.message.header().ad() { print!(" ad"); }
        if response.message.header().cd() { print!(" cd"); }
        println!("; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}",
                 response.message.header_counts().qdcount(),
                 response.message.header_counts().ancount(),
                 response.message.header_counts().nscount(),
                 response.message.header_counts().arcount());
        println!("");

        let mut question = response.message.question();
        if response.message.header_counts().qdcount() > 0 {
            println!(";; QUESTION SECTION");
            for item in &mut question {
                let item = item.unwrap();
                self.print_cell(format!(";{}", item.qname()), 32);
                self.print_cell(format!("{}", item.qclass()), 8);
                self.print_cell(format!("{}", item.qtype()), 8);
                println!("");
            }
            println!("");
        }

        let mut answer = question.answer().unwrap();
        if response.message.header_counts().ancount() > 0 {
            println!(";; ANSWER SECTION");
            self.print_records(&mut answer);
            println!("");
        }

        let mut authority = answer.next_section().unwrap().unwrap();
        if response.message.header_counts().nscount() > 0 {
            println!(";; AUTHORITY SECTION");
            self.print_records(&mut authority);
            println!("");
        }

        let mut additional = authority.next_section().unwrap().unwrap();
        if response.message.header_counts().arcount() > 0 {
            println!(";; ADDITIONAL SECTION");
            self.print_records(&mut additional);
            println!("");
        }

        println!(";; Query time: {} ms",
                 response.duration.as_secs() * 1000
                 + (response.duration.subsec_nanos() / 1_000_000) as u64);
        println!(";; SERVER: {}#{}",
                 response.server.ip(), response.server.port());
        println!(";; WHEN: {}",
                 response.start.format("%a %b %e %T %Z %Y"));
        println!(";; MSG SIZE  rcvd: {}", response.message.len());
        println!("");
        Ok(())
    }

    fn print_records(&self, section: &mut RecordSection) {
        for record in section {
            let record = record.unwrap()
                               .into_record::<AllRecordData<ParsedDname>>()
                               .unwrap().unwrap();
            // XXX We don’t have proper Display impls yet, so we need to
            //     convert to strings first to get the formatting.
            self.print_cell(format!("{}", record.name()), 24);
            self.print_cell(format!("{}", record.ttl()), 8);
            self.print_cell(format!("{}", record.class()), 8);
            self.print_cell(format!("{}", record.rtype()), 8);
            println!("{}", record.data());
        }
    }

    fn print_cell(&self, cell: String, len: usize) {
        // XXX dig uses tabs
        print!("{0:1$}", cell, len);
    }

    fn run() -> Result<(), Error> {
        let options = Self::from_args()?;
        let request = options.create_request()?;
        let response = options.query(request)?;
        options.print_result(response)
    }
}


//------------ Response -----------------------------------------------------

struct Response {
    message: Message,
    server: SocketAddr,
    start: DateTime<Local>,
    duration: Duration,
}


//------------ Main Function ------------------------------------------------

fn main() {
    if let Err(err) = Options::run() {
        println!("{}", err);
        exit(1);
    }
}
