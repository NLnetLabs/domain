//! Tests the TSIG implementation.

use std::{env, fs, io, thread};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;
use ring::rand::SystemRandom;
use unwrap::unwrap;
use interop::nsd;
use interop::domain::core::message::Message;
use interop::domain::core::message_builder::{
    AdditionalBuilder, AnswerBuilder, MessageBuilder, RecordSectionBuilder,
    StreamTarget,
};
use interop::domain::core::name::Dname;
use interop::domain::core::iana::{Rcode, Rtype};
use interop::domain::core::rdata::{A, Soa};
use interop::domain::core::utils::base64;
use interop::domain::tsig;

type TestMessage = Message<Vec<u8>>;
type TestBuilder = MessageBuilder<StreamTarget<Vec<u8>>>;
type TestAnswer = AnswerBuilder<StreamTarget<Vec<u8>>>;
type TestAdditional = AdditionalBuilder<StreamTarget<Vec<u8>>>;


//------------ Tests --------------------------------------------------------

/// Tests the TSIG client implementation against NSD as a server.
///
/// Spins up an NSD serving example.com. and then tries to AXFR that.
#[test]
fn tsig_client_nsd() {
    // Set up and start NSD with example.org and a TSIG key for AXFRing it.
    let rng = SystemRandom::new();

    let cur_dir = env::current_dir().unwrap();
    let base_dir = cur_dir.join("../target/test/tsig_client_nsd");
    fs::create_dir_all(&base_dir).unwrap();
    let base_dir = base_dir.canonicalize().unwrap();
    let nsdconfpath = base_dir.join("nsd.conf");
    let zonepath = cur_dir.join("zonefiles/example.com.txt");

    let (key, secret) = tsig::Key::generate(
        tsig::Algorithm::Sha1,
        &rng,
        Dname::from_str("test.key.").unwrap(),
        None,
        None
    ).unwrap();

    let mut conf = nsd::Config::all_in(&base_dir);
    conf.ip_address.push(SocketAddr::from_str("127.0.0.1:54321").unwrap());
    conf.verbosity = Some(3);
    conf.keys.push(nsd::KeyConfig::new("test.key.", "hmac-sha1", secret));
    conf.zones.push(nsd::ZoneConfig::new(
        "example.com", zonepath, vec![nsd::Acl::new(
            IpAddr::from_str("127.0.0.1").unwrap(), None, None,
            Some("test.key.".into())
        )]
    ));
    conf.save(&nsdconfpath).unwrap();
    let mut nsd = Command::new("/usr/sbin/nsd")
        .args(&["-c", &format!("{}", nsdconfpath.display()), "-d"])
        .spawn().unwrap();
    thread::sleep(Duration::from_secs(1));
    if nsd.try_wait().unwrap().is_some() {
        panic!("NSD didn't start.");
    }

    let res = thread::spawn(move || {
        // Create an AXFR request and send it to NSD.
        let request = TestBuilder::new_stream_vec();
        let mut request = unwrap!(request.request_axfr(
            unwrap!(Dname::<Vec<u8>>::from_str("example.com."))
        )).additional();
        let tran = unwrap!(
            tsig::ClientTransaction::request(&key, &mut request)
        );
        let sock = UdpSocket::bind("127.0.0.1:54320").unwrap();
        unwrap!(sock.send_to(
            request.as_target().as_dgram_slice(),
            "127.0.0.1:54321"
        ));
        let mut answer = loop {
            let mut buf = vec![0; 512];
            let (len, addr) = sock.recv_from(buf.as_mut()).unwrap();
            if addr != SocketAddr::from_str("127.0.0.1:54321").unwrap() {
                continue;
            }
            buf.truncate(len);
            let answer = Message::from_octets(buf).unwrap();
            if answer.header().id() == request.header().id() {
                break answer;
            }
        };
        if let Err(err) = tran.answer(&mut answer) {
            panic!("{:?}", err);
        }
    }).join();

    // Shut down NSD just to be sure.
    let _ = nsd.kill();
    unwrap!(res); // Panic if the thread paniced.
}

/// Tests the TSIG server implementation against drill as a client.
#[test]
fn tsig_server_drill() {
    let rng = SystemRandom::new();
    let (key, secret) = tsig::Key::generate(
        tsig::Algorithm::Sha1,
        &rng,
        Dname::from_str("test.key.").unwrap(),
        None,
        None
    ).unwrap();
    let secret = base64::encode_string(&secret);
    let secret = format!("test.key:{}:hmac-sha1", secret);

    let join = thread::spawn(move || {
        let sock = UdpSocket::bind("127.0.0.1:54322").unwrap();
        loop {
            let mut buf = vec![0; 512];
            let (len, addr) = sock.recv_from(buf.as_mut()).unwrap();
            buf.truncate(len);
            let mut request = match Message::from_octets(buf) {
                Ok(request) => request,
                Err(_) => continue,
            };
            let answer = TestBuilder::new_stream_vec();
            let answer = unwrap!(
                answer.start_answer(&request, Rcode::NoError)
            );
            let tran = match tsig::ServerTransaction::request(
                &&key, &mut request
            ) {
                Ok(Some(tran)) => tran,
                Ok(None) => {
                    sock.send_to(answer.as_slice(), addr).unwrap();
                    continue;
                }
                Err(error) => {
                    let answer = unwrap!(error.build_message(
                        &request,
                        TestBuilder::new_stream_vec()
                    ));
                    sock.send_to(answer.as_slice(), addr).unwrap();
                    continue;
                }
            };
            let mut answer = answer.additional();
            unwrap!(tran.answer(&mut answer));
            sock.send_to(answer.as_slice(), addr).unwrap();
        }
    });

    let status = Command::new("/usr/bin/drill")
        .args(&[
            "-p", "54322",
            "-y", &secret,
            "example.com", "@127.0.0.1"
        ])
        .status().unwrap();
    drop(join);
    assert!(status.success());
}

/// Test the client sequence implementation against NSD.
#[test]
fn tsig_client_sequence_nsd() {
    let rng = SystemRandom::new();

    let cur_dir = env::current_dir().unwrap();
    let base_dir = cur_dir.join("../target/test/tsig_client_sequence_nsd");
    fs::create_dir_all(&base_dir).unwrap();
    let base_dir = base_dir.canonicalize().unwrap();
    let nsdconfpath = base_dir.join("nsd.conf");
    let zonepath = cur_dir.join("zonefiles/big.example.com.txt");

    let (key, secret) = tsig::Key::generate(
        tsig::Algorithm::Sha1,
        &rng,
        Dname::from_str("test.key.").unwrap(),
        None,
        None
    ).unwrap();

    let mut conf = nsd::Config::all_in(&base_dir);
    conf.ip_address.push(SocketAddr::from_str("127.0.0.1:54323").unwrap());
    conf.verbosity = Some(3);
    conf.keys.push(nsd::KeyConfig::new("test.key.", "hmac-sha1", secret));
    conf.zones.push(nsd::ZoneConfig::new(
        "example.com", zonepath, vec![nsd::Acl::new(
            IpAddr::from_str("127.0.0.1").unwrap(), None, None,
            Some("test.key.".into())
        )]
    ));
    conf.save(&nsdconfpath).unwrap();
    let mut nsd = Command::new("/usr/sbin/nsd")
        .args(&["-c", &format!("{}", nsdconfpath.display()), "-d"])
        .spawn().unwrap();
    thread::sleep(Duration::from_secs(1));
    if nsd.try_wait().unwrap().is_some() {
        panic!("NSD didn't start.");
    }

    let res = thread::spawn(move || {
        let mut sock = unwrap!(TcpStream::connect("127.0.0.1:54323"));
        let request = TestBuilder::new_stream_vec();
        let mut request = unwrap!(request.request_axfr(
            unwrap!(Dname::<Vec<u8>>::from_str("example.com."))
        )).additional();
        let mut tran = unwrap!(
            tsig::ClientSequence::request(&key, &mut request)
        );
        unwrap!(sock.write_all(request.as_target().as_stream_slice()));
        loop {
            let mut len = [0u8; 2];
            sock.read_exact(&mut len).unwrap();
            let len = u16::from_be_bytes(len) as usize;
            assert!(len != 0);
            let mut buf = vec![0; len];
            sock.read_exact(&mut buf).unwrap();
            let mut answer = unwrap!(Message::from_octets(buf));
            unwrap!(tran.answer(&mut answer));
            // Last message has SOA as last record in answer section.
            // We don’t care about details.
            if answer.answer().unwrap().last().unwrap().unwrap().rtype()
                        == Rtype::Soa {
                break
            }
        }
        unwrap!(tran.done())
    }).join();

    // Shut down NSD just to be sure.
    let _ = nsd.kill();
    res.unwrap(); // Panic if the thread paniced.
}

/// Tests the TSIG server sequence implementation against drill.
#[test]
fn tsig_server_sequence_drill() {
    let rng = SystemRandom::new();
    let (key, secret) = tsig::Key::generate(
        tsig::Algorithm::Sha1,
        &rng,
        Dname::from_str("test.key.").unwrap(),
        None,
        None
    ).unwrap();
    let secret = base64::encode_string(&secret);
    let secret = format!("test.key:{}:hmac-sha1", secret);
    let listener = TcpListener::bind("127.0.0.1:54324").unwrap();
    let port = listener.local_addr().unwrap().port();

    let join = thread::spawn(move || {
        for sock in listener.incoming() {
            let mut sock = sock.unwrap();
            let mut buf = [0u8, 2];
            sock.read_exact(&mut buf).unwrap();
            let len = u16::from_be_bytes(buf) as usize;
            let mut buf = vec![0; len];
            sock.read_exact(&mut buf).unwrap();
            let mut request = Message::from_octets(buf).unwrap();
            let mut tran = tsig::ServerSequence::request(&&key, &mut request)
                                                .unwrap().unwrap();
            let mut answer = make_first_axfr(&request);
            unwrap!(tran.answer(&mut answer));
            send_tcp(
                &mut sock,
                answer.as_target().as_stream_slice()
            ).unwrap();
            for two in 0..10u8 {
                for one in 0..10u8 {
                    let mut answer = make_middle_axfr(&request, one, two);
                    unwrap!(tran.answer(&mut answer));
                    send_tcp(
                        &mut sock,
                        answer.as_target().as_stream_slice()
                    ).unwrap();
                }
            }
            let mut answer = make_last_axfr(&request);
            unwrap!(tran.answer(&mut answer));
            send_tcp(
                &mut sock,
                answer.as_target().as_stream_slice()
            ).unwrap();
        }
    });

    let status = Command::new("/usr/bin/drill")
        .args(&[
            "-p", &format!("{}", port),
            "-y", &secret,
            "-t",
            "example.com", "AXFR", "@127.0.0.1"
        ])
        .status().unwrap();
    drop(join);
    assert!(status.success());
}


//------------ Helpers ------------------------------------------------------

fn send_tcp(sock: &mut TcpStream, msg: &[u8]) -> Result<(), io::Error> {
    sock.write_all(&(msg.len() as u16).to_be_bytes())?;
    sock.write_all(msg)
}

fn make_first_axfr(request: &TestMessage) -> TestAdditional {
    let msg = TestBuilder::new_stream_vec();
    let mut msg = unwrap!(msg.start_answer(request, Rcode::NoError));
    push_soa(&mut msg);
    push_a(&mut msg, 0, 0, 0);
    msg.additional()
}

fn make_middle_axfr(
    request: &TestMessage,
    one: u8,
    two: u8
) -> TestAdditional {
    let msg = TestBuilder::new_stream_vec();
    let mut msg = unwrap!(msg.start_answer(request, Rcode::NoError));
    push_a(&mut msg, 1, one, two);
    msg.additional()
}

fn make_last_axfr(request: &TestMessage) -> TestAdditional {
    let msg = TestBuilder::new_stream_vec();
    let mut msg = unwrap!(msg.start_answer(request, Rcode::NoError));
    push_a(&mut msg, 2, 0, 0);
    push_soa(&mut msg);
    msg.additional()
}

fn push_soa(builder: &mut TestAnswer) {
    unwrap!(builder.push(
        (
            Dname::<Vec<u8>>::from_str("example.com.").unwrap(),
            3600,
            Soa::new(
                Dname::<Vec<u8>>::from_str("mname.example.com.").unwrap(),
                Dname::<Vec<u8>>::from_str("rname.example.com.").unwrap(),
                12.into(),
                3600, 3600, 3600, 3600
            )
        )
    ))
}

fn push_a(builder: &mut TestAnswer, zero: u8, one: u8, two: u8) {
    unwrap!(builder.push(
        (
            Dname::<Vec<u8>>::from_str("example.com.").unwrap(),
            3600,
            A::from_octets(10, zero, one, two)
        )
    ))
}

