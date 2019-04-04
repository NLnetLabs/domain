//! Tests the TSIG implementation.
extern crate interop;
extern crate ring;

use std::{env, fs, thread};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;
use ring::rand::SystemRandom;
use interop::nsd;
use interop::domain::core::bits::{Dname, Message, MessageBuilder};
use interop::domain::core::bits::message_builder::SectionBuilder;
use interop::domain::core::iana::{Rcode, Rtype};
use interop::domain::core::utils::base64;
use interop::domain::core::tsig;


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
            IpAddr::from_str("127.0.0.1").unwrap(), None, Some(54322),
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
        let request = MessageBuilder::request_axfr(
            Dname::from_str("example.com.").unwrap()
        ).additional();
        let (msg, tran) = tsig::ClientTransaction::request(&key, request)
                                                  .unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.send_to(msg.as_ref(), "127.0.0.1:54321").unwrap();
        let mut answer = loop {
            let mut buf = vec![0; 512];
            let (len, addr) = sock.recv_from(buf.as_mut()).unwrap();
            if addr != SocketAddr::from_str("127.0.0.1:54321").unwrap() {
                continue;
            }
            let answer = Message::from_bytes(buf[..len].into()).unwrap();
            if answer.header().id() == msg.header().id() {
                break answer;
            }
        };
        if let Err(err) = tran.answer(&mut answer) {
            panic!("{:?}", err);
        }
    }).join();

    // Shut down NSD just to be sure.
    let _ = nsd.kill();
    res.unwrap(); // Panic if the thread paniced.
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
            let mut request = match Message::from_bytes(buf[..len].into()) {
                Ok(request) => request,
                Err(_) => continue,
            };
            let mut answer = MessageBuilder::new_udp();
            answer.start_answer(&request, Rcode::NoError);
            let tran = match tsig::ServerTransaction::request(&&key,
                                                              &mut request) {
                Ok(Some(tran)) => tran,
                Ok(None) => {
                    sock.send_to(answer.freeze().as_slice(), addr).unwrap();
                    continue;
                }
                Err(error) => {
                    sock.send_to(error.as_slice(), addr).unwrap();
                    continue;
                }
            };
            let answer = tran.answer(answer.additional()).unwrap();
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
        let mut sock = TcpStream::connect("127.0.0.1:54323").unwrap();
        let request = MessageBuilder::request_axfr(
            Dname::from_str("example.com.").unwrap()
        ).additional();
        let (msg, mut tran) = tsig::ClientSequence::request(&key, request)
                                                   .unwrap();
        sock.write_all(&(msg.len() as u16).to_be_bytes()).unwrap();
        sock.write_all(msg.as_slice()).unwrap();
        loop {
            let mut len = [0u8; 2];
            sock.read_exact(&mut len).unwrap();
            let len = u16::from_be_bytes(len) as usize;
            assert!(len != 0);
            let mut buf = vec![0; len];
            sock.read_exact(&mut buf).unwrap();
            let mut answer = Message::from_bytes(buf.into()).unwrap();
            tran.answer(&mut answer).unwrap();
            // Last message has SOA as last record in answer section.
            // We don’t care about details.
            if answer.answer().unwrap().last().unwrap().unwrap().rtype()
                        == Rtype::Soa {
                break
            }
        }
        tran.done().unwrap()
    }).join();

    // Shut down NSD just to be sure.
    let _ = nsd.kill();
    res.unwrap(); // Panic if the thread paniced.
}

/*
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

    let join = thread::spawn(move || {
        let sock = TcpListener::bind("127.0.0.1:54324").unwrap();
        for stream in listener.incoming() {
            let mut buf = [0u8, 2];
            sock.read_exact(&mut len).unwrap();
            let mut buf = vec![0; len];
            sock.read_exact(&mut buf).unwrap();
            let mut request = Message::from_bytes(buf.into()).unwrap();
            let (request, tran) =
                tsig::ServerSequence::request(&&key, request).unwrap();
            
            
        }
    });

    let status = Command::new("/usr/bin/drill")
        .args(&[
            "-p", "54324",
            "-y", &secret,
            "-t",
            "example.com", "AXFR", "@127.0.0.1"
        ])
        .status().unwrap();
    drop(join);
    assert!(status.success());
}
*/

