//! Tests the TSIG implementation.
extern crate interop;
extern crate ring;

use std::{env, fs, thread};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;
use ring::rand::SystemRandom;
use interop::nsd;
use interop::domain::core::bits::{Dname, Message, MessageBuilder};
use interop::domain::core::bits::message_builder::SectionBuilder;
use interop::domain::core::iana::Rcode;
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
    let base_dir = cur_dir.join("../target/test");
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

    let _ = thread::spawn(move || {
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
            let request = match Message::from_bytes(buf[..len].into()) {
                Ok(request) => request,
                Err(_) => continue,
            };
            let mut answer = MessageBuilder::new_udp();
            answer.start_answer(&request, Rcode::NoError);
            let (_msg, tran) = match tsig::ServerTransaction::request(&&key,
                                                                    request) {
                Ok((msg, Some(tran))) => (msg, tran),
                Ok((_, None)) => {
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

