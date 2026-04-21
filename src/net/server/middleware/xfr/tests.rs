use core::future::{ready, Future, Ready};
use core::ops::ControlFlow;
use core::pin::Pin;
use core::str::FromStr;
use core::sync::atomic::{AtomicBool, Ordering};

use std::borrow::ToOwned;
use std::boxed::Box;
use std::fmt::Debug;
use std::sync::Arc;
use std::vec::Vec;

use bytes::Bytes;
use futures_util::stream::Once;
use futures_util::{Stream, StreamExt};
use octseq::Octets;
use tokio::sync::Semaphore;
use tokio::time::Instant;

use crate::base::iana::{
    Class, DigestAlgorithm, OptRcode, Rcode, SecurityAlgorithm,
};
use crate::base::{
    Message, MessageBuilder, Name, ParsedName, Rtype, Serial, ToName, Ttl,
};
use crate::net::server::message::{
    NonUdpTransportContext, Request, TransportSpecificContext,
    UdpTransportContext,
};
use crate::net::server::middleware::xfr::data_provider::{
    XfrData, XfrDataProvider, XfrDataProviderError,
};
use crate::net::server::service::{
    CallResult, Service, ServiceError, ServiceFeedback, ServiceResult,
};
use crate::rdata::{
    Aaaa, AllRecordData, Cname, Ds, Mx, Ns, Soa, Txt, ZoneRecordData, A,
};
use crate::tsig::{Algorithm, Key, KeyName};
use crate::zonefile::inplace::Zonefile;
use crate::zonetree::types::{EmptyZoneDiff, Rrset};
use crate::zonetree::{
    AnswerContent, InMemoryZoneDiff, InMemoryZoneDiffBuilder, SharedRrset,
    Zone,
};

use super::service::{XfrMiddlewareStream, XfrMiddlewareSvc};
use super::util::read_soa;

//------------ ExpectedRecords ------------------------------------------------

type ExpectedRecords = Vec<(Name<Bytes>, AllRecordData<Bytes, Name<Bytes>>)>;

//------------ Tests ----------------------------------------------------------

#[tokio::test]
async fn axfr_with_example_zone() {
    let zone = load_zone(include_bytes!(
        "../../../../../test-data/zonefiles/nsd-example.txt"
    ));

    let req = mk_axfr_request(zone.apex_name(), Default::default());

    let res = do_preprocess(zone.clone(), &req).await.unwrap();

    let ControlFlow::Break(mut stream) = res else {
        panic!("AXFR failed");
    };

    let zone_soa = get_zone_soa(&zone).await;

    let mut expected_records: ExpectedRecords = vec![
        (n("example.com"), zone_soa.clone().into()),
        (n("example.com"), Ns::new(n("example.com")).into()),
        (n("example.com"), A::new(p("192.0.2.1")).into()),
        (n("example.com"), Aaaa::new(p("2001:db8::3")).into()),
        (n("www.example.com"), Cname::new(n("example.com")).into()),
        (n("mail.example.com"), Mx::new(10, n("example.com")).into()),
        (n("a.b.c.mail.example.com"), A::new(p("127.0.0.1")).into()),
        (n("x.y.mail.example.com"), A::new(p("127.0.0.1")).into()),
        (n("some.ent.example.com"), A::new(p("127.0.0.1")).into()),
        (
            n("unsigned.example.com"),
            Ns::new(n("some.other.ns.net.example.com")).into(),
        ),
        (
            n("signed.example.com"),
            Ns::new(n("some.other.ns.net.example.com")).into(),
        ),
        (
            n("signed.example.com"),
            Ds::new(
                60485,
                SecurityAlgorithm::RSASHA1,
                DigestAlgorithm::SHA1,
                crate::utils::base16::decode(
                    "2BB183AF5F22588179A53B0A98631FAD1A292118",
                )
                .unwrap(),
            )
            .unwrap()
            .into(),
        ),
        (n("example.com"), zone_soa.into()),
    ];

    let msg = stream.next().await.unwrap().unwrap();
    assert!(matches!(
        msg.feedback(),
        Some(ServiceFeedback::BeginTransaction)
    ));

    let stream =
        assert_stream_eq(req.message(), &mut stream, &mut expected_records)
            .await;

    let msg = stream.next().await.unwrap().unwrap();
    assert!(matches!(
        msg.feedback(),
        Some(ServiceFeedback::EndTransaction)
    ));
}

#[tokio::test]
async fn axfr_multi_response() {
    let zone = load_zone(include_bytes!(
        "../../../../../test-data/zonefiles/big.example.com.txt"
    ));

    let req = mk_axfr_request(zone.apex_name(), Default::default());

    let res = do_preprocess(zone.clone(), &req).await.unwrap();

    let ControlFlow::Break(mut stream) = res else {
        panic!("AXFR failed");
    };

    let zone_soa = get_zone_soa(&zone).await;

    let mut expected_records: ExpectedRecords = vec![
        (n("example.com"), zone_soa.clone().into()),
        (n("example.com"), Ns::new(n("ns1.example.com")).into()),
        (n("example.com"), Ns::new(n("ns2.example.com")).into()),
        (n("example.com"), Mx::new(10, n("mail.example.com")).into()),
        (n("example.com"), A::new(p("192.0.2.1")).into()),
        (n("example.com"), Aaaa::new(p("2001:db8:10::1")).into()),
        (n("ns1.example.com"), A::new(p("192.0.2.2")).into()),
        (n("ns1.example.com"), Aaaa::new(p("2001:db8:10::2")).into()),
        (n("ns2.example.com"), A::new(p("192.0.2.3")).into()),
        (n("ns2.example.com"), Aaaa::new(p("2001:db8:10::3")).into()),
        (n("mail.example.com"), A::new(p("192.0.2.4")).into()),
        (n("mail.example.com"), Aaaa::new(p("2001:db8:10::4")).into()),
    ];

    for i in 1..=10000 {
        expected_records.push((
            n(&format!("host-{i}.example.com")),
            Txt::build_from_slice(b"text").unwrap().into(),
        ));
    }

    expected_records.push((n("example.com"), zone_soa.into()));

    let msg = stream.next().await.unwrap().unwrap();
    assert!(matches!(
        msg.feedback(),
        Some(ServiceFeedback::BeginTransaction)
    ));

    let stream =
        assert_stream_eq(req.message(), &mut stream, &mut expected_records)
            .await;

    let msg = stream.next().await.unwrap().unwrap();
    assert!(matches!(
        msg.feedback(),
        Some(ServiceFeedback::EndTransaction)
    ));
}

#[tokio::test]
async fn axfr_delegation_records() {
    // https://datatracker.ietf.org/doc/html/rfc5936#section-3.2
}

#[tokio::test]
async fn axfr_glue_records() {
    // https://datatracker.ietf.org/doc/html/rfc5936#section-3.3
}

#[tokio::test]
async fn axfr_name_compression_not_yet_supported() {
    // https://datatracker.ietf.org/doc/html/rfc5936#section-3.4
}

#[tokio::test]
async fn axfr_occluded_names() {
    // https://datatracker.ietf.org/doc/html/rfc5936#section-3.5
}

#[tokio::test]
async fn axfr_not_allowed_over_udp() {
    // https://datatracker.ietf.org/doc/html/rfc5936#section-4.2
    let zone = load_zone(include_bytes!(
        "../../../../../test-data/zonefiles/nsd-example.txt"
    ));

    let req = mk_udp_axfr_request(zone.apex_name(), Default::default());

    let res = do_preprocess(zone, &req).await.unwrap();

    let ControlFlow::Break(mut stream) = res else {
        panic!("AXFR failed");
    };

    let msg = stream.next().await.unwrap().unwrap();
    let resp_builder = msg.into_inner().0.unwrap();
    let resp = resp_builder.as_message();

    assert_eq!(resp.header().rcode(), Rcode::NOTIMP);
}

#[tokio::test]
async fn ixfr_rfc1995_section7_full_zone_reply() {
    // Based on https://datatracker.ietf.org/doc/html/rfc1995#section-7

    // initial zone content:
    // JAIN.AD.JP.         IN SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. (
    //                                   1 600 600 3600000 604800)
    // IN NS  NS.JAIN.AD.JP.
    // NS.JAIN.AD.JP.      IN A   133.69.136.1
    // NEZU.JAIN.AD.JP.    IN A   133.69.136.5

    // Final zone content:
    let rfc_1995_zone = r#"
JAIN.AD.JP.         IN SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. (
                              3 600 600 3600000 604800)
                IN NS  NS.JAIN.AD.JP.
NS.JAIN.AD.JP.      IN A   133.69.136.1
JAIN-BB.JAIN.AD.JP. IN A   133.69.136.3
JAIN-BB.JAIN.AD.JP. IN A   192.41.197.2
    "#;
    let zone = load_zone(rfc_1995_zone.as_bytes());

    // Create an object that knows how to provide zone and diff data for
    // our zone and no diffs.
    let zone_with_diffs = ZoneWithDiffs::new(zone.clone(), vec![]);

    // The following IXFR query
    let req =
        mk_udp_ixfr_request(zone.apex_name(), Serial(1), Default::default());

    let res = do_preprocess(zone_with_diffs, &req).await.unwrap();

    let ControlFlow::Break(mut stream) = res else {
        panic!("IXFR failed");
    };

    // could be replied to with the following full zone transfer message:
    let zone_soa = get_zone_soa(&zone).await;

    let mut expected_records: ExpectedRecords = vec![
        (n("JAIN.AD.JP."), zone_soa.clone().into()),
        (n("JAIN.AD.JP."), Ns::new(n("NS.JAIN.AD.JP.")).into()),
        (n("NS.JAIN.AD.JP."), A::new(p("133.69.136.1")).into()),
        (n("JAIN-BB.JAIN.AD.JP."), A::new(p("133.69.136.3")).into()),
        (n("JAIN-BB.JAIN.AD.JP."), A::new(p("192.41.197.2")).into()),
        (n("JAIN.AD.JP."), zone_soa.into()),
    ];

    assert_stream_eq(req.message(), &mut stream, &mut expected_records).await;
}

#[tokio::test]
async fn ixfr_rfc1995_section7_incremental_reply() {
    // Based on https://datatracker.ietf.org/doc/html/rfc1995#section-7
    let mut diffs = Vec::new();

    // initial zone content:
    // JAIN.AD.JP.         IN SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. (
    //                                   1 600 600 3600000 604800)
    // IN NS  NS.JAIN.AD.JP.
    // NS.JAIN.AD.JP.      IN A   133.69.136.1
    // NEZU.JAIN.AD.JP.    IN A   133.69.136.5

    // Final zone content:
    let rfc_1995_zone = r#"
JAIN.AD.JP.         IN SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. (
                              3 600 600 3600000 604800)
                IN NS  NS.JAIN.AD.JP.
NS.JAIN.AD.JP.      IN A   133.69.136.1
JAIN-BB.JAIN.AD.JP. IN A   133.69.136.3
JAIN-BB.JAIN.AD.JP. IN A   192.41.197.2
    "#;
    let zone = load_zone(rfc_1995_zone.as_bytes());

    // Diff 1: NEZU.JAIN.AD.JP. is removed and JAIN-BB.JAIN.AD.JP. is added.
    let mut diff = InMemoryZoneDiffBuilder::new();

    // -- Remove the old SOA.
    let mut rrset = Rrset::new(Rtype::SOA, Ttl::from_secs(0));
    let soa = Soa::new(
        n("NS.JAIN.AD.JP."),
        n("mohta.jain.ad.jp."),
        Serial(1),
        Ttl::from_secs(600),
        Ttl::from_secs(600),
        Ttl::from_secs(3600000),
        Ttl::from_secs(604800),
    );
    rrset.push_data(soa.into());
    diff.remove(n("JAIN.AD.JP"), Rtype::SOA, SharedRrset::new(rrset));

    // -- Remove the A record.
    let mut rrset = Rrset::new(Rtype::A, Ttl::from_secs(0));
    rrset.push_data(A::new(p("133.69.136.5")).into());
    diff.remove(n("NEZU.JAIN.AD.JP"), Rtype::A, SharedRrset::new(rrset));

    // -- Add the new SOA.
    let mut rrset = Rrset::new(Rtype::SOA, Ttl::from_secs(0));
    let soa = Soa::new(
        n("NS.JAIN.AD.JP."),
        n("mohta.jain.ad.jp."),
        Serial(2),
        Ttl::from_secs(600),
        Ttl::from_secs(600),
        Ttl::from_secs(3600000),
        Ttl::from_secs(604800),
    );
    rrset.push_data(soa.into());
    diff.add(n("JAIN.AD.JP"), Rtype::SOA, SharedRrset::new(rrset));

    // -- Add the new A records.
    let mut rrset = Rrset::new(Rtype::A, Ttl::from_secs(0));
    rrset.push_data(A::new(p("133.69.136.4")).into());
    rrset.push_data(A::new(p("192.41.197.2")).into());
    diff.add(n("JAIN-BB.JAIN.AD.JP"), Rtype::A, SharedRrset::new(rrset));

    diffs.push(diff.build().unwrap());

    // Diff 2: One of the IP addresses of JAIN-BB.JAIN.AD.JP. is changed.
    let mut diff = InMemoryZoneDiffBuilder::new();

    // -- Remove the old SOA.
    let mut rrset = Rrset::new(Rtype::SOA, Ttl::from_secs(0));
    let soa = Soa::new(
        n("NS.JAIN.AD.JP."),
        n("mohta.jain.ad.jp."),
        Serial(2),
        Ttl::from_secs(600),
        Ttl::from_secs(600),
        Ttl::from_secs(3600000),
        Ttl::from_secs(604800),
    );
    rrset.push_data(soa.into());
    diff.remove(n("JAIN.AD.JP"), Rtype::SOA, SharedRrset::new(rrset));

    // Remove the outdated IP address.
    let mut rrset = Rrset::new(Rtype::A, Ttl::from_secs(0));
    rrset.push_data(A::new(p("133.69.136.4")).into());
    diff.remove(n("JAIN-BB.JAIN.AD.JP"), Rtype::A, SharedRrset::new(rrset));

    // -- Add the new SOA.
    let mut rrset = Rrset::new(Rtype::SOA, Ttl::from_secs(0));
    let soa = Soa::new(
        n("NS.JAIN.AD.JP."),
        n("mohta.jain.ad.jp."),
        Serial(3),
        Ttl::from_secs(600),
        Ttl::from_secs(600),
        Ttl::from_secs(3600000),
        Ttl::from_secs(604800),
    );
    rrset.push_data(soa.into());
    diff.add(n("JAIN.AD.JP"), Rtype::SOA, SharedRrset::new(rrset));

    // Add the updated IP address.
    let mut rrset = Rrset::new(Rtype::A, Ttl::from_secs(0));
    rrset.push_data(A::new(p("133.69.136.3")).into());
    diff.add(n("JAIN-BB.JAIN.AD.JP"), Rtype::A, SharedRrset::new(rrset));

    diffs.push(diff.build().unwrap());

    // Create an object that knows how to provide zone and diff data for
    // our zone and diffs.
    let zone_with_diffs = ZoneWithDiffs::new(zone.clone(), diffs);

    // The following IXFR query
    let req =
        mk_ixfr_request(zone.apex_name(), Serial(1), Default::default());

    let res = do_preprocess(zone_with_diffs, &req).await.unwrap();

    let ControlFlow::Break(mut stream) = res else {
        panic!("IXFR failed");
    };

    let zone_soa = get_zone_soa(&zone).await;

    // could be replied to with the following incremental message:
    let mut expected_records: ExpectedRecords = vec![
        (n("JAIN.AD.JP."), zone_soa.clone().into()),
        (
            n("JAIN.AD.JP."),
            Soa::new(
                n("NS.JAIN.AD.JP."),
                n("mohta.jain.ad.jp."),
                Serial(1),
                Ttl::from_secs(600),
                Ttl::from_secs(600),
                Ttl::from_secs(3600000),
                Ttl::from_secs(604800),
            )
            .into(),
        ),
        (n("NEZU.JAIN.AD.JP."), A::new(p("133.69.136.5")).into()),
        (
            n("JAIN.AD.JP."),
            Soa::new(
                n("NS.JAIN.AD.JP."),
                n("mohta.jain.ad.jp."),
                Serial(2),
                Ttl::from_secs(600),
                Ttl::from_secs(600),
                Ttl::from_secs(3600000),
                Ttl::from_secs(604800),
            )
            .into(),
        ),
        (n("JAIN-BB.JAIN.AD.JP."), A::new(p("133.69.136.4")).into()),
        (n("JAIN-BB.JAIN.AD.JP."), A::new(p("192.41.197.2")).into()),
        (
            n("JAIN.AD.JP."),
            Soa::new(
                n("NS.JAIN.AD.JP."),
                n("mohta.jain.ad.jp."),
                Serial(2),
                Ttl::from_secs(600),
                Ttl::from_secs(600),
                Ttl::from_secs(3600000),
                Ttl::from_secs(604800),
            )
            .into(),
        ),
        (n("JAIN-BB.JAIN.AD.JP."), A::new(p("133.69.136.4")).into()),
        (
            n("JAIN.AD.JP."),
            Soa::new(
                n("NS.JAIN.AD.JP."),
                n("mohta.jain.ad.jp."),
                Serial(3),
                Ttl::from_secs(600),
                Ttl::from_secs(600),
                Ttl::from_secs(3600000),
                Ttl::from_secs(604800),
            )
            .into(),
        ),
        (n("JAIN-BB.JAIN.AD.JP."), A::new(p("133.69.136.3")).into()),
        (n("JAIN.AD.JP."), zone_soa.into()),
    ];

    let msg = stream.next().await.unwrap().unwrap();
    assert!(matches!(
        msg.feedback(),
        Some(ServiceFeedback::BeginTransaction)
    ));

    let stream =
        assert_stream_eq(req.message(), &mut stream, &mut expected_records)
            .await;

    let msg = stream.next().await.unwrap().unwrap();
    assert!(matches!(
        msg.feedback(),
        Some(ServiceFeedback::EndTransaction)
    ));
}

#[tokio::test]
async fn ixfr_rfc1995_section7_udp_packet_overflow() {
    // Based on https://datatracker.ietf.org/doc/html/rfc1995#section-7
    let zone = load_zone(include_bytes!(
        "../../../../../test-data/zonefiles/big.example.com.txt"
    ));

    let req =
        mk_udp_ixfr_request(zone.apex_name(), Serial(0), Default::default());

    let res = do_preprocess(zone.clone(), &req).await.unwrap();

    let ControlFlow::Break(mut stream) = res else {
        panic!("IXFR failed");
    };

    let zone_soa = get_zone_soa(&zone).await;

    let mut expected_records: ExpectedRecords =
        vec![(n("example.com"), zone_soa.into())];

    assert_stream_eq(req.message(), &mut stream, &mut expected_records).await;
}

#[tokio::test]
async fn ixfr_multi_response_tcp() {}

#[tokio::test]
async fn axfr_with_tsig_key() {
    // Define an XfrDataProvider that expects to receive a Request that is
    // generic over a type that we specify: Authentication. This is the
    // type over which the Request produced by TsigMiddlewareSvc is generic.
    // When the XfrMiddlewareSvc receives a Request<Octs, Authentication> it
    // passes it to the XfrDataProvider which in turn can inspect it.
    #[derive(Clone)]
    struct KeyReceivingXfrDataProvider {
        key: Arc<Key>,
        checked: Arc<AtomicBool>,
    }

    impl XfrDataProvider<Option<Arc<Key>>> for KeyReceivingXfrDataProvider {
        type Diff = EmptyZoneDiff;

        #[allow(clippy::type_complexity)]
        fn request<Octs>(
            &self,
            req: &Request<Octs, Option<Arc<Key>>>,
            _diff_from: Option<Serial>,
        ) -> Pin<
            Box<
                dyn Future<
                        Output = Result<
                            XfrData<Self::Diff>,
                            XfrDataProviderError,
                        >,
                    > + Sync
                    + Send,
            >,
        >
        where
            Octs: Octets + Send + Sync,
        {
            let key = req.metadata().as_ref().unwrap();
            assert_eq!(key.name(), self.key.name());
            self.checked.store(true, Ordering::SeqCst);
            Box::pin(ready(Err(XfrDataProviderError::Refused)))
        }
    }

    let key_name = KeyName::from_str("some_tsig_key_name").unwrap();
    let secret = crate::utils::base64::decode::<Vec<u8>>(
        "zlCZbVJPIhobIs1gJNQfrsS3xCxxsR9pMUrGwG8OgG8=",
    )
    .unwrap();
    let key = Arc::new(
        Key::new(Algorithm::Sha256, &secret, key_name, None, None).unwrap(),
    );

    let metadata = Some(key.clone());
    let req = mk_axfr_request(n("example.com"), metadata);
    let checked = Arc::new(AtomicBool::new(false));
    let xdp = KeyReceivingXfrDataProvider {
        key,
        checked: checked.clone(),
    };

    // Invoke XfrMiddlewareSvc with our custom XfrDataProvidedr.
    let _ = do_preprocess(xdp, &req).await;

    // Veirfy that our XfrDataProvider was invoked and received the expected
    // TSIG key name data.
    assert!(checked.load(Ordering::SeqCst));
}

//------------ Helper functions -------------------------------------------

fn n(name: &str) -> Name<Bytes> {
    Name::from_str(name).unwrap()
}

fn p<T: FromStr>(txt: &str) -> T
where
    <T as FromStr>::Err: Debug,
{
    txt.parse().unwrap()
}

fn load_zone(bytes: &[u8]) -> Zone {
    let mut zone_bytes = std::io::BufReader::new(bytes);
    let reader = Zonefile::load(&mut zone_bytes).unwrap();
    Zone::try_from(reader).unwrap()
}

async fn get_zone_soa(zone: &Zone) -> Soa<Name<Bytes>> {
    let read = zone.read();
    let zone_soa_answer =
        read_soa(&read, zone.apex_name().to_owned()).await.unwrap();
    let AnswerContent::Data(zone_soa_rrset) =
        zone_soa_answer.content().clone()
    else {
        unreachable!()
    };
    let first_rr = zone_soa_rrset.first().unwrap();
    let ZoneRecordData::Soa(soa) = first_rr.data() else {
        unreachable!()
    };
    soa.clone()
}

fn mk_axfr_request<T>(
    qname: impl ToName,
    metadata: T,
) -> Request<Vec<u8>, T> {
    mk_axfr_request_for_transport(
        qname,
        metadata,
        TransportSpecificContext::NonUdp(NonUdpTransportContext::new(None)),
    )
}

fn mk_udp_axfr_request<T>(
    qname: impl ToName,
    metadata: T,
) -> Request<Vec<u8>, T> {
    mk_axfr_request_for_transport(
        qname,
        metadata,
        TransportSpecificContext::Udp(UdpTransportContext::new(None)),
    )
}

fn mk_axfr_request_for_transport<T>(
    qname: impl ToName,
    metadata: T,
    transport_specific: TransportSpecificContext,
) -> Request<Vec<u8>, T> {
    let client_addr = "127.0.0.1:12345".parse().unwrap();
    let received_at = Instant::now();
    let msg = MessageBuilder::new_vec();
    let mut msg = msg.question();
    msg.push((qname, Rtype::AXFR)).unwrap();
    let msg = msg.into_message();

    Request::new(client_addr, received_at, msg, transport_specific, metadata)
}

fn mk_ixfr_request<T>(
    qname: impl ToName + Clone,
    serial: Serial,
    metadata: T,
) -> Request<Vec<u8>, T> {
    mk_ixfr_request_for_transport(
        qname,
        serial,
        metadata,
        TransportSpecificContext::NonUdp(NonUdpTransportContext::new(None)),
    )
}

fn mk_udp_ixfr_request<T>(
    qname: impl ToName + Clone,
    serial: Serial,
    metadata: T,
) -> Request<Vec<u8>, T> {
    mk_ixfr_request_for_transport(
        qname,
        serial,
        metadata,
        TransportSpecificContext::Udp(UdpTransportContext::new(None)),
    )
}

fn mk_ixfr_request_for_transport<T>(
    qname: impl ToName + Clone,
    serial: Serial,
    metadata: T,
    transport_specific: TransportSpecificContext,
) -> Request<Vec<u8>, T> {
    let client_addr = "127.0.0.1:12345".parse().unwrap();
    let received_at = Instant::now();
    let msg = MessageBuilder::new_vec();
    let mut msg = msg.question();
    msg.push((qname.clone(), Rtype::IXFR)).unwrap();

    let mut msg = msg.authority();
    let ttl = Ttl::from_secs(0);
    let soa = Soa::new(n("name"), n("rname"), serial, ttl, ttl, ttl, ttl);
    msg.push((qname, Class::IN, Ttl::from_secs(0), soa))
        .unwrap();
    let msg = msg.into_message();

    Request::new(client_addr, received_at, msg, transport_specific, metadata)
}

async fn do_preprocess<XDP>(
    zone: XDP,
    req: &Request<Vec<u8>, Option<Arc<Key>>>,
) -> Result<
    ControlFlow<
        XfrMiddlewareStream<
            <TestNextSvc as Service<Vec<u8>, Option<Arc<Key>>>>::Future,
            <TestNextSvc as Service<Vec<u8>, Option<Arc<Key>>>>::Stream,
            <<TestNextSvc as Service<Vec<u8>, Option<Arc<Key>>>>::Stream as Stream>::Item,
        >,
    >,
    OptRcode,
>
where
    XDP: XfrDataProvider<Option<Arc<Key>>> + Clone + Sync + Send + 'static,
    XDP::Diff: Debug + 'static,
{
    XfrMiddlewareSvc::<Vec<u8>, TestNextSvc, Option<Arc<Key>>, XDP>::preprocess(
        Arc::new(Semaphore::new(1)),
        Arc::new(Semaphore::new(1)),
        req,
        zone,
    )
    .await
}

async fn assert_stream_eq<
    O: octseq::Octets,
    S: Stream<Item = Result<CallResult<Vec<u8>>, ServiceError>> + Unpin,
>(
    req: &Message<O>,
    mut stream: S,
    expected_records: &mut ExpectedRecords,
) -> S {
    while !expected_records.is_empty() {
        let msg = stream.next().await.unwrap().unwrap();

        let resp_builder = msg.into_inner().0.unwrap();
        let resp = resp_builder.as_message();
        assert!(resp.is_answer(req));
        let mut records = resp.answer().unwrap().peekable();

        for (idx, rec) in records.by_ref().enumerate() {
            let rec = rec.unwrap();

            let rec = rec
                .into_record::<AllRecordData<_, ParsedName<_>>>()
                .unwrap()
                .unwrap();

            eprintln!(
                "XFR record {idx} {} {} {} {}",
                rec.owner(),
                rec.class(),
                rec.rtype(),
                rec.data(),
            );

            let pos = expected_records
                .iter()
                .position(|(name, data)| {
                    name == rec.owner() && data == rec.data()
                })
                .unwrap_or_else(|| {
                    panic!(
                        "XFR record {idx} {} {} {} {} was not expected",
                        rec.owner(),
                        rec.class(),
                        rec.rtype(),
                        rec.data(),
                    )
                });

            let _ = expected_records.remove(pos);

            eprintln!("Found {} {} {}", rec.owner(), rec.class(), rec.rtype())
        }

        assert!(records.next().is_none());
    }

    stream
}

#[derive(Clone)]
struct TestNextSvc;

impl Service<Vec<u8>, Option<Arc<Key>>> for TestNextSvc {
    type Target = Vec<u8>;
    type Stream = Once<Ready<ServiceResult<Self::Target>>>;
    type Future = Ready<Self::Stream>;

    fn call(
        &self,
        _request: Request<Vec<u8>, Option<Arc<Key>>>,
    ) -> Self::Future {
        todo!()
    }
}

#[derive(Clone)]
struct ZoneWithDiffs {
    zone: Zone,
    diffs: Vec<Arc<InMemoryZoneDiff>>,
}

impl ZoneWithDiffs {
    fn new(zone: Zone, diffs: Vec<InMemoryZoneDiff>) -> Self {
        Self {
            zone,
            diffs: diffs.into_iter().map(Arc::new).collect(),
        }
    }

    fn get_diffs(
        &self,
        diff_from: Option<Serial>,
    ) -> Vec<Arc<InMemoryZoneDiff>> {
        if self.diffs.first().map(|diff| diff.start_serial) == diff_from {
            self.diffs.clone()
        } else {
            vec![]
        }
    }
}

impl<RequestMeta> XfrDataProvider<RequestMeta> for ZoneWithDiffs {
    type Diff = Arc<InMemoryZoneDiff>;
    fn request<Octs>(
        &self,
        req: &Request<Octs, RequestMeta>,
        diff_from: Option<Serial>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        XfrData<Self::Diff>,
                        XfrDataProviderError,
                    >,
                > + Sync
                + Send,
        >,
    >
    where
        Octs: Octets + Send + Sync,
    {
        let res = req
            .message()
            .sole_question()
            .map_err(XfrDataProviderError::ParseError)
            .and_then(|q| {
                if q.qname() == self.zone.apex_name()
                    && q.qclass() == self.zone.class()
                {
                    Ok(XfrData::new(
                        self.zone.clone(),
                        self.get_diffs(diff_from),
                        false,
                    ))
                } else {
                    Err(XfrDataProviderError::UnknownZone)
                }
            });

        Box::pin(ready(res))
    }
}
