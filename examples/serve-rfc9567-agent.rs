#![cfg(feature = "siphasher")]
use core::future::pending;

use std::str::FromStr;
use std::sync::Arc;

use domain::rdata::rfc1035::TxtBuilder;
use tokio::net::{TcpSocket, UdpSocket};
use tracing_subscriber::EnvFilter;

use domain::base::iana::{Class, Rcode};
use domain::base::name::{Label, ToLabelIter};
use domain::base::{CharStr, NameBuilder, Ttl};
use domain::net::server::buf::VecBufSource;
use domain::net::server::dgram::DgramServer;
use domain::net::server::message::Request;
use domain::net::server::middleware::cookies::CookiesMiddlewareSvc;
use domain::net::server::middleware::edns::EdnsMiddlewareSvc;
use domain::net::server::middleware::mandatory::MandatoryMiddlewareSvc;
use domain::net::server::service::{CallResult, ServiceResult};
use domain::net::server::stream::StreamServer;
use domain::net::server::util::{mk_builder_for_target, service_fn};

//----------- my_service() ---------------------------------------------------

fn my_service(
    request: Request<Vec<u8>>,
    _metadata: (),
) -> ServiceResult<Vec<u8>> {
    let mut out_answer = None;
    if let Ok(question) = request.message().sole_question() {
        // We're expecting an RFC 9567 compatible query, i.e. a QNAME of the
        // form:
        //   _er.<decimal qtype>.<query name labels>.<decimal edns error code>._er.<our agent domain>
        // This has at least 6 labels.
        // See: https://www.rfc-editor.org/rfc/rfc9567#name-constructing-the-report-que
        let qname = question.qname();
        let num_labels = qname.label_count();
        if num_labels >= 6 {
            let mut iter = qname.iter_labels();
            let _er = iter.next().unwrap();
            let rep_qtype = iter.next().unwrap();
            let mut rep_qname = NameBuilder::new_vec();
            let mut second_last_label = Option::<&Label>::None;
            let mut last_label = None;
            loop {
                let label = iter.next().unwrap();
                if let Some(label) = second_last_label {
                    rep_qname.append_label(label.as_slice()).unwrap();
                }
                if label == "_er" {
                    break;
                } else {
                    second_last_label = last_label;
                    last_label = Some(label);
                }
            }
            let rep_qname = rep_qname.finish();
            let edns_err_code = last_label.unwrap();

            // Invoke local program to handle the error report
            // TODO
            eprintln!("Received error report:");
            eprintln!("QNAME: {rep_qname}");
            eprintln!("QTYPE: {rep_qtype}");
            eprintln!("EDNS error: {edns_err_code}");

            // https://www.rfc-editor.org/rfc/rfc9567#section-6.3-1
            // "It is RECOMMENDED that the authoritative server for the agent
            // domain reply with a positive response (i.e., not with NODATA or
            // NXDOMAIN) containing a TXT record."
            let builder = mk_builder_for_target();
            let mut answer = builder
                .start_answer(request.message(), Rcode::NOERROR)
                .unwrap();
            let mut txt_builder = TxtBuilder::<Vec<u8>>::new();
            let txt = {
                let cs =
                    CharStr::<Vec<u8>>::from_str("Report received").unwrap();
                txt_builder.append_charstr(&cs).unwrap();
                txt_builder.finish().unwrap()
            };
            answer
                .push((qname, Class::IN, Ttl::from_days(1), txt))
                .unwrap();
            out_answer = Some(answer);
        }
    }

    if out_answer.is_none() {
        let builder = mk_builder_for_target();
        out_answer = Some(
            builder
                .start_answer(request.message(), Rcode::REFUSED)
                .unwrap(),
        );
    }

    let additional = out_answer.unwrap().additional();
    Ok(CallResult::new(additional))
}

//----------- main() ---------------------------------------------------------

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // -----------------------------------------------------------------------
    // Setup logging. You can override the log level by setting environment
    // variable RUST_LOG, e.g. RUST_LOG=trace.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_thread_ids(true)
        .without_time()
        .try_init()
        .ok();

    // -----------------------------------------------------------------------
    // Create a service with accompanying middleware chain to answer incoming
    // requests.
    let svc = service_fn(my_service, ());
    // https://www.rfc-editor.org/rfc/rfc9567#section-6.3-2 "The monitoring
    // agent SHOULD respond to queries received over UDP that have no DNS
    // Cookie set with a response that has the truncation bit (TC bit) set to
    // challenge the resolver to requery over TCP."
    let svc = CookiesMiddlewareSvc::<Vec<u8>, _, _>::with_random_secret(svc);
    let svc = EdnsMiddlewareSvc::<Vec<u8>, _, _>::new(svc);
    let svc = MandatoryMiddlewareSvc::<Vec<u8>, _, _>::new(svc);
    let svc = Arc::new(svc);

    // -----------------------------------------------------------------------
    // Run a DNS server on UDP port 8053 on 127.0.0.1 using the my_service
    // service defined above and accompanying middleware.
    let udpsocket = UdpSocket::bind("127.0.0.1:8053").await.unwrap();
    let buf = Arc::new(VecBufSource);
    let srv = DgramServer::new(udpsocket, buf.clone(), svc.clone());
    tokio::spawn(async move { srv.run().await });

    // -----------------------------------------------------------------------
    // Run a DNS server on TCP port 8053 on 127.0.0.1 using the same service.
    let v4socket = TcpSocket::new_v4().unwrap();
    v4socket.set_reuseaddr(true).unwrap();
    v4socket.bind("127.0.0.1:8053".parse().unwrap()).unwrap();
    let v4listener = v4socket.listen(1024).unwrap();
    let buf = Arc::new(VecBufSource);
    let srv = StreamServer::new(v4listener, buf.clone(), svc);
    tokio::spawn(async move { srv.run().await });

    pending().await
}
