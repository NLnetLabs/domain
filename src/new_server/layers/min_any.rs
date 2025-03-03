//! Providing minimal responses to ANY queries.
//!
//! See [RFC 8482](https://datatracker.ietf.org/doc/html/rfc8482) for more.

use core::ops::ControlFlow;

use crate::{
    new_base::{
        wire::ParseBytes, CharStr, QClass, QType, Question, RClass, RType,
        Record, TTL,
    },
    new_rdata::{HInfo, RecordData},
    new_server::{
        exchange::{OutgoingResponse, ResponseCode},
        Exchange, LocalServiceLayer, ServiceLayer,
    },
};

/// A simple responder for ANY queries.
///
/// Conventionally, queries with `QTYPE=ANY` would result in large responses
/// containing all the records for a particular name.  While they have some
/// legitimate use cases, they are quite rare, and they can be abused towards
/// denial-of-service attacks.
///
/// In the spirit of [RFC 8482], this service layer responds to `QTYPE=ANY`
/// queries (regardless of the queried name or class) with a short hardcoded
/// response (specifically, a fake `HINFO` record with the `CPU` string set to
/// `RFC8482`, and the `OS` string empty).
///
/// [RFC 8482]: https://datatracker.ietf.org/doc/html/rfc8482
pub struct MinAnyLayer;

impl ServiceLayer for MinAnyLayer {
    async fn process_incoming(
        &self,
        exchange: &mut Exchange<'_>,
    ) -> ControlFlow<()> {
        match exchange.request.questions.as_slice() {
            [Question {
                qname,
                qtype: QType::ANY,
                qclass: QClass::IN,
            }] => {
                let record = Record {
                    rname: *qname,
                    rtype: RType::HINFO,
                    rclass: RClass::IN,
                    ttl: TTL::from(3600),
                    rdata: RecordData::HInfo(HInfo {
                        cpu: <&CharStr>::parse_bytes(b"\x07RFC8482").unwrap(),
                        os: CharStr::EMPTY,
                    }),
                };
                exchange.respond(ResponseCode::Success);
                exchange.response.answers.push(record);
                ControlFlow::Break(())
            }

            _ => ControlFlow::Continue(()),
        }
    }

    async fn process_outgoing(&self, _response: OutgoingResponse<'_, '_>) {
        // A later layer caught the request and built a response to it.  That
        // means that the request wasn't a QTYPE=ANY query, so we don't have
        // to do anything here.
    }
}

impl LocalServiceLayer for MinAnyLayer {
    async fn process_local_incoming(
        &self,
        exchange: &mut Exchange<'_>,
    ) -> ControlFlow<()> {
        self.process_incoming(exchange).await
    }

    async fn process_local_outgoing(
        &self,
        response: OutgoingResponse<'_, '_>,
    ) {
        self.process_outgoing(response).await
    }
}
