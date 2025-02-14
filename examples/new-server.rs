use std::ops::ControlFlow;

use log::trace;

use domain::new_server::{
    exchange::{OutgoingResponse, ResponseCode},
    layers::{
        cookie::{CookieMetadata, CookiePolicy, CookieSecrets},
        CookieLayer,
    },
    transport, Exchange, LocalService, LocalServiceLayer, Service,
    ServiceLayer,
};

pub struct MyService;

impl Service for MyService {
    async fn respond(&self, exchange: &mut Exchange<'_>) {
        let cookie = exchange
            .metadata
            .iter()
            .find_map(|m| m.try_as::<CookieMetadata>());

        if let Some(CookieMetadata::ServerCookie { .. }) = cookie {
            trace!(target: "MyService", "Request had a valid cookie");
        } else {
            trace!(target: "MyService", "Request did not have a valid cookie");
        }

        exchange.respond(ResponseCode::Success);

        // Copy all questions from the request to the response.
        exchange
            .response
            .questions
            .append(&mut exchange.request.questions);
    }
}

impl LocalService for MyService {
    async fn respond_local(&self, exchange: &mut Exchange<'_>) {
        self.respond(exchange).await
    }
}

pub struct MyLayer;

impl ServiceLayer for MyLayer {
    async fn process_incoming(
        &self,
        exchange: &mut Exchange<'_>,
    ) -> ControlFlow<()> {
        trace!(target: "MyLayer",
            "Incoming request (message ID {})",
            exchange.request.id);
        ControlFlow::Continue(())
    }

    async fn process_outgoing(&self, response: OutgoingResponse<'_, '_>) {
        trace!(target: "MyLayer",
            "Outgoing response (message ID {})",
            response.response.id);
    }
}

impl LocalServiceLayer for MyLayer {
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

#[tokio::main]
async fn main() {
    env_logger::init();

    let addr = "127.0.0.1:8080".parse().unwrap();
    let cookie_layer =
        CookieLayer::new(CookiePolicy::default(), CookieSecrets::generate());
    let service = (MyLayer, cookie_layer, MyService);
    let result = transport::serve_udp(addr, service).await;
    println!("Ended on result {result:?}");
}
