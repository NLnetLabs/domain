use crate::net::deckard::client::CurrStepValue;
use crate::net::deckard::connection::Connection;
use crate::net::deckard::parse_deckard::Deckard;
use domain::net::client::protocol::AsyncConnect;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

pub struct Connect {
    deckard: Deckard,
    step_value: Arc<CurrStepValue>,
}

impl Connect {
    #[allow(dead_code)]
    pub fn new(deckard: Deckard, step_value: Arc<CurrStepValue>) -> Connect {
        Self {
            deckard,
            step_value,
        }
    }
}

impl AsyncConnect for Connect {
    type Connection = Connection;
    type Fut = Pin<
        Box<
            dyn Future<Output = Result<Connection, std::io::Error>>
                + Send
                + Sync,
        >,
    >;

    fn connect(&self, _source_address: Option<SocketAddr>) -> Self::Fut {
        let deckard = self.deckard.clone();
        let step_value = self.step_value.clone();
        Box::pin(async move { Ok(Connection::new(deckard, step_value)) })
    }
}
