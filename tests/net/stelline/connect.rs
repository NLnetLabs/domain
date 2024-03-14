use crate::net::stelline::client::CurrStepValue;
use crate::net::stelline::connection::Connection;
use crate::net::stelline::parse_stelline::Stelline;
use domain::net::client::protocol::AsyncConnect;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

pub struct Connect {
    stelline: Stelline,
    step_value: Arc<CurrStepValue>,
}

impl Connect {
    #[allow(dead_code)]
    pub fn new(stelline: Stelline, step_value: Arc<CurrStepValue>) -> Connect {
        Self {
            stelline,
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
        let stelline = self.stelline.clone();
        let step_value = self.step_value.clone();
        Box::pin(async move { Ok(Connection::new(stelline, step_value)) })
    }
}
