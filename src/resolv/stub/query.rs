//! Query related things for the rotor-based DNS transport.

use bits::message::MessageBuf;
use super::sync::RotorSender;
use resolv::error::Result;


//------------ QueryState ---------------------------------------------------

/// The processing state of a query, ie., what's currently happening.
#[derive(Clone)]
struct QueryState {
    /// Are we in datagram state still?
    ///
    /// Either because of configuration or a truncated answer, a query may
    /// need to go to a stream server. This flag says if that happened
    /// already.
    dgram: bool,

    /// The index of the server we started with.
    ///
    /// This is relevant for round robin querying where we may start at any
    /// server.
    start_index: usize,

    /// The index of the server we asked last, if the query was started.
    ///
    /// This will always grow and the dispatcher will do the modulo number
    /// of servers thing.
    last_index: Option<usize>,

    /// The how manyth attempt is this?
    ///
    /// Starts counting at 0.
    attempt: usize,
}

impl QueryState {
    /// Creates a new query state value.
    fn new() -> QueryState {
        QueryState { dgram: true, start_index: 0, last_index: None, attempt: 0 }
    }

    /// Starts a query.
    fn start(&mut self, dgram: bool, start_index: usize) {
        self.dgram = dgram;
        self.start_index = start_index;
        self.last_index = Some(start_index);
        self.attempt = 0;
    }

    /// Restart the query for a new attempt.
    fn restart(&mut self, start_index: usize) {
        self.start_index = start_index;
        self.last_index = Some(start_index);
    }

    /// Progresses to the next server.
    ///
    /// Returns the index of the next server or None if we are done.
    ///
    /// If the server number is smaller than our original start index (which
    /// can happen with reconfiguration), we simple restart with the first
    /// server.
    fn next(&mut self, server_num: usize) -> Option<usize> {
        let mut last_index = self.last_index.unwrap(); // Yes, indeed!
        if server_num < self.start_index {
            self.start_index = 0;
            self.last_index = Some(0);
            Some(0)
        }
        else {
            last_index = (last_index + 1) % server_num;
            self.last_index = Some(last_index);
            if last_index == self.start_index {
                None
            }
            else {
                Some(last_index)
            }
        }
    }
}


//------------ Query --------------------------------------------------------

/// A query.
/// #[derive(Clone)]
pub struct Query {
    state: QueryState,
    request: MessageBuf,
    response: Option<Result<MessageBuf>>,
    sender: RotorSender<Result<MessageBuf>>,
}

impl Query {
    pub fn new(request: MessageBuf,
               sender: RotorSender<Result<MessageBuf>>) -> Query {
        Query { state: QueryState::new(), request: request, response: None,
                sender: sender }
    }

    pub fn id(&self) -> u16 {
        self.request.header().id()
    }

    pub fn request(&self) -> &MessageBuf {
        &self.request
    }

    pub fn request_data(&self) -> &[u8] {
        self.request.as_bytes()
    }

    pub fn request_mut(&mut self) -> &mut MessageBuf {
        &mut self.request
    }

    pub fn response(&self) -> &Option<Result<MessageBuf>> {
        &self.response
    }

    pub fn set_response(&mut self, response: Result<MessageBuf>) {
        self.response = Some(response)
    }

    pub fn start(&mut self, dgram: bool, start_index: usize) {
        self.state.start(dgram, start_index)
    }

    pub fn restart(&mut self, start_index: usize) {
        self.state.restart(start_index)
    }

    pub fn next(&mut self, server_num: usize) -> Option<usize> {
        self.state.next(server_num)
    }

    pub fn has_started(&self) -> bool {
        self.state.last_index.is_some()
    }

    pub fn is_dgram(&self) -> bool {
        self.state.dgram
    }
    
    pub fn is_truncated(&self) -> bool {
        if let Some(Ok(ref response)) = self.response {
            response.header().tc()
        }
        else { false }
    }

    pub fn new_attempt(&mut self, attempts: usize) -> bool {
        self.state.attempt += 1;
        self.state.attempt < attempts
    }

    pub fn send(self) {
        // XXX We drop unsendable queries on the floor. Perhaps we should
        //     log or something?
        let _ = self.sender.send(self.response.unwrap());
    }
}


