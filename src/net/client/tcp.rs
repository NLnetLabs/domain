//! A DNS over TCP transport

// RFC 7766 describes DNS over TCP
// RFC 7828 describes the edns-tcp-keepalive option

// TODO:
// - errors
//   - connect errors? Retry after connection refused?
//   - server errors
//     - ID out of range
//     - ID not in use
//     - reply for wrong query
// - timeouts
//   - request timeout
// - limit number of outstanding queries to 32K
// - create new TCP connection after end/failure of previous one

use std::collections::VecDeque;
use std::ops::DerefMut;
use std::sync::Arc;
use std::sync::Mutex as Std_mutex;
use std::time::{Duration, Instant};
use std::vec::Vec;
use bytes::{Bytes, BytesMut};

use crate::base::{Message, MessageBuilder, opt::{AllOptData, OptRecord,
	TcpKeepalive}, StaticCompressor, StreamTarget};
use crate::base::wire::Composer;
use octseq::{Octets, OctetsBuilder};

use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::sync::Notify;
use tokio::time::sleep;

const ERR_IDLE_TIMEOUT: &str = "idle connection was closed";
const ERR_READ_ERROR: &str = "read error";
const ERR_READ_TIMEOUT: &str = "read timeout";
const ERR_WRITE_ERROR: &str = "write error";
const ERR_TOO_MANY_QUERIES: &str = "too many outstanding queries";

// From RFC 7828. This should go somewhere with the option parsing
const EDNS_TCP_KEEPALIE_TO_MS: u64 = 100;

// Implement a simple response timer to see if the connection and the server
// are alive. Set the timer when the connection goes from idle to busy.
// Reset the timer each time a reply arrives. Cancel the timer when the
// connection goes back to idle. When the time expires, mark all outstanding
// queries as timed out and shutdown the connection.
//
// Note: nsd has 120 seconds, unbound has 3 seconds.
const RESPONSE_TIMEOUT_S: u64 = 19;

enum SingleQueryState {
	Busy,
	Done(Result<Message<Bytes>, Arc<std::io::Error>>),
	Canceled,
}

struct SingleQuery {
	state: SingleQueryState,
	complete: Arc<Notify>,
}

struct Queries {
	// Number of queries in the vector. The count of element that are
	// not None
	count: usize,

	// Number of queries that are still waiting for an answer
	busy: usize,

	// Index in the vector where to look for a space for a new query
	curr: usize,

	vec: Vec<Option<SingleQuery>>,
}

enum ConnState {
	Active(Option<Instant>),
	Idle(Instant),
	IdleTimeout,
	ReadError,
	ReadTimeout,
	WriteError,
}

struct Status {
	state: ConnState,

	// For edns-tcp-keepalive, we have a boolean the specifies if we
	// need to send one (typically at the start of the connection).
	// Initially we assume that the idle timeout is zero. A received
	// edns-tcp-keepalive option may change that. What the best way to
	// specify time in Rust? Currently we specify it in milliseconds.
	send_keepalive: bool,
	idle_timeout: Option<Duration>,
	do_shutdown: bool,
}

struct InnerTcpConnection {
	stream: Std_mutex<TcpStream>,

	/* status */
	status: Std_mutex<Status>,

	/* Vector with outstanding queries */
	query_vec: Std_mutex<Queries>,

	/* Vector with outstanding requests that need to be transmitted */
	tx_queue: Std_mutex<VecDeque<Vec<u8>>>,

	worker_notify: Notify,
	writer_notify: Notify,
}

pub struct TcpConnection {
	inner: Arc<InnerTcpConnection>,
}

enum QueryState {
	Busy(usize),	// index
	Done,
}

pub struct Query {
	transport: Arc<InnerTcpConnection>,
	query_msg: Message<Vec<u8>>,
	state: QueryState,
}

impl InnerTcpConnection {
	pub async fn connect<A: ToSocketAddrs>(addr: A) ->
		io::Result<InnerTcpConnection> {
		let tcp = TcpStream::connect(addr).await?;
		Ok(Self {
			stream: Std_mutex::new(tcp),
			status: Std_mutex::new(Status {
				state: ConnState::Active(None),
				send_keepalive: true,
				idle_timeout: None,
				do_shutdown: false,
			}),
			query_vec: Std_mutex::new(Queries {
				count: 0,
				busy: 0,
				curr: 0,
				vec: Vec::new()
			}),
			tx_queue: Std_mutex::new(VecDeque::new()),
			worker_notify: Notify::new(),
			writer_notify: Notify::new(),
			})
	}

	// Take a query out of query_vec and decrement the query count 
	fn take_query(&self, index: usize) -> Option<SingleQuery>
	{
		let mut query_vec = self.query_vec.lock().unwrap();
		self.vec_take_query(query_vec.deref_mut(), index)
	}

	// Very similar to take_query, but sometime the caller already has
	// a lock on the mutex
	fn vec_take_query(&self, query_vec: &mut Queries, index: usize) ->
		Option<SingleQuery>{
		let query = query_vec.vec[index].take();
		query_vec.count = query_vec.count - 1;
		if query_vec.count == 0 {
			// The worker may be waiting for this
			self.worker_notify.notify_one();
		}
		query
	}

	fn insert_answer(&self, answer: Message<Bytes>) {
		// We got an answer, reset the timer
		let mut status = self.status.lock().unwrap();
		status.state = ConnState::Active(Some(Instant::now()));
		drop(status);

		let ind16 = answer.header().id();
		let index: usize = ind16.into();

		let mut query_vec = self.query_vec.lock().unwrap();

		let vec_len = query_vec.vec.len();
		if index >= vec_len {
			// Index is out of bouds. We should mark
			// the TCP connection as broken
			return;
		}

		// Do we have a query with this ID?
		match &mut query_vec.vec[index] {
			None => {
				// No query with this ID. We should
				// mark the TCP connection as broken
				return;
			}
			Some(query) => {
				match &query.state {
					SingleQueryState::Busy => {
						query.state =
							SingleQueryState::
							Done(Ok(
							answer));
						query.complete.
							notify_one();
					}
					SingleQueryState::Canceled => {
						//`The query has been
						// canceled already
						// Clean up.
						let _ = self.vec_take_query(
							query_vec.deref_mut(),
							index);
					}
					SingleQueryState::Done(_) => {
						// Already got a
						// result.
						return;
					}
				}
			}
		}
		query_vec.busy = query_vec.busy-1;
		if query_vec.busy == 0 {
			let mut status = self.status.lock().unwrap();

			// Clear the activity timer. There is no need to do 
			// this because state will be set to either IdleTimeout
			// or Idle just below. However, it is nicer to keep 
			// this indenpendent.
			status.state = ConnState::Active(None);

			if status.idle_timeout == None {
				// Assume that we can just move to IdleTimeout
				// state
				status.state = ConnState::IdleTimeout;

				// Notify the worker. Then the worker can
				// close the tcp connection
				self.worker_notify.notify_one();
			}
			else {
				status.state =
					ConnState::Idle(Instant::now());

				// Notify the worker. The worker waits for
				// the timeout to expire
				self.worker_notify.notify_one();
			}
		}
	}

	fn handle_keepalive(&self, opt_value: TcpKeepalive) {
		if let Some(value) = opt_value.timeout() {
			let mut status = self.status.lock().unwrap();
			status.idle_timeout =
				Some(Duration::from_millis(u64::from(value) *
					EDNS_TCP_KEEPALIE_TO_MS));
		}
	}

	fn handle_opts<Octs: Octets + AsRef<[u8]>>
		(&self, opts: &OptRecord<Octs>) {
		for option in opts.iter() {
			let opt = option.unwrap();
			match opt {
				AllOptData::TcpKeepalive(tcpkeepalive) => {
					self.handle_keepalive(tcpkeepalive);
				}
				_ => {}
			}
		}
	}

	// This function is not async cancellation safe
	async fn reader(&self, sock: &mut ReadHalf<'_>) -> Result<(), &str> {
		loop {
		    let read_res = sock.read_u16().await;
		    let len = match read_res {
			Ok(len) => len,
			Err(error) => {
			    self.tcp_error(error);
			    let mut status = self.status.lock().unwrap();
			    status.state = ConnState::ReadError;
			    return Err(ERR_READ_ERROR);
			}
		    } as usize;

		    let mut buf = BytesMut::with_capacity(len);
			
		    loop {
			let curlen = buf.len();
			if curlen >= len {
				if curlen > len {
					panic!(
			"reader: got too much data {curlen}, expetect {len}");
				}

				// We got what we need
				break;
			}

			let read_res = sock.read_buf(&mut buf).await;

			match read_res {
			    Ok(readlen) => {
				if readlen == 0 {
				    let error = io::Error::new(
					io::ErrorKind::Other,
					"unexpected end of data");
				    self.tcp_error(error);
				    let mut status = self.status.lock().
					unwrap();
				    status.state = ConnState::ReadError;
				    return Err(ERR_READ_ERROR);
				}
			    }
			    Err(error) => {
				self.tcp_error(error);
				let mut status = self.status.lock().unwrap();
				status.state = ConnState::ReadError;
				return Err(ERR_READ_ERROR);
			    }
			};

			// Check if we are done at the head of the loop
		    }
			
		    let reply_message = Message::<Bytes>::from_octets(buf.into());

		    match reply_message {
			Ok(answer) => {
			    // Check for a edns-tcp-keepalive option
			    let opt_record = answer.opt();
			    if let Some(ref opts) = opt_record {
				    self.handle_opts(opts);
			    };
			    self.insert_answer(answer);
			}
			Err(_) => {
			    // The only possible error is short message
			    let error = io::Error::new(io::ErrorKind::Other,
				"short buf");
			    self.tcp_error(error);
			    let mut status = self.status.lock().unwrap();
			    status.state = ConnState::ReadError;
			    return Err(ERR_READ_ERROR);
			}
		    }
		}
	}

	fn tcp_error(&self, error: std::io::Error) {
		// Update all requests that are in progress. Don't wait for
		// any reply that may be on its way.
		let arc_error = Arc::new(error);
		let mut query_vec = self.query_vec.lock().unwrap();
		for query in &mut query_vec.vec {
			match query {
				None => {
					continue;
				}
				Some(q) => {
					match q.state {
						SingleQueryState::Busy => {
							q.state =
							SingleQueryState::
								Done(Err(
								arc_error
								.clone()));
							q.complete.
								notify_one();
						}
						SingleQueryState::Done(_) |
						SingleQueryState::Canceled =>
							// Nothing to do
							()
					}
				}
			}
		}
	}

	// This function is not async cancellation safe
	async fn writer(&self, sock: &mut WriteHalf<'_>) ->
		Result<(), &'static str> {
		loop {
			loop {
				// Check if we need to shutdown
				let status = self.status.lock().unwrap();
				let do_shutdown = status.do_shutdown;
				drop(status);

				if do_shutdown {
					// Ignore errors
					_ = sock.shutdown().await;

					// Do we need to clear do_shutdown?
					break;
				}

				let mut tx_queue = self.tx_queue.lock().
					unwrap();
				let head = tx_queue.pop_front();
				drop(tx_queue);
				match head {
				Some(vec) => {
					let res = sock.write_all(&vec).await;
					if let Err(error) = res {
						self.tcp_error(error);
						let mut status =
							self.status.lock().
							unwrap();
						status.state =
							ConnState::WriteError;
						return Err(ERR_WRITE_ERROR);
					}
					()
				}
				None =>
					break,
				}
			}

			self.writer_notify.notified().await;
		}
	}

	// This function is not async cancellation safe because it calls
	// reader and writer which are not async cancellation safe
	pub async fn worker(&self) -> Option<()> {
		let mut stream = self.stream.lock().unwrap();
		let (mut read_stream, mut write_stream) = stream.split();

		let reader_fut = self.reader(&mut read_stream);
		tokio::pin!(reader_fut);
		let writer_fut = self.writer(&mut write_stream);
		tokio::pin!(writer_fut);

		loop {
			let mut opt_timeout: Option<Duration> = None;
			let mut status = self.status.lock().unwrap();
			match status.state {
			    ConnState::Active(opt_instant) => {
				if let Some(instant) = opt_instant {
				    let timeout = Duration::from_secs(
					RESPONSE_TIMEOUT_S);
				    let elapsed = instant.elapsed();
				    if elapsed > timeout {
					let error = io::Error::new(
						io::ErrorKind::Other,
						"read timeout");
					self.tcp_error(error);
					status.state = ConnState::ReadTimeout;
					break;
				    }
				    opt_timeout = Some(timeout - elapsed);
				}
			    }
			    ConnState::Idle(instant) => {
				if let Some(timeout) = status.idle_timeout {
					let elapsed = instant.elapsed();
					if elapsed >= timeout {
						// Move to IdleTimeout and end
						// the loop
						status.state =
							ConnState::IdleTimeout;
						break;
					}
					opt_timeout = Some(timeout - elapsed);
				}
				else {
					panic!("Idle state but no timeout");
				}
			    }
			    ConnState::IdleTimeout |
			    ConnState::ReadError |
			    ConnState::WriteError =>
				(), // No timers here
			    ConnState::ReadTimeout => panic!(
				"should not be in loop with ReadTimeout")
			}
			drop(status);


			// For simplicity, make sure we always have a timeout
			let timeout = match opt_timeout {
				Some(timeout) => timeout,
				None =>
					// Just use the response timeout
					Duration::from_secs(RESPONSE_TIMEOUT_S)
			};

			let sleep_fut = sleep(timeout);
			let notify_fut = self.worker_notify.notified();

			tokio::select! {
				res = &mut reader_fut => {
				    match res {
					Ok(_) =>
					    // The reader should not
					    // terminate without
					    // error.
					    panic!("reader terminated"),
					Err(_) =>
					    // Reader failed. Break
					    // out of loop and
					    // shut down
					    break
				    }
				}
				res = &mut writer_fut => {
					match res {
						Ok(_) =>
						// The writer should not
						// terminate without
						// error.
					    panic!("reader terminated"),
					Err(_) =>
						// Writer failed. Break
						// out of loop and
						// shut down
						break
					}
				}

				_ = sleep_fut => {
					// Timeout expired, just
					// continue with the loop
					()
				}
				_ = notify_fut => {
					// Got notifies, go through the loop
					// to see what changed.
					()
				}

			}

			// Check if the connection is idle
			let status = self.status.lock().unwrap();
			match status.state {
				ConnState::Active(_) | ConnState::Idle(_) => {
					// Keep going
				}
				ConnState::IdleTimeout => {
					break
				}
				ConnState::ReadError |
				ConnState::ReadTimeout |
				ConnState::WriteError => {
					panic!("Should not be here");
				}
			}
			drop(status);
		}

		// We can't see a FIN directly because the writer_fut owns
		// write_stream.
		let mut status = self.status.lock().unwrap();
		status.do_shutdown = true;
		drop(status);

		// Kick writer
		self.writer_notify.notify_one();

		// Wait for writer to terminate. Ignore the result. We may
		// want a timer here
		_ = writer_fut.await;

		// Stay around until the last query result is collected
		loop {
			let query_vec = self.query_vec.lock().unwrap();
			if query_vec.count == 0 {
				// We are done
				break;
			}
			drop(query_vec);

			self.worker_notify.notified().await;
		}
		None
	}

	fn insert_at(query_vec: &mut Queries, index: usize,
		q: Option<SingleQuery>) {
		query_vec.vec[index] = q;
		query_vec.count = query_vec.count + 1;
		query_vec.busy = query_vec.busy + 1;
		query_vec.curr = index + 1;
	}

	// Insert a message in the query vector. Return the index
	fn insert(&self)
		-> Result<usize, &'static str> {
		let q = Some(SingleQuery {
			state: SingleQueryState::Busy,
			complete: Arc::new(Notify::new()),
		});
		let mut query_vec = self.query_vec.lock().unwrap();

		// Fail if there are to many entries already in this vector
		// We cannot have more than u16::MAX entries because the
		// index needs to fit in an u16. For efficiency we want to
		// keep the vector half empty. So we return a failure if
		// 2*count > u16::MAX
		if 2*query_vec.count > u16::MAX.into() {
			return Err(ERR_TOO_MANY_QUERIES);
		}

		let vec_len = query_vec.vec.len();

		// Append if the amount of empty space in the vector is less
		// than half. But limit vec_len to u16::MAX
		if vec_len < 2*(query_vec.count+1) && vec_len <
			u16::MAX.into() {
			// Just append
			query_vec.vec.push(q);
			query_vec.count = query_vec.count + 1;
			query_vec.busy = query_vec.busy + 1;
			let index = query_vec.vec.len()-1;
			return Ok(index);
		}
		let loc_curr = query_vec.curr;

		for index in loc_curr..vec_len {
			match query_vec.vec[index] {
				Some(_) => {
					// Already in use, just continue
					()
				}
				None => {
					Self::insert_at(&mut query_vec,
						index, q);
					return Ok(index);
				}
			}
		}

		// Nothing until the end of the vector. Try for the entire
		// vector
		for index in 0..vec_len {
			match query_vec.vec[index] {
				Some(_) => {
					// Already in use, just continue
					()
				}
				None => {
					Self::insert_at(&mut query_vec,
						index, q);
					return Ok(index);
				}
			}
		}

		// Still nothing, that is not good
		panic!("insert failed");
	}

	fn queue_query<Target: AsMut<[u8]> + AsRef<[u8]>>
		(&self, msg: &MessageBuilder<StaticCompressor<StreamTarget<Target>>>) {

		let vec = msg.as_target().as_target().as_stream_slice();

		// Store a clone of the request. That makes life easier
		// and requests tend to be small
		let mut tx_queue = self.tx_queue.lock().unwrap();
		tx_queue.push_back(vec.to_vec());
	}

	pub fn query<Octs: OctetsBuilder + AsMut<[u8]> + AsRef<[u8]> +
		Composer + Clone>
		(&self,
		query_msg: &mut MessageBuilder<StaticCompressor<StreamTarget<Octs>>>
		) -> Result<usize, &'static str> {

		// Check the state of the connection, fail if the connection
		// is in IdleTimeout. If the connection is Idle, move it
		// back to Active. Also check for the need to send a keepalive
		let mut status = self.status.lock().unwrap();
		match status.state {
			ConnState::Active(timer) => {
				// Set timer if we don't have one already
				if timer == None {
					status.state = ConnState::Active(Some(
						Instant::now()));
				}
				()
			}
			ConnState::Idle(_) => {
				// Go back to active
				status.state = ConnState::Active(Some(
					Instant::now()));
				()
			}
			ConnState::IdleTimeout => {
				// The connection has been closed. Report error
				return Err(ERR_IDLE_TIMEOUT);
			}
			ConnState::ReadError => {
				return Err(ERR_READ_ERROR);
			}
			ConnState::ReadTimeout => {
				return Err(ERR_READ_TIMEOUT);
			}
			ConnState::WriteError => {
				return Err(ERR_WRITE_ERROR);
			}
		}

		// Note that insert may fail if there are too many
		// outstanding queires. First call insert before checking
		// send_keepalive.
		let index = self.insert()?;

		let mut do_keepalive = false;
		if status.send_keepalive {
			do_keepalive = true;
			status.send_keepalive = false;
		}
		drop(status);

		let ind16: u16 = index.try_into().unwrap();

		// We set the ID to the array index. Defense in depth
		// suggests that a random ID is better because it works
		// even if TCP sequence numbers could be predicted. However,
		// Section 9.3 of RFC 5452 recommends retrying over TCP
		// if many spoofed answers arrive over UDP: "TCP, by the
		// nature of its use of sequence numbers, is far more
		// resilient against forgery by third parties."
		let hdr = query_msg.header_mut();
		hdr.set_id(ind16);

		if do_keepalive {
			let mut msgadd = query_msg.clone().additional();

				// send an empty keepalive option
				let res = msgadd.opt(|opt| {
					opt.tcp_keepalive(None)
				});
				match res {
					Ok(_) =>
					    self.queue_query(&msgadd),
					Err(_) => {
						// Adding keepalive option
						// failed. Send the original
						// request and turn the
						// send_keepalive flag back on
						let mut status =
							self.status.lock()
							.unwrap();
						status.send_keepalive =
							true;
						drop(status);
						self.queue_query(query_msg);
					}
				}
			} else {
				self.queue_query(query_msg);
			}

			// Now kick the writer to transmit the query
			self.writer_notify.notify_one();

			Ok(index)
		}

		pub async fn get_result<Octs: Octets>(&self,
			query_msg: &Message<Octs>, index: usize) ->
			Result<Message<Bytes>, Arc<std::io::Error>> {
			// Wait for reply
			let mut query_vec = self.query_vec.lock().unwrap();
			let local_notify = query_vec.vec[index].as_mut().
				unwrap().complete.clone();
			drop(query_vec);
			local_notify.notified().await;

			// take a look
			let opt_q = self.take_query(index);
			if let Some(q) = opt_q
			{
				if let SingleQueryState::Done(result) = q.state
				{
					if let Ok(answer) = &result
					{
						if !answer.is_answer(
							query_msg) {
						    return Err(Arc::new(
							io::Error::new(
							io::ErrorKind::Other,
							"wrong answer")));
						}
					}
					return result;
				}
				panic!("inconsistent state");
			}

			panic!("inconsistent state");
		}

	fn cancel(&self, index: usize) {
		let mut query_vec = self.query_vec.lock().unwrap();

		match &mut query_vec.vec[index] {
			None => {
				panic!("Cancel called, but nothing to cancel");
			}
			Some(query) => {
				match &query.state {
					SingleQueryState::Busy => {
						query.state =
							SingleQueryState::
								Canceled;
						return;
					}
					SingleQueryState::Canceled => {
						panic!("Already canceled");
					}
					SingleQueryState::Done(_) => {
						// Remove the result
						let _ = self.vec_take_query(
							query_vec.deref_mut(),
							index);
					}
				}
			}
		}
	}
}

impl TcpConnection {
	pub async fn connect<A: ToSocketAddrs>(addr: A) ->
		io::Result<TcpConnection> {
		let tcpconnection = InnerTcpConnection::connect(addr).await?;
		Ok(Self { inner: Arc::new(tcpconnection) })
	}
	pub async fn worker(&self) -> Option<()> {
		self.inner.worker().await
	}
	pub fn query<OctsBuilder: OctetsBuilder + AsMut<[u8]> + AsRef<[u8]> +
		Composer + Clone>
		(&self, query_msg: &mut MessageBuilder<StaticCompressor
		<StreamTarget<OctsBuilder>>>)
			-> Result<Query, &'static str> {
		let index = self.inner.query(query_msg)?;
		let msg = &query_msg.as_message();
		Ok(Query::new(self, msg, index))
	}
}


impl Query {
	fn new<Octs: Octets>(transport: &TcpConnection,
		query_msg: &Message<Octs>,
			index: usize) -> Query {
		let msg_ref: &[u8] = query_msg.as_ref();
		let vec = msg_ref.to_vec();
		let msg = Message::from_octets(vec).unwrap();
		Self {
			transport: transport.inner.clone(),
			query_msg: msg,
			state: QueryState::Busy(index)
		}
	}
	pub async fn get_result(&mut self) ->
		Result<Message<Bytes>, Arc<std::io::Error>> {
		// Just the result of get_result on tranport. We should record
		// that we got an answer to avoid asking again
		match self.state {
			QueryState::Busy(index) => {
				let result = self.transport.get_result(
					&self.query_msg, index).await;
				self.state = QueryState::Done;
				result
			}
			QueryState::Done => {
				panic!("Already done");
			}
		}
	}
}

impl Drop for Query {
	fn drop(&mut self) {
		match self.state {
			QueryState::Busy(index) => {
				self.transport.cancel(index);
			}
			QueryState::Done => {
				// Done, nothing to cancel
			}
		}
	}
}
