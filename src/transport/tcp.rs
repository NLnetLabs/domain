//! A DNS over TCP transport

// TODO:
// - errors
//   - read errors
//   - write errors
//   - connect errors? Retry after connection refused?
//   - server errors
//     - ID out of range
//     - ID not in use
//     - reply for wrong query
// - timeouts
//   - idle timeout
//   - channel timeout
//   - request timeout
// - create new TCP connection after end/failure of previous one

use std::sync::Arc;
use std::sync::Mutex as Std_mutex;
use std::vec::Vec;
use std::collections::VecDeque;
use bytes::{Bytes, BytesMut};

use crate::base::{Message, MessageBuilder, StaticCompressor, StreamTarget};
use octseq::{Octets, OctetsBuilder};

use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::sync::Notify;

enum SingleQueryState {
	Busy,
	Done(Result<Message<Bytes>, &'static str>),
	Canceled,
}

struct SingleQuery {
	state: SingleQueryState,
	complete: Arc<Notify>,
}

struct Queries {
	count: usize,
	vec: Vec<Option<SingleQuery>>,
}

struct InnerTcpConnection {
	stream: Std_mutex<TcpStream>,

	// Should deal with keepalive

	/* Vector with outstanding queries */
	query_vec: Std_mutex<Queries>,

	/* Vector with outstanding requests that need to be transmitted */
	tx_queue: Std_mutex<VecDeque<Vec<u8>>>,

	worker_notify: Notify,
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
			query_vec: Std_mutex::new(Queries {
				count: 0,
				vec: Vec::new()
			}),
			tx_queue: Std_mutex::new(VecDeque::new()),
			worker_notify: Notify::new(),
			})
	}

	fn insert_answer(&self, answer: Message<Bytes>) {
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
							return;
						}
						SingleQueryState::Canceled => {
							//`The query has been
							// canceled already
							// Clean up.
							let _ = query_vec.
								vec[index].
								take();
							query_vec.count =
								query_vec.
								count - 1;
							return;
						}
						SingleQueryState::Done(_) => {
							// Already got a
							// result.
							return;
						}
					}
				}
			}
	}

	async fn reader(&self, sock: &mut ReadHalf<'_>) {
		loop {
		    let len = sock.read_u16().await.unwrap() as usize;

		    let mut buf = BytesMut::with_capacity(len);
			
		    let reslen = sock.read_buf(&mut buf).await.unwrap();
			
		    let reply_message = Message::<Bytes>::from_octets(buf.into());
		    if let Ok(answer) = reply_message {
			self.insert_answer(answer);

		    // else try with the next message.
		    } else {
			panic!("Read error");
			//return Err(io::Error::new(
			   // io::ErrorKind::Other,
			 //   "short buf",
			//));
		    }
		}
	}

	async fn writer(&self, sock: &mut WriteHalf<'_>) {
		loop {
			let mut tx_queue = self.tx_queue.lock().unwrap();
			let head = tx_queue.pop_front();
			drop(tx_queue);
			match head {
			Some(vec) => {
				sock.write_all(&vec).await;
				()
			}
			None =>
				break,
			}
		}
	}

	pub async fn worker(&self) -> Option<()> {
		let mut stream = self.stream.lock().unwrap();
		let (mut read_stream, mut write_stream) = stream.split();

		let reader_fut = self.reader(&mut read_stream);
		tokio::pin!(reader_fut);

		loop {
			let writer_fut = self.writer(&mut write_stream);

			tokio::select! {
				read = &mut reader_fut => {
					panic!("reader terminated");
				}
				write = writer_fut => {
					// The writer is done. Wait 
					// for a notify
					()
				}
			}

			let notify_fut = self.worker_notify.notified();

			tokio::select! {
				read = &mut reader_fut => {
					panic!("reader terminated");
				}
				notify = notify_fut => {
					// Got notified, start writing
					()
				}
			}
		}
	}

	// Insert a message in the query vector. Return the index
	fn insert(&self)
		-> usize {
		let q = Some(SingleQuery {
			state: SingleQueryState::Busy,
			complete: Arc::new(Notify::new()),
		});
		let mut query_vec = self.query_vec.lock().unwrap();
		let vec_len = query_vec.vec.len();
		if vec_len < 2*(query_vec.count+1) {
			// Just append
			query_vec.vec.push(q);
			query_vec.count = query_vec.count + 1;
			let index = query_vec.vec.len()-1;
			return index;
		}
		panic!("Sould insert");
		0
	}

	fn queue_query<Target: AsMut<[u8]> + AsRef<[u8]>>
		(&self, msg: &MessageBuilder<StaticCompressor<StreamTarget<Target>>>) {

		let vec = msg.as_target().as_target().as_stream_slice();

		// Store a clone of the request. That makes life easier
		// and requests tend to be small
		let mut tx_queue = self.tx_queue.lock().unwrap();
		tx_queue.push_back(vec.to_vec());
	}

	pub async fn query<Target: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]>>
		(&self, query_msg: &mut MessageBuilder<StaticCompressor<StreamTarget<Target>>>)
		-> Result<Message<Bytes>, &'static str> {
		let index = self.insert();
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

		self.queue_query(query_msg);

		// Now kick the worker to transmit the query
		self.worker_notify.notify_one();

		// Wait for reply
		let mut query_vec = self.query_vec.lock().unwrap();
		let local_notify = query_vec.vec[index].as_mut().unwrap().
			complete.clone();
		drop(query_vec);
		local_notify.notified().await;
		println!("Got reply");

		// Get the lock again to take a look
		let mut query_vec = self.query_vec.lock().unwrap();
		let opt_q = query_vec.vec[index].take();
		query_vec.count = query_vec.count - 1;
		drop(query_vec);

		if let Some(q) = opt_q
		{
			if let SingleQueryState::Done(result) = q.state
			{
				if let Ok(answer) = &result
				{
					if !answer.is_answer(&query_msg.
						as_message()) {
					    // Wrong answer, try again?
					    panic!("wrong answer");
					}
				}
				return result;
			}
			panic!("inconsistent state");
		}

		panic!("inconsistent state");
	}

	pub fn query2<Octs: OctetsBuilder + AsMut<[u8]> + AsRef<[u8]>>
		(&self,
		query_msg: &mut MessageBuilder<StaticCompressor<StreamTarget
			<Octs>>>) -> usize {
		let index = self.insert();
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

		self.queue_query(query_msg);

		// Now kick the worker to transmit the query
		self.worker_notify.notify_one();

		index
	}

	pub async fn get_result<Octs: Octets>(&self, query_msg: &Message<Octs>,
		index: usize) -> Result<Message<Bytes>, &'static str> {
		// Wait for reply
		let mut query_vec = self.query_vec.lock().unwrap();
		let local_notify = query_vec.vec[index].as_mut().unwrap().
			complete.clone();
		drop(query_vec);
		local_notify.notified().await;

		// Get the lock again to take a look
		let mut query_vec = self.query_vec.lock().unwrap();
		let opt_q = query_vec.vec[index].take();
		query_vec.count = query_vec.count - 1;
		drop(query_vec);

		if let Some(q) = opt_q
		{
			if let SingleQueryState::Done(result) = q.state
			{
				if let Ok(answer) = &result
				{
					if !answer.is_answer(query_msg) {
					    // Wrong answer, try again?
					    panic!("wrong answer");
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
							SingleQueryState::Canceled;
						return;
					}
					SingleQueryState::Canceled => {
						panic!("Already canceled");
					}
					SingleQueryState::Done(_) => {
						// Remove the result
						let _ = query_vec.
							vec[index].take();
						query_vec.count =
							query_vec.count - 1;
						drop(query_vec);
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
	pub async fn query<Octs: OctetsBuilder + AsMut<[u8]> + AsRef<[u8]>>
		(&self, query_msg: &mut MessageBuilder<StaticCompressor<StreamTarget<Octs>>>)
		-> Result<Message<Bytes>, &'static str> {
		self.inner.query(query_msg).await
	}
	pub fn query2<OctsBuilder: OctetsBuilder + AsMut<[u8]> + AsRef<[u8]>>
		(&self, query_msg: &mut MessageBuilder<StaticCompressor
		<StreamTarget<OctsBuilder>>>)
			-> Result<Query, &'static str> {
		let index = self.inner.query2(query_msg);
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
			state: QueryState::Busy(index) }
	}
	pub async fn get_result(&mut self) ->
		Result<Message<Bytes>, &'static str> {
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
