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
// - separate Query object
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
use crate::base::octets;

use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::sync::Notify;

struct SingleQuery {
	reply: Option<Result<Message<Bytes>, &'static str>>,
	complete: Arc<Notify>,
}

struct Queries {
	count: usize,
	vec: Vec<Option<SingleQuery>>,
}

pub struct TcpConnection {
	stream: Std_mutex<TcpStream>,

	// Should deal with keepalive

	/* Vector with outstanding queries */
	query_vec: Std_mutex<Queries>,

	/* Vector with outstanding requests that need to be transmitted */
	tx_queue: Std_mutex<VecDeque<Vec<u8>>>,

	worker_notify: Notify,
}

// impl<'a, Octets: octets::OctetsBuilder + AsRef<[u8]> + AsMut<[u8]> + Clone + 'a> TcpConnection<'a> {
impl TcpConnection {
	pub async fn connect<A: ToSocketAddrs>(addr: A) ->
		io::Result<TcpConnection> {
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

			println!("Got ID {}", ind16);
			
			println!("Before query_vec.lock()");
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
					match &query.reply {
						None => {
							query.reply =
								Some(Ok(
								answer));
							query.complete.	
								notify_one();
							return;
						}
						_ => {
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
			println!("in loop");
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

			println!("Waiting for work");
			let notify_fut = self.worker_notify.notified();

			tokio::select! {
				read = &mut reader_fut => {
					panic!("reader terminated");
				}
				notify = notify_fut => {
					// Got notified, start writing
					println!("Got work");
					()
				}
			}
		}
	}

	// Insert a message in the query vector. Return the index
	fn insert(&self)
		-> usize {
		let q = Some(SingleQuery {
			reply: None,
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

	fn queue_query<Octets: octets::OctetsBuilder + AsRef<[u8]>>(&self, 
		msg: &MessageBuilder<StaticCompressor<StreamTarget<Octets>>>) {

		let query_vec = self.query_vec.lock().unwrap();
		let vec = msg.as_target().as_target().as_stream_slice();

		// Store a clone of the request. That makes life easier
		// and requests tend to be small
		let mut tx_queue = self.tx_queue.lock().unwrap();
		tx_queue.push_back(vec.to_vec());
	}

	pub async fn query<Octets: octets::OctetsBuilder + AsRef<[u8]> +
		AsMut<[u8]>>(&self,
		query_msg: &mut MessageBuilder<StaticCompressor<StreamTarget
			<Octets>>>) -> Result<Message<Bytes>, &'static str> {
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
		println!("Waiting for reply");
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
			if let Some(result) = q.reply
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

}
