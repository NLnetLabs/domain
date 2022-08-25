use std::str::FromStr;
use std::net::{UdpSocket};

use domain::base::{
        Dname, MessageBuilder, Rtype, StaticCompressor, StreamTarget,
        message::Message
};

fn create_message() -> StreamTarget<Vec<u8>> {
    // Create a message builder wrapping a compressor wrapping a stream
    // target.
    let mut msg = MessageBuilder::from_target(
        StaticCompressor::new(
                StreamTarget::new_vec()
        )
    ).unwrap();

    // Set the RD bit and a random ID in the header and proceed to
    // the question section.
    msg.header_mut().set_rd(true);
    msg.header_mut().set_random_id();
    let mut msg = msg.question();

    // Add a hard-coded question and proceed to the answer section.
    msg.push((Dname::<Vec<u8>>::from_str("example.com.").unwrap(), Rtype::A)).unwrap();

    // Skip to the additional section
    let mut msg = msg.additional();

    // Add an OPT record.
    msg.opt(|opt| {
            opt.set_udp_payload_size(4096);
            Ok(())
    }).unwrap();

    // Convert the builder into the actual message.
    msg.finish().into_target()
}

fn main() {
    // Bind a UDP socket to a kernel-provided port
    let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");

    let message = create_message();

    let server: String = "127.0.0.1".to_string();
    let port: u16 = 53;

    // Send message off to the server using our socket
    socket.send_to(&message.as_dgram_slice(), (server, port)).unwrap();

    // Create recv buffer
    let mut buffer = vec![0; 1232];

    // Recv in buffer
    socket.recv_from(&mut buffer).unwrap();

    // Parse and print the response 
    let response = match Message::from_octets(buffer){
        Ok(response) => Some(response),
        Err(_) => None,
    }.unwrap();
    
    // Left as an exercise to the implementer: break down the
    // response into sections and print them

}

