use domain::rdata::Dnskey;
use domain::crypto::common::PublicKey;
use domain::base::iana::SecurityAlgorithm;

fn main() {
	let keyraw = [0u8; 16];
	let input = "Hello World!";
	let bad_sig = [0u8; 16];
	let dnskey = Dnskey::new(256, 3, SecurityAlgorithm::ED25519, keyraw).unwrap();
	let public_key = PublicKey::from_dnskey(&dnskey).unwrap();
	let res = public_key.verify(input.as_bytes(), &bad_sig);
	println!("verify result: {res:?}");
}
