//! DNSSEC signing.
//!
//! **This module is experimental and likely to change significantly.**
//!
//! Signatures are at the heart of DNSSEC -- they confirm the authenticity of a
//! DNS record served by a secure-aware name server.  But name servers are not
//! usually creating those signatures themselves.  Within a DNS zone, it is the
//! zone administrator's responsibility to sign zone records (when the record's
//! time-to-live expires and/or when it changes).  Those signatures are stored
//! as regular DNS data and automatically served by name servers.

#![cfg(feature = "sign")]
#![cfg_attr(docsrs, doc(cfg(feature = "sign")))]

use core::{fmt, str};

use crate::base::iana::SecAlg;

pub mod key;
//pub mod openssl;
pub mod records;
pub mod ring;

/// A generic keypair.
///
/// This type cannot be used for computing signatures, as it does not implement
/// any cryptographic primitives.  Instead, it is a generic representation that
/// can be imported/exported or converted into a [`Signer`] (if the underlying
/// cryptographic implementation supports it).
pub enum KeyPair<B: AsRef<[u8]> + AsMut<[u8]>> {
    /// An RSA/SHA256 keypair.
    RsaSha256(RsaKey<B>),

    /// An ECDSA P-256/SHA-256 keypair.
    ///
    /// The private key is a single 32-byte big-endian integer.
    EcdsaP256Sha256([u8; 32]),

    /// An ECDSA P-384/SHA-384 keypair.
    ///
    /// The private key is a single 48-byte big-endian integer.
    EcdsaP384Sha384([u8; 48]),

    /// An Ed25519 keypair.
    ///
    /// The private key is a single 32-byte string.
    Ed25519([u8; 32]),

    /// An Ed448 keypair.
    ///
    /// The private key is a single 57-byte string.
    Ed448([u8; 57]),
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> KeyPair<B> {
    /// The algorithm used by this key.
    pub fn algorithm(&self) -> SecAlg {
        match self {
            Self::RsaSha256(_) => SecAlg::RSASHA256,
            Self::EcdsaP256Sha256(_) => SecAlg::ECDSAP256SHA256,
            Self::EcdsaP384Sha384(_) => SecAlg::ECDSAP384SHA384,
            Self::Ed25519(_) => SecAlg::ED25519,
            Self::Ed448(_) => SecAlg::ED448,
        }
    }

    /// Serialize this key in the conventional DNS format.
    ///
    /// - For RSA, see RFC 5702, section 6.
    /// - For ECDSA, see RFC 6605, section 6.
    /// - For EdDSA, see RFC 8080, section 6.
    pub fn into_dns(&self, w: &mut impl fmt::Write) -> fmt::Result {
        match self {
            Self::RsaSha256(k) => {
                w.write_str("Algorithm: 8 (RSASHA256)\n")?;
                k.into_dns(w)
            }

            Self::EcdsaP256Sha256(s) => {
                w.write_str("Algorithm: 13 (ECDSAP256SHA256)\n")?;
                base64(&*s, &mut *w)
            }

            Self::EcdsaP384Sha384(s) => {
                w.write_str("Algorithm: 14 (ECDSAP384SHA384)\n")?;
                base64(&*s, &mut *w)
            }

            Self::Ed25519(s) => {
                w.write_str("Algorithm: 15 (ED25519)\n")?;
                base64(&*s, &mut *w)
            }

            Self::Ed448(s) => {
                w.write_str("Algorithm: 16 (ED448)\n")?;
                base64(&*s, &mut *w)
            }
        }
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> Drop for KeyPair<B> {
    fn drop(&mut self) {
        // Zero the bytes for each field.
        match self {
            Self::RsaSha256(_) => {}
            Self::EcdsaP256Sha256(s) => s.fill(0),
            Self::EcdsaP384Sha384(s) => s.fill(0),
            Self::Ed25519(s) => s.fill(0),
            Self::Ed448(s) => s.fill(0),
        }
    }
}

/// An RSA private key.
///
/// All fields here are arbitrary-precision integers in big-endian format,
/// without any leading zero bytes.
pub struct RsaKey<B: AsRef<[u8]> + AsMut<[u8]>> {
    /// The public modulus.
    pub n: B,

    /// The public exponent.
    pub e: B,

    /// The private exponent.
    pub d: B,

    /// The first prime factor of `d`.
    pub p: B,

    /// The second prime factor of `d`.
    pub q: B,

    /// The exponent corresponding to the first prime factor of `d`.
    pub d_p: B,

    /// The exponent corresponding to the second prime factor of `d`.
    pub d_q: B,

    /// The inverse of the second prime factor modulo the first.
    pub q_i: B,
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> RsaKey<B> {
    /// Serialize this key in the conventional DNS format.
    ///
    /// The output does not include an 'Algorithm' specifier.
    ///
    /// See RFC 5702, section 6.2 for examples of this format.
    pub fn into_dns(&self, w: &mut impl fmt::Write) -> fmt::Result {
        w.write_str("Modulus:\t")?;
        base64(self.n.as_ref(), &mut *w)?;
        w.write_str("\nPublicExponent:\t")?;
        base64(self.e.as_ref(), &mut *w)?;
        w.write_str("\nPrivateExponent:\t")?;
        base64(self.d.as_ref(), &mut *w)?;
        w.write_str("\nPrime1:\t")?;
        base64(self.p.as_ref(), &mut *w)?;
        w.write_str("\nPrime2:\t")?;
        base64(self.q.as_ref(), &mut *w)?;
        w.write_str("\nExponent1:\t")?;
        base64(self.d_p.as_ref(), &mut *w)?;
        w.write_str("\nExponent2:\t")?;
        base64(self.d_q.as_ref(), &mut *w)?;
        w.write_str("\nCoefficient:\t")?;
        base64(self.q_i.as_ref(), &mut *w)?;
        w.write_char('\n')
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> Drop for RsaKey<B> {
    fn drop(&mut self) {
        // Zero the bytes for each field.
        self.n.as_mut().fill(0u8);
        self.e.as_mut().fill(0u8);
        self.d.as_mut().fill(0u8);
        self.p.as_mut().fill(0u8);
        self.q.as_mut().fill(0u8);
        self.d_p.as_mut().fill(0u8);
        self.d_q.as_mut().fill(0u8);
        self.q_i.as_mut().fill(0u8);
    }
}

/// A utility function to format data as Base64.
///
/// This is a simple implementation with the only requirement of being
/// constant-time and side-channel resistant.
fn base64(data: &[u8], w: &mut impl fmt::Write) -> fmt::Result {
    // Convert a single chunk of bytes into Base64.
    fn encode(data: [u8; 3]) -> [u8; 4] {
        let [a, b, c] = data;

        // Expand the chunk using integer operations; it's pretty fast.
        let chunk = (a as u32) << 16 | (b as u32) << 8 | (c as u32);
        // 0b00000000_XXXXXXXX_XXXXXXXX_XXXXXXXXu32
        let chunk = (chunk & 0x00FFF000) << 4 | (chunk & 0x00000FFF);
        // (0b0000XXXX_XXXXXXXXu16, 0b0000XXXX_XXXXXXXXu16)
        let chunk = (chunk & 0x0FC00FC0) << 2 | (chunk & 0x003F003F);
        // (0b00XXXXXXu8, 0b00XXXXXXu8, 0b00XXXXXXu8, 0b00XXXXXXu8)

        // Classify each output byte as A-Z, a-z, 0-9, + or /.
        let bcast = 0x01010101u32;
        let uppers = chunk + (128 - 26) * bcast;
        let lowers = chunk + (128 - 52) * bcast;
        let digits = chunk + (128 - 62) * bcast;
        let pluses = chunk + (128 - 63) * bcast;

        // For each byte, the LSB is set if it is in the class.
        let uppers = !uppers >> 7;
        let lowers = (uppers & !lowers) >> 7;
        let digits = (lowers & !digits) >> 7;
        let pluses = (digits & !pluses) >> 7;
        let slashs = pluses >> 7;

        // Add the corresponding offset for each class.
        let chunk = chunk
            + (uppers & bcast) * (b'A' - 0) as u32
            + (lowers & bcast) * (b'a' - 26) as u32
            + (digits & bcast) * (b'0' - 52) as u32
            + (pluses & bcast) * (b'+' - 62) as u32
            + (slashs & bcast) * (b'/' - 63) as u32;

        // Convert back into a byte array.
        chunk.to_be_bytes()
    }

    // TODO: Use 'slice::array_chunks()' or 'slice::as_chunks()'.
    let mut chunks = data.chunks_exact(3);

    // Iterate over the whole chunks in the input.
    for chunk in &mut chunks {
        let chunk = <[u8; 3]>::try_from(chunk).unwrap();
        let chunk = encode(chunk);
        let chunk = str::from_utf8(&chunk).unwrap();
        w.write_str(chunk)?;
    }

    // Encode the final chunk and handle padding.
    let mut chunk = [0u8; 3];
    chunk[..chunks.remainder().len()].copy_from_slice(chunks.remainder());
    let mut chunk = encode(chunk);
    match chunks.remainder().len() {
        0 => return Ok(()),
        1 => chunk[2..].fill(b'='),
        2 => chunk[3..].fill(b'='),
        3 => {}
        _ => unreachable!(),
    }
    let chunk = str::from_utf8(&chunk).unwrap();
    w.write_str(chunk)
}
