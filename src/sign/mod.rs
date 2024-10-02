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

use std::vec::Vec;

use crate::base::iana::SecAlg;

pub mod key;
//pub mod openssl;
pub mod records;
pub mod ring;

/// Signing DNS records.
///
/// Implementors of this trait own a private key and sign DNS records for a zone
/// with that key.  Signing is a synchronous operation performed on the current
/// thread; this rules out implementations like HSMs, where I/O communication is
/// necessary.
pub trait Sign<Buffer> {
    /// An error in constructing a signature.
    type Error;

    /// The signature algorithm used.
    ///
    /// The following algorithms can be used:
    /// - [`SecAlg::RSAMD5`] (highly insecure, do not use)
    /// - [`SecAlg::DSA`] (highly insecure, do not use)
    /// - [`SecAlg::RSASHA1`] (insecure, not recommended)
    /// - [`SecAlg::DSA_NSEC3_SHA1`] (highly insecure, do not use)
    /// - [`SecAlg::RSASHA1_NSEC3_SHA1`] (insecure, not recommended)
    /// - [`SecAlg::RSASHA256`]
    /// - [`SecAlg::RSASHA512`] (not recommended)
    /// - [`SecAlg::ECC_GOST`] (do not use)
    /// - [`SecAlg::ECDSAP256SHA256`]
    /// - [`SecAlg::ECDSAP384SHA384`]
    /// - [`SecAlg::ED25519`]
    /// - [`SecAlg::ED448`]
    fn algorithm(&self) -> SecAlg;

    /// Compute a signature.
    ///
    /// A regular signature of the given byte sequence is computed and is turned
    /// into the selected buffer type.  This provides a lot of flexibility in
    /// how buffers are constructed; they may be heap-allocated or have a static
    /// size.
    fn sign(&self, data: &[u8]) -> Result<Buffer, Self::Error>;
}

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
                base64_encode(&*s, &mut *w)
            }

            Self::EcdsaP384Sha384(s) => {
                w.write_str("Algorithm: 14 (ECDSAP384SHA384)\n")?;
                base64_encode(&*s, &mut *w)
            }

            Self::Ed25519(s) => {
                w.write_str("Algorithm: 15 (ED25519)\n")?;
                base64_encode(&*s, &mut *w)
            }

            Self::Ed448(s) => {
                w.write_str("Algorithm: 16 (ED448)\n")?;
                base64_encode(&*s, &mut *w)
            }
        }
    }

    /// Parse a key from the conventional DNS format.
    ///
    /// - For RSA, see RFC 5702, section 6.
    /// - For ECDSA, see RFC 6605, section 6.
    /// - For EdDSA, see RFC 8080, section 6.
    pub fn from_dns(data: &str) -> Result<Self, ()>
    where
        B: From<Vec<u8>>,
    {
        /// Parse private keys for most algorithms (except RSA).
        fn parse_pkey<const N: usize>(data: &str) -> Result<[u8; N], ()> {
            // Extract the 'PrivateKey' field.
            let (_, val, data) = parse_dns_pair(data)?
                .filter(|&(k, _, _)| k == "PrivateKey")
                .ok_or(())?;

            if !data.trim_ascii().is_empty() {
                // There were more fields following.
                return Err(());
            }

            let mut buf = [0u8; N];
            if base64_decode(val.as_bytes(), &mut buf)? != N {
                // The private key was of the wrong size.
                return Err(());
            }

            Ok(buf)
        }

        // The first line should specify the key format.
        let (_, _, data) = parse_dns_pair(data)?
            .filter(|&(k, v, _)| (k, v) == ("Private-key-format", "v1.2"))
            .ok_or(())?;

        // The second line should specify the algorithm.
        let (_, val, data) = parse_dns_pair(data)?
            .filter(|&(k, _, _)| k == "Algorithm")
            .ok_or(())?;

        // Parse the algorithm.
        let mut words = val.split_ascii_whitespace();
        let code = words.next().ok_or(())?.parse::<u8>().map_err(|_| ())?;
        let name = words.next().ok_or(())?;

        match (code, name) {
            (8, "(RSASHA256)") => RsaKey::from_dns(data).map(Self::RsaSha256),
            (13, "(ECDSAP256SHA256)") => {
                parse_pkey(data).map(Self::EcdsaP256Sha256)
            }
            (14, "(ECDSAP384SHA384)") => {
                parse_pkey(data).map(Self::EcdsaP384Sha384)
            }
            (15, "(ED25519)") => parse_pkey(data).map(Self::Ed25519),
            (16, "(ED448)") => parse_pkey(data).map(Self::Ed448),
            _ => Err(()),
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
    /// See RFC 5702, section 6 for examples of this format.
    pub fn into_dns(&self, w: &mut impl fmt::Write) -> fmt::Result {
        w.write_str("Modulus:\t")?;
        base64_encode(self.n.as_ref(), &mut *w)?;
        w.write_str("\nPublicExponent:\t")?;
        base64_encode(self.e.as_ref(), &mut *w)?;
        w.write_str("\nPrivateExponent:\t")?;
        base64_encode(self.d.as_ref(), &mut *w)?;
        w.write_str("\nPrime1:\t")?;
        base64_encode(self.p.as_ref(), &mut *w)?;
        w.write_str("\nPrime2:\t")?;
        base64_encode(self.q.as_ref(), &mut *w)?;
        w.write_str("\nExponent1:\t")?;
        base64_encode(self.d_p.as_ref(), &mut *w)?;
        w.write_str("\nExponent2:\t")?;
        base64_encode(self.d_q.as_ref(), &mut *w)?;
        w.write_str("\nCoefficient:\t")?;
        base64_encode(self.q_i.as_ref(), &mut *w)?;
        w.write_char('\n')
    }

    /// Parse a key from the conventional DNS format.
    ///
    /// See RFC 5702, section 6.
    pub fn from_dns(mut data: &str) -> Result<Self, ()>
    where
        B: From<Vec<u8>>,
    {
        let mut n = None;
        let mut e = None;
        let mut d = None;
        let mut p = None;
        let mut q = None;
        let mut d_p = None;
        let mut d_q = None;
        let mut q_i = None;

        while let Some((key, val, rest)) = parse_dns_pair(data)? {
            let field = match key {
                "Modulus" => &mut n,
                "PublicExponent" => &mut e,
                "PrivateExponent" => &mut d,
                "Prime1" => &mut p,
                "Prime2" => &mut q,
                "Exponent1" => &mut d_p,
                "Exponent2" => &mut d_q,
                "Coefficient" => &mut q_i,
                _ => return Err(()),
            };

            if field.is_some() {
                // This field has already been filled.
                return Err(());
            }

            let mut buffer = vec![0u8; (val.len() + 3) / 4 * 3];
            let size = base64_decode(val.as_bytes(), &mut buffer)?;
            buffer.truncate(size);

            *field = Some(buffer.into());
            data = rest;
        }

        for field in [&n, &e, &d, &p, &q, &d_p, &d_q, &q_i] {
            if field.is_none() {
                // A field was missing.
                return Err(());
            }
        }

        Ok(Self {
            n: n.unwrap(),
            e: e.unwrap(),
            d: d.unwrap(),
            p: p.unwrap(),
            q: q.unwrap(),
            d_p: d_p.unwrap(),
            d_q: d_q.unwrap(),
            q_i: q_i.unwrap(),
        })
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

/// Extract the next key-value pair in a DNS private key file.
fn parse_dns_pair(data: &str) -> Result<Option<(&str, &str, &str)>, ()> {
    // Trim any pending newlines.
    let data = data.trim_ascii_start();

    // Get the first line (NOTE: CR LF is handled later).
    let (line, rest) = data.split_once('\n').unwrap_or((data, ""));

    // Split the line by a colon.
    let (key, val) = line.split_once(':').ok_or(())?;

    // Trim the key and value (incl. for CR LFs).
    Ok(Some((key.trim_ascii(), val.trim_ascii(), rest)))
}

/// A utility function to format data as Base64.
///
/// This is a simple implementation with the only requirement of being
/// constant-time and side-channel resistant.
fn base64_encode(data: &[u8], w: &mut impl fmt::Write) -> fmt::Result {
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
            - (digits & bcast) * (52 - b'0') as u32
            - (pluses & bcast) * (62 - b'+') as u32
            - (slashs & bcast) * (63 - b'/') as u32;

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
        _ => unreachable!(),
    }
    let chunk = str::from_utf8(&chunk).unwrap();
    w.write_str(chunk)
}

/// A utility function to decode Base64 data.
///
/// This is a simple implementation with the only requirement of being
/// constant-time and side-channel resistant.
///
/// Incorrect padding or garbage bytes will result in an error.
fn base64_decode(encoded: &[u8], decoded: &mut [u8]) -> Result<usize, ()> {
    /// Decode a single chunk of bytes from Base64.
    fn decode(data: [u8; 4]) -> Result<[u8; 3], ()> {
        let chunk = u32::from_be_bytes(data);
        let bcast = 0x01010101u32;

        // Mask out non-ASCII bytes early.
        if chunk & 0x80808080 != 0 {
            return Err(());
        }

        // Classify each byte as A-Z, a-z, 0-9, + or /.
        let uppers = chunk + (128 - b'A' as u32) * bcast;
        let lowers = chunk + (128 - b'a' as u32) * bcast;
        let digits = chunk + (128 - b'0' as u32) * bcast;
        let pluses = chunk + (128 - b'+' as u32) * bcast;
        let slashs = chunk + (128 - b'/' as u32) * bcast;

        // For each byte, the LSB is set if it is in the class.
        let uppers = (uppers ^ (uppers - bcast * 26)) >> 7;
        let lowers = (lowers ^ (lowers - bcast * 26)) >> 7;
        let digits = (digits ^ (digits - bcast * 10)) >> 7;
        let pluses = (pluses ^ (pluses - bcast)) >> 7;
        let slashs = (slashs ^ (slashs - bcast)) >> 7;

        // Check if an input was in none of the classes.
        if bcast & !(uppers | lowers | digits | pluses | slashs) != 0 {
            return Err(());
        }

        // Subtract the corresponding offset for each class.
        let chunk = chunk
            - (uppers & bcast) * (b'A' - 0) as u32
            - (lowers & bcast) * (b'a' - 26) as u32
            + (digits & bcast) * (52 - b'0') as u32
            + (pluses & bcast) * (62 - b'+') as u32
            + (slashs & bcast) * (63 - b'/') as u32;

        // Compress the chunk using integer operations.
        // (0b00XXXXXXu8, 0b00XXXXXXu8, 0b00XXXXXXu8, 0b00XXXXXXu8)
        let chunk = (chunk & 0x3F003F00) >> 2 | (chunk & 0x003F003F);
        // (0b0000XXXX_XXXXXXXXu16, 0b0000XXXX_XXXXXXXXu16)
        let chunk = (chunk & 0x0FFF0000) >> 4 | (chunk & 0x00000FFF);
        // 0b00000000_XXXXXXXX_XXXXXXXX_XXXXXXXXu32
        let [_, a, b, c] = chunk.to_be_bytes();

        Ok([a, b, c])
    }

    // Uneven inputs are not allowed; use padding.
    if encoded.len() % 4 != 0 {
        return Err(());
    }

    // The index into the decoded buffer.
    let mut index = 0usize;

    // Iterate over the whole chunks in the input.
    // TODO: Use 'slice::array_chunks()' or 'slice::as_chunks()'.
    for chunk in encoded.chunks_exact(4) {
        let mut chunk = <[u8; 4]>::try_from(chunk).unwrap();

        // Check for padding.
        let ppos = chunk.iter().position(|&b| b == b'=').unwrap_or(4);
        if chunk[ppos..].iter().any(|&b| b != b'=') {
            // A padding byte was followed by a non-padding byte.
            return Err(());
        }

        // Mask out the padding for the main decoder.
        chunk[ppos..].fill(b'A');

        // Determine how many output bytes there are.
        let amount = match ppos {
            0 | 1 => return Err(()),
            2 => 1,
            3 => 2,
            4 => 3,
            _ => unreachable!(),
        };

        if index + amount >= decoded.len() {
            // The input was too long, or the output was too short.
            return Err(());
        }

        // Decode the chunk and write the unpadded amount.
        let chunk = decode(chunk)?;
        decoded[index..][..amount].copy_from_slice(&chunk[..amount]);
        index += amount;
    }

    Ok(index)
}
