use core::{fmt, mem, str};

use std::vec::Vec;

use crate::base::iana::SecAlg;
use crate::rdata::Dnskey;
use crate::utils::base64;

/// A generic secret key.
///
/// This type cannot be used for computing signatures, as it does not implement
/// any cryptographic primitives.  Instead, it is a generic representation that
/// can be imported/exported or converted into a [`Sign`] (if the underlying
/// cryptographic implementation supports it).
///
/// [`Sign`]: super::Sign
pub enum SecretKey<B: AsRef<[u8]> + AsMut<[u8]>> {
    /// An RSA/SHA256 keypair.
    RsaSha256(RsaSecretKey<B>),

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

impl<B: AsRef<[u8]> + AsMut<[u8]>> SecretKey<B> {
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
        w.write_str("Private-key-format: v1.2\n")?;
        match self {
            Self::RsaSha256(k) => {
                w.write_str("Algorithm: 8 (RSASHA256)\n")?;
                k.into_dns(w)
            }

            Self::EcdsaP256Sha256(s) => {
                w.write_str("Algorithm: 13 (ECDSAP256SHA256)\n")?;
                writeln!(w, "PrivateKey: {}", base64::encode_display(s))
            }

            Self::EcdsaP384Sha384(s) => {
                w.write_str("Algorithm: 14 (ECDSAP384SHA384)\n")?;
                writeln!(w, "PrivateKey: {}", base64::encode_display(s))
            }

            Self::Ed25519(s) => {
                w.write_str("Algorithm: 15 (ED25519)\n")?;
                writeln!(w, "PrivateKey: {}", base64::encode_display(s))
            }

            Self::Ed448(s) => {
                w.write_str("Algorithm: 16 (ED448)\n")?;
                writeln!(w, "PrivateKey: {}", base64::encode_display(s))
            }
        }
    }

    /// Parse a key from the conventional DNS format.
    ///
    /// - For RSA, see RFC 5702, section 6.
    /// - For ECDSA, see RFC 6605, section 6.
    /// - For EdDSA, see RFC 8080, section 6.
    pub fn from_dns(data: &str) -> Result<Self, DnsFormatError>
    where
        B: From<Vec<u8>>,
    {
        /// Parse private keys for most algorithms (except RSA).
        fn parse_pkey<const N: usize>(
            data: &str,
        ) -> Result<[u8; N], DnsFormatError> {
            // Extract the 'PrivateKey' field.
            let (_, val, data) = parse_dns_pair(data)?
                .filter(|&(k, _, _)| k == "PrivateKey")
                .ok_or(DnsFormatError::Misformatted)?;

            if !data.trim().is_empty() {
                // There were more fields following.
                return Err(DnsFormatError::Misformatted);
            }

            let buf: Vec<u8> = base64::decode(val)
                .map_err(|_| DnsFormatError::Misformatted)?;
            let buf = buf
                .as_slice()
                .try_into()
                .map_err(|_| DnsFormatError::Misformatted)?;

            Ok(buf)
        }

        // The first line should specify the key format.
        let (_, _, data) = parse_dns_pair(data)?
            .filter(|&(k, v, _)| (k, v) == ("Private-key-format", "v1.2"))
            .ok_or(DnsFormatError::UnsupportedFormat)?;

        // The second line should specify the algorithm.
        let (_, val, data) = parse_dns_pair(data)?
            .filter(|&(k, _, _)| k == "Algorithm")
            .ok_or(DnsFormatError::Misformatted)?;

        // Parse the algorithm.
        let mut words = val.split_whitespace();
        let code = words
            .next()
            .ok_or(DnsFormatError::Misformatted)?
            .parse::<u8>()
            .map_err(|_| DnsFormatError::Misformatted)?;
        let name = words.next().ok_or(DnsFormatError::Misformatted)?;
        if words.next().is_some() {
            return Err(DnsFormatError::Misformatted);
        }

        match (code, name) {
            (8, "(RSASHA256)") => {
                RsaSecretKey::from_dns(data).map(Self::RsaSha256)
            }
            (13, "(ECDSAP256SHA256)") => {
                parse_pkey(data).map(Self::EcdsaP256Sha256)
            }
            (14, "(ECDSAP384SHA384)") => {
                parse_pkey(data).map(Self::EcdsaP384Sha384)
            }
            (15, "(ED25519)") => parse_pkey(data).map(Self::Ed25519),
            (16, "(ED448)") => parse_pkey(data).map(Self::Ed448),
            _ => Err(DnsFormatError::UnsupportedAlgorithm),
        }
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> Drop for SecretKey<B> {
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

/// A generic RSA private key.
///
/// All fields here are arbitrary-precision integers in big-endian format,
/// without any leading zero bytes.
pub struct RsaSecretKey<B: AsRef<[u8]> + AsMut<[u8]>> {
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

impl<B: AsRef<[u8]> + AsMut<[u8]>> RsaSecretKey<B> {
    /// Serialize this key in the conventional DNS format.
    ///
    /// The output does not include an 'Algorithm' specifier.
    ///
    /// See RFC 5702, section 6 for examples of this format.
    pub fn into_dns(&self, w: &mut impl fmt::Write) -> fmt::Result {
        w.write_str("Modulus: ")?;
        write!(w, "{}", base64::encode_display(&self.n))?;
        w.write_str("\nPublicExponent: ")?;
        write!(w, "{}", base64::encode_display(&self.e))?;
        w.write_str("\nPrivateExponent: ")?;
        write!(w, "{}", base64::encode_display(&self.d))?;
        w.write_str("\nPrime1: ")?;
        write!(w, "{}", base64::encode_display(&self.p))?;
        w.write_str("\nPrime2: ")?;
        write!(w, "{}", base64::encode_display(&self.q))?;
        w.write_str("\nExponent1: ")?;
        write!(w, "{}", base64::encode_display(&self.d_p))?;
        w.write_str("\nExponent2: ")?;
        write!(w, "{}", base64::encode_display(&self.d_q))?;
        w.write_str("\nCoefficient: ")?;
        write!(w, "{}", base64::encode_display(&self.q_i))?;
        w.write_char('\n')
    }

    /// Parse a key from the conventional DNS format.
    ///
    /// See RFC 5702, section 6.
    pub fn from_dns(mut data: &str) -> Result<Self, DnsFormatError>
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
                _ => return Err(DnsFormatError::Misformatted),
            };

            if field.is_some() {
                // This field has already been filled.
                return Err(DnsFormatError::Misformatted);
            }

            let buffer: Vec<u8> = base64::decode(val)
                .map_err(|_| DnsFormatError::Misformatted)?;

            *field = Some(buffer.into());
            data = rest;
        }

        for field in [&n, &e, &d, &p, &q, &d_p, &d_q, &q_i] {
            if field.is_none() {
                // A field was missing.
                return Err(DnsFormatError::Misformatted);
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

impl<B: AsRef<[u8]> + AsMut<[u8]>> Drop for RsaSecretKey<B> {
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

/// A generic public key.
pub enum PublicKey<B: AsRef<[u8]>> {
    /// An RSA/SHA-1 public key.
    RsaSha1(RsaPublicKey<B>),

    // TODO: RSA/SHA-1 with NSEC3/SHA-1?
    /// An RSA/SHA-256 public key.
    RsaSha256(RsaPublicKey<B>),

    /// An RSA/SHA-512 public key.
    RsaSha512(RsaPublicKey<B>),

    /// An ECDSA P-256/SHA-256 public key.
    ///
    /// The public key is stored in uncompressed format:
    ///
    /// - A single byte containing the value 0x04.
    /// - The encoding of the `x` coordinate (32 bytes).
    /// - The encoding of the `y` coordinate (32 bytes).
    EcdsaP256Sha256([u8; 65]),

    /// An ECDSA P-384/SHA-384 public key.
    ///
    /// The public key is stored in uncompressed format:
    ///
    /// - A single byte containing the value 0x04.
    /// - The encoding of the `x` coordinate (48 bytes).
    /// - The encoding of the `y` coordinate (48 bytes).
    EcdsaP384Sha384([u8; 97]),

    /// An Ed25519 public key.
    ///
    /// The public key is a 32-byte encoding of the public point.
    Ed25519([u8; 32]),

    /// An Ed448 public key.
    ///
    /// The public key is a 57-byte encoding of the public point.
    Ed448([u8; 57]),
}

impl<B: AsRef<[u8]>> PublicKey<B> {
    /// The algorithm used by this key.
    pub fn algorithm(&self) -> SecAlg {
        match self {
            Self::RsaSha1(_) => SecAlg::RSASHA1,
            Self::RsaSha256(_) => SecAlg::RSASHA256,
            Self::RsaSha512(_) => SecAlg::RSASHA512,
            Self::EcdsaP256Sha256(_) => SecAlg::ECDSAP256SHA256,
            Self::EcdsaP384Sha384(_) => SecAlg::ECDSAP384SHA384,
            Self::Ed25519(_) => SecAlg::ED25519,
            Self::Ed448(_) => SecAlg::ED448,
        }
    }

    /// Construct a DNSKEY record with the given flags.
    pub fn into_dns<Octs>(self, flags: u16) -> Dnskey<Octs>
    where
        Octs: From<Vec<u8>> + AsRef<[u8]>,
    {
        let protocol = 3u8;
        let algorithm = self.algorithm();
        let public_key = match self {
            Self::RsaSha1(k) | Self::RsaSha256(k) | Self::RsaSha512(k) => {
                let (n, e) = (k.n.as_ref(), k.e.as_ref());
                let e_len_len = if e.len() < 256 { 1 } else { 3 };
                let len = e_len_len + e.len() + n.len();
                let mut buf = Vec::with_capacity(len);
                if let Ok(e_len) = u8::try_from(e.len()) {
                    buf.push(e_len);
                } else {
                    // RFC 3110 is not explicit about the endianness of this,
                    // but 'ldns' (in 'ldns_key_buf2rsa_raw()') uses network
                    // byte order, which I suppose makes sense.
                    let e_len = u16::try_from(e.len()).unwrap();
                    buf.extend_from_slice(&e_len.to_be_bytes());
                }
                buf.extend_from_slice(e);
                buf.extend_from_slice(n);
                buf
            }

            // From my reading of RFC 6605, the marker byte is not included.
            Self::EcdsaP256Sha256(k) => k[1..].to_vec(),
            Self::EcdsaP384Sha384(k) => k[1..].to_vec(),

            Self::Ed25519(k) => k.to_vec(),
            Self::Ed448(k) => k.to_vec(),
        };

        Dnskey::new(flags, protocol, algorithm, public_key.into()).unwrap()
    }
}

/// A generic RSA public key.
///
/// All fields here are arbitrary-precision integers in big-endian format,
/// without any leading zero bytes.
pub struct RsaPublicKey<B: AsRef<[u8]>> {
    /// The public modulus.
    pub n: B,

    /// The public exponent.
    pub e: B,
}

impl<B> From<RsaSecretKey<B>> for RsaPublicKey<B>
where
    B: AsRef<[u8]> + AsMut<[u8]> + Default,
{
    fn from(mut value: RsaSecretKey<B>) -> Self {
        Self {
            n: mem::take(&mut value.n),
            e: mem::take(&mut value.e),
        }
    }
}

/// Extract the next key-value pair in a DNS private key file.
fn parse_dns_pair(
    data: &str,
) -> Result<Option<(&str, &str, &str)>, DnsFormatError> {
    // TODO: Use 'trim_ascii_start()' etc. once they pass the MSRV.

    // Trim any pending newlines.
    let data = data.trim_start();

    // Stop if there's no more data.
    if data.is_empty() {
        return Ok(None);
    }

    // Get the first line (NOTE: CR LF is handled later).
    let (line, rest) = data.split_once('\n').unwrap_or((data, ""));

    // Split the line by a colon.
    let (key, val) =
        line.split_once(':').ok_or(DnsFormatError::Misformatted)?;

    // Trim the key and value (incl. for CR LFs).
    Ok(Some((key.trim(), val.trim(), rest)))
}

/// An error in loading a [`SecretKey`] from the conventional DNS format.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DnsFormatError {
    /// The key file uses an unsupported version of the format.
    UnsupportedFormat,

    /// The key file did not follow the DNS format correctly.
    Misformatted,

    /// The key file used an unsupported algorithm.
    UnsupportedAlgorithm,
}

impl fmt::Display for DnsFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedFormat => "unsupported format",
            Self::Misformatted => "misformatted key file",
            Self::UnsupportedAlgorithm => "unsupported algorithm",
        })
    }
}

impl std::error::Error for DnsFormatError {}

#[cfg(test)]
mod tests {
    use std::{string::String, vec::Vec};

    use crate::base::iana::SecAlg;

    const KEYS: &[(SecAlg, u16)] = &[
        (SecAlg::RSASHA256, 27096),
        (SecAlg::ECDSAP256SHA256, 40436),
        (SecAlg::ECDSAP384SHA384, 17013),
        (SecAlg::ED25519, 43769),
        (SecAlg::ED448, 34114),
    ];

    #[test]
    fn secret_from_dns() {
        for &(algorithm, key_tag) in KEYS {
            let name = format!("test.+{:03}+{}", algorithm.to_int(), key_tag);
            let path = format!("test-data/dnssec-keys/K{}.private", name);
            let data = std::fs::read_to_string(path).unwrap();
            let key = super::SecretKey::<Vec<u8>>::from_dns(&data).unwrap();
            assert_eq!(key.algorithm(), algorithm);
        }
    }

    #[test]
    fn secret_roundtrip() {
        for &(algorithm, key_tag) in KEYS {
            let name = format!("test.+{:03}+{}", algorithm.to_int(), key_tag);
            let path = format!("test-data/dnssec-keys/K{}.private", name);
            let data = std::fs::read_to_string(path).unwrap();
            let key = super::SecretKey::<Vec<u8>>::from_dns(&data).unwrap();
            let mut same = String::new();
            key.into_dns(&mut same).unwrap();
            assert_eq!(data, same);
        }
    }
}
