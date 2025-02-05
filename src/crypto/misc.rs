use crate::base::iana::{Class, DigestAlg, SecAlg};
use crate::base::scan::{IterScanner, Scanner};
use crate::base::wire::Composer;
use crate::base::zonefile_fmt::{DisplayKind, ZonefileFmt};
use crate::base::{Name, Rtype};
use crate::dep::octseq::{EmptyBuilder, FromBuilder};
use crate::dnssec::sign::error::SignError;
use crate::rdata::{Dnskey, Ds};

use std::boxed::Box;
use std::vec::Vec;
use std::{error, fmt};

//----------- SignRaw --------------------------------------------------------

/// Low-level signing functionality.
///
/// Types that implement this trait own a private key and can sign arbitrary
/// information (in the form of slices of bytes).
///
/// Implementing types should validate keys during construction, so that
/// signing does not fail due to invalid keys.  If the implementing type
/// allows [`sign_raw()`] to be called on unvalidated keys, it will have to
/// check the validity of the key for every signature; this is unnecessary
/// overhead when many signatures have to be generated.
///
/// [`sign_raw()`]: SignRaw::sign_raw()
pub trait SignRaw {
    /// The signature algorithm used.
    ///
    /// See [RFC 8624, section 3.1] for IETF implementation recommendations.
    ///
    /// [RFC 8624, section 3.1]: https://datatracker.ietf.org/doc/html/rfc8624#section-3.1
    fn algorithm(&self) -> SecAlg;

    /// The raw public key.
    ///
    /// This can be used to verify produced signatures.  It must use the same
    /// algorithm as returned by [`algorithm()`].
    ///
    /// [`algorithm()`]: Self::algorithm()
    fn raw_public_key(&self) -> PublicKeyBytes;

    /// Sign the given bytes.
    ///
    /// # Errors
    ///
    /// See [`SignError`] for a discussion of possible failure cases.  To the
    /// greatest extent possible, the implementation should check for failure
    /// cases beforehand and prevent them (e.g. when the keypair is created).
    fn sign_raw(&self, data: &[u8]) -> Result<Signature, SignError>;
}

//----------- PublicKeyBytes -------------------------------------------------

/// A low-level public key.
#[derive(Clone, Debug)]
pub enum PublicKeyBytes {
    /// An RSA/SHA-1 public key.
    RsaSha1(RsaPublicKeyBytes),

    /// An RSA/SHA-1 with NSEC3 public key.
    RsaSha1Nsec3Sha1(RsaPublicKeyBytes),

    /// An RSA/SHA-256 public key.
    RsaSha256(RsaPublicKeyBytes),

    /// An RSA/SHA-512 public key.
    RsaSha512(RsaPublicKeyBytes),

    /// An ECDSA P-256/SHA-256 public key.
    ///
    /// The public key is stored in uncompressed format:
    ///
    /// - A single byte containing the value 0x04.
    /// - The encoding of the `x` coordinate (32 bytes).
    /// - The encoding of the `y` coordinate (32 bytes).
    EcdsaP256Sha256(Box<[u8; 65]>),

    /// An ECDSA P-384/SHA-384 public key.
    ///
    /// The public key is stored in uncompressed format:
    ///
    /// - A single byte containing the value 0x04.
    /// - The encoding of the `x` coordinate (48 bytes).
    /// - The encoding of the `y` coordinate (48 bytes).
    EcdsaP384Sha384(Box<[u8; 97]>),

    /// An Ed25519 public key.
    ///
    /// The public key is a 32-byte encoding of the public point.
    Ed25519(Box<[u8; 32]>),

    /// An Ed448 public key.
    ///
    /// The public key is a 57-byte encoding of the public point.
    Ed448(Box<[u8; 57]>),
}

//--- Inspection

impl PublicKeyBytes {
    /// The algorithm used by this key.
    pub fn algorithm(&self) -> SecAlg {
        match self {
            Self::RsaSha1(_) => SecAlg::RSASHA1,
            Self::RsaSha1Nsec3Sha1(_) => SecAlg::RSASHA1_NSEC3_SHA1,
            Self::RsaSha256(_) => SecAlg::RSASHA256,
            Self::RsaSha512(_) => SecAlg::RSASHA512,
            Self::EcdsaP256Sha256(_) => SecAlg::ECDSAP256SHA256,
            Self::EcdsaP384Sha384(_) => SecAlg::ECDSAP384SHA384,
            Self::Ed25519(_) => SecAlg::ED25519,
            Self::Ed448(_) => SecAlg::ED448,
        }
    }

    /// The size of this key, in bits.
    ///
    /// For RSA keys, this measures the size of the public modulus.  For all
    /// other algorithms, it is the size of the fixed-width public key.
    pub fn key_size(&self) -> usize {
        match self {
            Self::RsaSha1(k)
            | Self::RsaSha1Nsec3Sha1(k)
            | Self::RsaSha256(k)
            | Self::RsaSha512(k) => k.key_size(),

            // ECDSA public keys have a marker byte and two points.
            Self::EcdsaP256Sha256(k) => (k.len() - 1) / 2 * 8,
            Self::EcdsaP384Sha384(k) => (k.len() - 1) / 2 * 8,

            // EdDSA public key sizes are measured in encoded form.
            Self::Ed25519(k) => k.len() * 8,
            Self::Ed448(k) => k.len() * 8,
        }
    }

    /// The raw key tag computation for this value.
    fn raw_key_tag(&self) -> u32 {
        fn compute(data: &[u8]) -> u32 {
            data.chunks(2)
                .map(|chunk| {
                    let mut buf = [0u8; 2];
                    // A 0 byte is appended for an incomplete chunk.
                    buf[..chunk.len()].copy_from_slice(chunk);
                    u16::from_be_bytes(buf) as u32
                })
                .sum()
        }

        match self {
            Self::RsaSha1(k)
            | Self::RsaSha1Nsec3Sha1(k)
            | Self::RsaSha256(k)
            | Self::RsaSha512(k) => k.raw_key_tag(),

            Self::EcdsaP256Sha256(k) => compute(&k[1..]),
            Self::EcdsaP384Sha384(k) => compute(&k[1..]),
            Self::Ed25519(k) => compute(&**k),
            Self::Ed448(k) => compute(&**k),
        }
    }

    /// Compute a digest of this public key.
    fn digest(&self, context: &mut ::ring::digest::Context) {
        match self {
            Self::RsaSha1(k)
            | Self::RsaSha1Nsec3Sha1(k)
            | Self::RsaSha256(k)
            | Self::RsaSha512(k) => k.digest(context),

            Self::EcdsaP256Sha256(k) => context.update(&k[1..]),
            Self::EcdsaP384Sha384(k) => context.update(&k[1..]),
            Self::Ed25519(k) => context.update(&**k),
            Self::Ed448(k) => context.update(&**k),
        }
    }
}

//--- Conversion to and from DNSKEYs

impl PublicKeyBytes {
    /// Parse a public key as stored in a DNSKEY record.
    pub fn from_dnskey_format(
        algorithm: SecAlg,
        data: &[u8],
    ) -> Result<Self, FromDnskeyError> {
        match algorithm {
            SecAlg::RSASHA1 => {
                RsaPublicKeyBytes::from_dnskey_format(data).map(Self::RsaSha1)
            }
            SecAlg::RSASHA1_NSEC3_SHA1 => {
                RsaPublicKeyBytes::from_dnskey_format(data)
                    .map(Self::RsaSha1Nsec3Sha1)
            }
            SecAlg::RSASHA256 => RsaPublicKeyBytes::from_dnskey_format(data)
                .map(Self::RsaSha256),
            SecAlg::RSASHA512 => RsaPublicKeyBytes::from_dnskey_format(data)
                .map(Self::RsaSha512),

            SecAlg::ECDSAP256SHA256 => {
                let mut key = Box::new([0u8; 65]);
                if key.len() == 1 + data.len() {
                    key[0] = 0x04;
                    key[1..].copy_from_slice(data);
                    Ok(Self::EcdsaP256Sha256(key))
                } else {
                    Err(FromDnskeyError::InvalidKey)
                }
            }
            SecAlg::ECDSAP384SHA384 => {
                let mut key = Box::new([0u8; 97]);
                if key.len() == 1 + data.len() {
                    key[0] = 0x04;
                    key[1..].copy_from_slice(data);
                    Ok(Self::EcdsaP384Sha384(key))
                } else {
                    Err(FromDnskeyError::InvalidKey)
                }
            }

            SecAlg::ED25519 => Box::<[u8]>::from(data)
                .try_into()
                .map(Self::Ed25519)
                .map_err(|_| FromDnskeyError::InvalidKey),
            SecAlg::ED448 => Box::<[u8]>::from(data)
                .try_into()
                .map(Self::Ed448)
                .map_err(|_| FromDnskeyError::InvalidKey),

            _ => Err(FromDnskeyError::UnsupportedAlgorithm),
        }
    }

    /// Serialize this public key as stored in a DNSKEY record.
    pub fn to_dnskey_format(&self) -> Box<[u8]> {
        match self {
            Self::RsaSha1(k)
            | Self::RsaSha1Nsec3Sha1(k)
            | Self::RsaSha256(k)
            | Self::RsaSha512(k) => k.to_dnskey_format(),

            // From my reading of RFC 6605, the marker byte is not included.
            Self::EcdsaP256Sha256(k) => k[1..].into(),
            Self::EcdsaP384Sha384(k) => k[1..].into(),

            Self::Ed25519(k) => k.as_slice().into(),
            Self::Ed448(k) => k.as_slice().into(),
        }
    }
}

//--- Comparison

impl PartialEq for PublicKeyBytes {
    fn eq(&self, other: &Self) -> bool {
        use ::ring::constant_time::verify_slices_are_equal;

        match (self, other) {
            (Self::RsaSha1(a), Self::RsaSha1(b)) => a == b,
            (Self::RsaSha1Nsec3Sha1(a), Self::RsaSha1Nsec3Sha1(b)) => a == b,
            (Self::RsaSha256(a), Self::RsaSha256(b)) => a == b,
            (Self::RsaSha512(a), Self::RsaSha512(b)) => a == b,
            (Self::EcdsaP256Sha256(a), Self::EcdsaP256Sha256(b)) => {
                verify_slices_are_equal(&**a, &**b).is_ok()
            }
            (Self::EcdsaP384Sha384(a), Self::EcdsaP384Sha384(b)) => {
                verify_slices_are_equal(&**a, &**b).is_ok()
            }
            (Self::Ed25519(a), Self::Ed25519(b)) => {
                verify_slices_are_equal(&**a, &**b).is_ok()
            }
            (Self::Ed448(a), Self::Ed448(b)) => {
                verify_slices_are_equal(&**a, &**b).is_ok()
            }
            _ => false,
        }
    }
}

impl Eq for PublicKeyBytes {}

//----------- RsaPublicKeyBytes ----------------------------------------------

/// A generic RSA public key.
///
/// All fields here are arbitrary-precision integers in big-endian format,
/// without any leading zero bytes.
#[derive(Clone, Debug)]
pub struct RsaPublicKeyBytes {
    /// The public modulus.
    pub n: Box<[u8]>,

    /// The public exponent.
    pub e: Box<[u8]>,
}

//--- Inspection

impl RsaPublicKeyBytes {
    /// The size of the public modulus, in bits.
    pub fn key_size(&self) -> usize {
        self.n.len() * 8 - self.n[0].leading_zeros() as usize
    }

    /// The raw key tag computation for this value.
    fn raw_key_tag(&self) -> u32 {
        let mut res = 0u32;

        // Extended exponent lengths start with '00 (exp_len >> 8)', which is
        // just zero for shorter exponents.  That doesn't affect the result,
        // so let's just do it unconditionally.
        res += (self.e.len() >> 8) as u32;
        res += u16::from_be_bytes([self.e.len() as u8, self.e[0]]) as u32;

        let mut chunks = self.e[1..].chunks_exact(2);
        res += chunks
            .by_ref()
            .map(|chunk| u16::from_be_bytes(chunk.try_into().unwrap()) as u32)
            .sum::<u32>();

        let n = if !chunks.remainder().is_empty() {
            res +=
                u16::from_be_bytes([chunks.remainder()[0], self.n[0]]) as u32;
            &self.n[1..]
        } else {
            &self.n
        };

        res += n
            .chunks(2)
            .map(|chunk| {
                let mut buf = [0u8; 2];
                buf[..chunk.len()].copy_from_slice(chunk);
                u16::from_be_bytes(buf) as u32
            })
            .sum::<u32>();

        res
    }

    /// Compute a digest of this public key.
    fn digest(&self, context: &mut ::ring::digest::Context) {
        // Encode the exponent length.
        if let Ok(exp_len) = u8::try_from(self.e.len()) {
            context.update(&[exp_len]);
        } else if let Ok(exp_len) = u16::try_from(self.e.len()) {
            context.update(&[0u8, (exp_len >> 8) as u8, exp_len as u8]);
        } else {
            unreachable!("RSA exponents are (much) shorter than 64KiB")
        }

        context.update(&self.e);
        context.update(&self.n);
    }
}

//--- Conversion to and from DNSKEYs

impl RsaPublicKeyBytes {
    /// Parse an RSA public key as stored in a DNSKEY record.
    pub fn from_dnskey_format(data: &[u8]) -> Result<Self, FromDnskeyError> {
        if data.len() < 3 {
            return Err(FromDnskeyError::InvalidKey);
        }

        // The exponent length is encoded as 1 or 3 bytes.
        let (exp_len, off) = if data[0] != 0 {
            (data[0] as usize, 1)
        } else if data[1..3] != [0, 0] {
            // NOTE: Even though this is the extended encoding of the length,
            // a user could choose to put a length less than 256 over here.
            let exp_len = u16::from_be_bytes(data[1..3].try_into().unwrap());
            (exp_len as usize, 3)
        } else {
            // The extended encoding of the length just held a zero value.
            return Err(FromDnskeyError::InvalidKey);
        };

        // NOTE: off <= 3 so is safe to index up to.
        let e: Box<[u8]> = data[off..]
            .get(..exp_len)
            .ok_or(FromDnskeyError::InvalidKey)?
            .into();

        // NOTE: The previous statement indexed up to 'exp_len'.
        let n: Box<[u8]> = data[off + exp_len..].into();

        // Empty values and leading zeros are not allowed.
        if e.is_empty() || n.is_empty() || e[0] == 0 || n[0] == 0 {
            return Err(FromDnskeyError::InvalidKey);
        }

        Ok(Self { n, e })
    }

    /// Serialize this public key as stored in a DNSKEY record.
    pub fn to_dnskey_format(&self) -> Box<[u8]> {
        let mut key = Vec::new();

        // Encode the exponent length.
        if let Ok(exp_len) = u8::try_from(self.e.len()) {
            key.reserve_exact(1 + self.e.len() + self.n.len());
            key.push(exp_len);
        } else if let Ok(exp_len) = u16::try_from(self.e.len()) {
            key.reserve_exact(3 + self.e.len() + self.n.len());
            key.push(0u8);
            key.extend(&exp_len.to_be_bytes());
        } else {
            unreachable!("RSA exponents are (much) shorter than 64KiB")
        }

        key.extend(&*self.e);
        key.extend(&*self.n);
        key.into_boxed_slice()
    }
}

//--- Comparison

impl PartialEq for RsaPublicKeyBytes {
    fn eq(&self, other: &Self) -> bool {
        use ::ring::constant_time::verify_slices_are_equal;

        verify_slices_are_equal(&self.n, &other.n).is_ok()
            && verify_slices_are_equal(&self.e, &other.e).is_ok()
    }
}

impl Eq for RsaPublicKeyBytes {}

//----------- Key ------------------------------------------------------------

/// A DNSSEC key for a particular zone.
///
/// # Serialization
///
/// Keys can be parsed from or written in the conventional format used by the
/// BIND name server.  This is a simplified version of the zonefile format.
///
/// In this format, a public key is a line-oriented text file.  Each line is
/// either blank (having only whitespace) or a single DNSKEY record in the
/// presentation format.  In either case, the line may end with a comment (an
/// ASCII semicolon followed by arbitrary content until the end of the line).
/// The file must contain a single DNSKEY record line.
///
/// The DNSKEY record line contains the following fields, separated by ASCII
/// whitespace:
///
/// - The owner name.  This is an absolute name ending with a dot.
/// - Optionally, the class of the record (usually `IN`).
/// - The record type (which must be `DNSKEY`).
/// - The DNSKEY record data, which has the following sub-fields:
///   - The key flags, which describe the key's uses.
///   - The protocol used (expected to be `3`).
///   - The key algorithm (see [`SecAlg`]).
///   - The public key encoded as a Base64 string.
#[derive(Clone)]
pub struct Key<Octs> {
    /// The owner of the key.
    owner: Name<Octs>,

    /// The flags associated with the key.
    ///
    /// These flags are stored in the DNSKEY record.
    flags: u16,

    /// The public key, in bytes.
    ///
    /// This identifies the key and can be used for signatures.
    key: PublicKeyBytes,
}

//--- Construction

impl<Octs> Key<Octs> {
    /// Construct a new DNSSEC key manually.
    pub fn new(owner: Name<Octs>, flags: u16, key: PublicKeyBytes) -> Self {
        Self { owner, flags, key }
    }
}

//--- Inspection

impl<Octs> Key<Octs> {
    /// The owner name attached to the key.
    pub fn owner(&self) -> &Name<Octs> {
        &self.owner
    }

    /// The flags attached to the key.
    pub fn flags(&self) -> u16 {
        self.flags
    }

    /// The raw public key.
    pub fn raw_public_key(&self) -> &PublicKeyBytes {
        &self.key
    }

    /// The signing algorithm used.
    pub fn algorithm(&self) -> SecAlg {
        self.key.algorithm()
    }

    /// The size of this key, in bits.
    pub fn key_size(&self) -> usize {
        self.key.key_size()
    }

    /// Whether this is a zone signing key.
    ///
    /// From [RFC 4034, section 2.1.1]:
    ///
    /// > Bit 7 of the Flags field is the Zone Key flag.  If bit 7 has value
    /// > 1, then the DNSKEY record holds a DNS zone key, and the DNSKEY RR's
    /// > owner name MUST be the name of a zone.  If bit 7 has value 0, then
    /// > the DNSKEY record holds some other type of DNS public key and MUST
    /// > NOT be used to verify RRSIGs that cover RRsets.
    ///
    /// [RFC 4034, section 2.1.1]: https://datatracker.ietf.org/doc/html/rfc4034#section-2.1.1
    pub fn is_zone_signing_key(&self) -> bool {
        self.flags & (1 << 8) != 0
    }

    /// Whether this key has been revoked.
    ///
    /// From [RFC 5011, section 3]:
    ///
    /// > Bit 8 of the DNSKEY Flags field is designated as the 'REVOKE' flag.
    /// > If this bit is set to '1', AND the resolver sees an RRSIG(DNSKEY)
    /// > signed by the associated key, then the resolver MUST consider this
    /// > key permanently invalid for all purposes except for validating the
    /// > revocation.
    ///
    /// [RFC 5011, section 3]: https://datatracker.ietf.org/doc/html/rfc5011#section-3
    pub fn is_revoked(&self) -> bool {
        self.flags & (1 << 7) != 0
    }

    /// Whether this is a secure entry point.
    ///
    /// From [RFC 4034, section 2.1.1]:
    ///
    /// > Bit 15 of the Flags field is the Secure Entry Point flag, described
    /// > in [RFC3757].  If bit 15 has value 1, then the DNSKEY record holds a
    /// > key intended for use as a secure entry point.  This flag is only
    /// > intended to be a hint to zone signing or debugging software as to
    /// > the intended use of this DNSKEY record; validators MUST NOT alter
    /// > their behavior during the signature validation process in any way
    /// > based on the setting of this bit.  This also means that a DNSKEY RR
    /// > with the SEP bit set would also need the Zone Key flag set in order
    /// > to be able to generate signatures legally.  A DNSKEY RR with the SEP
    /// > set and the Zone Key flag not set MUST NOT be used to verify RRSIGs
    /// > that cover RRsets.
    ///
    /// [RFC 4034, section 2.1.1]: https://datatracker.ietf.org/doc/html/rfc4034#section-2.1.1
    /// [RFC3757]: https://datatracker.ietf.org/doc/html/rfc3757
    pub fn is_secure_entry_point(&self) -> bool {
        self.flags & 1 != 0
    }

    /// The key tag.
    pub fn key_tag(&self) -> u16 {
        // NOTE: RSA/MD5 uses a different algorithm.

        // NOTE: A u32 can fit the sum of 65537 u16s without overflowing.  A
        //   key can never exceed 64KiB anyway, so we won't even get close to
        //   the limit.  Let's just add into a u32 and normalize it after.
        let mut res = 0u32;

        // Add basic DNSKEY fields.
        res += self.flags as u32;
        res += u16::from_be_bytes([3, self.algorithm().to_int()]) as u32;

        // Add the raw key tag from the public key.
        res += self.key.raw_key_tag();

        // Normalize and return the result.
        (res as u16).wrapping_add((res >> 16) as u16)
    }

    /// The digest of this key.
    pub fn digest(
        &self,
        algorithm: DigestAlg,
    ) -> Result<Ds<Box<[u8]>>, DigestError>
    where
        Octs: AsRef<[u8]>,
    {
        let mut context = ::ring::digest::Context::new(match algorithm {
            DigestAlg::SHA1 => &::ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
            DigestAlg::SHA256 => &::ring::digest::SHA256,
            DigestAlg::SHA384 => &::ring::digest::SHA384,
            _ => return Err(DigestError::UnsupportedAlgorithm),
        });

        // Add the owner name.
        if self
            .owner
            .as_slice()
            .iter()
            .any(|&b| b.is_ascii_uppercase())
        {
            let mut owner = [0u8; 256];
            owner[..self.owner.len()].copy_from_slice(self.owner.as_slice());
            owner.make_ascii_lowercase();
            context.update(&owner[..self.owner.len()]);
        } else {
            context.update(self.owner.as_slice());
        }

        // Add basic DNSKEY fields.
        context.update(&self.flags.to_be_bytes());
        context.update(&[3, self.algorithm().to_int()]);

        // Add the public key.
        self.key.digest(&mut context);

        // Finalize the digest.
        let digest = context.finish().as_ref().into();
        Ok(Ds::new(self.key_tag(), self.algorithm(), algorithm, digest)
            .unwrap())
    }
}

//--- Conversion to and from DNSKEYs

impl<Octs: AsRef<[u8]>> Key<Octs> {
    /// Deserialize a key from DNSKEY record data.
    ///
    /// # Errors
    ///
    /// Fails if the DNSKEY uses an unknown protocol or contains an invalid
    /// public key (e.g. one of the wrong size for the signature algorithm).
    pub fn from_dnskey(
        owner: Name<Octs>,
        dnskey: Dnskey<Octs>,
    ) -> Result<Self, FromDnskeyError> {
        if dnskey.protocol() != 3 {
            return Err(FromDnskeyError::UnsupportedProtocol);
        }

        let flags = dnskey.flags();
        let algorithm = dnskey.algorithm();
        let key = dnskey.public_key().as_ref();
        let key = PublicKeyBytes::from_dnskey_format(algorithm, key)?;
        Ok(Self { owner, flags, key })
    }

    /// Serialize the key into DNSKEY record data.
    ///
    /// The owner name can be combined with the returned record to serialize a
    /// complete DNS record if necessary.
    pub fn to_dnskey(&self) -> Dnskey<Box<[u8]>> {
        Dnskey::new(
            self.flags,
            3,
            self.key.algorithm(),
            self.key.to_dnskey_format(),
        )
        .expect("long public key")
    }

    /// Parse a DNSSEC key from the conventional format used by BIND.
    ///
    /// See the type-level documentation for a description of this format.
    pub fn parse_from_bind(data: &str) -> Result<Self, ParseDnskeyTextError>
    where
        Octs: FromBuilder,
        Octs::Builder: EmptyBuilder + Composer,
    {
        /// Find the next non-blank line in the file.
        fn next_line(mut data: &str) -> Option<(&str, &str)> {
            let mut line;
            while !data.is_empty() {
                (line, data) =
                    data.trim_start().split_once('\n').unwrap_or((data, ""));
                if !line.is_empty() && !line.starts_with(';') {
                    // We found a line that does not start with a comment.
                    line = line
                        .split_once(';')
                        .map_or(line, |(line, _)| line)
                        .trim_end();
                    return Some((line, data));
                }
            }

            None
        }

        // Ensure there is a single DNSKEY record line in the input.
        let (line, rest) =
            next_line(data).ok_or(ParseDnskeyTextError::Misformatted)?;
        if next_line(rest).is_some() {
            return Err(ParseDnskeyTextError::Misformatted);
        }

        // Parse the entire record.
        let mut scanner = IterScanner::new(line.split_ascii_whitespace());

        let name = scanner
            .scan_name()
            .map_err(|_| ParseDnskeyTextError::Misformatted)?;

        let _ = Class::scan(&mut scanner)
            .map_err(|_| ParseDnskeyTextError::Misformatted)?;

        if Rtype::scan(&mut scanner).map_or(true, |t| t != Rtype::DNSKEY) {
            return Err(ParseDnskeyTextError::Misformatted);
        }

        let data = Dnskey::scan(&mut scanner)
            .map_err(|_| ParseDnskeyTextError::Misformatted)?;

        Self::from_dnskey(name, data)
            .map_err(ParseDnskeyTextError::FromDnskey)
    }

    /// Serialize this key in the conventional format used by BIND.
    ///
    /// See the type-level documentation for a description of this format.
    pub fn format_as_bind(&self, mut w: impl fmt::Write) -> fmt::Result {
        writeln!(
            w,
            "{} IN DNSKEY {}",
            self.owner().fmt_with_dot(),
            self.to_dnskey().display_zonefile(DisplayKind::Simple),
        )
    }

    /// Display this key in the conventional format used by BIND.
    ///
    /// See the type-level documentation for a description of this format.
    pub fn display_as_bind(&self) -> impl fmt::Display + '_ {
        struct Display<'a, Octs>(&'a Key<Octs>);
        impl<Octs: AsRef<[u8]>> fmt::Display for Display<'_, Octs> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.format_as_bind(f)
            }
        }
        Display(self)
    }
}

//--- Comparison

impl<Octs: AsRef<[u8]>> PartialEq for Key<Octs> {
    fn eq(&self, other: &Self) -> bool {
        self.owner() == other.owner()
            && self.flags() == other.flags()
            && self.raw_public_key() == other.raw_public_key()
    }
}

//--- Debug

impl<Octs: AsRef<[u8]>> fmt::Debug for Key<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("owner", self.owner())
            .field("flags", &self.flags())
            .field("raw_public_key", self.raw_public_key())
            .finish()
    }
}

//----------- Signature ------------------------------------------------------

/// A cryptographic signature.
///
/// The format of the signature varies depending on the underlying algorithm:
///
/// - RSA: the signature is a single integer `s`, which is less than the key's
///   public modulus `n`.  `s` is encoded as bytes and ordered from most
///   significant to least significant digits.  It must be at least 64 bytes
///   long and at most 512 bytes long.  Leading zero bytes can be inserted for
///   padding.
///
///   See [RFC 3110](https://datatracker.ietf.org/doc/html/rfc3110).
///
/// - ECDSA: the signature has a fixed length (64 bytes for P-256, 96 for
///   P-384).  It is the concatenation of two fixed-length integers (`r` and
///   `s`, each of equal size).
///
///   See [RFC 6605](https://datatracker.ietf.org/doc/html/rfc6605) and [SEC 1
///   v2.0](https://www.secg.org/sec1-v2.pdf).
///
/// - EdDSA: the signature has a fixed length (64 bytes for ED25519, 114 bytes
///   for ED448).  It is the concatenation of two curve points (`R` and `S`)
///   that are encoded into bytes.
///
/// Signatures are too big to pass by value, so they are placed on the heap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signature {
    RsaSha1(Box<[u8]>),
    RsaSha1Nsec3Sha1(Box<[u8]>),
    RsaSha256(Box<[u8]>),
    RsaSha512(Box<[u8]>),
    EcdsaP256Sha256(Box<[u8; 64]>),
    EcdsaP384Sha384(Box<[u8; 96]>),
    Ed25519(Box<[u8; 64]>),
    Ed448(Box<[u8; 114]>),
}

impl Signature {
    /// The algorithm used to make the signature.
    pub fn algorithm(&self) -> SecAlg {
        match self {
            Self::RsaSha1(_) => SecAlg::RSASHA1,
            Self::RsaSha1Nsec3Sha1(_) => SecAlg::RSASHA1_NSEC3_SHA1,
            Self::RsaSha256(_) => SecAlg::RSASHA256,
            Self::RsaSha512(_) => SecAlg::RSASHA512,
            Self::EcdsaP256Sha256(_) => SecAlg::ECDSAP256SHA256,
            Self::EcdsaP384Sha384(_) => SecAlg::ECDSAP384SHA384,
            Self::Ed25519(_) => SecAlg::ED25519,
            Self::Ed448(_) => SecAlg::ED448,
        }
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::RsaSha1(s)
            | Self::RsaSha1Nsec3Sha1(s)
            | Self::RsaSha256(s)
            | Self::RsaSha512(s) => s,
            Self::EcdsaP256Sha256(s) => &**s,
            Self::EcdsaP384Sha384(s) => &**s,
            Self::Ed25519(s) => &**s,
            Self::Ed448(s) => &**s,
        }
    }
}

impl From<Signature> for Box<[u8]> {
    fn from(value: Signature) -> Self {
        match value {
            Signature::RsaSha1(s)
            | Signature::RsaSha1Nsec3Sha1(s)
            | Signature::RsaSha256(s)
            | Signature::RsaSha512(s) => s,
            Signature::EcdsaP256Sha256(s) => s as _,
            Signature::EcdsaP384Sha384(s) => s as _,
            Signature::Ed25519(s) => s as _,
            Signature::Ed448(s) => s as _,
        }
    }
}

//============ Error Types ===================================================

//----------- DigestError ----------------------------------------------------

/// An error when computing a digest.
#[derive(Clone, Debug)]
pub enum DigestError {
    UnsupportedAlgorithm,
}

//--- Display, Error

impl fmt::Display for DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedAlgorithm => "unsupported algorithm",
        })
    }
}

impl error::Error for DigestError {}

//----------- FromDnskeyError ------------------------------------------------

/// An error in reading a DNSKEY record.
#[derive(Clone, Debug)]
pub enum FromDnskeyError {
    UnsupportedAlgorithm,
    UnsupportedProtocol,
    InvalidKey,
}

//--- Display, Error

impl fmt::Display for FromDnskeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedAlgorithm => "unsupported algorithm",
            Self::UnsupportedProtocol => "unsupported protocol",
            Self::InvalidKey => "malformed key",
        })
    }
}

impl error::Error for FromDnskeyError {}

//----------- ParseDnskeyTextError -------------------------------------------

#[derive(Clone, Debug)]
pub enum ParseDnskeyTextError {
    Misformatted,
    FromDnskey(FromDnskeyError),
}

//--- Display, Error

impl fmt::Display for ParseDnskeyTextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Misformatted => "misformatted DNSKEY record",
            Self::FromDnskey(e) => return e.fmt(f),
        })
    }
}

impl error::Error for ParseDnskeyTextError {}

//============ Test ==========================================================

#[cfg(test)]
#[cfg(feature = "std")]
mod test {
    use super::*;
    use crate::base::iana::{Class, Rtype};
    use std::string::ToString;

    type Ds = crate::rdata::Ds<Vec<u8>>;

    const KEYS: &[(SecAlg, u16, usize)] = &[
        (SecAlg::RSASHA1, 439, 2048),
        (SecAlg::RSASHA1_NSEC3_SHA1, 22204, 2048),
        (SecAlg::RSASHA256, 60616, 2048),
        (SecAlg::ECDSAP256SHA256, 42253, 256),
        (SecAlg::ECDSAP384SHA384, 33566, 384),
        (SecAlg::ED25519, 56037, 256),
        (SecAlg::ED448, 7379, 456),
    ];

    #[test]
    fn parse_from_bind() {
        for &(algorithm, key_tag, _) in KEYS {
            let name =
                format!("test.+{:03}+{:05}", algorithm.to_int(), key_tag);

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let _ = Key::<Vec<u8>>::parse_from_bind(&data).unwrap();
        }
    }

    #[test]
    fn key_size() {
        for &(algorithm, key_tag, key_size) in KEYS {
            let name =
                format!("test.+{:03}+{:05}", algorithm.to_int(), key_tag);

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let key = Key::<Vec<u8>>::parse_from_bind(&data).unwrap();
            assert_eq!(key.key_size(), key_size);
        }
    }

    #[test]
    fn key_tag() {
        for &(algorithm, key_tag, _) in KEYS {
            let name =
                format!("test.+{:03}+{:05}", algorithm.to_int(), key_tag);

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let key = Key::<Vec<u8>>::parse_from_bind(&data).unwrap();
            assert_eq!(key.to_dnskey().key_tag(), key_tag);
            assert_eq!(key.key_tag(), key_tag);
        }
    }

    #[test]
    fn digest() {
        for &(algorithm, key_tag, _) in KEYS {
            let name =
                format!("test.+{:03}+{:05}", algorithm.to_int(), key_tag);

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let key = Key::<Vec<u8>>::parse_from_bind(&data).unwrap();

            // Scan the DS record from the file.
            let path = format!("test-data/dnssec-keys/K{}.ds", name);
            let data = std::fs::read_to_string(path).unwrap();
            let mut scanner = IterScanner::new(data.split_ascii_whitespace());
            let _ = scanner.scan_name().unwrap();
            let _ = Class::scan(&mut scanner).unwrap();
            assert_eq!(Rtype::scan(&mut scanner).unwrap(), Rtype::DS);
            let ds = Ds::scan(&mut scanner).unwrap();

            assert_eq!(key.digest(ds.digest_type()).unwrap(), ds);
        }
    }

    #[test]
    fn dnskey_roundtrip() {
        for &(algorithm, key_tag, _) in KEYS {
            let name =
                format!("test.+{:03}+{:05}", algorithm.to_int(), key_tag);

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let key = Key::<Vec<u8>>::parse_from_bind(&data).unwrap();
            let dnskey = key.to_dnskey().convert();
            let same = Key::from_dnskey(key.owner().clone(), dnskey).unwrap();
            assert_eq!(key, same);
        }
    }

    #[test]
    fn bind_format_roundtrip() {
        for &(algorithm, key_tag, _) in KEYS {
            let name =
                format!("test.+{:03}+{:05}", algorithm.to_int(), key_tag);

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let key = Key::<Vec<u8>>::parse_from_bind(&data).unwrap();
            let bind_fmt_key = key.display_as_bind().to_string();
            let same = Key::parse_from_bind(&bind_fmt_key).unwrap();
            assert_eq!(key, same);
        }
    }
}
