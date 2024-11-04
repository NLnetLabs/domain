//! A generic representation of secret keys.

use core::{fmt, str};

use secrecy::{ExposeSecret, SecretBox};
use std::boxed::Box;
use std::vec::Vec;

use crate::base::iana::SecAlg;
use crate::utils::base64;
use crate::validate::RsaPublicKeyBytes;

//----------- SecretKeyBytes -------------------------------------------------

/// A secret key expressed as raw bytes.
///
/// This is a low-level generic representation of a secret key from any one of
/// the commonly supported signature algorithms.  It is useful for abstracting
/// over most cryptographic implementations, and it provides functionality for
/// importing and exporting keys from and to the disk.
///
/// # Serialization
///
/// This type can be used to interact with private keys stored in the format
/// popularized by BIND.  The format is rather under-specified, but examples
/// of it are available in [RFC 5702], [RFC 6605], and [RFC 8080].
///
/// [RFC 5702]: https://www.rfc-editor.org/rfc/rfc5702
/// [RFC 6605]: https://www.rfc-editor.org/rfc/rfc6605
/// [RFC 8080]: https://www.rfc-editor.org/rfc/rfc8080
///
/// In this format, a private key is a line-oriented text file.  Each line is
/// either blank (having only whitespace) or a key-value entry.  Entries have
/// three components: a key, an ASCII colon, and a value.  Keys contain ASCII
/// text (except for colons) and values contain any data up to the end of the
/// line.  Whitespace at either end of the key and the value will be ignored.
///
/// Every file begins with two entries:
///
/// - `Private-key-format` specifies the format of the file.  The RFC examples
///   above use version 1.2 (serialised `v1.2`), but recent versions of BIND
///   have defined a new version 1.3 (serialized `v1.3`).
///
///   This value should be treated akin to Semantic Versioning principles.  If
///   the major version (the first number) is unknown to a parser, it should
///   fail, since it does not know the layout of the following fields.  If the
///   minor version is greater than what a parser is expecting, it should
///   ignore any following fields it did not expect.
///
/// - `Algorithm` specifies the signing algorithm used by the private key.
///   This can affect the format of later fields.  The value consists of two
///   whitespace-separated words: the first is the ASCII decimal number of the
///   algorithm (see [`SecAlg`]); the second is the name of the algorithm in
///   ASCII parentheses (with no whitespace inside).  Valid combinations are:
///
///   - `8 (RSASHA256)`: RSA with the SHA-256 digest.
///   - `10 (RSASHA512)`: RSA with the SHA-512 digest.
///   - `13 (ECDSAP256SHA256)`: ECDSA with the P-256 curve and SHA-256 digest.
///   - `14 (ECDSAP384SHA384)`: ECDSA with the P-384 curve and SHA-384 digest.
///   - `15 (ED25519)`: Ed25519.
///   - `16 (ED448)`: Ed448.
///
/// The value of every following entry is a Base64-encoded string of variable
/// length, using the RFC 4648 variant (i.e. with `+` and `/`, and `=` for
/// padding).  It is unclear whether padding is required or optional.
///
/// In the case of RSA, the following fields are defined (their conventional
/// symbolic names are also provided):
///
/// - `Modulus` (n)
/// - `PublicExponent` (e)
/// - `PrivateExponent` (d)
/// - `Prime1` (p)
/// - `Prime2` (q)
/// - `Exponent1` (d_p)
/// - `Exponent2` (d_q)
/// - `Coefficient` (q_inv)
///
/// For all other algorithms, there is a single `PrivateKey` field, whose
/// contents should be interpreted as:
///
/// - For ECDSA, the private scalar of the key, as a fixed-width byte string
///   interpreted as a big-endian integer.
///
/// - For EdDSA, the private scalar of the key, as a fixed-width byte string.
pub enum SecretKeyBytes {
    /// An RSA/SHA-256 keypair.
    RsaSha256(RsaSecretKeyBytes),

    /// An ECDSA P-256/SHA-256 keypair.
    ///
    /// The private key is a single 32-byte big-endian integer.
    EcdsaP256Sha256(SecretBox<[u8; 32]>),

    /// An ECDSA P-384/SHA-384 keypair.
    ///
    /// The private key is a single 48-byte big-endian integer.
    EcdsaP384Sha384(SecretBox<[u8; 48]>),

    /// An Ed25519 keypair.
    ///
    /// The private key is a single 32-byte string.
    Ed25519(SecretBox<[u8; 32]>),

    /// An Ed448 keypair.
    ///
    /// The private key is a single 57-byte string.
    Ed448(SecretBox<[u8; 57]>),
}

//--- Inspection

impl SecretKeyBytes {
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
}

//--- Converting to and from the BIND format

impl SecretKeyBytes {
    /// Serialize this secret key in the conventional format used by BIND.
    ///
    /// The key is formatted in the private key v1.2 format and written to the
    /// given formatter.  See the type-level documentation for a description
    /// of this format.
    pub fn format_as_bind(&self, mut w: impl fmt::Write) -> fmt::Result {
        writeln!(w, "Private-key-format: v1.2")?;
        match self {
            Self::RsaSha256(k) => {
                writeln!(w, "Algorithm: 8 (RSASHA256)")?;
                k.format_as_bind(w)
            }

            Self::EcdsaP256Sha256(s) => {
                let s = s.expose_secret();
                writeln!(w, "Algorithm: 13 (ECDSAP256SHA256)")?;
                writeln!(w, "PrivateKey: {}", base64::encode_display(s))
            }

            Self::EcdsaP384Sha384(s) => {
                let s = s.expose_secret();
                writeln!(w, "Algorithm: 14 (ECDSAP384SHA384)")?;
                writeln!(w, "PrivateKey: {}", base64::encode_display(s))
            }

            Self::Ed25519(s) => {
                let s = s.expose_secret();
                writeln!(w, "Algorithm: 15 (ED25519)")?;
                writeln!(w, "PrivateKey: {}", base64::encode_display(s))
            }

            Self::Ed448(s) => {
                let s = s.expose_secret();
                writeln!(w, "Algorithm: 16 (ED448)")?;
                writeln!(w, "PrivateKey: {}", base64::encode_display(s))
            }
        }
    }

    /// Display this secret key in the conventional format used by BIND.
    ///
    /// This is a simple wrapper around [`Self::format_as_bind()`].
    pub fn display_as_bind(&self) -> impl fmt::Display + '_ {
        struct Display<'a>(&'a SecretKeyBytes);
        impl fmt::Display for Display<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.format_as_bind(f)
            }
        }
        Display(self)
    }

    /// Parse a secret key from the conventional format used by BIND.
    ///
    /// This parser supports the private key v1.2 format, but it should be
    /// compatible with any future v1.x key.  See the type-level documentation
    /// for a description of this format.
    pub fn parse_from_bind(data: &str) -> Result<Self, BindFormatError> {
        /// Parse private keys for most algorithms (except RSA).
        fn parse_pkey<const N: usize>(
            mut data: &str,
        ) -> Result<SecretBox<[u8; N]>, BindFormatError> {
            // Look for the 'PrivateKey' field.
            while let Some((key, val, rest)) = parse_bind_entry(data)? {
                data = rest;

                if key != "PrivateKey" {
                    continue;
                }

                // TODO: Evaluate security of 'base64::decode()'.
                let val: Vec<u8> = base64::decode(val)
                    .map_err(|_| BindFormatError::Misformatted)?;
                let val: Box<[u8]> = val.into_boxed_slice();
                let val: Box<[u8; N]> = val
                    .try_into()
                    .map_err(|_| BindFormatError::Misformatted)?;

                return Ok(val.into());
            }

            // The 'PrivateKey' field was not found.
            Err(BindFormatError::Misformatted)
        }

        // The first line should specify the key format.
        let (_, _, data) = parse_bind_entry(data)?
            .filter(|&(k, v, _)| {
                k == "Private-key-format"
                    && v.strip_prefix("v1.")
                        .and_then(|minor| minor.parse::<u8>().ok())
                        .map_or(false, |minor| minor >= 2)
            })
            .ok_or(BindFormatError::UnsupportedFormat)?;

        // The second line should specify the algorithm.
        let (_, val, data) = parse_bind_entry(data)?
            .filter(|&(k, _, _)| k == "Algorithm")
            .ok_or(BindFormatError::Misformatted)?;

        // Parse the algorithm.
        let mut words = val.split_whitespace();
        let code = words
            .next()
            .and_then(|code| code.parse::<u8>().ok())
            .ok_or(BindFormatError::Misformatted)?;
        let name = words.next().ok_or(BindFormatError::Misformatted)?;
        if words.next().is_some() {
            return Err(BindFormatError::Misformatted);
        }

        match (code, name) {
            (8, "(RSASHA256)") => {
                RsaSecretKeyBytes::parse_from_bind(data).map(Self::RsaSha256)
            }
            (13, "(ECDSAP256SHA256)") => {
                parse_pkey(data).map(Self::EcdsaP256Sha256)
            }
            (14, "(ECDSAP384SHA384)") => {
                parse_pkey(data).map(Self::EcdsaP384Sha384)
            }
            (15, "(ED25519)") => parse_pkey(data).map(Self::Ed25519),
            (16, "(ED448)") => parse_pkey(data).map(Self::Ed448),
            _ => Err(BindFormatError::UnsupportedAlgorithm),
        }
    }
}

//----------- RsaSecretKeyBytes ---------------------------------------------------

/// An RSA secret key expressed as raw bytes.
///
/// All fields here are arbitrary-precision integers in big-endian format.
/// The public values, `n` and `e`, must not have leading zeros; the remaining
/// values may be padded with leading zeros.
pub struct RsaSecretKeyBytes {
    /// The public modulus.
    pub n: Box<[u8]>,

    /// The public exponent.
    pub e: Box<[u8]>,

    /// The private exponent.
    pub d: SecretBox<[u8]>,

    /// The first prime factor of `d`.
    pub p: SecretBox<[u8]>,

    /// The second prime factor of `d`.
    pub q: SecretBox<[u8]>,

    /// The exponent corresponding to the first prime factor of `d`.
    pub d_p: SecretBox<[u8]>,

    /// The exponent corresponding to the second prime factor of `d`.
    pub d_q: SecretBox<[u8]>,

    /// The inverse of the second prime factor modulo the first.
    pub q_i: SecretBox<[u8]>,
}

//--- Conversion to and from the BIND format

impl RsaSecretKeyBytes {
    /// Serialize this secret key in the conventional format used by BIND.
    ///
    /// The key is formatted in the private key v1.2 format and written to the
    /// given formatter.  Note that the header and algorithm lines are not
    /// written.  See the type-level documentation of [`SecretKeyBytes`] for a
    /// description of this format.
    pub fn format_as_bind(&self, mut w: impl fmt::Write) -> fmt::Result {
        w.write_str("Modulus: ")?;
        writeln!(w, "{}", base64::encode_display(&self.n))?;
        w.write_str("PublicExponent: ")?;
        writeln!(w, "{}", base64::encode_display(&self.e))?;
        w.write_str("PrivateExponent: ")?;
        writeln!(w, "{}", base64::encode_display(&self.d.expose_secret()))?;
        w.write_str("Prime1: ")?;
        writeln!(w, "{}", base64::encode_display(&self.p.expose_secret()))?;
        w.write_str("Prime2: ")?;
        writeln!(w, "{}", base64::encode_display(&self.q.expose_secret()))?;
        w.write_str("Exponent1: ")?;
        writeln!(w, "{}", base64::encode_display(&self.d_p.expose_secret()))?;
        w.write_str("Exponent2: ")?;
        writeln!(w, "{}", base64::encode_display(&self.d_q.expose_secret()))?;
        w.write_str("Coefficient: ")?;
        writeln!(w, "{}", base64::encode_display(&self.q_i.expose_secret()))?;
        Ok(())
    }

    /// Display this secret key in the conventional format used by BIND.
    ///
    /// This is a simple wrapper around [`Self::format_as_bind()`].
    pub fn display_as_bind(&self) -> impl fmt::Display + '_ {
        struct Display<'a>(&'a RsaSecretKeyBytes);
        impl fmt::Display for Display<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.format_as_bind(f)
            }
        }
        Display(self)
    }

    /// Parse a secret key from the conventional format used by BIND.
    ///
    /// This parser supports the private key v1.2 format, but it should be
    /// compatible with any future v1.x key.  Note that the header and
    /// algorithm lines are ignored.  See the type-level documentation of
    /// [`SecretKeyBytes`] for a description of this format.
    pub fn parse_from_bind(mut data: &str) -> Result<Self, BindFormatError> {
        let mut n = None;
        let mut e = None;
        let mut d = None;
        let mut p = None;
        let mut q = None;
        let mut d_p = None;
        let mut d_q = None;
        let mut q_i = None;

        while let Some((key, val, rest)) = parse_bind_entry(data)? {
            let field = match key {
                "Modulus" => &mut n,
                "PublicExponent" => &mut e,
                "PrivateExponent" => &mut d,
                "Prime1" => &mut p,
                "Prime2" => &mut q,
                "Exponent1" => &mut d_p,
                "Exponent2" => &mut d_q,
                "Coefficient" => &mut q_i,
                _ => {
                    data = rest;
                    continue;
                }
            };

            if field.is_some() {
                // This field has already been filled.
                return Err(BindFormatError::Misformatted);
            }

            let buffer: Vec<u8> = base64::decode(val)
                .map_err(|_| BindFormatError::Misformatted)?;

            *field = Some(buffer.into_boxed_slice());
            data = rest;
        }

        for field in [&n, &e, &d, &p, &q, &d_p, &d_q, &q_i] {
            if field.is_none() {
                // A field was missing.
                return Err(BindFormatError::Misformatted);
            }
        }

        Ok(Self {
            n: n.unwrap(),
            e: e.unwrap(),
            d: d.unwrap().into(),
            p: p.unwrap().into(),
            q: q.unwrap().into(),
            d_p: d_p.unwrap().into(),
            d_q: d_q.unwrap().into(),
            q_i: q_i.unwrap().into(),
        })
    }
}

//--- Into<RsaPublicKeyBytes>

impl<'a> From<&'a RsaSecretKeyBytes> for RsaPublicKeyBytes {
    fn from(value: &'a RsaSecretKeyBytes) -> Self {
        RsaPublicKeyBytes {
            n: value.n.clone(),
            e: value.e.clone(),
        }
    }
}

//----------- Helpers for parsing the BIND format ----------------------------

/// Extract the next key-value pair in a BIND-format private key file.
fn parse_bind_entry(
    data: &str,
) -> Result<Option<(&str, &str, &str)>, BindFormatError> {
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
        line.split_once(':').ok_or(BindFormatError::Misformatted)?;

    // Trim the key and value (incl. for CR LFs).
    Ok(Some((key.trim(), val.trim(), rest)))
}

//============ Error types ===================================================

//----------- BindFormatError ------------------------------------------------

/// An error in loading a [`SecretKeyBytes`] from the conventional DNS format.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum BindFormatError {
    /// The key file uses an unsupported version of the format.
    UnsupportedFormat,

    /// The key file did not follow the DNS format correctly.
    Misformatted,

    /// The key file used an unsupported algorithm.
    UnsupportedAlgorithm,
}

//--- Display

impl fmt::Display for BindFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedFormat => "unsupported format",
            Self::Misformatted => "misformatted key file",
            Self::UnsupportedAlgorithm => "unsupported algorithm",
        })
    }
}

//--- Error

impl std::error::Error for BindFormatError {}

//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use std::{string::ToString, vec::Vec};

    use crate::base::iana::SecAlg;

    const KEYS: &[(SecAlg, u16)] = &[
        (SecAlg::RSASHA256, 60616),
        (SecAlg::ECDSAP256SHA256, 42253),
        (SecAlg::ECDSAP384SHA384, 33566),
        (SecAlg::ED25519, 56037),
        (SecAlg::ED448, 7379),
    ];

    #[test]
    fn secret_from_dns() {
        for &(algorithm, key_tag) in KEYS {
            let name =
                format!("test.+{:03}+{:05}", algorithm.to_int(), key_tag);
            let path = format!("test-data/dnssec-keys/K{}.private", name);
            let data = std::fs::read_to_string(path).unwrap();
            let key = super::SecretKeyBytes::parse_from_bind(&data).unwrap();
            assert_eq!(key.algorithm(), algorithm);
        }
    }

    #[test]
    fn secret_roundtrip() {
        for &(algorithm, key_tag) in KEYS {
            let name =
                format!("test.+{:03}+{:05}", algorithm.to_int(), key_tag);
            let path = format!("test-data/dnssec-keys/K{}.private", name);
            let data = std::fs::read_to_string(path).unwrap();
            let key = super::SecretKeyBytes::parse_from_bind(&data).unwrap();
            let same = key.display_as_bind().to_string();
            let data = data.lines().collect::<Vec<_>>();
            let same = same.lines().collect::<Vec<_>>();
            assert_eq!(data, same);
        }
    }
}
