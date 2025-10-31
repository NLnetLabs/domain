//! DNSSEC code that is used both by DNSSEC signing and DNSSEC validation.

#![cfg(any(feature = "ring", feature = "openssl"))]
#![cfg_attr(docsrs, doc(cfg(any(feature = "ring", feature = "openssl"))))]
#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use crate::base::iana::{Class, Nsec3HashAlgorithm};
use crate::base::scan::{IterScanner, Scanner, ScannerError};
use crate::base::wire::Composer;
use crate::base::zonefile_fmt::{DisplayKind, ZonefileFmt};
use crate::base::{Name, Record, Rtype, ToName, Ttl};
use crate::crypto::common::{DigestBuilder, DigestType};
use crate::dep::octseq::{
    EmptyBuilder, FromBuilder, OctetsBuilder, Truncate,
};
use crate::rdata::nsec3::{Nsec3Salt, OwnerHash};
use crate::rdata::{Dnskey, Nsec3param};

use std::error;
use std::fmt;
use std::str::FromStr;

//------------ Nsec3HashError -------------------------------------------------

/// An error when creating an NSEC3 hash.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Nsec3HashError {
    /// The requested algorithm for NSEC3 hashing is not supported.
    UnsupportedAlgorithm,

    /// Data could not be appended to a buffer.
    ///
    /// This could indicate an out of memory condition.
    AppendError,

    /// The hashing process produced an invalid owner hash.
    ///
    /// See: [OwnerHashError](crate::rdata::nsec3::OwnerHashError)
    OwnerHashError,

    /// The hashing process produced a hash that already exists.
    CollisionDetected,

    /// The hash provider did not provide a hash for the given owner name.
    MissingHash,
}

//--- Display

impl std::fmt::Display for Nsec3HashError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Nsec3HashError::UnsupportedAlgorithm => {
                f.write_str("Unsupported algorithm")
            }
            Nsec3HashError::AppendError => {
                f.write_str("Append error: out of memory?")
            }
            Nsec3HashError::OwnerHashError => {
                f.write_str("Hashing produced an invalid owner hash")
            }
            Nsec3HashError::CollisionDetected => {
                f.write_str("Hash collision detected")
            }
            Nsec3HashError::MissingHash => {
                f.write_str("Missing hash for owner name")
            }
        }
    }
}

/// Compute an [RFC 5155] NSEC3 hash using default settings.
///
/// See: [Nsec3param::default].
///
/// [RFC 5155]: https://www.rfc-editor.org/rfc/rfc5155
pub fn nsec3_default_hash<N, HashOcts>(
    owner: N,
) -> Result<OwnerHash<HashOcts>, Nsec3HashError>
where
    N: ToName,
    HashOcts: AsRef<[u8]> + EmptyBuilder + OctetsBuilder + Truncate,
    for<'a> HashOcts: From<&'a [u8]>,
{
    let params = Nsec3param::<HashOcts>::default();
    nsec3_hash(
        owner,
        params.hash_algorithm(),
        params.iterations(),
        params.salt(),
    )
}

/// Compute an [RFC 5155] NSEC3 hash.
///
/// Computes an NSEC3 hash according to [RFC 5155] section 5:
///
/// > IH(salt, x, 0) = H(x || salt)
/// > IH(salt, x, k) = H(IH(salt, x, k-1) || salt), if k > 0
///
/// Then the calculated hash of an owner name is:
///
/// > IH(salt, owner name, iterations),
///
/// Note that the `iterations` parameter is the number of _additional_
/// iterations as defined in [RFC 5155] section 3.1.3.
///
/// [RFC 5155]: https://www.rfc-editor.org/rfc/rfc5155
pub fn nsec3_hash<N, SaltOcts, HashOcts>(
    owner: N,
    algorithm: Nsec3HashAlgorithm,
    iterations: u16,
    salt: &Nsec3Salt<SaltOcts>,
) -> Result<OwnerHash<HashOcts>, Nsec3HashError>
where
    N: ToName,
    SaltOcts: AsRef<[u8]>,
    HashOcts: AsRef<[u8]> + EmptyBuilder + OctetsBuilder + Truncate,
    for<'a> HashOcts: From<&'a [u8]>,
{
    if algorithm != Nsec3HashAlgorithm::SHA1 {
        return Err(Nsec3HashError::UnsupportedAlgorithm);
    }

    /// Compute the hash octets.
    fn mk_hash<N, SaltOcts, HashOcts>(
        owner: N,
        iterations: u16,
        salt: &Nsec3Salt<SaltOcts>,
    ) -> Result<HashOcts, HashOcts::AppendError>
    where
        N: ToName,
        SaltOcts: AsRef<[u8]>,
        HashOcts: AsRef<[u8]> + EmptyBuilder + OctetsBuilder + Truncate,
        for<'a> HashOcts: From<&'a [u8]>,
    {
        let mut canonical_owner = HashOcts::empty();
        owner.compose_canonical(&mut canonical_owner)?;

        let mut ctx = DigestBuilder::new(DigestType::Sha1);
        ctx.update(canonical_owner.as_ref());
        ctx.update(salt.as_slice());
        let mut h = ctx.finish();

        for _ in 0..iterations {
            let mut ctx = DigestBuilder::new(DigestType::Sha1);
            ctx.update(h.as_ref());
            ctx.update(salt.as_slice());
            h = ctx.finish();
        }

        Ok(h.as_ref().into())
    }

    let hash = mk_hash(owner, iterations, salt)
        .map_err(|_| Nsec3HashError::AppendError)?;

    let owner_hash = OwnerHash::from_octets(hash)
        .map_err(|_| Nsec3HashError::OwnerHashError)?;

    Ok(owner_hash)
}

//------------ parse_from_bind -----------------------------------------------

/// Parse a DNSSEC key from the conventional format used by BIND.
///
/// See the type-level documentation for a description of this format.
pub fn parse_from_bind<Octs>(
    data: &str,
) -> Result<Record<Name<Octs>, Dnskey<Octs>>, ParseDnskeyTextError>
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
    let (line, rest) = next_line(data).ok_or(ParseDnskeyTextError)?;
    if next_line(rest).is_some() {
        return Err(ParseDnskeyTextError);
    }

    // Parse the entire record.
    let mut scanner = IterScanner::new(line.split_ascii_whitespace());

    let name = scanner.scan_name().map_err(|_| ParseDnskeyTextError)?;

    // We can have an optional TTL here. Try to scan either a TTL or a
    // Class. Return Some(ttl) if we found a TTL. Return None if we
    // Successfully scanned a class. Otherwise return an error.
    let opt_ttl = scanner
        .scan_ascii_str(|s| {
            if let Ok(ttl) = u32::from_str(s) {
                Ok(Some(Ttl::from_secs(ttl)))
            } else if Class::from_str(s).is_ok() {
                Ok(None)
            } else {
                Err(ScannerError::custom("TTL or Class expected"))
            }
        })
        .map_err(|_| ParseDnskeyTextError)?;

    if opt_ttl.is_some() {
        // The previous token was a TTL. If opt_ttl is None then the previous
        // token was a class.
        let _ =
            Class::scan(&mut scanner).map_err(|_| ParseDnskeyTextError)?;
    }

    if Rtype::scan(&mut scanner).map_or(true, |t| t != Rtype::DNSKEY) {
        return Err(ParseDnskeyTextError);
    }

    let data =
        Dnskey::scan(&mut scanner).map_err(|_| ParseDnskeyTextError)?;

    Ok(Record::new(
        name,
        Class::IN,
        opt_ttl.unwrap_or(Ttl::ZERO),
        data,
    ))
}

//------------ format_as_bind ------------------------------------------------
// # Serialization
//
// Keys can be parsed from or written in the conventional format used by the
// BIND name server.  This is a simplified version of the zonefile format.
//
// In this format, a public key is a line-oriented text file.  Each line is
// either blank (having only whitespace) or a single DNSKEY record in the
// presentation format.  In either case, the line may end with a comment (an
// ASCII semicolon followed by arbitrary content until the end of the line).
// The file must contain a single DNSKEY record line.
//
// The DNSKEY record line contains the following fields, separated by ASCII
// whitespace:
//
// - The owner name.  This is an absolute name ending with a dot.
// - Optionally, the class of the record (usually `IN`).
// - The record type (which must be `DNSKEY`).
// - The DNSKEY record data, which has the following sub-fields:
//   - The key flags, which describe the key's uses.
//   - The protocol used (expected to be `3`).
//   - The key algorithm (see [`SecurityAlgorithm`]).
//   - The public key encoded as a Base64 string.

/// Serialize this key in the conventional format used by BIND.
///
/// See the type-level documentation for a description of this format.
fn format_as_bind<N, O>(
    record: &Record<N, Dnskey<O>>,
    mut w: impl fmt::Write,
) -> fmt::Result
where
    N: ToName,
    O: AsRef<[u8]>,
{
    writeln!(
        w,
        "{} IN DNSKEY {}",
        record.owner().fmt_with_dot(),
        record.data().display_zonefile(DisplayKind::Simple),
    )
}

//------------ display_as_bind -----------------------------------------------
/// Display this key in the conventional format used by BIND.
///
/// See the type-level documentation for a description of this format.
pub fn display_as_bind<N, O>(
    record: &Record<N, Dnskey<O>>,
) -> impl fmt::Display + '_
where
    N: ToName,
    O: AsRef<[u8]>,
{
    /// Display type to return.
    struct Display<'a, N, O>(&'a Record<N, Dnskey<O>>);
    impl<N, O> fmt::Display for Display<'_, N, O>
    where
        N: ToName,
        O: AsRef<[u8]>,
    {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            format_as_bind(self.0, f)
        }
    }
    Display(record)
}

//----------- ParseDnskeyTextError -------------------------------------------

#[derive(Clone, Debug)]
/// Error from parsing a DNSKEY record in presentation format.
pub struct ParseDnskeyTextError;

//--- Display, Error

impl fmt::Display for ParseDnskeyTextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("misformatted DNSKEY record")
    }
}

impl error::Error for ParseDnskeyTextError {}

//============ Test ==========================================================

#[cfg(test)]
#[cfg(feature = "std")]
mod test {
    use std::string::ToString;
    use std::vec::Vec;

    use crate::base::iana::SecurityAlgorithm;
    use crate::dnssec::common::{display_as_bind, parse_from_bind};

    const KEYS: &[(SecurityAlgorithm, u16, usize)] = &[
        (SecurityAlgorithm::RSASHA1, 439, 2048),
        (SecurityAlgorithm::RSASHA1_NSEC3_SHA1, 22204, 2048),
        (SecurityAlgorithm::RSASHA256, 60616, 2048),
        (SecurityAlgorithm::ECDSAP256SHA256, 42253, 256),
        (SecurityAlgorithm::ECDSAP384SHA384, 33566, 384),
        (SecurityAlgorithm::ED25519, 56037, 256),
        (SecurityAlgorithm::ED448, 7379, 456),
    ];

    #[test]
    fn test_parse_from_bind() {
        for &(algorithm, key_tag, _) in KEYS {
            let name =
                format!("test.+{:03}+{:05}", algorithm.to_int(), key_tag);

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let _ = parse_from_bind::<Vec<u8>>(&data).unwrap();
        }
    }

    #[test]
    fn test_parse_from_bind_ttl() {
        for &(algorithm, key_tag, _) in
            &[(SecurityAlgorithm::RSASHA256, 60616, 2048)]
        {
            let name =
                format!("test-ttl.+{:03}+{:05}", algorithm.to_int(), key_tag);

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let _ = parse_from_bind::<Vec<u8>>(&data).unwrap();
        }
    }

    #[test]
    fn key_tag() {
        for &(algorithm, key_tag, _) in KEYS {
            let name =
                format!("test.+{:03}+{:05}", algorithm.to_int(), key_tag);

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let key = parse_from_bind::<Vec<u8>>(&data).unwrap();
            assert_eq!(key.data().key_tag(), key_tag);
        }
    }

    #[test]
    fn bind_format_roundtrip() {
        for &(algorithm, key_tag, _) in KEYS {
            let name =
                format!("test.+{:03}+{:05}", algorithm.to_int(), key_tag);

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let key = parse_from_bind::<Vec<u8>>(&data).unwrap();
            let bind_fmt_key = display_as_bind(&key).to_string();
            let same = parse_from_bind::<Vec<u8>>(&bind_fmt_key).unwrap();
            assert_eq!(key, same);
        }
    }
}
