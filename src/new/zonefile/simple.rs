//! A simple zonefile scanner.
//!
//! [`ZonefileScanner`] can be used to parse a zonefile directly out of an I/O
//! source.  It returns a sequence of zonefile entries, which are records or
//! directives.  It aims to be reasonably efficient -- the scanner re-uses
//! allocations between returned records, expecting callers to copy them out
//! if they need to.
//!
//! # Usage
//!
//! ```
//! # use domain::new::base::name::RevNameBuf;
//! # use domain::new::zonefile::simple::{ZonefileScanner, Entry};
//! let zonefile: &[u8] = br#"
//! @   IN 42 SOA m r 20 7200 600 3600000 60
//!           A 127.0.0.1
//! foo       NS ns.foo.net.
//! "#;
//! let origin: RevNameBuf = "example.org".parse().unwrap();
//! let mut scanner = ZonefileScanner::new(zonefile, Some(&origin));
//! while let Some(entry) = scanner.scan().unwrap() {
//!     println!("{:?}", entry);
//! }
//! ```

use core::fmt;
use std::{io, path::PathBuf, vec::Vec};

use crate::new::{
    base::{
        name::{Name, NameBuf, RevName, RevNameBuf},
        RClass, Record, TTL,
    },
    rdata::RecordData,
};

use super::{
    entries::{Entries, EntriesError},
    scanner::{Scan, ScanError, Scanner},
};

//----------- ZonefileScanner ------------------------------------------------

/// A simple zonefile scanner.
///
/// The zonefile is read in a streaming fashion -- it can thus be arbitrarily
/// large.  Each record is scanned into a local buffer and can be borrowed for
/// inspection and copying.
#[derive(Debug)]
pub struct ZonefileScanner<R: io::BufRead> {
    /// The entries in the zonefile.
    entries: Entries<R>,

    /// The current origin, if one is known.
    origin: Option<RevNameBuf>,

    /// The implicit owner for the next record.
    next_owner: Option<RevNameBuf>,

    /// The implicit TTL for the next record.
    next_ttl: Option<TTL>,

    /// The implicit class for the next record.
    next_class: Option<RClass>,

    /// A bump allocator for storing indirect data.
    alloc: bumpalo::Bump,

    /// A buffer for handling tokens.
    buffer: Vec<u8>,
}

//--- Construction

impl<R: io::BufRead> ZonefileScanner<R> {
    /// Construct a new [`ZonefileScanner`].
    ///
    /// If the zonefile is relative to a certain origin, it can be specified
    /// here.  Otherwise, the zonefile can specify its own origin internally,
    /// or it cannot contain relative domain names.
    ///
    /// The given source is assumed to correspond to the beginning of the
    /// zonefile, for the purpose of calculating line numbers.  If some lines
    /// are stripped from the beginning of the actual zonefile, line numbers
    /// reported by the zonefile scanner will be inaccurate.
    pub fn new(source: R, origin: Option<&RevName>) -> Self {
        Self {
            entries: Entries::new(source),
            origin: origin.map(RevNameBuf::copy_from),
            next_owner: None,
            next_ttl: None,
            next_class: None,
            alloc: bumpalo::Bump::new(),
            buffer: Vec::new(),
        }
    }
}

//--- Clone

impl<R: io::BufRead + Clone> Clone for ZonefileScanner<R> {
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
            origin: self.origin.clone(),
            next_owner: self.next_owner.clone(),
            next_ttl: self.next_ttl,
            next_class: self.next_class,
            alloc: bumpalo::Bump::new(),
            buffer: Vec::new(),
        }
    }
}

//--- Interaction

impl<R: io::BufRead> ZonefileScanner<R> {
    /// Scan the next entry and return a reference to it.
    pub fn scan(&mut self) -> Result<Option<Entry<'_>>, ZonefileError> {
        // Reset buffers from previous records.
        self.alloc.reset();
        self.buffer.clear();

        // Ignore directives for setting the origin and TTL.
        let entry = loop {
            let Some(entry) = self.entries.next_entry()? else {
                return Ok(None);
            };

            // Parse directives.
            if entry.content.starts_with(b"$") {
                match Self::scan_directive(
                    entry.content,
                    &mut self.origin,
                    &mut self.next_ttl,
                    &self.alloc,
                    &mut self.buffer,
                ) {
                    Ok(Some(entry)) => return Ok(Some(entry)),

                    // If it's not an include directive, keep going.
                    Ok(None) => continue,

                    Err(error) => {
                        return Err(ZonefileError::Directive {
                            error,
                            line_number: entry.line_numbers.start,
                        });
                    }
                }
            }

            break entry;
        };

        match Self::scan_record(
            entry.content,
            &self.origin,
            &mut self.next_owner,
            &mut self.next_ttl,
            &mut self.next_class,
            &self.alloc,
            &mut self.buffer,
        ) {
            Ok(record) => Ok(Some(Entry::Record(record))),
            Err(error) => Err(ZonefileError::Record {
                error,
                line_number: entry.line_numbers.start,
            }),
        }
    }

    /// Scan a directive.
    fn scan_directive<'a>(
        entry: &[u8],
        origin: &mut Option<RevNameBuf>,
        last_ttl: &mut Option<TTL>,
        alloc: &'a bumpalo::Bump,
        buffer: &mut Vec<u8>,
    ) -> Result<Option<Entry<'a>>, DirectiveError> {
        // Extract the directive.
        let pos = entry
            .iter()
            .take_while(|&b| !b.is_ascii_whitespace())
            .count();
        let (directive, args) = entry.split_at(pos);

        let mut scanner = Scanner::new(args, None);
        scanner.skip_ws();

        // Select the appropriate sub-directive.
        if directive.eq_ignore_ascii_case(b"$INCLUDE") {
            Ok(Some(Self::scan_include_directive(
                scanner, origin, alloc, buffer,
            )?))
        } else if directive.eq_ignore_ascii_case(b"$ORIGIN") {
            Self::scan_origin_directive(scanner, origin, alloc, buffer)?;
            Ok(None)
        } else if directive.eq_ignore_ascii_case(b"$TTL") {
            Self::scan_ttl_directive(scanner, last_ttl, alloc, buffer)?;
            Ok(None)
        } else {
            Err(DirectiveError::UnknownDirective)
        }
    }

    /// Scan an include directive.
    fn scan_include_directive<'a>(
        mut scanner: Scanner<'_>,
        origin: &Option<RevNameBuf>,
        alloc: &'a bumpalo::Bump,
        buffer: &mut Vec<u8>,
    ) -> Result<Entry<'a>, DirectiveError> {
        let file_name: PathBuf = scanner
            .scan_token(buffer)
            .transpose()
            .ok_or(DirectiveError::MissingFields)?
            .ok()
            .and_then(|token| core::str::from_utf8(token).ok())
            .ok_or(DirectiveError::InvalidIncludePath)?
            .into();

        let mut origin = origin.clone();
        if !scanner.remaining().is_empty() {
            origin = Some(
                RevNameBuf::scan(&mut scanner, alloc, buffer)
                    .map_err(|_| DirectiveError::InvalidOrigin)?,
            );
        }
        let origin = origin.map(|origin| {
            let bytes = alloc.alloc_slice_copy(origin.as_bytes());
            // SAFETY: 'RevName::as_bytes()' is always valid.
            unsafe { RevName::from_bytes_unchecked(bytes) }
        });

        Ok(Entry::Include { file_name, origin })
    }

    /// Scan an origin directive.
    fn scan_origin_directive(
        mut scanner: Scanner<'_>,
        origin: &mut Option<RevNameBuf>,
        alloc: &bumpalo::Bump,
        buffer: &mut Vec<u8>,
    ) -> Result<(), DirectiveError> {
        if scanner.remaining().is_empty() {
            return Err(DirectiveError::MissingFields);
        }

        *origin = Some(
            RevNameBuf::scan(&mut scanner, alloc, buffer)
                .map_err(|_| DirectiveError::InvalidOrigin)?,
        );
        Ok(())
    }

    /// Scan a TTL directive.
    fn scan_ttl_directive(
        mut scanner: Scanner<'_>,
        last_ttl: &mut Option<TTL>,
        alloc: &bumpalo::Bump,
        buffer: &mut Vec<u8>,
    ) -> Result<(), DirectiveError> {
        if scanner.remaining().is_empty() {
            return Err(DirectiveError::MissingFields);
        }

        *last_ttl = Some(
            TTL::scan(&mut scanner, alloc, buffer)
                .map_err(|_| DirectiveError::InvalidTTL)?,
        );
        Ok(())
    }

    /// Scan a record.
    fn scan_record<'a>(
        entry: &[u8],
        origin: &Option<RevNameBuf>,
        last_owner: &mut Option<RevNameBuf>,
        last_ttl: &mut Option<TTL>,
        last_rclass: &mut Option<RClass>,
        alloc: &'a bumpalo::Bump,
        buffer: &mut Vec<u8>,
    ) -> Result<ScannedRecord<'a>, RecordError> {
        let mut scanner = Scanner::new(entry, origin.as_ref().map(|n| &**n));

        // Try parsing the record name.
        let owner = match *scanner.remaining() {
            [] => unreachable!(
                "'scan_record' is only called on non-empty entries"
            ),
            [c, ..] if c.is_ascii_whitespace() => {
                // The domain name is implicit.  Use the last owner name.
                let owner = last_owner
                    .as_ref()
                    .ok_or(RecordError::MissingFirstField)?;
                let bytes = alloc.alloc_slice_copy(owner.as_bytes());
                // SAFETY: 'RevName::as_bytes()' is guaranteed to be valid.
                unsafe { RevName::from_bytes_unchecked(bytes) }
            }
            _ => {
                // Parse the domain name explicitly.
                let owner = <&'a RevName>::scan(&mut scanner, alloc, buffer)
                    .map_err(RecordError::OwnerError)?;
                *last_owner = Some(RevNameBuf::copy_from(owner));
                owner
            }
        };

        // Try parsing the TTL, class, and type.
        let mut rclass = None;
        let mut ttl = None;
        loop {
            // Skip to the next field.
            if !scanner.skip_ws() {
                return Err(RecordError::MissingFields);
            }

            let input = scanner.remaining();

            // Try parsing a TTL.
            let c = input.first().ok_or(RecordError::MissingFields)?;
            if c.is_ascii_digit() {
                if ttl.is_some() {
                    return Err(RecordError::MultipleTTLs);
                }

                ttl = Some(
                    TTL::scan(&mut scanner, alloc, buffer)
                        .map_err(RecordError::TTLError)?,
                );
                continue;
            }

            // Try parsing a class.
            let mut temp = scanner.clone();
            if let Ok(parsed) = RClass::scan(&mut temp, alloc, buffer) {
                if rclass.is_some() {
                    return Err(RecordError::MultipleClasses);
                }

                rclass = Some(parsed);
                scanner = temp;
                continue;
            }

            // We will assume it's a valid record type.
            break;
        }

        let rclass = rclass
            .or(*last_rclass)
            .ok_or(RecordError::MissingFirstField)?;
        *last_rclass = Some(rclass);

        let ttl = ttl.or(*last_ttl).ok_or(RecordError::MissingFirstField)?;
        *last_ttl = Some(ttl);

        // Parse the record data.
        let data =
            // NOTE: If the unknown record data format is used for a type we
            // recognize, we will scan it as 'UnknownRecordData' and then
            // parse the bytes to ensure validity.  Unfortunately, it is not
            // possible to parse bytes into '&RevName' (it would need access
            // to the bump allocator).  So we just parse as 'RevNameBuf' and
            // push all names onto the bump allocator afterwards.  Hopefully,
            // the compiler is able to inline this fairly large type away.
            <RecordData<'a, NameBuf>>::scan(&mut scanner, alloc, buffer)
                .map_err(RecordError::DataError)?
                .map_names(|name| {
                    let bytes = alloc.alloc_slice_copy(name.as_bytes());
                    // SAFETY: 'Name::as_bytes()' is always valid.
                    unsafe { Name::from_bytes_unchecked(bytes) }
                });
        Ok(Record {
            rname: owner,
            rtype: data.rtype(),
            rclass,
            ttl,
            rdata: data,
        })
    }
}

//----------- Type Aliases ---------------------------------------------------

/// A scanned record.
pub type ScannedRecord<'a> = Record<&'a RevName, RecordData<'a, &'a Name>>;

/// An entry in a zonefile.
#[derive(Debug, PartialEq, Eq)]
pub enum Entry<'a> {
    /// A zonefile record.
    Record(ScannedRecord<'a>),

    /// An include directive.
    Include {
        /// The file name to include.
        file_name: PathBuf,

        /// The origin domain name to use.
        origin: Option<&'a RevName>,
    },
}

//----------- ScanError ------------------------------------------------------

/// An error in scanning a zonefile.
#[derive(Debug)]
pub enum ZonefileError {
    /// An error in scanning a record.
    Record {
        /// The scanning error that occurred.
        error: RecordError,

        /// The line number of the entry.
        line_number: usize,
    },

    /// An error in scanning a directive.
    Directive {
        /// The scanning error that occurred.
        error: DirectiveError,

        /// The line number of the entry.
        line_number: usize,
    },

    /// An error in disambiguating entries.
    Entries(EntriesError),
}

#[cfg(feature = "std")]
impl std::error::Error for ZonefileError {}

//--- Conversion from error types

impl From<EntriesError> for ZonefileError {
    fn from(error: EntriesError) -> Self {
        Self::Entries(error)
    }
}

//--- Formatting

impl fmt::Display for ZonefileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Record { error, line_number } => {
                write!(f, "failed to parse the record on line {line_number}: {error}")
            }
            Self::Directive { error, line_number } => {
                write!(f, "failed to parse the directive on line {line_number}: {error}")
            }
            Self::Entries(error) => error.fmt(f),
        }
    }
}

//----------- RecordError ----------------------------------------------------

/// An error in scanning a zonefile record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// An unknown record data type was encountered.
    UnknownRecordType,

    /// The origin name was requested, but none was set.
    MissingOrigin,

    /// A field in the first record was left implicit.
    MissingFirstField,

    /// A record was missing some fields.
    MissingFields,

    /// A record specified multiple TTLs.
    MultipleTTLs,

    /// A record specified multiple classes.
    MultipleClasses,

    /// The record name could not be scanned.
    OwnerError(ScanError),

    /// The record class could not be scanned.
    ClassError(ScanError),

    /// The TTL could not be scanned.
    TTLError(ScanError),

    /// The record data could not be scanned.
    DataError(ScanError),
}

#[cfg(feature = "std")]
impl std::error::Error for RecordError {}

//--- Formatting

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnknownRecordType => "unknown record type",
            Self::MissingOrigin => "the origin name is unknown",
            Self::MissingFirstField => "could not infer an omitted field",
            Self::MissingFields => "one or more required fields were missing",
            Self::MultipleTTLs => "multiple TTLs were specified",
            Self::MultipleClasses => "multiple record classes were specified",
            Self::OwnerError(err) => {
                return write!(f, "could not parse the owner name: {err}")
            }
            Self::ClassError(err) => {
                return write!(f, "could not parse the record class: {err}")
            }
            Self::TTLError(err) => {
                return write!(f, "could not parse the record TTL: {err}")
            }
            Self::DataError(err) => {
                return write!(f, "could not parse the record data: {err}")
            }
        })
    }
}

//----------- DirectiveError -------------------------------------------------

/// An error in scanning a zonefile directive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectiveError {
    /// A directive was missing some fields.
    MissingFields,

    /// An include directive contained an invalid file name.
    InvalidIncludePath,

    /// An invalid origin name was specified.
    InvalidOrigin,

    /// An invalid TTL was specified.
    InvalidTTL,

    /// An unknown directive was used.
    UnknownDirective,
}

#[cfg(feature = "std")]
impl std::error::Error for DirectiveError {}

//--- Formatting

impl fmt::Display for DirectiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MissingFields => "one or more required fields were missing",
            Self::InvalidIncludePath => "could not parse the include path",
            Self::InvalidOrigin => "could not parse the origin name",
            Self::InvalidTTL => "could not parse the TTL",
            Self::UnknownDirective => "unrecognized directive",
        })
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use core::net::Ipv4Addr;
    use std::path::PathBuf;

    use crate::new::{
        base::{
            name::{NameBuf, RevNameBuf},
            wire::{U16, U32},
            RClass, RType, Record, Serial, TTL,
        },
        rdata::{Mx, Ns, RecordData, Soa, A},
    };

    use super::{Entry, ZonefileScanner};

    #[test]
    fn rfc1035() {
        let source: &[u8] = br#"
$TTL 42
@   IN  SOA     VENERA      Action-domains (
                                 20     ; SERIAL
                                 7200   ; REFRESH
                                 600    ; RETRY
                                 3600000; EXPIRE
                                 60)    ; MINIMUM

        NS      A.ISI.EDU.
        NS      VENERA
        NS      VAXA
        MX      10      VENERA
        MX      20      VAXA

A       A       26.3.0.103

VENERA  A       10.1.0.52
        A       128.9.0.32

VAXA    A       10.2.0.27
        A       128.9.0.33


$INCLUDE <SUBSYS>ISI-MAILBOXES.TXT
"#;

        let origin: RevNameBuf = "ISI.EDU".parse().unwrap();

        let addrs = [
            Ipv4Addr::new(26, 3, 0, 103),
            Ipv4Addr::new(10, 1, 0, 52),
            Ipv4Addr::new(128, 9, 0, 32),
            Ipv4Addr::new(10, 2, 0, 27),
            Ipv4Addr::new(128, 9, 0, 33),
        ]
        .map(A::from);

        let records = [
            Record::<RevNameBuf, RecordData<'_, NameBuf>> {
                rname: origin.clone(),
                rtype: RType::SOA,
                rclass: RClass::IN,
                ttl: TTL::from(42),
                rdata: RecordData::Soa(Soa {
                    mname: "VENERA.ISI.EDU".parse().unwrap(),
                    rname: "Action-domains.ISI.EDU".parse().unwrap(),
                    serial: Serial::from(20),
                    refresh: U32::new(7200),
                    retry: U32::new(600),
                    expire: U32::new(3_600_000),
                    minimum: U32::new(60),
                }),
            },
            Record {
                rname: origin.clone(),
                rtype: RType::NS,
                rclass: RClass::IN,
                ttl: TTL::from(42),
                rdata: RecordData::Ns(Ns {
                    server: "A.ISI.EDU".parse().unwrap(),
                }),
            },
            Record {
                rname: origin.clone(),
                rtype: RType::NS,
                rclass: RClass::IN,
                ttl: TTL::from(42),
                rdata: RecordData::Ns(Ns {
                    server: "VENERA.ISI.EDU".parse().unwrap(),
                }),
            },
            Record {
                rname: origin.clone(),
                rtype: RType::NS,
                rclass: RClass::IN,
                ttl: TTL::from(42),
                rdata: RecordData::Ns(Ns {
                    server: "VAXA.ISI.EDU".parse().unwrap(),
                }),
            },
            Record {
                rname: origin.clone(),
                rtype: RType::MX,
                rclass: RClass::IN,
                ttl: TTL::from(42),
                rdata: RecordData::Mx(Mx {
                    preference: U16::new(10),
                    exchange: "VENERA.ISI.EDU".parse().unwrap(),
                }),
            },
            Record {
                rname: origin.clone(),
                rtype: RType::MX,
                rclass: RClass::IN,
                ttl: TTL::from(42),
                rdata: RecordData::Mx(Mx {
                    preference: U16::new(20),
                    exchange: "VAXA.ISI.EDU".parse().unwrap(),
                }),
            },
            Record {
                rname: "A.ISI.EDU".parse().unwrap(),
                rtype: RType::A,
                rclass: RClass::IN,
                ttl: TTL::from(42),
                rdata: RecordData::A(addrs[0]),
            },
            Record {
                rname: "VENERA.ISI.EDU".parse().unwrap(),
                rtype: RType::A,
                rclass: RClass::IN,
                ttl: TTL::from(42),
                rdata: RecordData::A(addrs[1]),
            },
            Record {
                rname: "VENERA.ISI.EDU".parse().unwrap(),
                rtype: RType::A,
                rclass: RClass::IN,
                ttl: TTL::from(42),
                rdata: RecordData::A(addrs[2]),
            },
            Record {
                rname: "VAXA.ISI.EDU".parse().unwrap(),
                rtype: RType::A,
                rclass: RClass::IN,
                ttl: TTL::from(42),
                rdata: RecordData::A(addrs[3]),
            },
            Record {
                rname: "VAXA.ISI.EDU".parse().unwrap(),
                rtype: RType::A,
                rclass: RClass::IN,
                ttl: TTL::from(42),
                rdata: RecordData::A(addrs[4]),
            },
        ];

        let mut expected = records
            .iter()
            .map(|r| {
                Entry::Record(Record {
                    rname: &*r.rname,
                    rtype: r.rtype,
                    rclass: r.rclass,
                    ttl: r.ttl,
                    rdata: r.rdata.map_names_by_ref(|n| &**n),
                })
            })
            .chain([Entry::Include {
                file_name: PathBuf::from("<SUBSYS>ISI-MAILBOXES.TXT"),
                origin: Some(&origin),
            }]);

        let mut scanner = ZonefileScanner::new(source, Some(&origin));
        loop {
            let expected = expected.next();
            let actual = scanner.scan().unwrap();
            assert_eq!(expected, actual);
            if expected.is_none() {
                break;
            }
        }
    }
}
