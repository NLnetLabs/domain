//! Reading and writing zone files.
//!
//! A "zone file" is a textual representation of a DNS zone.  The zone file
//! specifies the records that make up the zone.  Each record is specified on
//! its own line, and consists of several whitespace-separated fields.
//!
//! Here's a simple example of a zone file (from [RFC 1034, section 6.1]):
//!
//! ```text
//! .       IN      SOA     SRI-NIC.ARPA. HOSTMASTER.SRI-NIC.ARPA. (
//!                         870611          ;serial
//!                         1800            ;refresh every 30 min
//!                         300             ;retry every 5 min
//!                         604800          ;expire after a week
//!                         86400)          ;minimum of a day
//!                 NS      A.ISI.EDU.
//!                 NS      C.ISI.EDU.
//!                 NS      SRI-NIC.ARPA.
//!
//! EDU.    86400   NS      SRI-NIC.ARPA.
//!         86400   NS      C.ISI.EDU.
//!
//! ACC.ARPA.       A       26.6.0.65
//!                 HINFO   PDP-11/70 UNIX
//!                 MX      10 ACC.ARPA.
//!
//! USC-ISIC.ARPA.  CNAME   C.ISI.EDU.
//!
//! 65.0.6.26.IN-ADDR.ARPA.  PTR    ACC.ARPA.
//! 52.0.0.10.IN-ADDR.ARPA.  PTR    C.ISI.EDU.
//! 103.0.3.26.IN-ADDR.ARPA. PTR    A.ISI.EDU.
//!
//! A.ISI.EDU. 86400 A      26.3.0.103
//! C.ISI.EDU. 86400 A      10.0.0.52
//! ```
//!
//! [RFC 1034, section 6.1]: https://datatracker.ietf.org/doc/html/rfc1034#section-6.1
//!
//! The basic elements of the format become visible quickly.  Each line begins
//! a new DNS record, with whitespace-separated fields specifying the owner
//! name, record class, TTL, record type, and record data.  All fields except
//! the record type and data are optional -- when omitted, the last explicitly
//! specified values are used.  The format of the record data fields depends
//! on the record data type.  Semicolons begin comments and parentheses allow
//! record data to be continued across multiple lines.
//!
//! This module provides functionality for parsing records from a zone file,
//! and for serializing records into the zone file format.  It is designed to
//! maximize performance while maintaining a user-friendly API.  It minimizes
//! heap allocations (e.g. by reusing buffers) and supports parallelization.
//!
//! ## Usage
//!
// TODO
//!
//! ## Compatibility
//!
//! Unfortunately, the zone file format is quite underspecified.  While most
//! implementations are compatible enough with each other, users can only rely
//! on syntax exactly like the examples in the RFCs.  Contradictions in those
//! reference specifications have muddled the waters further.
//!
//! Zone files were designed to be written by hand.  The format offers various
//! niceties to this end, e.g. by allowing duplicate information to be omitted
//! in many places.  However, as the Internet has grown exponentially, zone
//! files are almost always machine generated.  Most zone files today actually
//! use a subset of the original syntax, and avoid the underspecified parts of
//! the format.
//!
//! This module only supports the most commonly used subset of the format.  It
//! does not allow for edge cases (i.e. situations where the RFCs are unclear)
//! that are also rejected by other implementations.  The specific subset it
//! employs is documented below.  These restrictions are not expected to cause
//! problems for the vast majority of users.
//!
//! ## Specification
//!
//! This section details the subset of the zone file format supported by this
//! module.  An official, concrete specification of the format has not been
//! published yet, so other implementations may support more or less.
//!
//! ```text
//! zone-file = ( entry? ws* comment? "\n" )*
//! entry = record | directive
//!
//! # Includes "\n" when wrapped within parentheses.
//! ws = [ \t\r]
//! comment = ";" [^\n]*
//!
//! # If the name, TTL or class are omitted, use the respective field of the
//! # closest preceding record where it was explicitly specified.  If no such
//! # record exists (e.g. because this is the first record), the file is
//! # malformed.
//! record = name? (ws+ (ttl (ws+ class)? | class (ws+ ttl)?) )? ws+ data
//!
//! # If it does not end with a period, a period and the origin name are
//! # appended.  The special name "@" means the origin name.  When the full
//! # domain name is encoded in the wire format, it must fit within 255 bytes.
//! # If an origin name is necessary but unknown, an error occurs.
//! name = (label ".")* label "."? | "@"
//!   # Must contain at most 63 bytes (after escapes are processed).
//!   label = ([a-zA-Z0-9-] | "\\" ascii-printable)+
//!
//! # All printable / graphic ASCII characters.
//! ascii-printable = '!'..='~'
//!
//! # An integer number of seconds.
//! ttl = [0-9]+
//!
//! # "CS" and "HS" exist, but are long obsolete.
//! # "CH" is obselete too, but some name servers abuse it for metadata.
//! class = "IN" | "CH" | "CLASS" [0-9]+
//!
//! # If the format of the record type is unknown, 'unknown-data' is used.
//! data = type ws+ (unknown-data | known-data)
//!
//! # Includes the identifiers for supported record types.
//! type = (...) | "TYPE" [0-9]+
//!
//! unknown-data = "\\#" ws+ ud-size ws+ ud-data
//!   # The size of the record data, in bytes.
//!   ud-size = [0-9]+
//!   ud-data = (ud-word (ws+ ud-word)*)?
//!   ud-word = ([0-9a-fA-F] [0-9a-fA-F])+
//!
//! known-data = (d-word (ws+ d-word)*)?
//!   d-word = ([^"\\\(\); \t\r\n] | "\\" ascii-printable | quoted-string)+
//!
//! quoted-string = "\"" ([^"\\\n] | "\\" (ascii-printable | ws))* "\""
//!
//! # A directive changes how the file is parsed.
//! directive = include-dir | origin-dir | ttl-dir
//!
//! # Like '#include' in C, process the referenced file in place here.
//! # 'name' (or this file's origin) is used as the origin for that file.
//! include-dir = "$INCLUDE" ws+ file-path (ws+ name)?
//! file-path = ([^ \\\t\r\n\(\)";] | "\\" ascii-printable | quoted-string)*
//!
//! # Set the origin name for all future entries in this file.
//! origin-dir = "$ORIGIN" ws+ name
//!
//! # Explicitly set a TTL, for use in implicit TTLs for records in this file.
//! ttl-dir = "$TTL" ws+ ttl
//! ```
//!
//! Every DNS record type (that is allowed within a zone file) has a standard
//! zone file format, which specifies how record data of that type should be
//! formatted in zone files.  As new record types are added occasionally, they
//! are the extensible part of the zone file format.  The format for a record
//! data type is documented on its type in [`rdata`](super::rdata).

#![cfg(feature = "zonefile")]
#![cfg_attr(docsrs, doc(cfg(feature = "zonefile")))]

pub mod entries;
pub mod scanner;
pub mod simple;
