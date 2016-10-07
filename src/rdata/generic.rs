
use std::fmt;
use ::master::{Scanner, ScanResult, SyntaxError};

/// Scan generic master format record data into a bytes buf.
///
/// This function *only* scans the generic record data format defined
/// in [RFC 3597].
///
/// [RFC 3597]: https:://tools.ietf.org/html/rfc3597
/// [`domain::rdata::scan_into()`]: ../../rdata/fn.scan_into.html
pub fn scan<S: Scanner>(scanner: &mut S) -> ScanResult<Vec<u8>> {
    let mut target = Vec::new();
    try!(scanner.skip_literal(b"\\#"));
    let mut len = try!(scanner.scan_u16());
    target.reserve(len as usize);
    while len > 0 {
        try!(scanner.scan_hex_word(|v| {
            if len == 0 { Err(SyntaxError::LongGenericData) }
            else {
                target.push(v);
                len -= 1;
                Ok(())
            }
        }))
    }
    Ok(target)
}

pub fn fmt(data: &[u8], f: &mut fmt::Formatter) -> fmt::Result {
    let mut some = false;
    for chunk in data.chunks(2) {
        if some { try!(write!(f, " ")); }
        else { some = true }
        try!(write!(f, "{:02x}", chunk[0]));
        if let Some(ch) = chunk.get(1) {
            try!(write!(f, "{:02x}", ch));
        }
    }
    Ok(())
}
