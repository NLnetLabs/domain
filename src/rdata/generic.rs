
use ::bits::bytes::BytesBuf;
use ::master::{Scanner, ScanResult, SyntaxError};

/// Scan generic master format record data into a bytes buf.
///
/// This function *only* scans the generic record data format defined
/// in [RFC 3597]. Use [`domain::rdata::scan_into()`] for a function that
/// tries to also scan the specific record data format for record type
/// `rtype`.
///
/// [RFC 3597]: https:://tools.ietf.org/html/rfc3597
/// [`domain::rdata::scan_into()`]: ../../rdata/fn.scan_into.html
fn scan_into<S: Scanner>(scanner: &mut S, target: &mut Vec<u8>)
                         -> ScanResult<()> {
    try!(scanner.skip_literal(b"\\#"));
    let mut len = try!(scanner.scan_u16());
    target.reserve(len as usize);
    while len > 0 {
        try!(scanner.scan_hex_word(|v| {
            if len == 0 { Err(SyntaxError::LongGenericData) }
            else {
                target.push_u8(v);
                len -= 1;
                Ok(())
            }
        }))
    }
    Ok(())
}

pub fn scan<S: Scanner>(scanner: &mut S) -> ScanResult<Vec<u8>> {
    let mut res = Vec::new();
    try!(scan_into(scanner, &mut res));
    Ok(res)
}
