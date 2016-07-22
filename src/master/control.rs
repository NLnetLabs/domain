
use std::ascii::AsciiExt;
use std::io;
use ::bits::name::DNameBuf;
use ::master::{Pos, Zonefile};
use ::master::error::{Error, Result};
use ::master::stream::{Newline, Stream};


pub fn scan_opt_control<R: io::Read>(stream: &mut Stream<R>,
                                     file: &mut Zonefile)
                                     -> Result<Option<Newline>> {
    Ok(match try!(ControlType::scan_opt(stream)) {
        None => None,
        Some(ControlType::Origin) => Some(try!(scan_origin(stream, file))),
        Some(ControlType::Include) => Some(try!(scan_include(stream, file))),
        Some(ControlType::Ttl) => Some(try!(scan_ttl(stream, file))),
        Some(ControlType::Other(name, pos))
            => Some(try!(scan_other(stream, name, pos, file)))
    })
}


//------------ ControlType ---------------------------------------------------

enum ControlType {
    Origin,
    Include,
    Ttl,
    Other(String, Pos)
}

impl ControlType {
    pub fn scan_opt<R: io::Read>(stream: &mut Stream<R>)
                                 -> Result<Option<Self>> {
        let pos = stream.pos();
        match stream.skip_char(b'$') {
            Ok(()) => { }
            Err(Error::Syntax(..)) => return Ok(None),
            Err(err) => return Err(err)
        }
        stream.scan_word(|word| {
            if word.eq_ignore_ascii_case(b"ORIGIN") {
                Ok(ControlType::Origin)
            }
            else if word.eq_ignore_ascii_case(b"INCLUDE") {
                Ok(ControlType::Include)
            }
            else if word.eq_ignore_ascii_case(b"TTL") {
                Ok(ControlType::Ttl)
            }
            else {
                // XXX Zonefile-encode non-ASCII characters.
                Ok(ControlType::Other(String::from_utf8_lossy(word)
                                             .into_owned(), pos))
            }
        }).map(|x| Some(x))
    }
}


//------------ Scanner functions for control types ---------------------------

/// Scans the $ORIGIN control entity.
fn scan_origin<R: io::Read>(stream: &mut Stream<R>,
                            file: &mut Zonefile) -> Result<Newline> {
    try!(stream.skip_opt_space());
    let origin = try!(DNameBuf::scan_absolute(stream));
    let res = try!(stream.scan_newline());
    file.set_origin(origin);
    Ok(res)
}

/// Scans the $INCLUDE control entity.
fn scan_include<R: io::Read>(stream: &mut Stream<R>,
                             file: &mut Zonefile) -> Result<Newline> {
    try!(stream.skip_opt_space());
    let path = try!(stream.scan_phrase(|path| Ok(Vec::from(path))));
    try!(stream.skip_opt_space());
    let origin = DNameBuf::scan_with_origin(stream, file.origin()).ok();
    let res = try!(stream.scan_newline());
    file.add_include(path, origin);
    Ok(res)
}

/// Scans the $TTL control entitiy defined in RFC 2308.
fn scan_ttl<R: io::Read>(stream: &mut Stream<R>,
                         file: &mut Zonefile) -> Result<Newline> {
    try!(stream.skip_opt_space());
    let ttl = try!(stream.scan_u32());
    let res = try!(stream.scan_newline());
    file.set_ttl(ttl);
    Ok(res)
}

fn scan_other<R: io::Read>(stream: &mut Stream<R>, name: String,
                           pos: Pos, file: &mut Zonefile) -> Result<Newline> {
    let res = try!(stream.skip_entry());
    file.add_warning(pos, format!("Unknown control entry '${}'", name));
    Ok(res)
}

