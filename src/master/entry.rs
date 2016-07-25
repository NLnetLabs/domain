
use std::ascii::AsciiExt;
use std::io;
use std::rc::Rc;
use ::bits::DNameBuf;
use ::iana::Class;
use ::master::{Error, Pos, Result, Stream};
use ::master::record::{MasterRecord, map_origin};


//------------ Entry ---------------------------------------------------------

pub enum Entry {
    Origin(Rc<DNameBuf>),
    Include { path: Vec<u8>, origin: Option<Rc<DNameBuf>> },
    Ttl(u32),
    Control { name: Vec<u8>, start: Pos },
    Record(MasterRecord)
}

impl Entry {
    pub fn scan<R: io::Read>(stream: &mut Stream<R>,
                             last_owner: Option<Rc<DNameBuf>>,
                             last_class: Option<Class>,
                             origin: &Option<Rc<DNameBuf>>,
                             default_ttl: Option<u32>)
                             -> Result<Option<Self>> {
        while let Ok(()) = stream.scan_newline() { }
        if let Ok(true) = stream.is_eof() {
            return Ok(None)
        }
        let res = match try!(ControlType::scan_opt(stream)) {
            Some(ControlType::Origin) => {
                let origin = map_origin(origin);
                Entry::Origin(Rc::new(try!(DNameBuf::scan(stream, origin))))
            }
            Some(ControlType::Include) => {
                Entry::Include {
                    path: try!(stream.scan_phrase_copy()),
                    origin: DNameBuf::scan(stream, map_origin(origin))
                                     .map(|n| Rc::new(n)).ok()
                }
            }
            Some(ControlType::Ttl) => {
                Entry::Ttl(try!(stream.scan_u32()))
            }
            Some(ControlType::Other(name, pos)) => {
                Entry::Control { name: name, start: pos }
            }
            None => {
                Entry::Record(try!(MasterRecord::scan(stream, last_owner,
                                                      last_class, origin,
                                                      default_ttl)))
            }
        };
        try!(stream.scan_newline());
        Ok(Some(res))
    }
}


//------------ ControlType ---------------------------------------------------

enum ControlType {
    Origin,
    Include,
    Ttl,
    Other(Vec<u8>, Pos)
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
                // XXX Master-encode non-ASCII characters.
                Ok(ControlType::Other(word.to_owned(), pos))
            }
        }).map(|x| Some(x))
    }
}

