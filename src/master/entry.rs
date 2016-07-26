
use std::ascii::AsciiExt;
use std::io;
use std::rc::Rc;
use ::bits::DNameBuf;
use ::iana::Class;
use ::master::{Pos, Result, Stream};
use ::master::record::{MasterRecord, map_origin};


//------------ Entry ---------------------------------------------------------

#[derive(Clone, Debug)]
pub enum Entry {
    Origin(Rc<DNameBuf>),
    Include { path: Vec<u8>, origin: Option<Rc<DNameBuf>> },
    Ttl(u32),
    Control { name: Vec<u8>, start: Pos },
    Record(MasterRecord),
    Blank
}

impl Entry {
    pub fn scan<R: io::Read>(stream: &mut Stream<R>,
                             last_owner: Option<Rc<DNameBuf>>,
                             last_class: Option<Class>,
                             origin: &Option<Rc<DNameBuf>>,
                             default_ttl: Option<u32>)
                             -> Result<Option<Self>> {
        if let Ok(true) = stream.is_eof() {
            Ok(None)
        }
        else if let Ok(entry) = Entry::scan_control(stream, origin) {
            Ok(Some(entry))
        }
        else if let Ok(record) = MasterRecord::scan(stream, last_owner,
                                                    last_class, origin,
                                                    default_ttl) {
            Ok(Some(Entry::Record(record)))
        }
        else {
            try!(stream.skip_space());
            try!(stream.scan_newline());
            Ok(Some(Entry::Blank))
        }
    }

    fn scan_control<R: io::Read>(stream: &mut Stream<R>,
                                 origin: &Option<Rc<DNameBuf>>)
                                 -> Result<Self> {
        match try!(ControlType::scan(stream)) {
            ControlType::Origin => {
                let origin = map_origin(origin);
                let name = try!(DNameBuf::scan(stream, origin));
                try!(stream.scan_newline());
                Ok(Entry::Origin(Rc::new(name)))
            }
            ControlType::Include => {
                let path = try!(stream.scan_phrase_copy());
                let origin = DNameBuf::scan(stream, map_origin(origin))
                                      .map(|n| Rc::new(n)).ok();
                try!(stream.scan_newline());
                Ok(Entry::Include { path: path, origin: origin })
            }
            ControlType::Ttl => {
                let ttl = try!(stream.scan_u32());
                try!(stream.scan_newline());
                Ok(Entry::Ttl(ttl))
            }
            ControlType::Other(name, pos) => {
                try!(stream.skip_entry());
                Ok(Entry::Control { name: name, start: pos })
            }
        }
    }
}


//------------ ControlType ---------------------------------------------------

#[derive(Clone, Debug)]
enum ControlType {
    Origin,
    Include,
    Ttl,
    Other(Vec<u8>, Pos)
}

impl ControlType {
    pub fn scan<R: io::Read>(stream: &mut Stream<R>) -> Result<Self> {
        let pos = stream.pos();
        try!(stream.skip_char(b'$'));
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
                Ok(ControlType::Other(word.to_owned(), pos))
            }
        })
    }
}

