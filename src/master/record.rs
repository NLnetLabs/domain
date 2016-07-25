
use std::io;
use std::rc::Rc;
use ::bits::{DNameBuf, DNameSlice};
use ::iana::{Class, RRType};
use ::rdata;
use super::{Result, Stream, SyntaxError};


#[derive(Clone, Debug, PartialEq)]
pub struct MasterRecord {
    owner: Rc<DNameBuf>,
    rtype: RRType,
    class: Class,
    ttl: u32,
    rdata: Vec<u8>,
}

impl MasterRecord {
    pub fn new(owner: Rc<DNameBuf>, rtype: RRType, class: Class, ttl: u32,
               rdata: Vec<u8>) -> Self {
        MasterRecord { owner: owner, rtype: rtype, class: class,
                       ttl: ttl, rdata: rdata }
    }
}

impl MasterRecord {
    pub fn scan<R: io::Read>(stream: &mut Stream<R>,
                             last_owner: Option<Rc<DNameBuf>>,
                             last_class: Option<Class>,
                             origin: &Option<Rc<DNameBuf>>,
                             default_ttl: Option<u32>) -> Result<Self> {
        let owner = try!(MasterRecord::scan_owner(stream, last_owner,
                                                  &origin));
        let (ttl, class) = try!(MasterRecord::scan_ttl_class(stream,
                                                             default_ttl,
                                                             last_class));
        let rtype = try!(RRType::scan(stream));
        let rdata = try!(rdata::scan(rtype, stream, map_origin(origin)));
        try!(stream.scan_newline());
        Ok(MasterRecord::new(owner, rtype, class, ttl, rdata))
    }

    /// Scans the owner.
    ///
    /// Returns new owner and origin.
    fn scan_owner<R: io::Read>(stream: &mut Stream<R>,
                               last_owner: Option<Rc<DNameBuf>>,
                               origin: &Option<Rc<DNameBuf>>)
                               -> Result<Rc<DNameBuf>> {
        if try!(stream.skip_opt_space()) {
            if let Some(owner) = last_owner { Ok(owner) }
            else { stream.err(SyntaxError::NoLastOwner) }
        }
        else if let Ok(()) = stream.skip_literal(b"@") {
            if let &Some(ref origin) = origin { Ok(origin.clone()) }
            else { stream.err(SyntaxError::NoOrigin) }
        }
        else {
            Ok(Rc::new(try!(DNameBuf::scan(stream, map_origin(origin)))))
        }
    }

    fn scan_ttl_class<R: io::Read>(stream: &mut Stream<R>,
                                   default_ttl: Option<u32>,
                                   last_class: Option<Class>)
                                   -> Result<(u32, Class)> {
        let (ttl, class) = match stream.scan_u32() {
            Ok(ttl) => {
                try!(stream.skip_opt_space());
                match Class::scan(stream) {
                    Ok(class) => {
                        try!(stream.skip_opt_space());
                        (Some(ttl), Some(class))
                    }
                    Err(_) => (Some(ttl), None)
                }
            }
            Err(_) => {
                match Class::scan(stream) {
                    Ok(class) => {
                        try!(stream.skip_opt_space());
                        match stream.scan_u32() {
                            Ok(ttl) => {
                                try!(stream.skip_opt_space());
                                (Some(ttl), Some(class))
                            }
                            Err(_) => (None, Some(class))
                        }
                    }
                    Err(_) => (None, None)
                }
            }
        };
        let ttl = match ttl.or(default_ttl) {
            Some(ttl) => ttl,
            None => return stream.err(SyntaxError::NoDefaultTtl)
        };
        let class = match class.or(last_class) {
            Some(class) => class,
            None => return stream.err(SyntaxError::NoLastClass)
        };
        Ok((ttl, class))
    }
}


pub fn map_origin<'a>(origin: &'a Option<Rc<DNameBuf>>)
                      -> Option<&'a DNameSlice> {
    match origin {
        &Some(ref rc) => Some(rc),
        &None => None
    }
}
