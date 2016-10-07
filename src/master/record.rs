
use std::fmt;
use std::rc::Rc;
use ::bits::{DNameBuf, DNameSlice, RecordData};
use ::iana::{Class, Rtype};
use ::rdata::MasterRecordData;
use super::{ScanError, ScanResult, Scanner, SyntaxError};


#[derive(Clone, Debug)]
pub struct MasterRecord {
    pub owner: Rc<DNameBuf>,
    pub class: Class,
    pub ttl: u32,
    pub rdata: MasterRecordData,
}

impl MasterRecord {
    pub fn new(owner: Rc<DNameBuf>, class: Class, ttl: u32,
               rdata: MasterRecordData) -> Self {
        MasterRecord { owner: owner, class: class,
                       ttl: ttl, rdata: rdata }
    }
}

impl MasterRecord {
    pub fn scan<S: Scanner>(stream: &mut S,
                             last_owner: Option<Rc<DNameBuf>>,
                             last_class: Option<Class>,
                             origin: &Option<Rc<DNameBuf>>,
                             default_ttl: Option<u32>) -> ScanResult<Self> {
        let owner = try!(MasterRecord::scan_owner(stream, last_owner,
                                                  &origin));
        let (ttl, class) = try!(MasterRecord::scan_ttl_class(stream,
                                                             default_ttl,
                                                             last_class));
        let rtype = try!(Rtype::scan(stream));
        let rdata = try!(MasterRecordData::scan(rtype, stream,
                                                map_origin(origin)));
        try!(stream.scan_newline());
        Ok(MasterRecord::new(owner, class, ttl, rdata))
    }

    /// Scans the owner.
    ///
    /// Returns new owner and origin.
    fn scan_owner<S: Scanner>(stream: &mut S,
                               last_owner: Option<Rc<DNameBuf>>,
                               origin: &Option<Rc<DNameBuf>>)
                               -> ScanResult<Rc<DNameBuf>> {
        let pos = stream.pos();
        if let Ok(()) = stream.scan_space() {
            if let Some(owner) = last_owner { Ok(owner) }
            else { Err(ScanError::Syntax(SyntaxError::NoLastOwner, pos)) }
        }
        else if let Ok(()) = stream.skip_literal(b"@") {
            if let Some(ref origin) = *origin { Ok(origin.clone()) }
            else { Err(ScanError::Syntax(SyntaxError::NoOrigin, pos)) }
        }
        else {
            Ok(Rc::new(try!(stream.scan_dname(map_origin(origin)))))
        }
    }

    fn scan_ttl_class<S: Scanner>(stream: &mut S, default_ttl: Option<u32>,
                                   last_class: Option<Class>)
                                   -> ScanResult<(u32, Class)> {
        let pos = stream.pos();
        let (ttl, class) = match stream.scan_u32() {
            Ok(ttl) => {
                match Class::scan(stream) {
                    Ok(class) => {
                        (Some(ttl), Some(class))
                    }
                    Err(_) => (Some(ttl), None)
                }
            }
            Err(_) => {
                match Class::scan(stream) {
                    Ok(class) => {
                        match stream.scan_u32() {
                            Ok(ttl) => {
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
            None => {
                return Err(ScanError::Syntax(SyntaxError::NoDefaultTtl, pos))
            }
        };
        let class = match class.or(last_class) {
            Some(class) => class,
            None => {
                return Err(ScanError::Syntax(SyntaxError::NoLastClass, pos))
            }
        };
        Ok((ttl, class))
    }
}

impl fmt::Display for MasterRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} {} {}",
               self.owner, self.ttl, self.class,
               self.rdata.rtype(), self.rdata)
    }
}


pub fn map_origin(origin: &Option<Rc<DNameBuf>>) -> Option<&DNameSlice> {
    match *origin {
        Some(ref rc) => Some(rc),
        None => None
    }
}
