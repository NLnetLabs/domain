
use std::io;
use ::bits::{DName, DNameBuf};
use ::bits::nest::{Nest, NestBuf};
use ::bits::record::GenericRecord;
use ::iana::{Class, RRType};
use ::master::{Newline, Result, Stream, SyntaxError, Zonefile,};
use ::rdata;


pub fn scan_record<R: io::Read>(stream: &mut Stream<R>, file: &mut Zonefile)
                                -> Result<Newline> {
    let owner = DName::Owned(try!(scan_owner(stream, file)));
    let (ttl, class) = try!(scan_ttl_class(stream, file));
    let rtype = try!(RRType::scan(stream));
    let mut rdata = NestBuf::new();
    try!(rdata::scan_into(rtype, stream, file.origin(), &mut rdata));
    let res = try!(stream.scan_newline());
    file.add_record(GenericRecord::new_generic(owner, class, rtype, ttl, 
                                               Nest::Owned(rdata)));
    Ok(res)
}

fn scan_owner<R: io::Read>(stream: &mut Stream<R>, file: &mut Zonefile)
                           -> Result<DNameBuf> {
    if try!(stream.skip_opt_space()) {
        if let Some(name) = file.last_owner() {
            stream.ok(name)
        }
        else {
            stream.err(SyntaxError::NoLastOwner)
        }
    }
    else {
        let res = try!(DNameBuf::scan(stream, file.origin()));
        try!(stream.skip_opt_space());
        Ok(res)
    }
}

fn scan_ttl_class<R: io::Read>(stream: &mut Stream<R>, file: &mut Zonefile)
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
    let ttl = match ttl.or(file.ttl()) {
        Some(ttl) => ttl,
        None => return stream.err(SyntaxError::NoDefaultTtl)
    };
    let class = match class.or(file.last_class()) {
        Some(class) => class,
        None => return stream.err(SyntaxError::NoLastClass)
    };
    Ok((ttl, class))
}
