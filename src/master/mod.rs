
use ::bits::{DNameBuf, DNameSlice};
use ::iana::Class;

pub use self::error::{Error, Result, SyntaxError, SyntaxResult};
pub use self::stream::Stream;


pub mod control;
pub mod error;
pub mod record;
pub mod stream;


//------------ Zonefile ------------------------------------------------------

pub struct Zonefile {
    origin: Option<DNameBuf>,
    includes: Vec<Include>,
    ttl: Option<u32>,
    warnings: Vec<(Pos, String)>
}

impl Zonefile {
    pub fn origin(&self) -> Option<&DNameSlice> {
        match self.origin {
            Some(ref name) => Some(name),
            None => None
        }
    }

    pub fn set_origin(&mut self, origin: DNameBuf) {
        self.origin = Some(origin)
    }

    pub fn ttl(&self) -> Option<u32> {
        self.ttl
    }

    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = Some(ttl)
    }

    pub fn last_class(&self) -> Option<Class> {
        unimplemented!()
    }

    pub fn last_owner(&self) -> Option<DNameBuf> {
        unimplemented!()
    }


    pub fn add_include(&mut self, path: Vec<u8>, origin: Option<DNameBuf>) {
        self.includes.push(Include { path: path, origin: origin })
    }

    pub fn add_warning(&mut self, pos: Pos, text: String) {
        self.warnings.push((pos, text))
    }
}


//------------ Include ------------------------------------------------------

pub struct Include {
    pub path: Vec<u8>,
    pub origin: Option<DNameBuf>,
}


//------------ Pos -----------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Pos {
    line: usize,
    col: usize
}

impl Pos {
    pub fn new() -> Pos {
        Pos { line: 1, col: 1 }
    }

    pub fn update(&mut self, ch: u8) {
        match ch {
            b'\n' => self.line += 1,
            _ => self.col += 1
        }
    }
}



