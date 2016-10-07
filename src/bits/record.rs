//! Resource Records

use std::fmt;
use super::{Composer, ComposeError, ComposeResult, DName, GenericRecordData,
            PackedDName, ParsedRecordData, Parser, ParseResult, RecordData};
use ::iana::{Class, Rtype};


//------------ Record --------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Record<N: DName, D: RecordData> {
    name: N,
    class: Class,
    ttl: u32,
    data: D
}


/// # Creation and Element Access
///
impl<N: DName, D: RecordData> Record<N, D> {
    /// Creates a new record from its parts.
    pub fn new(name: N, class: Class, ttl: u32, data: D) -> Self {
        Record{name: name, class: class, ttl: ttl, data: data}
    }

    /// Returns a reference to the domain name.
    pub fn name(&self) -> &N {
        &self.name
    }

    /// Returns a mutable reference to the domain name.
    pub fn name_mut(&mut self) -> &mut N {
        &mut self.name
    }

    /// Returns the record type.
    pub fn rtype(&self) -> Rtype {
        self.data.rtype()
    }

    /// Returns the record class.
    pub fn class(&self) -> Class {
        self.class
    }

    /// Sets the record’s class.
    pub fn set_class(&mut self, class: Class) {
        self.class = class
    }

    /// Returns the record’s time-to-live.
    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Sets the record’s time-to-live.
    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl
    }

    /// Return a reference to the record data.
    pub fn data(&self) -> &D {
        &self.data
    }

    /// Returns a mutable reference to the record data.
    pub fn data_mut(&mut self) -> &mut D {
        &mut self.data
    }

    /// Converts the record into its record data.
    pub fn into_data(self) -> D {
        self.data
    }
}


/// # Parsing
///
impl<'a, D: ParsedRecordData<'a>> Record<PackedDName<'a>, D> {
    pub fn parse(parser: &mut Parser<'a>) -> ParseResult<Option<Self>> {
        let name = try!(PackedDName::parse(parser));
        let rtype = try!(Rtype::parse(parser));
        let class = try!(Class::parse(parser));
        let ttl = try!(parser.parse_u32());
        let rdlen = try!(parser.parse_u16()) as usize;
        try!(parser.set_limit(rdlen));
        let data = try!(D::parse(rtype, parser));
        if data.is_none() {
            try!(parser.skip(rdlen));
        }
        parser.remove_limit();
        Ok(data.map(|data| Record::new(name, class, ttl, data)))
    }
}

impl<'a> Record<PackedDName<'a>, GenericRecordData<'a>> {
    pub fn parse_generic(parser: &mut Parser<'a>) -> ParseResult<Self> {
        Self::parse(parser).map(Option::unwrap)
    }
}
    

/// # Composing
///
impl<N: DName, D: RecordData> Record<N, D> {
    pub fn compose<C: AsMut<Composer>>(&self, mut composer: C)
                                       -> ComposeResult<()> {
        try!(self.name.compose(composer.as_mut()));
        try!(self.data.rtype().compose(composer.as_mut()));
        try!(self.class.compose(composer.as_mut()));
        try!(composer.as_mut().compose_u32(self.ttl));
        let pos = composer.as_mut().pos();
        try!(composer.as_mut().compose_u16(0));
        try!(self.data.compose(composer.as_mut()));
        let delta = composer.as_mut().delta(pos) - 2;
        if delta > (::std::u16::MAX as usize) {
            return Err(ComposeError::Overflow)
        }
        composer.as_mut().update_u16(pos, delta as u16);
        Ok(())
    }
}


//--- Display

impl<N: DName, D: RecordData + fmt::Display> fmt::Display for Record<N, D> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}\t{}\t{}\t{}\t{}",
               self.name, self.ttl, self.class, self.data.rtype(),
               self.data)
    }
}


//------------ GenericRecord -------------------------------------------------

pub type GenericRecord<'a> = Record<PackedDName<'a>, GenericRecordData<'a>>;

