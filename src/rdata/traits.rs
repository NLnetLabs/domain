use ::bytes::{BytesBuf};
use ::question::Result;

pub trait BuildRecordData {
    fn rtype(&self) -> u16;
    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()>;
}

pub trait RecordDataSlice<'a>: Sized {
    type Owned: BuildRecordData;

    fn parse(rtype: u16, rdata: &'a[u8], context: &'a [u8])
             -> Result<Option<Self>>;
    fn to_owned(&self) -> Self::Owned;
}

pub trait ConcreteRecordData<'a>: Sized {
    fn rtype() -> u16;
    fn rname() -> &'static str;
    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()>;
    fn parse(rdata: &'a[u8], context: &'a [u8]) -> Result<Self>;
    fn to_owned(&self) -> Self;
}

impl<'a, C: ConcreteRecordData<'a>> BuildRecordData for C {
    fn rtype(&self) -> u16 { Self::rtype() }
    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()> {
        self.push_buf(buf)
    }
}

impl<'a, C: ConcreteRecordData<'a>> RecordDataSlice<'a> for C {
    type Owned = Self;

    fn parse(rtype: u16, rdata: &'a[u8], context: &'a [u8])
             -> Result<Option<Self>> {
        if rtype != Self::rtype() { Ok(None) }
        else { Ok(Some(try!(Self::parse(rdata, context)))) }
    }
    fn to_owned(&self) -> Self {
        self.to_owned()
    }
}
