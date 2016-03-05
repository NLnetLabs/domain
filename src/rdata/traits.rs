use ::bytes::{BytesBuf};
use ::question::Result;

pub trait BuildRecordData {
    fn rtype(&self) -> u16;
    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()>;
}

pub trait RecordDataSlice<'a>: Sized {
    fn parse(rtype: u16, rdata: &'a[u8]) -> Option<Result<Self>>;
}

pub trait ConcreteRecordData<'a>: Sized {
    fn rtype() -> u16;
    fn rname() -> &'static str;
    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()>;
    fn parse(rdata: &'a[u8]) -> Result<Self>;
}

impl<'a, C: ConcreteRecordData<'a>> BuildRecordData for C {
    fn rtype(&self) -> u16 { Self::rtype() }
    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()> {
        self.push_buf(buf)
    }
}

impl<'a, C: ConcreteRecordData<'a>> RecordDataSlice<'a> for C {
    fn parse(rtype: u16, rdata: &'a[u8]) -> Option<Result<Self>> {
        if rtype != Self::rtype() { None }
        else { Some(Self::parse(rdata)) }
    }
}
