use super::ingress::Fragment;
use super::error::Result;

pub trait RecordData: Sized {
    fn rtype() -> u16;
    fn from_fragment(frag: &mut Fragment) -> Result<Self>;
}
