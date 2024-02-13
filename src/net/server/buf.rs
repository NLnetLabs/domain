use std::vec::Vec;

//------------ BufSource ----------------------------------------------------

pub trait BufSource {
    type Output: AsRef<[u8]> + AsMut<[u8]>;

    fn create_buf(&self) -> Self::Output;

    fn create_sized(&self, size: usize) -> Self::Output;
}

//----------- VecBufSource --------------------------------------------------

pub struct VecBufSource;

impl BufSource for VecBufSource {
    type Output = Vec<u8>;

    fn create_buf(&self) -> Self::Output {
        vec![0; 1024]
    }

    fn create_sized(&self, size: usize) -> Self::Output {
        vec![0; size]
    }
}
