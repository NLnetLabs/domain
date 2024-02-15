//! Buffer types and allocation strategies.
use std::vec::Vec;

use super::traits::buf::BufSource;

//----------- VecBufSource --------------------------------------------------

/// A source for creating [`Vec<u8>`] based buffers.
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
