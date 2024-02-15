/// A source for creating new buffers.
/// 
/// A buffer source is used by servers to allocate new buffers when needed,
/// for example to store an incoming request.
/// 
/// If the size is known in advance a specific size of buffer can be
/// requested, otherwise use the default.
pub trait BufSource {
    type Output: AsRef<[u8]> + AsMut<[u8]>;

    /// Creates a buffer with the default properties for this source.
    fn create_buf(&self) -> Self::Output;

    /// Creates a buffer large enough to hold the specified number of bytes.
    fn create_sized(&self, size: usize) -> Self::Output;
}
