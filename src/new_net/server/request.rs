//! DNS request messages.

use crate::new_base::Message;

/// A DNS request message.
pub struct RequestMessage<'b> {
    /// The underlying [`Message`].
    pub message: &'b Message,

    /// Cached indices of the initial questions and records.
    indices: [(u16, u16); 8],

    /// Cached indices of the EDNS options in the message.
    edns_indices: [(u16, u16); 8],

    /// The number of components before the end of every section.
    section_offsets: [u16; 4],
}
