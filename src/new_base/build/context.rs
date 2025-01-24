//! Context for building DNS messages.

//----------- BuilderContext -------------------------------------------------

/// Context for building a DNS message.
///
/// This type holds auxiliary information necessary for building DNS messages,
/// e.g. name compression state.  To construct it, call [`default()`].
///
/// [`default()`]: Self::default()
#[derive(Clone, Debug, Default)]
pub struct BuilderContext {
    // TODO: Name compression.
    /// The current size of the message contents.
    pub size: usize,

    /// The state of the DNS message.
    pub state: MessageState,
}

//----------- MessageState ---------------------------------------------------

/// The state of a DNS message being built.
///
/// A DNS message consists of a header, questions, answers, authorities, and
/// additionals.  [`MessageState`] remembers the start position of the last
/// question or record in the message, allowing it to be modifying or removed
/// (for additional flexibility in the building process).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum MessageState {
    /// Questions are being built.
    ///
    /// The message already contains zero or more DNS questions.  If there is
    /// a last DNS question, its start position is unknown, so it cannot be
    /// modified or removed.
    ///
    /// This is the default state for an empty message.
    #[default]
    Questions,

    /// A question is being built.
    ///
    /// The message contains one or more DNS questions.  The last question can
    /// be modified or truncated.
    MidQuestion {
        /// The offset of the question name.
        ///
        /// The offset is measured from the start of the message contents.
        name: u16,
    },

    /// Answer records are being built.
    ///
    /// The message already contains zero or more DNS answer records.  If
    /// there is a last DNS record, its start position is unknown, so it
    /// cannot be modified or removed.
    Answers,

    /// An answer record is being built.
    ///
    /// The message contains one or more DNS answer records.  The last record
    /// can be modified or truncated.
    MidAnswer {
        /// The offset of the record name.
        ///
        /// The offset is measured from the start of the message contents.
        name: u16,

        /// The offset of the record data.
        ///
        /// The offset is measured from the start of the message contents.
        data: u16,
    },

    /// Authority records are being built.
    ///
    /// The message already contains zero or more DNS authority records.  If
    /// there is a last DNS record, its start position is unknown, so it
    /// cannot be modified or removed.
    Authorities,

    /// An authority record is being built.
    ///
    /// The message contains one or more DNS authority records.  The last
    /// record can be modified or truncated.
    MidAuthority {
        /// The offset of the record name.
        ///
        /// The offset is measured from the start of the message contents.
        name: u16,

        /// The offset of the record data.
        ///
        /// The offset is measured from the start of the message contents.
        data: u16,
    },

    /// Additional records are being built.
    ///
    /// The message already contains zero or more DNS additional records.  If
    /// there is a last DNS record, its start position is unknown, so it
    /// cannot be modified or removed.
    Additionals,

    /// An additional record is being built.
    ///
    /// The message contains one or more DNS additional records.  The last
    /// record can be modified or truncated.
    MidAdditional {
        /// The offset of the record name.
        ///
        /// The offset is measured from the start of the message contents.
        name: u16,

        /// The offset of the record data.
        ///
        /// The offset is measured from the start of the message contents.
        data: u16,
    },
}

impl MessageState {
    /// The current section index.
    ///
    /// Questions, answers, authorities, and additionals are mapped to 0, 1,
    /// 2, and 3, respectively.
    pub const fn section_index(&self) -> u8 {
        match self {
            Self::Questions | Self::MidQuestion { .. } => 0,
            Self::Answers | Self::MidAnswer { .. } => 1,
            Self::Authorities | Self::MidAuthority { .. } => 2,
            Self::Additionals | Self::MidAdditional { .. } => 3,
        }
    }
}
