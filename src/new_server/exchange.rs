//! Request-response exchanges for DNS servers.

use core::any::{Any, TypeId};
use std::{boxed::Box, time::SystemTime, vec::Vec};

use bumpalo::Bump;

use crate::{
    new_base::{
        build::{BuilderContext, MessageBuilder},
        name::{RevName, RevNameBuf},
        parse::SplitMessageBytes,
        wire::{BuildBytes, ParseError, TruncationError, U16},
        HeaderFlags, Message, Question, RType, Record,
    },
    new_edns::EdnsOption,
    new_rdata::{Opt, RecordData},
};

//----------- Exchange -------------------------------------------------------

/// A DNS request-response exchange.
///
/// An [`Exchange`] represents a request sent to a DNS server and the server's
/// response (as it is being built).  It tracks basic information about the
/// request, such as when it was sent and the connection it originates from,
/// as well as metadata stored by layers in the DNS server.
pub struct Exchange<'a> {
    /// An allocator for storing parts of the message.
    pub alloc: Allocator<'a>,

    /// When the exchange began (i.e. when the request was received).
    pub reception: SystemTime,

    /// The request message.
    pub request: ParsedMessage<'a>,

    /// The response message being built.
    pub response: ParsedMessage<'a>,

    /// Dynamic metadata stored by the DNS server.
    pub metadata: Vec<Metadata>,
}

//----------- OutgoingResponse -----------------------------------------------

/// An [`Exchange`] with an initialized response message.
pub struct OutgoingResponse<'e, 'a> {
    /// An allocator for storing parts of the message.
    pub alloc: &'e mut Allocator<'a>,

    /// The response message being built.
    pub response: &'e mut ParsedMessage<'a>,

    /// Dynamic metadata stored by the DNS server.
    pub metadata: &'e mut Vec<Metadata>,
}

impl<'e, 'a> OutgoingResponse<'e, 'a> {
    /// Construct an [`OutgoingResponse`] on an [`Exchange`].
    pub fn new(exchange: &'e mut Exchange<'a>) -> Self {
        Self {
            alloc: &mut exchange.alloc,
            response: &mut exchange.response,
            metadata: &mut exchange.metadata,
        }
    }

    /// Reborrow this response for a shorter lifetime.
    pub fn reborrow(&mut self) -> OutgoingResponse<'_, 'a> {
        OutgoingResponse {
            alloc: self.alloc,
            response: self.response,
            metadata: self.metadata,
        }
    }
}

//----------- ParsedMessage --------------------------------------------------

/// A pre-parsed DNS message.
///
/// This is a simple representation of DNS messages outside the wire format,
/// making it easy to inspect and modify them efficiently.
#[derive(Clone, Default, Debug)]
pub struct ParsedMessage<'a> {
    /// The message ID.
    pub id: U16,

    /// The message flags.
    pub flags: HeaderFlags,

    /// Questions in the message.
    pub questions: Vec<Question<&'a RevName>>,

    /// Answer records in the message.
    pub answers: Vec<Record<&'a RevName, RecordData<'a, &'a RevName>>>,

    /// Authority records in the message.
    pub authorities: Vec<Record<&'a RevName, RecordData<'a, &'a RevName>>>,

    /// Additional records in the message.
    ///
    /// If there is an EDNS record, it will be included here, but its record
    /// data (which contains the EDNS options) will be empty.  The options are
    /// stored in the `options` field for easier access.
    pub additional: Vec<Record<&'a RevName, RecordData<'a, &'a RevName>>>,

    /// EDNS options in the message.
    ///
    /// These options will be appended to the EDNS record in the additional
    /// section (there must be one for any options to exist).  The order of
    /// the options is meaningless.
    pub options: Vec<EdnsOption<'a>>,
}

impl<'a> ParsedMessage<'a> {
    /// Parse an existing [`Message`].
    ///
    /// Decompressed domain names are allocated using the given [`Bump`].
    pub fn parse(
        message: &'a Message,
        alloc: &mut Allocator<'a>,
    ) -> Result<Self, ParseError> {
        type ParsedQuestion = Question<RevNameBuf>;
        type ParsedRecord<'a> =
            Record<RevNameBuf, RecordData<'a, RevNameBuf>>;

        /// Map a domain name by placing it in a [`Bump`].
        fn map_name<'a>(
            name: RevNameBuf,
            alloc: &mut Allocator<'a>,
        ) -> &'a RevName {
            // Allocate the domain name.
            let name = alloc.alloc_slice_copy(name.as_bytes());
            // SAFETY: 'name' has the same bytes as the input 'name'.
            unsafe { RevName::from_bytes_unchecked(name) }
        }

        let mut this = Self::default();
        let mut offset = 0;

        // Parse the message header.
        this.id = message.header.id;
        this.flags = message.header.flags;
        let counts = message.header.counts;

        // Parse the question section.
        this.questions
            .reserve(counts.questions.get().max(256) as usize);
        for _ in 0..counts.questions.get() {
            let (question, rest) = ParsedQuestion::split_message_bytes(
                &message.contents,
                offset,
            )?;

            this.questions.push(Question {
                qname: map_name(question.qname, alloc),
                qtype: question.qtype,
                qclass: question.qclass,
            });
            offset = rest;
        }

        // Parse the answer section.
        this.answers.reserve(counts.answers.get().max(256) as usize);
        for _ in 0..counts.answers.get() {
            let (answer, rest) =
                ParsedRecord::split_message_bytes(&message.contents, offset)?;

            this.answers.push(Record {
                rname: map_name(answer.rname, alloc),
                rtype: answer.rtype,
                rclass: answer.rclass,
                ttl: answer.ttl,
                rdata: answer.rdata.map_names(|n| map_name(n, alloc)),
            });
            offset = rest;
        }

        // Parse the authority section.
        this.authorities
            .reserve(counts.authorities.get().max(256) as usize);
        for _ in 0..counts.authorities.get() {
            let (authority, rest) =
                ParsedRecord::split_message_bytes(&message.contents, offset)?;

            this.authorities.push(Record {
                rname: map_name(authority.rname, alloc),
                rtype: authority.rtype,
                rclass: authority.rclass,
                ttl: authority.ttl,
                rdata: authority.rdata.map_names(|n| map_name(n, alloc)),
            });
            offset = rest;
        }

        // The EDNS record data.
        let mut edns_data = None;

        // Parse the additional section.
        this.additional
            .reserve(counts.additional.get().max(256) as usize);
        for _ in 0..counts.additional.get() {
            let (mut additional, rest) =
                ParsedRecord::split_message_bytes(&message.contents, offset)?;

            if let RecordData::Opt(opt) = additional.rdata {
                if edns_data.is_some() {
                    // A message cannot contain two distinct EDNS records.
                    return Err(ParseError);
                }

                edns_data = Some(opt);

                // Deduplicate the EDNS data.
                additional.rdata = RecordData::Opt(Opt::EMPTY);
            }

            this.additional.push(Record {
                rname: map_name(additional.rname, alloc),
                rtype: additional.rtype,
                rclass: additional.rclass,
                ttl: additional.ttl,
                rdata: additional.rdata.map_names(|n| map_name(n, alloc)),
            });
            offset = rest;
        }

        // Ensure there's no other content in the message.
        if offset != message.contents.len() {
            return Err(ParseError);
        }

        // Parse EDNS options.
        if let Some(edns_data) = edns_data {
            for option in edns_data.options() {
                this.options.push(option?);
            }
        }

        Ok(this)
    }

    /// Build this message into the given buffer.
    ///
    /// If the message was too large, a [`TruncationError`] is returned.
    pub fn build<'b>(
        &self,
        buffer: &'b mut [u8],
    ) -> Result<&'b Message, TruncationError> {
        // Construct a 'MessageBuilder'.
        if buffer.len() < 12 {
            return Err(TruncationError);
        }
        let mut context = BuilderContext::default();
        let mut builder = MessageBuilder::new(buffer, &mut context);

        // Build the message header.
        let header = builder.header_mut();
        header.id = self.id;
        header.flags = self.flags;
        header.counts.questions.set(self.questions.len() as u16);
        header.counts.answers.set(self.answers.len() as u16);
        header.counts.authorities.set(self.authorities.len() as u16);
        header.counts.additional.set(self.additional.len() as u16);

        // Build the question section.
        for question in &self.questions {
            builder
                .build_question(question)?
                .expect("No answers, authorities, or additionals are built");
        }

        // Build the answer section.
        for answer in &self.answers {
            builder
                .build_answer(answer)?
                .expect("No authorities, or additionals are built");
        }

        // Build the authority section.
        for authority in &self.authorities {
            builder
                .build_authority(authority)?
                .expect("No additionals are built");
        }

        // Build the additional section.
        let mut edns_built = false;
        for additional in &self.additional {
            if additional.rtype == RType::OPT {
                // Technically, multiple OPT records are an error.  But this
                // isn't the right place to report that.
                debug_assert!(!edns_built, "Multiple EDNS records found");

                let mut builder = builder.build_additional(additional)?;
                let mut delegate = builder.delegate();
                let mut uninit = delegate.uninitialized();
                for option in &self.options {
                    uninit = option.build_bytes(uninit)?;
                }
                let uninit_len = uninit.len();
                let appended = delegate.uninitialized().len() - uninit_len;
                delegate.mark_appended(appended);
                core::mem::drop(delegate);
                builder.commit();

                edns_built = true;
                continue;
            }

            builder.build_additional(additional)?;
        }

        debug_assert!(
            self.options.is_empty() || edns_built,
            "EDNS options found, but no OPT record",
        );

        Ok(builder.finish())
    }
}

impl ParsedMessage<'_> {
    /// Reset this object to a blank message.
    ///
    /// This is helpful in order to reuse the underlying allocations.
    pub fn reset(&mut self) {
        self.id = U16::new(0);
        self.flags = HeaderFlags::default();
        self.questions.clear();
        self.answers.clear();
        self.authorities.clear();
        self.additional.clear();
        self.options.clear();
    }
}

//----------- Metadata -------------------------------------------------------

/// Arbitrary metadata about a DNS exchange.
///
/// This is an enhanced version of `Box<dyn Any + Send + 'static>` that can
/// perform downcasting more efficiently.
pub struct Metadata {
    /// The type ID of the object.
    type_id: TypeId,

    /// The underlying object.
    object: Box<dyn Any + Send + 'static>,
}

impl Metadata {
    /// Wrap an object in [`Metadata`].
    pub fn new<T: Any + Send + 'static>(object: T) -> Self {
        let type_id = TypeId::of::<T>();
        let object = Box::new(object) as Box<dyn Any + Send + 'static>;
        Self { type_id, object }
    }

    /// Check whether this is metadata of a certain type.
    pub fn is<T: Any + Send + 'static>(&self) -> bool {
        self.type_id == TypeId::of::<T>()
    }

    /// Try downcasting to a reference of a particular type.
    pub fn try_as<T: Any + Send + 'static>(&self) -> Option<&T> {
        if !self.is::<T>() {
            return None;
        }

        let pointer: *const (dyn Any + Send + 'static) = &*self.object;
        // SAFETY: 'pointer' was created by 'Box<T>::into_raw()', and thus is
        // safe to dereference (the pointer will only be dropped when 'self'
        // is, but that cannot happen during the current lifetime).
        Some(unsafe { &*pointer.cast::<T>() })
    }

    /// Try downcasting to a mutable reference of a particular type.
    pub fn try_as_mut<T: Any + Send + 'static>(&mut self) -> Option<&mut T> {
        if !self.is::<T>() {
            return None;
        }

        let pointer: *mut (dyn Any + Send + 'static) = &mut *self.object;
        // SAFETY: 'pointer' was created by 'Box<T>::into_raw()', and thus is
        // safe to dereference (the pointer will only be dropped when 'self'
        // is, but that cannot happen during the current lifetime).
        Some(unsafe { &mut *pointer.cast::<T>() })
    }

    /// Try moving this object out of the [`Metadata`].
    pub fn try_into<T: Any + Send + 'static>(self) -> Result<T, Self> {
        if !self.is::<T>() {
            return Err(self);
        }

        let pointer: *mut _ = Box::into_raw(self.object);
        // SAFETY: 'pointer' was created by 'Box<T>::into_raw()', and thus is
        // safe to move into the same 'Box<T>'.
        Ok(*unsafe { Box::from_raw(pointer.cast::<T>()) })
    }
}

//----------- Allocator ------------------------------------------------------

/// A bump allocator with a fixed lifetime.
///
/// This is a wrapper around [`bumpalo::Bump`] that guarantees thread safety.
#[derive(Debug)]
#[repr(transparent)]
pub struct Allocator<'a> {
    /// The underlying allocator.
    ///
    /// In order to share access to a [`Bump`], even on a single thread, it
    /// must be a shared reference (`&'a Bump`).  That is how we store it
    /// here.  However, we guarantee that the [`Allocator`] is constructed
    /// from a mutable reference -- thus that this is the only reference to
    /// the bump allocator.  It is never exposed publicly, so it cannot be
    /// copied and used from multiple threads.
    inner: &'a Bump,
}

impl<'a> Allocator<'a> {
    /// Construct a new [`Allocator`].
    pub const fn new(inner: &'a mut Bump) -> Self {
        // NOTE: The 'Bump' is mutably borrowed for lifetime 'a; the reference
        // we store is thus guaranteed to be unique.
        Self { inner }
    }

    /// Allocate an object.
    pub fn alloc<T>(&mut self, val: T) -> &'a mut T {
        self.inner.alloc(val)
    }

    /// Allocate a slice and copy the given contents into it.
    pub fn alloc_slice_copy<T: Copy>(&mut self, src: &[T]) -> &'a mut [T] {
        self.inner.alloc_slice_copy(src)
    }
}

// SAFETY: An 'Allocator' contains '&Bump', which is '!Send' because 'Bump' is
// '!Sync'.  However, we guarantee that there are no other references to the
// 'Bump' -- that this is really '&mut Bump' (which is 'Send').
unsafe impl Send for Allocator<'_> {}

// NOTE: 'Allocator' acts a bit like the nightly-only 'std::sync::Exclusive',
// since it doesn't provide any shared access to the underlying 'Bump'.  It is
// sound for it to implement 'Sync', but we defer this until necessary.
