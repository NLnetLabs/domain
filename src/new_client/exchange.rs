//! Request-response exchanges for DNS servers.
//!
//! This module provides a number of utility types for the DNS service layer
//! architecture.  In particular, an [`Exchange`] represents a DNS request as
//! it is being passed along a server pipeline, and an [`OutgoingResponse`] is
//! the corresponding response as it is passed back through.

use core::{
    alloc::Layout,
    any::{Any, TypeId},
};
use std::{boxed::Box, vec::Vec};

use bumpalo::Bump;

use crate::{
    new_base::{
        build::{BuilderContext, MessageBuilder},
        name::{RevName, RevNameBuf},
        parse::SplitMessageBytes,
        wire::{BuildBytes, ParseError, SizePrefixed, TruncationError, U16},
        HeaderFlags, Message, Question, RType, Record, SectionCounts,
    },
    new_edns::{EdnsFlags, EdnsOption, EdnsRecord},
    new_rdata::{Opt, RecordData},
    utils::UnsizedClone,
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

    /// The request message.
    pub request: ParsedMessage<'a>,

    /// The response message being built.
    pub response: ParsedMessage<'a>,

    /// Dynamic metadata stored by the DNS server.
    pub metadata: Vec<Metadata>,
}

impl<'a> Exchange<'a> {
    pub fn new(bump: &'a mut Bump) -> Self {
        Self {
            alloc: Allocator::new(bump),
            request: ParsedMessage::default(),
            response: ParsedMessage::default(),
            metadata: Vec::new(),
        }
    }
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
        message: &Message,
        alloc: &mut Allocator<'a>,
    ) -> Result<Self, ParseError> {
        type ParsedQuestion = Question<RevNameBuf>;
        type ParsedRecord<'a> =
            Record<RevNameBuf, RecordData<'a, RevNameBuf>>;

        let mut this = ParsedMessage::<'a>::default();
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

            this.questions
                .push(question.map_name(|n| &*alloc.alloc_unsized(&*n)));
            offset = rest;
        }

        // Parse the answer section.
        this.answers.reserve(counts.answers.get().max(256) as usize);
        for _ in 0..counts.answers.get() {
            let (answer, rest) =
                ParsedRecord::split_message_bytes(&message.contents, offset)?;

            this.answers.push(Record {
                rname: alloc.alloc_unsized(&*answer.rname),
                rtype: answer.rtype,
                rclass: answer.rclass,
                ttl: answer.ttl,
                rdata: answer
                    .rdata
                    .map_names(|n| &*alloc.alloc_unsized(&*n))
                    .clone_to_bump(alloc.inner),
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
                rname: alloc.alloc_unsized(&*authority.rname),
                rtype: authority.rtype,
                rclass: authority.rclass,
                ttl: authority.ttl,
                rdata: authority
                    .rdata
                    .map_names(|n| &*alloc.alloc_unsized(&*n))
                    .clone_to_bump(alloc.inner),
            });
            offset = rest;
        }

        // The EDNS record data.
        let mut edns_data = None;

        // Parse the additional section.
        this.additional
            .reserve(counts.additional.get().max(256) as usize);
        for _ in 0..counts.additional.get() {
            let (additional, rest) =
                ParsedRecord::split_message_bytes(&message.contents, offset)?;

            if let RecordData::Opt(opt) = additional.rdata {
                if edns_data.is_some() {
                    // A message cannot contain two distinct EDNS records.
                    return Err(ParseError);
                }

                edns_data = Some(opt);

                // XXX: Deduplicate the EDNS data.
                // additional.rdata = RecordData::Opt(Opt::EMPTY);
            }

            this.additional.push(Record {
                rname: alloc.alloc_unsized(&*additional.rname),
                rtype: additional.rtype,
                rclass: additional.rclass,
                ttl: additional.ttl,
                rdata: additional
                    .rdata
                    .map_names(|n| &*alloc.alloc_unsized(&*n))
                    .clone_to_bump(alloc.inner),
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
                this.options.push(option?.clone_to_bump(alloc.inner));
            }
        }

        Ok(this)
    }

    /// Build this message into the given buffer.
    ///
    /// If the message could not fit in the given buffer, a
    /// [`TruncationError`] is returned.
    pub fn build<'b, 'c>(
        &self,
        context: &'c mut BuilderContext,
        buffer: &'b mut [u8],
    ) -> Result<MessageBuilder<'b, 'c>, TruncationError> {
        // Construct a 'MessageBuilder'.
        if buffer.len() < 12 {
            return Err(TruncationError);
        }
        let mut builder = MessageBuilder::new(buffer, context);

        // Build the message header.
        let header = builder.header_mut();
        header.id = self.id;
        header.flags = self.flags;
        header.counts = SectionCounts::default();

        // Build the question section.
        for question in &self.questions {
            builder
                .build_question(question)?
                .expect("No answers, authorities, or additionals are built")
                .commit();
        }

        // Build the answer section.
        for answer in &self.answers {
            builder
                .build_answer(answer)?
                .expect("No authorities, or additionals are built")
                .commit();
        }

        // Build the authority section.
        for authority in &self.authorities {
            builder
                .build_authority(authority)?
                .expect("No additionals are built")
                .commit();
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
                delegate.commit();
                builder.commit();

                edns_built = true;
                continue;
            }

            builder.build_additional(additional)?.commit();
        }

        debug_assert!(
            self.options.is_empty() || edns_built,
            "EDNS options found, but no OPT record",
        );

        Ok(builder)
    }
}

impl ParsedMessage<'_> {
    /// Whether this message has an EDNS record.
    pub fn has_edns(&self) -> bool {
        self.additional.iter().any(|r| r.rtype == RType::OPT)
    }

    pub fn set_max_udp_payload_size(&mut self, max_payload_size: u16) {
        self.additional
            .iter_mut()
            .find_map(|r| match r.rtype {
                RType::OPT => {
                    r.rclass.code.set(max_payload_size);
                    Some(())
                }
                _ => None,
            })
            .unwrap_or_else(|| {
                self.additional.push(
                    EdnsRecord {
                        max_udp_payload: max_payload_size.into(),
                        ext_rcode: 0,
                        version: 0,
                        flags: EdnsFlags::default(),
                        options: SizePrefixed::new(Opt::EMPTY),
                    }
                    .into(),
                )
            });
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

//----------- ResponseCode ---------------------------------------------------

/// A (possibly extended) DNS response code.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ResponseCode {
    /// The request was answered successfully.
    Success,

    /// The request was misformatted.
    FormatError,

    /// The server encountered an internal error.
    ServerFailure,

    /// The queried domain name does not exist.
    NonExistentDomain,

    /// The server does not support the requested kind of query.
    NotImplemented,

    /// Policy prevents the server from answering the query.
    Refused,

    /// The TSIG record in the request was invalid.
    InvalidTSIG,

    /// The server does not support the request's OPT record version.
    UnsupportedOptVersion,

    /// The request did not contain a valid EDNS server cookie.
    BadCookie,
}

impl ResponseCode {
    /// This code's representation in the DNS message header.
    pub const fn header_bits(&self) -> u8 {
        match self {
            Self::Success => 0,
            Self::FormatError => 1,
            Self::ServerFailure => 2,
            Self::NonExistentDomain => 3,
            Self::NotImplemented => 4,
            Self::Refused => 5,
            Self::InvalidTSIG => 9,
            Self::UnsupportedOptVersion => 0,
            Self::BadCookie => 7,
        }
    }

    /// This code's representation in the EDNS record header.
    pub const fn edns_bits(&self) -> u8 {
        match self {
            Self::Success => 0,
            Self::FormatError => 0,
            Self::ServerFailure => 0,
            Self::NonExistentDomain => 0,
            Self::NotImplemented => 0,
            Self::Refused => 0,
            Self::InvalidTSIG => 0,
            Self::UnsupportedOptVersion => 1,
            Self::BadCookie => 1,
        }
    }
}

//----------- Metadata -------------------------------------------------------

/// Arbitrary metadata about a DNS exchange.
///
/// This should be used by [`ServiceLayer`](super::ServiceLayer)s for storing
/// information they have extracted from an incoming DNS request message.  The
/// metadata may be relevant to future layers: for example, some may wish to
/// handle TSIG-signed requests differently from others.  The metadata is also
/// relevant to the original layer in [`process_outgoing()`], as it does not
/// have access to the original request.
///
/// [`process_outgoing()`]: super::ServiceLayer::process_outgoing()
///
/// # Implementation
///
/// This is an enhanced version of `Box<dyn Any + Send + 'static>` that can
/// perform downcasting more efficiently.  It stores the [`TypeId`] of the
/// object inline, allowing it to skip a vtable lookup.
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
/// It is equivalent to `&'a mut Bump`, but `&mut &'a mut Bump` does not work
/// (allocated objects only last for the shorter lifetime, not for `'a`).
/// `&mut Allocator<'a>` does work, giving objects of lifetime `'a`.
///
/// # Thread Safety
///
/// [`Bump`] is not thread safe; using it from multiple threads simultaneously
/// would cause undefined behaviour.  [`Allocator`] implements [`Send`], and
/// so it cannot directly expose shared references to the underlying [`Bump`];
/// a user could get `&Bump` on one thread, send the [`Allocator`] to another
/// thread, then get `&Bump` over there.  This is why [`Allocator`] copies
/// [`Bump`]'s methods instead of implementing [`Deref`] to [`Bump`].
///
/// [`Deref`]: core::ops::Deref
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
    pub fn new(inner: &'a mut Bump) -> Self {
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

    pub fn alloc_unsized<T: ?Sized + UnsizedClone>(
        &mut self,
        val: &T,
    ) -> &'a mut T {
        let layout = Layout::for_value(val);
        let ptr = self.inner.alloc_layout(layout).as_ptr().cast::<()>();
        unsafe {
            val.unsized_clone(ptr);
        };
        let ptr = val.ptr_with_address(ptr);
        unsafe { &mut *ptr }
    }
}

// SAFETY: An 'Allocator' contains '&Bump', which is '!Send' because 'Bump' is
// '!Sync'.  However, we guarantee that there are no other references to the
// 'Bump' -- that this is really '&mut Bump' (which is 'Send').
unsafe impl Send for Allocator<'_> {}

// NOTE: 'Allocator' acts a bit like the nightly-only 'std::sync::Exclusive',
// since it doesn't provide any shared access to the underlying 'Bump'.  It is
// sound for it to implement 'Sync', but we defer this until necessary.
