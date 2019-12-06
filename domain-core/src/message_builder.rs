//! Building a new DNS message.

use core::mem;
use core::convert::TryInto;
#[cfg(feature = "std")] use std::collections::HashMap;
#[cfg(feature = "std")] use std::vec::Vec;
use core::ops::{Deref, DerefMut};
#[cfg(feature = "bytes")] use bytes::BytesMut;
use unwrap::unwrap;
use crate::header::{Header, HeaderCounts, HeaderSection};
use crate::iana::{OptionCode, OptRcode};
use crate::message::Message;
use crate::name::{ToDname, Label};
use crate::octets::{Compose, IntoOctets, Octets64, OctetsBuilder, ShortBuf};
use crate::opt::{OptHeader, OptData};
use crate::question::Question;
use crate::rdata::RecordData;
use crate::record::Record;


//------------ MessageBuilder ------------------------------------------------

#[derive(Clone, Debug)]
pub struct MessageBuilder<Target> {
    target: Target,
}

impl<Target: OctetsBuilder> MessageBuilder<Target> {
    pub fn from_target(mut target: Target) -> Result<Self, ShortBuf> {
        target.truncate(0);
        target.append_slice(HeaderSection::new().as_slice())?;
        Ok(MessageBuilder {
            target,
        })
    }
}

#[cfg(feature = "std")]
impl MessageBuilder<Vec<u8>> {
    pub fn new_vec() -> Self {
        unwrap!(Self::from_target(Vec::new()))
    }
}

#[cfg(feature = "std")]
impl MessageBuilder<StreamTarget<Vec<u8>>> {
    pub fn new_stream_vec() -> Self {
        unwrap!(Self::from_target(
            unwrap!(StreamTarget::new(Vec::new()))
        ))
    }
}

#[cfg(feature="bytes")]
impl MessageBuilder<BytesMut> {
    pub fn new_bytes() -> Self {
        unwrap!(Self::from_target(BytesMut::new()))
    }
}

#[cfg(feature="bytes")]
impl MessageBuilder<StreamTarget<BytesMut>> {
    pub fn new_stream_bytes() -> Self {
        unwrap!(Self::from_target(
            unwrap!(StreamTarget::new(BytesMut::new()))
        ))
    }
}

impl<Target: OctetsBuilder> MessageBuilder<Target> {
    pub fn question(self) -> QuestionBuilder<Target> {
        QuestionBuilder::new(self)
    }

    pub fn answer(self) -> AnswerBuilder<Target> {
        self.question().answer()
    }

    pub fn authority(self) -> AuthorityBuilder<Target> {
        self.question().answer().authority()
    }

    pub fn additional(self) -> AdditionalBuilder<Target> {
        self.question().answer().authority().additional()
    }

    pub fn finish(self) -> Target {
        self.target
    }

    pub fn as_target(&self) -> &Target {
        &self.target
    }

    fn as_target_mut(&mut self) -> &mut Target {
        &mut self.target
    }

    pub fn as_message(&self) -> Message<&[u8]>
    where Target: AsRef<[u8]> {
        unsafe { Message::from_octets_unchecked(self.target.as_ref()) }
    }

    pub fn into_message(self) -> Message<Target::Octets>
    where Target: IntoOctets {
        unsafe { Message::from_octets_unchecked(self.target.into_octets()) }
    }

    pub fn header(&self) -> &Header {
        Header::for_message_slice(self.target.as_ref())
    }

    pub fn header_mut(&mut self) -> &mut Header {
        Header::for_message_slice_mut(self.target.as_mut())
    }

    pub fn counts(&self) -> &HeaderCounts {
        HeaderCounts::for_message_slice(self.target.as_ref())
    }

    fn counts_mut(&mut self) -> &mut HeaderCounts {
        HeaderCounts::for_message_slice_mut(self.target.as_mut())
    }
}


//------------ QuestionBuilder -----------------------------------------------

#[derive(Clone, Debug)]
pub struct QuestionBuilder<Target> {
    builder: MessageBuilder<Target>,
}

impl<Target: OctetsBuilder> QuestionBuilder<Target> {
    fn new(builder: MessageBuilder<Target>) -> Self {
        Self { builder }
    }

    pub fn as_target(&self) -> &Target {
        self.builder.as_target()
    }

    pub fn rewind(&mut self) {
        self.as_target_mut().truncate(mem::size_of::<HeaderSection>());
        self.counts_mut().set_qdcount(0);
    }

    pub fn builder(mut self) -> MessageBuilder<Target> {
        self.rewind();
        self.builder
    }

    pub fn question(self) -> QuestionBuilder<Target> {
        self
    }

    pub fn answer(self) -> AnswerBuilder<Target> {
        AnswerBuilder::new(self.builder)
    }

    pub fn authority(self) -> AuthorityBuilder<Target> {
        self.answer().authority()
    }

    pub fn additional(self) -> AdditionalBuilder<Target> {
        self.answer().authority().additional()
    }

    pub fn finish(self) -> Target {
        self.builder.finish()
    }

    pub fn into_message(self) -> Message<Target::Octets>
    where Target: IntoOctets {
        self.builder.into_message()
    }

    pub fn as_builder(&self) -> &MessageBuilder<Target> {
        &self.builder
    }

    pub fn push<N: ToDname, Q: Into<Question<N>>>(
        &mut self,
        question: Q
    ) -> Result<(), ShortBuf> {
        question.into().compose(self.as_target_mut())?;
        self.counts_mut().inc_qdcount();
        Ok(())
    }
}


//--- From

impl<Target> From<MessageBuilder<Target>> for QuestionBuilder<Target>
where Target: OctetsBuilder {
    fn from(src: MessageBuilder<Target>) -> Self {
        src.question()
    }
}

impl<Target> From<AnswerBuilder<Target>> for QuestionBuilder<Target>
where Target: OctetsBuilder {
    fn from(src: AnswerBuilder<Target>) -> Self {
        src.question()
    }
}

impl<Target> From<AuthorityBuilder<Target>> for QuestionBuilder<Target>
where Target: OctetsBuilder {
    fn from(src: AuthorityBuilder<Target>) -> Self {
        src.question()
    }
}

impl<Target> From<AdditionalBuilder<Target>> for QuestionBuilder<Target>
where Target: OctetsBuilder {
    fn from(src: AdditionalBuilder<Target>) -> Self {
        src.question()
    }
}


//--- Deref, DerefMut, AsRef, and AsMut

impl<Target> Deref for QuestionBuilder<Target> {
    type Target = MessageBuilder<Target>;

    fn deref(&self) -> &Self::Target {
        &self.builder
    }
}

impl<Target> DerefMut for QuestionBuilder<Target> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.builder
    }
}

impl<Target> AsRef<MessageBuilder<Target>> for QuestionBuilder<Target> {
    fn as_ref(&self) -> &MessageBuilder<Target> {
        &self.builder
    }
}

impl<Target> AsMut<MessageBuilder<Target>> for QuestionBuilder<Target> {
    fn as_mut(&mut self) -> &mut MessageBuilder<Target> {
        &mut self.builder
    }
}


//------------ RecordSectionBuilder ------------------------------------------

pub trait RecordSectionBuilder {
    fn push<N, D, R>(&mut self, record: R) -> Result<(), ShortBuf>
    where N: ToDname, D: RecordData, R: Into<Record<N, D>>;
}


//------------ AnswerBuilder -------------------------------------------------

#[derive(Clone, Debug)]
pub struct AnswerBuilder<Target> {
    builder: MessageBuilder<Target>,
    start: usize,
}

impl<Target: OctetsBuilder> AnswerBuilder<Target> {
    fn new(builder: MessageBuilder<Target>) -> Self {
        AnswerBuilder {
            start: builder.target.as_ref().len(),
            builder
        }
    }

    pub fn as_target(&self) -> &Target {
        self.builder.as_target()
    }

    pub fn rewind(&mut self) {
        self.builder.target.truncate(self.start);
        self.counts_mut().set_ancount(0);
    }

    pub fn builder(self) -> MessageBuilder<Target> {
        self.question().builder()
    }

    pub fn question(mut self) -> QuestionBuilder<Target> {
        self.rewind();
        QuestionBuilder::new(self.builder)
    }

    pub fn authority(self) -> AuthorityBuilder<Target> {
        AuthorityBuilder::new(self)
    }

    pub fn additional(self) -> AdditionalBuilder<Target> {
        self.authority().additional()
    }

    pub fn finish(self) -> Target {
        self.builder.finish()
    }

    pub fn into_message(self) -> Message<Target::Octets>
    where Target: IntoOctets {
        self.builder.into_message()
    }
}


//--- Deref, DerefMut, AsRef, and AsMut

impl<Target> Deref for AnswerBuilder<Target> {
    type Target = MessageBuilder<Target>;

    fn deref(&self) -> &Self::Target {
        &self.builder
    }
}

impl<Target> DerefMut for AnswerBuilder<Target> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.builder
    }
}


//--- RecordSectionBuilder

impl<Target> RecordSectionBuilder for AnswerBuilder<Target>
where Target: OctetsBuilder {
    fn push<N, D, R>(&mut self, record: R) -> Result<(), ShortBuf>
    where N: ToDname, D: RecordData, R: Into<Record<N, D>> {
        record.into().compose(self.as_target_mut())?;
        self.counts_mut().inc_ancount();
        Ok(())
    }
}


//------------ AuthorityBuilder ----------------------------------------------

#[derive(Clone, Debug)]
pub struct AuthorityBuilder<Target> {
    answer: AnswerBuilder<Target>,
    start: usize
}

impl<Target: OctetsBuilder> AuthorityBuilder<Target> {
    fn new(answer: AnswerBuilder<Target>) -> Self {
        AuthorityBuilder {
            start: answer.as_target().as_ref().len(),
            answer
        }
    }

    pub fn rewind(&mut self) {
        self.answer.as_target_mut().truncate(self.start);
        self.counts_mut().set_nscount(0);
    }

    pub fn builder(self) -> MessageBuilder<Target> {
        self.question().builder()
    }

    pub fn question(self) -> QuestionBuilder<Target> {
        self.answer().question()
    }

    pub fn answer(mut self) -> AnswerBuilder<Target> {
        self.rewind();
        self.answer
    }

    pub fn additional(self) -> AdditionalBuilder<Target> {
        AdditionalBuilder::new(self)
    }

    pub fn finish(self) -> Target {
        self.answer.finish()
    }

    pub fn into_message(self) -> Message<Target::Octets>
    where Target: IntoOctets {
        self.answer.into_message()
    }

    pub fn as_target(&self) -> &Target {
        self.answer.as_target()
    }

    fn as_target_mut(&mut self) -> &mut Target {
        self.answer.as_target_mut()
    }
}


//--- Deref, DerefMut, AsRef, and AsMut

impl<Target> Deref for AuthorityBuilder<Target> {
    type Target = MessageBuilder<Target>;

    fn deref(&self) -> &Self::Target {
        self.answer.deref()
    }
}

impl<Target> DerefMut for AuthorityBuilder<Target> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.answer.deref_mut()
    }
}


//--- RecordSectionBuilder

impl<Target: OctetsBuilder> RecordSectionBuilder for AuthorityBuilder<Target> {
    fn push<N, D, R>(&mut self, record: R) -> Result<(), ShortBuf>
    where N: ToDname, D: RecordData, R: Into<Record<N, D>> {
        record.into().compose(self.as_target_mut())?;
        self.counts_mut().inc_nscount();
        Ok(())
    }
}


//------------ AdditionalBuilder ---------------------------------------------

#[derive(Clone, Debug)]
pub struct AdditionalBuilder<Target> {
    authority: AuthorityBuilder<Target>,
    start: usize,
}

impl<Target: OctetsBuilder> AdditionalBuilder<Target> {
    fn new(authority: AuthorityBuilder<Target>) -> Self {
        AdditionalBuilder {
            start: authority.as_target().as_ref().len(),
            authority
        }
    }

    pub fn as_target(&self) -> &Target {
        self.authority.as_target()
    }

    pub fn rewind(&mut self) {
        self.authority.as_target_mut().truncate(self.start);
        self.counts_mut().set_arcount(0);
    }

    pub fn builder(self) -> MessageBuilder<Target> {
        self.question().builder()
    }

    pub fn question(self) -> QuestionBuilder<Target> {
        self.answer().question()
    }

    pub fn answer(self) -> AnswerBuilder<Target> {
        self.authority().answer()
    }

    pub fn authority(mut self) -> AuthorityBuilder<Target> {
        self.rewind();
        self.authority
    }

    pub fn opt(self) -> Result<OptBuilder<Target>, Self> {
        OptBuilder::new(self)
    }

    pub fn finish(self) -> Target {
        self.authority.finish()
    }

    pub fn into_message(self) -> Message<Target::Octets>
    where Target: IntoOctets {
        self.authority.into_message()
    }
}


//--- Deref, DerefMut, AsRef, and AsMut

impl<Target> Deref for AdditionalBuilder<Target> {
    type Target = MessageBuilder<Target>;

    fn deref(&self) -> &Self::Target {
        self.authority.deref()
    }
}

impl<Target> DerefMut for AdditionalBuilder<Target> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.authority.deref_mut()
    }
}


//--- RecordSectionBuilder

impl<Target> RecordSectionBuilder for AdditionalBuilder<Target>
where Target: OctetsBuilder {
    fn push<N, D, R>(&mut self, record: R) -> Result<(), ShortBuf>
    where N: ToDname, D: RecordData, R: Into<Record<N, D>> {
        record.into().compose(self.as_target_mut())?;
        self.counts_mut().inc_ancount();
        Ok(())
    }
}


//------------ OptBuilder ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct OptBuilder<Target> {
    additional: AdditionalBuilder<Target>,
    start: usize,
    arcount: u16,
}

impl<Target: OctetsBuilder> OptBuilder<Target> {
    fn new(
        mut additional: AdditionalBuilder<Target>
    ) -> Result<Self, AdditionalBuilder<Target>> {
        let start = additional.as_target().as_ref().len();
        let arcount = additional.counts().arcount();

        let err = additional.as_target_mut().append_all(|target| {
            OptHeader::default().compose(target)?;
            0u16.compose(target)
        }).is_err();
        if err {
            return Err(additional)
        }
        additional.counts_mut().inc_arcount();

        Ok(OptBuilder {
            additional, start, arcount
        })
    }

    pub fn rewind(self) -> AdditionalBuilder<Target> {
        let mut res = self.additional;
        res.as_target_mut().truncate(self.start);
        res.counts_mut().set_arcount(self.arcount);
        res
    }

    pub fn push<Opt: OptData>(&mut self, opt: &Opt) -> Result<(), ShortBuf> {
        self.append_raw_option(opt.code(), |target| {
            opt.compose(target)
        })
    }

    pub fn append_raw_option<F>(
        &mut self, code: OptionCode, op: F
    ) -> Result<(), ShortBuf>
    where F: FnOnce(&mut Target) -> Result<(), ShortBuf> {
        // Add the option.
        let pos = self.as_target().as_ref().len();
        self.as_target_mut().append_all(|target| {
            code.compose(target)?;
            op(target)
        })?;

        // Update the length. If the option is too long, truncate and return
        // an error.
        let len = self.as_target().as_ref().len()
                - self.start
                - (mem::size_of::<OptHeader>() + 2);
        if len > usize::from(u16::max_value()) {
            self.as_target_mut().truncate(pos);
            return Err(ShortBuf)
        }
        let start = self.start + mem::size_of::<OptHeader>();
        self.as_target_mut().as_mut()[start..start + 2]
            .copy_from_slice(&(len as u16).to_be_bytes());
        Ok(())
    }

    pub fn udp_payload_size(&self) -> u16 {
        self.opt_header().udp_payload_size()
    }

    pub fn set_udp_payload_size(&mut self, value: u16) {
        self.opt_header_mut().set_udp_payload_size(value)
    }

    pub fn rcode(&self) -> OptRcode {
        self.opt_header().rcode(*self.header())
    }

    pub fn set_rcode(&mut self, rcode: OptRcode) {
        self.header_mut().set_rcode(rcode.rcode());
        self.opt_header_mut().set_rcode(rcode)
    }

    fn opt_header(&self) -> &OptHeader {
        OptHeader::for_record_slice(&self.as_target().as_ref()[self.start..])
    }

    fn opt_header_mut(&mut self) -> &mut OptHeader {
        let start = self.start;
        OptHeader::for_record_slice_mut(
            &mut self.as_target_mut().as_mut()[start..]
        )
    }

    pub fn builder(self) -> MessageBuilder<Target> {
        self.additional().builder()
    }

    pub fn question(self) -> QuestionBuilder<Target> {
        self.additional().question()
    }

    pub fn answer(self) -> AnswerBuilder<Target> {
        self.additional().answer()
    }

    pub fn authority(self) -> AuthorityBuilder<Target> {
        self.additional().authority()
    }

    pub fn additional(self) -> AdditionalBuilder<Target> {
        self.additional
    }

    pub fn finish(self) -> Target {
        self.additional.finish()
    }

    pub fn into_message(self) -> Message<Target::Octets>
    where Target: IntoOctets {
        self.additional.into_message()
    }

    pub fn as_target(&self) -> &Target {
        self.additional.as_target()
    }

    fn as_target_mut(&mut self) -> &mut Target {
        self.additional.as_target_mut()
    }
}


//--- Deref, DerefMut, AsRef, and AsMut

impl<Target> Deref for OptBuilder<Target> {
    type Target = MessageBuilder<Target>;

    fn deref(&self) -> &Self::Target {
        self.additional.deref()
    }
}

impl<Target> DerefMut for OptBuilder<Target> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.additional.deref_mut()
    }
}


//------------ StreamTarget --------------------------------------------------

#[derive(Clone, Debug)]
pub struct StreamTarget<Target> {
    target: Target
}

impl<Target: OctetsBuilder> StreamTarget<Target> {
    pub fn new(mut target: Target) -> Result<Self, ShortBuf> {
        target.truncate(0);
        0u16.compose(&mut target)?;
        Ok(StreamTarget { target })
    }

    pub fn as_target(&self) -> &Target {
        &self.target
    }
    
    pub fn into_target(self) -> Target {
        self.target
    }

    fn update_shim(&mut self) {
        let len = (self.target.len() - 2) as u16;
        self.target.as_mut()[..2].copy_from_slice(&len.to_be_bytes())
    }

    pub fn as_stream_slice(&self) -> &[u8] {
        self.target.as_ref()
    }

    pub fn as_dgram_slice(&self) -> &[u8] {
        &self.target.as_ref()[2..]
    }
}

impl<Target: AsRef<[u8]>> AsRef<[u8]> for StreamTarget<Target> {
    fn as_ref(&self) -> &[u8] {
        &self.target.as_ref()[2..]
    }
}

impl<Target: AsMut<[u8]>> AsMut<[u8]> for StreamTarget<Target> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.target.as_mut()[2..]
    }
}

impl<Target: OctetsBuilder> OctetsBuilder for StreamTarget<Target> {
    fn append_slice(&mut self, slice: &[u8]) -> Result<(), ShortBuf> {
        match self.target.append_slice(slice) {
            Ok(()) => {
                self.update_shim();
                Ok(())
            }
            Err(ShortBuf) => Err(ShortBuf)
        }
    }

    fn truncate(&mut self, len: usize) {
        self.target.truncate(len + 2);
        self.update_shim();
    }
}





//------------ StaticCompressor ----------------------------------------------

#[derive(Clone, Debug)]
pub struct StaticCompressor<Target> {
    target: Target,
    entries: [u16; 20],
    len: usize,
}

impl<Target> StaticCompressor<Target> {
    pub fn new(target: Target) -> Self {
        StaticCompressor {
            target,
            entries: Default::default(),
            len: 0
        }
    }

    pub fn as_target(&self) -> &Target {
        &self.target
    }

    pub fn into_target(self) -> Target {
        self.target
    }

    pub fn as_slice(&self) -> &[u8]
    where Target: AsRef<[u8]> {
        self.target.as_ref()
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8]
    where Target: AsMut<[u8]> {
        self.target.as_mut()
    }

    fn get<'a, N: Iterator<Item = &'a Label> + Clone>(
        &self,
        name: N,
    ) -> Option<u16>
    where Target: AsRef<[u8]> {
        self.entries[..self.len].iter().find_map(|&pos| {
            if name.clone().eq(
                Label::iter_slice(self.target.as_ref(), pos as usize)
            ) {
                Some(pos)
            }
            else {
                None
            }
        })
    }

    fn insert(&mut self, pos: usize) -> bool {
        if pos < 0xc000 && self.len < self.entries.len() {
            self.entries[self.len] = pos as u16;
            self.len += 1;
            true
        }
        else {
            false
        }
    }
}

impl<Target: AsRef<[u8]>> AsRef<[u8]> for StaticCompressor<Target> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<Target: AsMut<[u8]>> AsMut<[u8]> for StaticCompressor<Target> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_slice_mut()
    }
}

impl<Target: OctetsBuilder> OctetsBuilder for StaticCompressor<Target> {
    fn append_slice(&mut self, slice: &[u8]) -> Result<(), ShortBuf> {
        self.target.append_slice(slice)
    }

    fn truncate(&mut self, len: usize) {
        self.target.truncate(len);
        if len < 0xC000 {
            let len = len as u16;
            for i in 0..self.len {
                if self.entries[i] >= len {
                    self.len = i;
                    break
                }
            }
        }
    }

    fn append_compressed_dname<N: ToDname>(
        &mut self,
        name: &N
    ) -> Result<(), ShortBuf> {
        let mut name = name.iter_labels();
        loop {
            // If we already know this name, append it as a compressed label.
            if let Some(pos) = self.get(name.clone()) {
                return (pos | 0xC000).compose(self)
            }

            // So we don’t know the name. Try inserting it into the
            // compressor. If we can’t insert anymore, just write out what’s
            // left and return.
            if !self.insert(self.target.len()) {
                while let Some(label) = name.next() {
                    label.compose(self)?;
                }
                return Ok(())
            }

            // Advance to the parent. If the parent is root, just write that
            // and return. Because we do that, there will always be a label
            // left here.
            let label = unwrap!(name.next());
            label.compose(self)?;
            if label.is_root() {
                return Ok(())
            }
        }
    }
}


//------------ TreeCompressor ------------------------------------------------

#[cfg(feature = "std")]
#[derive(Clone, Debug)]
pub struct TreeCompressor<Target> {
    target: Target,
    start: Node,
}

#[cfg(feature = "std")]
#[derive(Clone, Debug, Default)]
struct Node {
    parents: HashMap<Octets64, Self>,
    value: Option<u16>,
}

#[cfg(feature = "std")]
impl Node {
    fn drop_above(&mut self, len: u16) {
        self.value = match self.value {
            Some(value) if value < len => Some(value),
            _ => None
        };
        self.parents.values_mut().for_each(|node| node.drop_above(len))
    }
}

#[cfg(feature = "std")]
impl<Target> TreeCompressor<Target> {
    pub fn new(target: Target) -> Self {
        TreeCompressor {
            target,
            start: Default::default()
        }
    }

    pub fn as_target(&self) -> &Target {
        &self.target
    }

    pub fn into_target(self) -> Target {
        self.target
    }

    pub fn as_slice(&self) -> &[u8]
    where Target: AsRef<[u8]> {
        self.target.as_ref()
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8]
    where Target: AsMut<[u8]> {
        self.target.as_mut()
    }

    fn get<'a, N: Iterator<Item = &'a Label> + Clone>(
        &self,
        name: N
    ) -> Option<u16> {
        let mut node = &self.start;
        for label in name {
            if label.is_root() {
                return node.value;
            }
            node = node.parents.get(label.as_ref())?;
        }
        None
    }

    fn insert<'a, N: Iterator<Item = &'a Label> + Clone>(
        &mut self,
        name: N,
        pos: usize
    ) -> bool {
        if pos >= 0xC000 {
            return false
        }
        let pos = pos as u16;
        let mut node = &mut self.start;
        for label in name {
            if label.is_root() {
                node.value = Some(pos);
                break
            }
            node = node.parents.entry(
                unwrap!(label.as_ref().try_into())
            ).or_default();
        }
        true
    }
}

#[cfg(feature = "std")]
impl<Target: AsRef<[u8]>> AsRef<[u8]> for TreeCompressor<Target> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

#[cfg(feature = "std")]
impl<Target: AsMut<[u8]>> AsMut<[u8]> for TreeCompressor<Target> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_slice_mut()
    }
}

#[cfg(feature = "std")]
impl<Target: OctetsBuilder> OctetsBuilder for TreeCompressor<Target> {
    fn append_slice(&mut self, slice: &[u8]) -> Result<(), ShortBuf> {
        self.target.append_slice(slice)
    }

    fn truncate(&mut self, len: usize) {
        self.target.truncate(len);
        if len < 0xC000 {
            self.start.drop_above(len as u16)
        }
    }

    fn append_compressed_dname<N: ToDname>(
        &mut self,
        name: &N
    ) -> Result<(), ShortBuf> {
        let mut name = name.iter_labels();
        loop {
            // If we already know this name, append it as a compressed label.
            if let Some(pos) = self.get(name.clone()) {
                return (pos | 0xC000).compose(self)
            }

            // So we don’t know the name. Try inserting it into the
            // compressor. If we can’t insert anymore, just write out what’s
            // left and return.
            if !self.insert(name.clone(), self.target.len()) {
                while let Some(label) = name.next() {
                    label.compose(self)?;
                }
                return Ok(())
            }

            // Advance to the parent. If the parent is root, just write that
            // and return. Because we do that, there will always be a label
            // left here.
            let label = unwrap!(name.next());
            label.compose(self)?;
            if label.is_root() {
                return Ok(())
            }
        }
    }
}

