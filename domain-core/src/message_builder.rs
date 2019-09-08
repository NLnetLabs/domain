//! Building a new DNS message.

use core::mem;
use core::cmp::min;
#[cfg(feature = "std")] use std::collections::HashMap;
#[cfg(feature = "std")] use std::vec::Vec;
use core::ops::{Deref, DerefMut};
#[cfg(feature = "bytes")] use bytes::BytesMut;
use unwrap::unwrap;
use crate::compose::{Compose, ComposeTarget, TryCompose};
use crate::header::{Header, HeaderCounts, HeaderSection};
use crate::message::Message;
use crate::name::{ToDname, Label};
#[cfg(feature = "std")] use crate::name::OwnedLabel;
use crate::octets::OctetsBuilder;
use crate::parse::ShortBuf;
use crate::question::Question;
use crate::rdata::RecordData;
use crate::record::Record;


//------------ MessageBuilder ------------------------------------------------

pub struct MessageBuilder<Target> {
    target: Target,
}

impl<Target: ComposeTarget> MessageBuilder<Target> {
    pub fn from_target(mut target: Target) -> Self {
        target.append_slice(HeaderSection::new().as_slice());
        MessageBuilder {
            target,
        }
    }

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

    fn as_target(&self) -> &Target {
        &self.target
    }

    fn as_target_mut(&mut self) -> &mut Target {
        &mut self.target
    }
}

impl<Octets, Comp> MessageBuilder<DgramTarget<Octets, Comp>> {
    pub fn as_message_ref(&self) -> Message<&[u8]>
    where Octets: AsRef<[u8]> {
        unsafe { Message::from_octets_unchecked(self.target.as_ref()) }
    }

    pub fn into_message(self) -> Message<Octets::Octets>
    where Octets: OctetsBuilder {
        self.target.into_message()
    }
}

#[cfg(feature = "std")]
impl MessageBuilder<DgramTarget<Vec<u8>, StaticCompressor>> {
    pub fn new_dgram_vec() -> Self {
        Self::from_target(DgramTarget::new())
    }
}

#[cfg(feature="bytes")] 
impl MessageBuilder<DgramTarget<BytesMut, StaticCompressor>> {
    pub fn new_dgram_bytes() -> Self {
        Self::from_target(DgramTarget::new())
    }
}

impl<Target> MessageBuilder<Target> {
    pub fn header(&self) -> &Header
    where Target: AsRef<[u8]> {
        Header::for_message_slice(self.target.as_ref())
    }

    pub fn header_mut(&mut self) -> &mut Header
    where Target: AsMut<[u8]> {
        Header::for_message_slice_mut(self.target.as_mut())
    }

    pub fn counts(&self) -> &HeaderCounts
    where Target: AsRef<[u8]> {
        HeaderCounts::for_message_slice(self.target.as_ref())
    }

    fn counts_mut(&mut self) -> &mut HeaderCounts
    where Target: AsMut<[u8]> {
        HeaderCounts::for_message_slice_mut(self.target.as_mut())
    }
}


//------------ QuestionBuilder -----------------------------------------------

pub struct QuestionBuilder<Target> {
    builder: MessageBuilder<Target>,
}

impl<Target: ComposeTarget> QuestionBuilder<Target> {
    fn new(builder: MessageBuilder<Target>) -> Self {
        Self { builder }
    }

    fn rewind(mut self) -> MessageBuilder<Target> {
        self.as_target_mut().truncate(mem::size_of::<HeaderSection>());
        self.counts_mut().set_qdcount(0);
        self.builder
    }

    pub fn builder(self) -> MessageBuilder<Target> {
        self.rewind()
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

    pub fn as_builder(&self) -> &MessageBuilder<Target> {
        &self.builder
    }
}

impl<Octets, Comp> QuestionBuilder<DgramTarget<Octets, Comp>> {
    pub fn into_message(self) -> Message<Octets::Octets>
    where Octets: OctetsBuilder, Comp: Compressor {
        self.finish().into_message()
    }
}

impl<Target: TryCompose + AsMut<[u8]>> QuestionBuilder<Target> {
    pub fn push<N: ToDname, Q: Into<Question<N>>>(
        &mut self,
        question: Q
    ) -> Result<(), ShortBuf> {
        self.target.try_compose(|target| {
            question.into().compose(target)
        })?;
        self.counts_mut().inc_qdcount();
        Ok(())
    }
}


//--- From

/*
impl<Target> From<AnswerBuilder<Target>> for QuestionBuilder<Target>
where Target: OctetsBuilder {
    fn from(value: AnswerBuilder<Target>) -> Self {
        value.rewind();
        QuestionBuilder { builder: value.builder }
    }
}
*/


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

pub struct AnswerBuilder<Target> {
    builder: MessageBuilder<Target>,
    start: usize,
}

impl<Target: ComposeTarget + AsRef<[u8]>> AnswerBuilder<Target> {
    fn new(builder: MessageBuilder<Target>) -> Self {
        AnswerBuilder {
            start: builder.target.as_ref().len(),
            builder
        }
    }

    fn rewind(mut self) -> QuestionBuilder<Target> {
        self.builder.target.truncate(self.start);
        self.counts_mut().set_ancount(0);
        QuestionBuilder::new(self.builder)
    }

    pub fn builder(self) -> MessageBuilder<Target> {
        self.question().builder()
    }

    pub fn question(self) -> QuestionBuilder<Target> {
        self.rewind()
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
}

impl<Octets, Comp> AnswerBuilder<DgramTarget<Octets, Comp>> {
    pub fn into_message(self) -> Message<Octets::Octets>
    where Octets: OctetsBuilder, Comp: Compressor {
        self.finish().into_message()
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
where Target: ComposeTarget + TryCompose {
    fn push<N, D, R>(&mut self, record: R) -> Result<(), ShortBuf>
    where N: ToDname, D: RecordData, R: Into<Record<N, D>> {
        self.as_target_mut().try_compose(|target| {
            record.into().compose(target)
        })?;
        self.counts_mut().inc_ancount();
        Ok(())
    }
}


//------------ AuthorityBuilder ----------------------------------------------

pub struct AuthorityBuilder<Target> {
    answer: AnswerBuilder<Target>,
    start: usize
}

impl<Target: ComposeTarget> AuthorityBuilder<Target> {
    fn new(answer: AnswerBuilder<Target>) -> Self {
        AuthorityBuilder {
            start: answer.as_target().as_ref().len(),
            answer
        }
    }

    fn rewind(mut self) -> AnswerBuilder<Target> {
        self.answer.as_target_mut().truncate(self.start);
        self.counts_mut().set_nscount(0);
        self.answer
    }

    pub fn builder(self) -> MessageBuilder<Target> {
        self.question().builder()
    }

    pub fn question(self) -> QuestionBuilder<Target> {
        self.answer().question()
    }

    pub fn answer(self) -> AnswerBuilder<Target> {
        self.rewind()
    }

    pub fn additional(self) -> AdditionalBuilder<Target> {
        AdditionalBuilder::new(self)
    }

    pub fn finish(self) -> Target {
        self.answer.finish()
    }

    fn as_target(&self) -> &Target {
        self.answer.as_target()
    }

    fn as_target_mut(&mut self) -> &mut Target {
        self.answer.as_target_mut()
    }
}

impl<Octets, Comp> AuthorityBuilder<DgramTarget<Octets, Comp>> {
    pub fn into_message(self) -> Message<Octets::Octets>
    where Octets: OctetsBuilder, Comp: Compressor {
        self.finish().into_message()
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

impl<Target> RecordSectionBuilder for AuthorityBuilder<Target>
where Target: ComposeTarget + TryCompose {
    fn push<N, D, R>(&mut self, record: R) -> Result<(), ShortBuf>
    where N: ToDname, D: RecordData, R: Into<Record<N, D>> {
        self.as_target_mut().try_compose(|target| {
            record.into().compose(target)
        })?;
        self.counts_mut().inc_nscount();
        Ok(())
    }
}


//------------ AdditionalBuilder ---------------------------------------------

pub struct AdditionalBuilder<Target> {
    authority: AuthorityBuilder<Target>,
    start: usize,
}

impl<Target: ComposeTarget> AdditionalBuilder<Target> {
    fn new(authority: AuthorityBuilder<Target>) -> Self {
        AdditionalBuilder {
            start: authority.as_target().as_ref().len(),
            authority
        }
    }

    fn rewind(mut self) -> AuthorityBuilder<Target> {
        self.authority.as_target_mut().truncate(self.start);
        self.counts_mut().set_arcount(0);
        self.authority
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

    pub fn authority(self) -> AuthorityBuilder<Target> {
        self.rewind()
    }

    pub fn finish(self) -> Target {
        self.authority.finish()
    }
}

impl<Octets, Comp> AdditionalBuilder<DgramTarget<Octets, Comp>> {
    pub fn into_message(self) -> Message<Octets::Octets>
    where Octets: OctetsBuilder, Comp: Compressor {
        self.finish().into_message()
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
where Target: ComposeTarget + TryCompose {
    fn push<N, D, R>(&mut self, record: R) -> Result<(), ShortBuf>
    where N: ToDname, D: RecordData, R: Into<Record<N, D>> {
        self.as_target_mut().try_compose(|target| {
            record.into().compose(target)
        })?;
        self.counts_mut().inc_ancount();
        Ok(())
    }
}


//------------ DgramTarget ---------------------------------------------------

#[derive(Clone)]
pub struct DgramTarget<Target, Compressor> {
    target: Target,
    limit: usize,
    exhausted: bool,
    compressor: Compressor,
}

impl<Target: OctetsBuilder, Comp> DgramTarget<Target, Comp> {
    pub fn new() -> Self
    where Comp: Compressor {
        Self::from_target(Target::empty())
    }

    pub fn from_target(mut target: Target) -> Self
    where Comp: Compressor {
        target.truncate(0); // XXX Do we want to do this?
        Self {
            target,
            limit: Target::MAX_CAPACITY,
            exhausted: false,
            compressor: Default::default(),
        }
    }

    fn into_message(self) -> Message<Target::Octets> {
        unsafe { Message::from_octets_unchecked(self.target.finish()) }
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    pub fn set_limit(&mut self, limit: Option<usize>) {
        if let Some(limit) = limit {
            self.limit = min(limit, Target::MAX_CAPACITY);
        }
        else {
            self.limit = Target::MAX_CAPACITY;
        }
    }

    fn compress_pos(&self) -> Option<u16> {
        let res = self.target.len();
        if res > 0x0300 {
            None
        }
        else {
            Some(res as u16)
        }
    }
}

impl<Target, Comp> Default for DgramTarget<Target, Comp>
where Target: OctetsBuilder, Comp: Compressor {
    fn default() -> Self {
        Self::new()
    }
}

impl<Target: AsRef<[u8]>, Comp> AsRef<[u8]> for DgramTarget<Target, Comp> {
    fn as_ref(&self) -> &[u8] {
        self.target.as_ref()
    }
}

impl<Target: AsMut<[u8]>, Comp> AsMut<[u8]> for DgramTarget<Target, Comp> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.target.as_mut()
    }
}

impl<Target, Comp> ComposeTarget for DgramTarget<Target, Comp>
where Target: OctetsBuilder, Comp: Compressor {
    type LenTarget = Self;

    fn append_slice(&mut self, slice: &[u8]) {
        match slice.len().checked_sub(self.limit - self.target.len()) {
            Some(len) => {
                self.target.append_slice(&slice[..len]);
                self.exhausted = true;
            }
            None => self.target.append_slice(slice)
        }
    }

    fn truncate(&mut self, len: usize) {
        self.target.truncate(len)
    }

    fn append_compressed_dname<N: ToDname>(&mut self, name: &N) {
        let mut name = name.iter_labels();
        loop {
            // If the name is known to the compressor, append compressed
            // label and be done.
            if let Some(pos) = self.compressor.get(
                name.clone(), self.target.as_ref()
            ) {
                (pos | 0xC000).compose(self);
                return
            }

            // The name is not known. Insert it into the compressor if the
            // message isn’t too long for that yet.
            if let Some(pos) = self.compress_pos() {
                self.compressor.insert(name.clone(), pos)
            }
            else {
                // Just write out the uncompressed name and be done.
                while let Some(label) = name.next() {
                    label.compose(self);
                }
                return
            }

            // Advance to the parent name. If the parent is the root, just
            // write that and be done. Because we do that, there will always
            // be a next label here.
            let label = unwrap!(name.next());
            if label.is_root() {
                0u8.compose(self);
                return
            }
            else {
                label.compose(self)
            }
        }
    }

    fn len_prefixed<F: FnOnce(&mut Self::LenTarget)>(&mut self, op: F) {
        let pos = self.target.as_ref().len();
        self.target.append_slice(&[0; 2]);
        op(self);
        if !self.exhausted {
            let len = (self.target.as_ref().len() - pos - 2) as u16;
            self.target.as_mut()[pos..pos + 2]
                .copy_from_slice(&len.to_be_bytes());
        }
    }
}

impl<Target, Comp> TryCompose for DgramTarget<Target, Comp>
where Target: OctetsBuilder, Comp: Compressor {
    type Target = Self;

    fn try_compose<F>(&mut self, op: F) -> Result<(), ShortBuf>
    where F: FnOnce(&mut Self::Target) {
        let pos = self.target.len();
        op(self);
        if self.exhausted {
            self.target.truncate(pos);
            self.exhausted = false;
            Err(ShortBuf)
        }
        else {
            Ok(())
        }
    }
}


//------------ StreamTarget --------------------------------------------------

pub struct StreamTarget<Target, Compressor> {
    target: Target,
    exhausted: bool,
    compressor: Compressor,
}

impl<Target: OctetsBuilder, Comp: Compressor> StreamTarget<Target, Comp> {
    pub fn new() -> Self {
        Self::from_target(Target::empty())
    }

    pub fn from_target(mut target: Target) -> Self {
        target.truncate(0);
        target.append_slice(&[0; 2]);
        Self {
            target,
            exhausted: false,
            compressor: Default::default(),
        }
    }

    fn limit(&self) -> usize {
        min(Target::MAX_CAPACITY, 0x1_0001)
    }

    fn compress_pos(&self) -> Option<u16> {
        let res = self.target.len() - 2;
        if res > 0x0300 {
            None
        }
        else {
            Some(res as u16)
        }
    }

    fn update_shim(&mut self) {
        let len = (self.target.len() - 2) as u16;
        self.target.as_mut()[..2].copy_from_slice(&len.to_be_bytes())
    }
}

impl<Target, Comp> Default for StreamTarget<Target, Comp>
where Target: OctetsBuilder, Comp: Compressor {
    fn default() -> Self {
        Self::new()
    }
}

impl<Target: AsRef<[u8]>, Comp> AsRef<[u8]> for StreamTarget<Target, Comp> {
    fn as_ref(&self) -> &[u8] {
        self.target.as_ref()
    }
}

impl<Target: AsMut<[u8]>, Comp> AsMut<[u8]> for StreamTarget<Target, Comp> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.target.as_mut()
    }
}

impl<Target, Comp> ComposeTarget for StreamTarget<Target, Comp>
where Target: OctetsBuilder, Comp: Compressor {
    type LenTarget = Self;

    fn append_slice(&mut self, slice: &[u8]) {
        match slice.len().checked_sub(self.limit() - self.target.len()) {
            Some(len) => {
                self.target.append_slice(&slice[..len]);
                self.exhausted = true;
            }
            None => {
                self.target.append_slice(slice);
                self.update_shim();
            }
        }
    }

    fn truncate(&mut self, len: usize) {
        self.target.truncate(len)
    }

    fn append_compressed_dname<N: ToDname>(&mut self, name: &N) {
        let mut name = name.iter_labels();
        loop {
            // If the name is known to the compressor, append compressed
            // label and be done.
            if let Some(pos) = self.compressor.get(
                name.clone(), self.target.as_ref()
            ) {
                (pos | 0xC000).compose(self);
                return
            }

            // The name is not known. Insert it into the compressor if the
            // message isn’t too long for that yet.
            if let Some(pos) = self.compress_pos() {
                self.compressor.insert(name.clone(), pos)
            }
            else {
                // Just write out the uncompressed name and be done.
                while let Some(label) = name.next() {
                    label.compose(self);
                }
                return
            }

            // Advance to the parent name. If the parent is the root, just
            // write that and be done. Because we do that, there will always
            // be a next label here.
            let label = unwrap!(name.next());
            if label.is_root() {
                0u8.compose(self);
                return
            }
            else {
                label.compose(self)
            }
        }
    }

    fn len_prefixed<F: FnOnce(&mut Self::LenTarget)>(&mut self, op: F) {
        let pos = self.target.as_ref().len();
        self.target.append_slice(&[0; 2]);
        op(self);
        if !self.exhausted {
            let len = (self.target.as_ref().len() - pos - 2) as u16;
            self.target.as_mut()[pos..pos + 2]
                .copy_from_slice(&len.to_be_bytes());
        }
    }
}

impl<Target, Comp> TryCompose for StreamTarget<Target, Comp>
where Target: OctetsBuilder, Comp: Compressor {
    type Target = Self;

    fn try_compose<F>(&mut self, op: F) -> Result<(), ShortBuf>
    where F: FnOnce(&mut Self::Target) {
        let pos = self.target.len();
        op(self);
        if self.exhausted {
            self.target.truncate(pos);
            self.update_shim();
            self.exhausted = false;
            Err(ShortBuf)
        }
        else {
            Ok(())
        }
    }
}


//------------ Compressor ----------------------------------------------------

pub trait Compressor: Default {
    fn insert<'a, N: Iterator<Item = &'a Label> + Clone>(
        &mut self,
        name: N,
        pos: u16
    );

    fn get<'a, N: Iterator<Item = &'a Label> + Clone>(
        &self,
        name: N,
        slice: &[u8]
    ) -> Option<u16>;
}


//------------ Uncompressed --------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct Uncompressed;

impl Compressor for Uncompressed {
    fn insert<'a, N: Iterator<Item = &'a Label> + Clone>(
        &mut self,
        _name: N,
        _pos: u16
    ) {
    }

    fn get<'a, N: Iterator<Item = &'a Label> + Clone>(
        &self,
        _name: N,
        _slice: &[u8]
    ) -> Option<u16> {
        None
    }
}



//------------ StaticCompressor ----------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct StaticCompressor {
    entries: [u16; 20],
    len: usize,
}

impl Compressor for StaticCompressor {
    fn insert<'a, N: Iterator<Item = &'a Label> + Clone>(
        &mut self,
        _name: N,
        pos: u16
    ) {
        if self.len < 20 {
            self.entries[self.len] = pos;
            self.len += 1
        }
    }

    fn get<'a, N: Iterator<Item = &'a Label> + Clone>(
        &self,
        name: N,
        slice: &[u8]
    ) -> Option<u16> {
        self.entries[..self.len].iter().find_map(|&pos| {
            if pos as usize > slice.len() {
                return None
            }
            if name.clone().eq(Label::iter_slice(slice, pos as usize)) {
                Some(pos)
            }
            else {
                None
            }
        })
    }
}


//------------ TreeCompressor ------------------------------------------------

#[cfg(feature = "std")]
#[derive(Default)]
pub struct TreeCompressor {
    start: Node,
}

#[cfg(feature = "std")]
#[derive(Default)]
struct Node {
    parents: HashMap<OwnedLabel, Self>,
    value: Option<u16>,
}

#[cfg(feature = "std")]
impl TreeCompressor {
    pub fn new() -> Self {
        Default::default()
    }
}

#[cfg(feature = "std")]
impl Compressor for TreeCompressor {
    fn insert<'a, N: Iterator<Item = &'a Label> + Clone>(
        &mut self,
        name: N,
        pos: u16
    ) {
        let mut node = &mut self.start;
        for label in name {
            if label.is_root() {
                node.value = Some(pos);
                return
            }
            node = node.parents.entry(label.into()).or_default();
        }
    }

    fn get<'a, N: Iterator<Item = &'a Label> + Clone>(
        &self,
        name: N,
        _slice: &[u8]
    ) -> Option<u16> {
        let mut node = &self.start;
        for label in name {
            if label.is_root() {
                return node.value;
            }
            node = node.parents.get(label)?;
        }
        None
    }
}

