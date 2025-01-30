//! Responding to DNS requests.
//!
//! # Architecture
//!
//! A _transport_ implements a network interface allowing it to receive DNS
//! requests and return DNS responses.  Transports can be implemented on UDP,
//! TCP, TLS, etc., and users can implement their own transports.
//!
//! A _service_ implements the business logic of handling a DNS request and
//! building a DNS response.  A service can be composed of multiple _layers_,
//! each of which can inspect the request and prepare part of the response.
//! Many common layers are already implemented, but users can define more.

#![cfg(feature = "unstable-server-transport")]
#![cfg_attr(docsrs, doc(cfg(feature = "unstable-server-transport")))]

use core::{future::Future, ops::ControlFlow};

use crate::new_base::{
    build::{MessageBuilder, QuestionBuilder, RecordBuilder},
    Header,
};

mod impls;

pub mod request;
pub use request::RequestMessage;

pub mod transport;

//----------- Service --------------------------------------------------------

/// A (multi-threaded) DNS service, that computes responses for requests.
///
/// Given a DNS request message, a service computes an appropriate response.
/// Services are usually wrapped in a network transport that receives requests
/// and returns the service's responses.
///
/// Use [`LocalService`] for a single-threaded equivalent.
///
/// # Layering
///
/// Additional functionality can be added to a service by prefixing it with
/// service layers, usually in a tuple.  A number of blanket implementations
/// are provided to simplify this.
pub trait Service: LocalService<Producer: Send> + Sync {
    /// Respond to a DNS request.
    ///
    /// The provided consumer must have been provided the entire DNS request
    /// message.  This method will use the extracted information to formulate
    /// a response message, in the form of a producer type.
    ///
    /// The returned future implements [`Send`].  Use [`LocalService`] and
    /// [`LocalService::respond_local()`] if [`Send`] is not necessary.
    fn respond(
        &self,
        request: &RequestMessage<'_>,
    ) -> impl Future<Output = Self::Producer> + Send;
}

//----------- LocalService ---------------------------------------------------

/// A (single-threaded) DNS service, that computes responses for requests.
///
/// Given a DNS request message, a service computes an appropriate response.
/// Services are usually wrapped in a network transport that receives requests
/// and returns the service's responses.
///
/// Use [`Service`] for a multi-threaded equivalent.
///
/// # Layering
///
/// Additional functionality can be added to a service by prefixing it with
/// service layers, usually in a tuple.  A number of blanket implementations
/// are provided to simplify this.
pub trait LocalService {
    /// A producer of DNS responses.
    ///
    /// This type returns components to insert in a DNS response message.  It
    /// is constructed by [`Self::respond_local()`].
    ///
    /// # Lifetimes
    ///
    /// The producer can borrow from the request message (`'req`).  Note that
    /// it cannot borrow from the response message.
    type Producer: ProduceMessage;

    /// Respond to a DNS request.
    ///
    /// The provided consumer must have been provided the entire DNS request
    /// message.  This method will use the extracted information to formulate
    /// a response message, in the form of a producer type.
    ///
    /// The returned future does not implement [`Send`].  Use [`Service`] and
    /// [`Service::respond()`] for a [`Send`]-implementing version.
    #[allow(async_fn_in_trait)]
    async fn respond_local(
        &self,
        request: &RequestMessage<'_>,
    ) -> Self::Producer;
}

//----------- ServiceLayer ---------------------------------------------------

/// A (multi-threaded) layer wrapping a DNS [`Service`].
///
/// A layer can be wrapped around a service, inspecting the requests sent to
/// it and transforming the responses returned by it.
///
/// Use [`LocalServiceLayer`] for a single-threaded equivalent.
///
/// # Combinations
///
/// Layers can be combined (usually in a tuple) into larger layers.  A number
/// of blanket implementations are provided to simplify this.
pub trait ServiceLayer:
    LocalServiceLayer<Producer: Send, Transformer: Send> + Sync
{
    /// Respond to a DNS request.
    ///
    /// The provided consumer must have been provided the entire DNS request
    /// message.  If the request should be forwarded through to the wrapped
    /// service, [`ControlFlow::Continue`] is returned, with a transformer to
    /// modify the wrapped service's response.  However, if the request should
    /// be responded to directly by this layer, without any interaction from
    /// the wrapped service, [`ControlFlow::Break`] is returned.
    ///
    /// The returned future implements [`Send`].  Use [`LocalServiceLayer`]
    /// and [`LocalServiceLayer::respond_local()`] if [`Send`] is not
    /// necessary.
    fn respond(
        &self,
        request: &RequestMessage<'_>,
    ) -> impl Future<Output = ControlFlow<Self::Producer, Self::Transformer>> + Send;
}

//----------- LocalServiceLayer ----------------------------------------------

/// A (single-threaded) layer wrapping a DNS [`Service`].
///
/// A layer can be wrapped around a service, inspecting the requests sent to
/// it and transforming the responses returned by it.
///
/// Use [`ServiceLayer`] for a multi-threaded equivalent.
///
/// # Combinations
///
/// Layers can be combined (usually in a tuple) into larger layers.  A number
/// of blanket implementations are provided to simplify this.
pub trait LocalServiceLayer {
    /// A producer of DNS responses.
    ///
    /// This type returns components to insert in a DNS response message.  It
    /// is constructed by [`Self::respond_local()`], if a response is returned
    /// early (without the wrapped service interacting with it).
    ///
    /// # Lifetimes
    ///
    /// The producer can borrow from the request message (`'req`).  Note that
    /// it cannot borrow from the response message.
    type Producer: ProduceMessage;

    /// A transformer of DNS responses.
    ///
    /// This type modifies the response from the wrapped service, by adding,
    /// removing, or modifying the components of the response message.  It is
    /// constructed by [`Self::respond_local()`], if an early return does not
    /// occur.
    ///
    /// # Lifetimes
    ///
    /// The transformer can borrow from the request message (`'req`).  Note
    /// that it cannot borrow from the response message.
    type Transformer: TransformMessage;

    /// Respond to a DNS request.
    ///
    /// The provided consumer must have been provided the entire DNS request
    /// message.  If the request should be forwarded through to the wrapped
    /// service, [`ControlFlow::Continue`] is returned, with a transformer to
    /// modify the wrapped service's response.  However, if the request should
    /// be responded to directly by this layer, without any interaction from
    /// the wrapped service, [`ControlFlow::Break`] is returned.
    ///
    /// The returned future does not implement [`Send`].  Use [`ServiceLayer`]
    /// and [`ServiceLayer::respond()`] for a [`Send`]-implementing version.
    #[allow(async_fn_in_trait)]
    async fn respond_local(
        &self,
        request: &RequestMessage<'_>,
    ) -> ControlFlow<Self::Producer, Self::Transformer>;
}

//----------- ProduceMessage -------------------------------------------------

/// A type that produces a DNS message.
///
/// This interface is similar to [`Iterator`], except that it can iterate over
/// the different components of a message (questions, answers, authorities,
/// and additional records).
///
/// # Architecture
///
/// This interface is convenient when multiple transformers need to modify the
/// message as it is being built.  Rather than forcing each transformer to
/// parse and rewrite the message, this interface allows the message to built
/// up over a single iteration, with every transformer directly examining each
/// component added to the message.
///
/// # Examples
pub trait ProduceMessage {
    /// The header of the message.
    ///
    /// The provided header will be uninitialized, and this method is expected
    /// to reset it entirely.  The default implementation does nothing.
    fn header(&mut self, header: &mut Header) {
        let _ = header;
    }

    /// The next DNS question in the message.
    ///
    /// This method is expected to add at most one question using the given
    /// message builder.  If a question is added, its builder is returned so
    /// that it can be modified or filtered before being finalized.
    ///
    /// This must act like a fused iterator; if no question is added, then
    /// future calls to the same method will also add no questions.
    ///
    /// The default implementation of this method will add no questions.
    ///
    /// # Errors
    ///
    /// If new records cannot be inserted in the message (because it is full),
    /// the method is responsible for returning gracefully.  The message may
    /// be marked as truncated, for example.
    fn next_question<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<QuestionBuilder<'b>> {
        let _ = builder;
        None
    }

    /// The next answer record in the message.
    ///
    /// This method is expected to add at most one answer record using the
    /// given message builder.  If a record is added, its builder is returned
    /// so that it can be modified or filtered before being finalized.
    ///
    /// This must act like a fused iterator; if no record is added, then
    /// future calls to the same method will also add no records.
    ///
    /// The default implementation of this method will add no records.
    ///
    /// # Errors
    ///
    /// If new records cannot be inserted in the message (because it is full),
    /// the method is responsible for returning gracefully.  The message may
    /// be marked as truncated, for example.
    fn next_answer<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<RecordBuilder<'b>> {
        let _ = builder;
        None
    }

    /// The next authority record in the message.
    ///
    /// This method is expected to add at most one authority record using the
    /// given message builder.  If a record is added, its builder is returned
    /// so that it can be modified or filtered before being finalized.
    ///
    /// This must act like a fused iterator; if no record is added, then
    /// future calls to the same method will also add no records.
    ///
    /// The default implementation of this method will add no records.
    ///
    /// # Errors
    ///
    /// If new records cannot be inserted in the message (because it is full),
    /// the method is responsible for returning gracefully.  The message may
    /// be marked as truncated, for example.
    fn next_authority<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<RecordBuilder<'b>> {
        let _ = builder;
        None
    }

    /// The next additional record in the message.
    ///
    /// This method is expected to add at most one additional record using the
    /// given message builder.  If a record is added, its builder is returned
    /// so that it can be modified or filtered before being finalized.
    ///
    /// This must act like a fused iterator; if no record is added, then
    /// future calls to the same method will also add no records.
    ///
    /// The default implementation of this method will add no records.
    ///
    /// # Errors
    ///
    /// If new records cannot be inserted in the message (because it is full),
    /// the method is responsible for returning gracefully.  The message may
    /// be marked as truncated, for example.
    fn next_additional<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<RecordBuilder<'b>> {
        let _ = builder;
        None
    }
}

//----------- TransformMessage -----------------------------------------------

/// A type that modifies a DNS message as it is being built.
///
/// This interface is designed around [`ProduceMessage`]: as the components of
/// the message are produced, they are passed through methods of this trait to
/// be modified or filtered out.  Furthermore, implementing types can add more
/// components to the message as they also implement [`ProduceMessage`].
///
/// # Examples
pub trait TransformMessage: ProduceMessage {
    /// Modify the header of the message.
    ///
    /// The provided header has been initialized; this method can choose to
    /// modify it.  The default implementation does nothing.
    fn modify_header(&mut self, header: &mut Header) {
        let _ = header;
    }

    /// Modify a question added to the message.
    ///
    /// This method is called when a question is being added to the message.
    /// The question can be modified.
    ///
    /// If [`ControlFlow::Continue`] is returned, the question is preserved,
    /// and can be passed through future transformations.  Otherwise, the
    /// question is removed.
    ///
    /// The default implementation of this method passes the question through
    /// transparently.
    fn modify_question(
        &mut self,
        builder: &mut QuestionBuilder<'_>,
    ) -> ControlFlow<()> {
        let _ = builder;
        ControlFlow::Continue(())
    }

    /// Modify an answer record added to the message.
    ///
    /// This method is called when an answer record is being added to the
    /// message.  The record (and its data) can be modified.
    ///
    /// If [`ControlFlow::Continue`] is returned, the record is preserved,
    /// and can be passed through future transformations.  Otherwise, the
    /// record is removed.
    ///
    /// The default implementation of this method passes the record through
    /// transparently.
    fn modify_answer(
        &mut self,
        builder: &mut RecordBuilder<'_>,
    ) -> ControlFlow<()> {
        let _ = builder;
        ControlFlow::Continue(())
    }

    /// Modify an authority record added to the message.
    ///
    /// This method is called when an authority record is being added to the
    /// message.  The record (and its data) can be modified.
    ///
    /// If [`ControlFlow::Continue`] is returned, the record is preserved,
    /// and can be passed through future transformations.  Otherwise, the
    /// record is removed.
    ///
    /// The default implementation of this method passes the record through
    /// transparently.
    fn modify_authority(
        &mut self,
        builder: &mut RecordBuilder<'_>,
    ) -> ControlFlow<()> {
        let _ = builder;
        ControlFlow::Continue(())
    }

    /// Modify an additional record added to the message.
    ///
    /// This method is called when an additional record is being added to the
    /// message.  The record (and its data) can be modified.
    ///
    /// If [`ControlFlow::Continue`] is returned, the record is preserved,
    /// and can be passed through future transformations.  Otherwise, the
    /// record is removed.
    ///
    /// The default implementation of this method passes the record through
    /// transparently.
    fn modify_additional(
        &mut self,
        builder: &mut RecordBuilder<'_>,
    ) -> ControlFlow<()> {
        let _ = builder;
        ControlFlow::Continue(())
    }
}
