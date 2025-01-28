//! Blanket implementations for service traits.

use core::ops::ControlFlow;

#[cfg(feature = "std")]
use std::{boxed::Box, rc::Rc, sync::Arc, vec::Vec};

use either::Either::{self, Left, Right};

use crate::{
    new_base::{
        build::{MessageBuilder, QuestionBuilder, RecordBuilder},
        name::RevNameBuf,
        Header, Question, Record,
    },
    new_rdata::RecordData,
};

use super::{
    ConsumeMessage, ProduceMessage, Service, ServiceLayer, TransformMessage,
};

//----------- impl Service ---------------------------------------------------

impl<'req, T: ?Sized + Service<'req>> Service<'req> for &T {
    type Consumer = T::Consumer;

    type Producer = T::Producer;

    fn consume(&self) -> Self::Consumer {
        T::consume(self)
    }

    fn respond(&self, request: Self::Consumer) -> Self::Producer {
        T::respond(self, request)
    }
}

impl<'req, T: ?Sized + Service<'req>> Service<'req> for &mut T {
    type Consumer = T::Consumer;

    type Producer = T::Producer;

    fn consume(&self) -> Self::Consumer {
        T::consume(self)
    }

    fn respond(&self, request: Self::Consumer) -> Self::Producer {
        T::respond(self, request)
    }
}

#[cfg(feature = "std")]
impl<'req, T: ?Sized + Service<'req>> Service<'req> for Box<T> {
    type Consumer = T::Consumer;

    type Producer = T::Producer;

    fn consume(&self) -> Self::Consumer {
        T::consume(self)
    }

    fn respond(&self, request: Self::Consumer) -> Self::Producer {
        T::respond(self, request)
    }
}

#[cfg(feature = "std")]
impl<'req, T: ?Sized + Service<'req>> Service<'req> for Rc<T> {
    type Consumer = T::Consumer;

    type Producer = T::Producer;

    fn consume(&self) -> Self::Consumer {
        T::consume(self)
    }

    fn respond(&self, request: Self::Consumer) -> Self::Producer {
        T::respond(self, request)
    }
}

#[cfg(feature = "std")]
impl<'req, T: ?Sized + Service<'req>> Service<'req> for Arc<T> {
    type Consumer = T::Consumer;

    type Producer = T::Producer;

    fn consume(&self) -> Self::Consumer {
        T::consume(self)
    }

    fn respond(&self, request: Self::Consumer) -> Self::Producer {
        T::respond(self, request)
    }
}

impl<'req, A, S: ?Sized> Service<'req> for (A, S)
where
    A: ServiceLayer<'req>,
    S: Service<'req>,
{
    type Consumer = (A::Consumer, S::Consumer);

    type Producer = Either<A::Producer, (A::Transformer, S::Producer)>;

    fn consume(&self) -> Self::Consumer {
        (self.0.consume(), self.1.consume())
    }

    fn respond(&self, request: Self::Consumer) -> Self::Producer {
        match self.0.respond(request.0) {
            ControlFlow::Continue(t) => Right((t, self.1.respond(request.1))),
            ControlFlow::Break(p) => Left(p),
        }
    }
}

macro_rules! impl_service_tuple {
    ($($layers:ident)* .. $service:ident) => {
        impl<'req, $($layers,)* $service: ?Sized>
        Service<'req> for ($($layers,)* $service,)
        where
            $($layers: ServiceLayer<'req>,)*
            $service: Service<'req>,
        {
            type Consumer =
                <(($($layers),*,), $service) as Service<'req>>::Consumer;

            type Producer =
                <(($($layers),*,), $service) as Service<'req>>::Producer;

            fn consume(&self) -> Self::Consumer {
                #[allow(non_snake_case)]
                let ($($layers,)* $service,) = self;
                (($($layers),*,), $service).consume()
            }

            fn respond(&self, request: Self::Consumer) -> Self::Producer {
                #[allow(non_snake_case)]
                let ($($layers,)* $service,) = self;
                (($($layers),*,), $service).respond(request)
            }
        }
    };
}

impl_service_tuple!(A B..S);
impl_service_tuple!(A B C..S);
impl_service_tuple!(A B C D..S);
impl_service_tuple!(A B C D E..S);
impl_service_tuple!(A B C D E F..S);
impl_service_tuple!(A B C D E F G..S);
impl_service_tuple!(A B C D E F G H..S);
impl_service_tuple!(A B C D E F G H I..S);
impl_service_tuple!(A B C D E F G H I J..S);
impl_service_tuple!(A B C D E F G H I J K..S);

//----------- impl ServiceLayer ----------------------------------------------

impl<'req, T: ?Sized + ServiceLayer<'req>> ServiceLayer<'req> for &T {
    type Consumer = T::Consumer;

    type Producer = T::Producer;

    type Transformer = T::Transformer;

    fn consume(&self) -> Self::Consumer {
        T::consume(self)
    }

    fn respond(
        &self,
        request: Self::Consumer,
    ) -> ControlFlow<Self::Producer, Self::Transformer> {
        T::respond(self, request)
    }
}

impl<'req, T: ?Sized + ServiceLayer<'req>> ServiceLayer<'req> for &mut T {
    type Consumer = T::Consumer;

    type Producer = T::Producer;

    type Transformer = T::Transformer;

    fn consume(&self) -> Self::Consumer {
        T::consume(self)
    }

    fn respond(
        &self,
        request: Self::Consumer,
    ) -> ControlFlow<Self::Producer, Self::Transformer> {
        T::respond(self, request)
    }
}

#[cfg(feature = "std")]
impl<'req, T: ?Sized + ServiceLayer<'req>> ServiceLayer<'req> for Box<T> {
    type Consumer = T::Consumer;

    type Producer = T::Producer;

    type Transformer = T::Transformer;

    fn consume(&self) -> Self::Consumer {
        T::consume(self)
    }

    fn respond(
        &self,
        request: Self::Consumer,
    ) -> ControlFlow<Self::Producer, Self::Transformer> {
        T::respond(self, request)
    }
}

#[cfg(feature = "std")]
impl<'req, T: ?Sized + ServiceLayer<'req>> ServiceLayer<'req> for Rc<T> {
    type Consumer = T::Consumer;

    type Producer = T::Producer;

    type Transformer = T::Transformer;

    fn consume(&self) -> Self::Consumer {
        T::consume(self)
    }

    fn respond(
        &self,
        request: Self::Consumer,
    ) -> ControlFlow<Self::Producer, Self::Transformer> {
        T::respond(self, request)
    }
}

#[cfg(feature = "std")]
impl<'req, T: ?Sized + ServiceLayer<'req>> ServiceLayer<'req> for Arc<T> {
    type Consumer = T::Consumer;

    type Producer = T::Producer;

    type Transformer = T::Transformer;

    fn consume(&self) -> Self::Consumer {
        T::consume(self)
    }

    fn respond(
        &self,
        request: Self::Consumer,
    ) -> ControlFlow<Self::Producer, Self::Transformer> {
        T::respond(self, request)
    }
}

impl<'req, A, B: ?Sized> ServiceLayer<'req> for (A, B)
where
    A: ServiceLayer<'req>,
    B: ServiceLayer<'req>,
{
    type Consumer = (A::Consumer, B::Consumer);

    type Producer = Either<A::Producer, (A::Transformer, B::Producer)>;

    type Transformer = (A::Transformer, B::Transformer);

    fn consume(&self) -> Self::Consumer {
        (self.0.consume(), self.1.consume())
    }

    fn respond(
        &self,
        request: Self::Consumer,
    ) -> ControlFlow<Self::Producer, Self::Transformer> {
        let at = match self.0.respond(request.0) {
            ControlFlow::Continue(at) => at,
            ControlFlow::Break(ap) => return ControlFlow::Break(Left(ap)),
        };

        match self.1.respond(request.1) {
            ControlFlow::Continue(bt) => ControlFlow::Continue((at, bt)),
            ControlFlow::Break(bp) => ControlFlow::Break(Right((at, bp))),
        }
    }
}

macro_rules! impl_service_layer_tuple {
    ($first:ident .. $last:ident: $($middle:ident)+) => {
        impl<'req, $first, $($middle,)+ $last: ?Sized>
        ServiceLayer<'req> for ($first, $($middle,)+ $last)
        where
            $first: ServiceLayer<'req>,
            $($middle: ServiceLayer<'req>,)+
            $last: ServiceLayer<'req>,
        {
            type Consumer =
                <($first, ($($middle,)+ $last)) as ServiceLayer<'req>>
                    ::Consumer;

            type Producer =
                <($first, ($($middle,)+ $last)) as ServiceLayer<'req>>
                    ::Producer;

            type Transformer =
                <($first, ($($middle,)+ $last)) as ServiceLayer<'req>>
                    ::Transformer;

            fn consume(&self) -> Self::Consumer
            {
                #[allow(non_snake_case)]
                let ($first, $($middle,)+ $last) = self;
                ($first, ($($middle,)+ $last)).consume()
            }

            fn respond(
                &self,
                request: Self::Consumer,
            ) -> ControlFlow<Self::Producer, Self::Transformer>
            {
                #[allow(non_snake_case)]
                let ($first, $($middle,)+ ref $last) = self;
                ($first, ($($middle,)+ $last)).respond(request)
            }
        }
    }
}

impl_service_layer_tuple!(A..C: B);
impl_service_layer_tuple!(A..D: B C);
impl_service_layer_tuple!(A..E: B C D);
impl_service_layer_tuple!(A..F: B C D E);
impl_service_layer_tuple!(A..G: B C D E F);
impl_service_layer_tuple!(A..H: B C D E F G);
impl_service_layer_tuple!(A..I: B C D E F G H);
impl_service_layer_tuple!(A..J: B C D E F G H I);
impl_service_layer_tuple!(A..K: B C D E F G H I J);
impl_service_layer_tuple!(A..L: B C D E F G H I J K);

#[cfg(feature = "std")]
impl<'req, T: ServiceLayer<'req>> ServiceLayer<'req> for [T] {
    type Consumer = Box<[T::Consumer]>;
    type Producer = (Box<[T::Transformer]>, T::Producer);
    type Transformer = Box<[T::Transformer]>;

    fn consume(&self) -> Self::Consumer {
        self.iter().map(T::consume).collect()
    }

    fn respond(
        &self,
        request: Self::Consumer,
    ) -> ControlFlow<Self::Producer, Self::Transformer> {
        let mut transformers = Vec::new();
        // TODO (MSRV 1.80): Use Box<[T]>: IntoIterator
        let request: Vec<_> = request.into();
        for (layer, request) in self.iter().zip(request) {
            match layer.respond(request) {
                ControlFlow::Continue(t) => transformers.push(t),
                ControlFlow::Break(p) => {
                    return ControlFlow::Break((transformers.into(), p));
                }
            }
        }
        ControlFlow::Continue(transformers.into())
    }
}

#[cfg(feature = "std")]
impl<'req, T: ServiceLayer<'req>> ServiceLayer<'req> for Vec<T> {
    type Consumer = Box<[T::Consumer]>;
    type Producer = (Box<[T::Transformer]>, T::Producer);
    type Transformer = Box<[T::Transformer]>;

    fn consume(&self) -> Self::Consumer {
        self.as_slice().consume()
    }

    fn respond(
        &self,
        request: Self::Consumer,
    ) -> ControlFlow<Self::Producer, Self::Transformer> {
        self.as_slice().respond(request)
    }
}

//----------- impl ConsumeMessage --------------------------------------------

impl<'msg, T: ?Sized + ConsumeMessage<'msg>> ConsumeMessage<'msg> for &mut T {
    fn consume_header(&mut self, header: &'msg Header) {
        T::consume_header(self, header);
    }

    fn consume_question(&mut self, question: &Question<RevNameBuf>) {
        T::consume_question(self, question);
    }

    fn consume_answer(
        &mut self,
        answer: &Record<RevNameBuf, RecordData<'msg, RevNameBuf>>,
    ) {
        T::consume_answer(self, answer);
    }

    fn consume_authority(
        &mut self,
        authority: &Record<RevNameBuf, RecordData<'msg, RevNameBuf>>,
    ) {
        T::consume_authority(self, authority);
    }

    fn consume_additional(
        &mut self,
        additional: &Record<RevNameBuf, RecordData<'msg, RevNameBuf>>,
    ) {
        T::consume_additional(self, additional);
    }
}

#[cfg(feature = "std")]
impl<'msg, T: ?Sized + ConsumeMessage<'msg>> ConsumeMessage<'msg> for Box<T> {
    fn consume_header(&mut self, header: &'msg Header) {
        T::consume_header(self, header);
    }

    fn consume_question(&mut self, question: &Question<RevNameBuf>) {
        T::consume_question(self, question);
    }

    fn consume_answer(
        &mut self,
        answer: &Record<RevNameBuf, RecordData<'msg, RevNameBuf>>,
    ) {
        T::consume_answer(self, answer);
    }

    fn consume_authority(
        &mut self,
        authority: &Record<RevNameBuf, RecordData<'msg, RevNameBuf>>,
    ) {
        T::consume_authority(self, authority);
    }

    fn consume_additional(
        &mut self,
        additional: &Record<RevNameBuf, RecordData<'msg, RevNameBuf>>,
    ) {
        T::consume_additional(self, additional);
    }
}

impl<'msg, A, B> ConsumeMessage<'msg> for Either<A, B>
where
    A: ConsumeMessage<'msg>,
    B: ConsumeMessage<'msg>,
{
    fn consume_header(&mut self, header: &'msg Header) {
        either::for_both!(self, x => x.consume_header(header))
    }

    fn consume_question(&mut self, question: &Question<RevNameBuf>) {
        either::for_both!(self, x => x.consume_question(question))
    }

    fn consume_answer(
        &mut self,
        answer: &Record<RevNameBuf, RecordData<'msg, RevNameBuf>>,
    ) {
        either::for_both!(self, x => x.consume_answer(answer))
    }

    fn consume_authority(
        &mut self,
        authority: &Record<RevNameBuf, RecordData<'msg, RevNameBuf>>,
    ) {
        either::for_both!(self, x => x.consume_authority(authority))
    }

    fn consume_additional(
        &mut self,
        additional: &Record<RevNameBuf, RecordData<'msg, RevNameBuf>>,
    ) {
        either::for_both!(self, x => x.consume_additional(additional))
    }
}

macro_rules! impl_consume_message_tuple {
    ($($middle:ident)* .. $last:ident) => {
        impl<'msg, $($middle,)* $last: ?Sized>
        ConsumeMessage<'msg> for ($($middle,)* $last,)
        where
            $($middle: ConsumeMessage<'msg>,)*
            $last: ConsumeMessage<'msg>,
        {
            fn consume_header(&mut self, header: &'msg Header) {
                #[allow(non_snake_case)]
                let ($($middle,)* ref mut $last,) = self;
                $($middle.consume_header(header);)*
                $last.consume_header(header);
            }

            fn consume_question(&mut self, question: &Question<RevNameBuf>) {
                #[allow(non_snake_case)]
                let ($($middle,)* ref mut $last,) = self;
                $($middle.consume_question(question);)*
                $last.consume_question(question);
            }

            fn consume_answer(
                &mut self,
                answer: &Record<RevNameBuf, RecordData<'msg, RevNameBuf>>,
            ) {
                #[allow(non_snake_case)]
                let ($($middle,)* ref mut $last,) = self;
                $($middle.consume_answer(answer);)*
                $last.consume_answer(answer);
            }

            fn consume_authority(
                &mut self,
                authority: &Record<RevNameBuf, RecordData<'msg, RevNameBuf>>,
            ) {
                #[allow(non_snake_case)]
                let ($($middle,)* ref mut $last,) = self;
                $($middle.consume_authority(authority);)*
                $last.consume_authority(authority);
            }

            fn consume_additional(
                &mut self,
                additional: &Record<RevNameBuf, RecordData<'msg, RevNameBuf>>,
            ) {
                #[allow(non_snake_case)]
                let ($($middle,)* ref mut $last,) = self;
                $($middle.consume_additional(additional);)*
                $last.consume_additional(additional);
            }
        }
    };
}

impl_consume_message_tuple!(..A);
impl_consume_message_tuple!(A..B);
impl_consume_message_tuple!(A B..C);
impl_consume_message_tuple!(A B C..D);
impl_consume_message_tuple!(A B C D..E);
impl_consume_message_tuple!(A B C D E..F);
impl_consume_message_tuple!(A B C D E F..G);
impl_consume_message_tuple!(A B C D E F G..H);
impl_consume_message_tuple!(A B C D E F G H..I);
impl_consume_message_tuple!(A B C D E F G H I..J);
impl_consume_message_tuple!(A B C D E F G H I J..K);
impl_consume_message_tuple!(A B C D E F G H I J K..L);

impl<'msg, T: ConsumeMessage<'msg>> ConsumeMessage<'msg> for [T] {
    fn consume_header(&mut self, header: &'msg Header) {
        self.iter_mut()
            .for_each(|layer| layer.consume_header(header));
    }

    fn consume_question(&mut self, question: &Question<RevNameBuf>) {
        self.iter_mut()
            .for_each(|layer| layer.consume_question(question));
    }

    fn consume_answer(
        &mut self,
        answer: &Record<RevNameBuf, RecordData<'msg, RevNameBuf>>,
    ) {
        self.iter_mut()
            .for_each(|layer| layer.consume_answer(answer));
    }

    fn consume_authority(
        &mut self,
        authority: &Record<RevNameBuf, RecordData<'msg, RevNameBuf>>,
    ) {
        self.iter_mut()
            .for_each(|layer| layer.consume_authority(authority));
    }

    fn consume_additional(
        &mut self,
        additional: &Record<RevNameBuf, RecordData<'msg, RevNameBuf>>,
    ) {
        self.iter_mut()
            .for_each(|layer| layer.consume_additional(additional));
    }
}

#[cfg(feature = "std")]
impl<'msg, T: ConsumeMessage<'msg>> ConsumeMessage<'msg> for Vec<T> {
    fn consume_header(&mut self, header: &'msg Header) {
        self.as_mut_slice().consume_header(header)
    }

    fn consume_question(&mut self, question: &Question<RevNameBuf>) {
        self.as_mut_slice().consume_question(question)
    }

    fn consume_answer(
        &mut self,
        answer: &Record<RevNameBuf, RecordData<'msg, RevNameBuf>>,
    ) {
        self.as_mut_slice().consume_answer(answer)
    }

    fn consume_authority(
        &mut self,
        authority: &Record<RevNameBuf, RecordData<'msg, RevNameBuf>>,
    ) {
        self.as_mut_slice().consume_authority(authority)
    }

    fn consume_additional(
        &mut self,
        additional: &Record<RevNameBuf, RecordData<'msg, RevNameBuf>>,
    ) {
        self.as_mut_slice().consume_additional(additional)
    }
}

//----------- impl ProduceMessage --------------------------------------------

impl<T: ?Sized + ProduceMessage> ProduceMessage for &mut T {
    fn header(&mut self, header: &mut Header) {
        T::header(self, header);
    }

    fn next_question<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<QuestionBuilder<'b>> {
        T::next_question(self, builder)
    }

    fn next_answer<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<RecordBuilder<'b>> {
        T::next_answer(self, builder)
    }

    fn next_authority<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<RecordBuilder<'b>> {
        T::next_authority(self, builder)
    }

    fn next_additional<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<RecordBuilder<'b>> {
        T::next_additional(self, builder)
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + ProduceMessage> ProduceMessage for Box<T> {
    fn header(&mut self, header: &mut Header) {
        T::header(self, header);
    }

    fn next_question<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<QuestionBuilder<'b>> {
        T::next_question(self, builder)
    }

    fn next_answer<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<RecordBuilder<'b>> {
        T::next_answer(self, builder)
    }

    fn next_authority<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<RecordBuilder<'b>> {
        T::next_authority(self, builder)
    }

    fn next_additional<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<RecordBuilder<'b>> {
        T::next_additional(self, builder)
    }
}

impl<A, B> ProduceMessage for Either<A, B>
where
    A: ProduceMessage,
    B: ProduceMessage,
{
    fn header(&mut self, header: &mut Header) {
        either::for_both!(self, x => x.header(header));
    }

    fn next_question<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<QuestionBuilder<'b>> {
        either::for_both!(self, x => x.next_question(builder))
    }

    fn next_answer<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<RecordBuilder<'b>> {
        either::for_both!(self, x => x.next_answer(builder))
    }

    fn next_authority<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<RecordBuilder<'b>> {
        either::for_both!(self, x => x.next_authority(builder))
    }

    fn next_additional<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<RecordBuilder<'b>> {
        either::for_both!(self, x => x.next_additional(builder))
    }
}

impl<A, B: ?Sized> ProduceMessage for (A, B)
where
    A: TransformMessage,
    B: ProduceMessage,
{
    fn header(&mut self, header: &mut Header) {
        B::header(&mut self.1, header);
        A::modify_header(&mut self.0, header);
    }

    fn next_question<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<QuestionBuilder<'b>> {
        loop {
            let mut delegate = builder.reborrow();
            let mut question = match self.1.next_question(&mut delegate) {
                Some(question) => question,
                None => break,
            };

            if self.0.modify_question(&mut question).is_break() {
                continue;
            }

            return builder.resume_question();
        }

        self.0.next_question(builder)
    }

    fn next_answer<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<RecordBuilder<'b>> {
        loop {
            let mut delegate = builder.reborrow();
            let mut answer = match self.1.next_answer(&mut delegate) {
                Some(answer) => answer,
                None => break,
            };

            if self.0.modify_answer(&mut answer).is_break() {
                continue;
            }

            core::mem::drop(answer);
            return builder.resume_answer();
        }

        self.0.next_answer(builder)
    }

    fn next_authority<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<RecordBuilder<'b>> {
        loop {
            let mut delegate = builder.reborrow();
            let mut authority = match self.1.next_authority(&mut delegate) {
                Some(authority) => authority,
                None => break,
            };

            if self.0.modify_authority(&mut authority).is_break() {
                continue;
            }

            core::mem::drop(authority);
            return builder.resume_authority();
        }

        self.0.next_authority(builder)
    }

    fn next_additional<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<RecordBuilder<'b>> {
        loop {
            let mut delegate = builder.reborrow();
            let mut additional = match self.1.next_additional(&mut delegate) {
                Some(additional) => additional,
                None => break,
            };

            if self.0.modify_additional(&mut additional).is_break() {
                continue;
            }

            core::mem::drop(additional);
            return builder.resume_additional();
        }

        self.0.next_additional(builder)
    }
}

macro_rules! impl_produce_message_tuple {
    ($first:ident .. $last:ident: $($middle:ident)*) => {
        impl<$first, $($middle,)* $last: ?Sized>
        ProduceMessage for ($first, $($middle,)* $last)
        where
            $first: TransformMessage,
            $($middle: TransformMessage,)*
            $last: ProduceMessage,
        {
            fn header(&mut self, header: &mut Header) {
                #[allow(non_snake_case)]
                let ($first, $($middle,)* ref mut $last) = self;
                ($first, ($($middle,)* $last))
                    .header(header)
            }

            fn next_question<'b>(
                &mut self,
                builder: &'b mut MessageBuilder<'_>,
            ) -> Option<QuestionBuilder<'b>> {
                #[allow(non_snake_case)]
                let ($first, $($middle,)* ref mut $last) = self;
                ($first, ($($middle,)* $last))
                    .next_question(builder)
            }

            fn next_answer<'b>(
                &mut self,
                builder: &'b mut MessageBuilder<'_>,
            ) -> Option<RecordBuilder<'b>> {
                #[allow(non_snake_case)]
                let ($first, $($middle,)* ref mut $last) = self;
                ($first, ($($middle,)* $last))
                    .next_answer(builder)
            }

            fn next_authority<'b>(
                &mut self,
                builder: &'b mut MessageBuilder<'_>,
            ) -> Option<RecordBuilder<'b>> {
                #[allow(non_snake_case)]
                let ($first, $($middle,)* ref mut $last) = self;
                ($first, ($($middle,)* $last))
                    .next_authority(builder)
            }

            fn next_additional<'b>(
                &mut self,
                builder: &'b mut MessageBuilder<'_>,
            ) -> Option<RecordBuilder<'b>> {
                #[allow(non_snake_case)]
                let ($first, $($middle,)* ref mut $last) = self;
                ($first, ($($middle,)* $last))
                    .next_additional(builder)
            }
        }
    };
}

impl_produce_message_tuple!(A..C: B);
impl_produce_message_tuple!(A..D: B C);
impl_produce_message_tuple!(A..E: B C D);
impl_produce_message_tuple!(A..F: B C D E);
impl_produce_message_tuple!(A..G: B C D E F);
impl_produce_message_tuple!(A..H: B C D E F G);
impl_produce_message_tuple!(A..I: B C D E F G H);
impl_produce_message_tuple!(A..J: B C D E F G H I);
impl_produce_message_tuple!(A..K: B C D E F G H I J);
impl_produce_message_tuple!(A..L: B C D E F G H I J K);

impl<T: TransformMessage> ProduceMessage for [T] {
    fn header(&mut self, header: &mut Header) {
        if let [ref mut layers @ .., ref mut last] = self {
            last.header(header);
            for layer in layers.iter_mut().rev() {
                layer.modify_header(header);
            }
        }
    }

    fn next_question<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<QuestionBuilder<'b>> {
        let mut layers = self;
        while let [ref mut nested @ .., ref mut last] = layers {
            let mut delegate = builder.reborrow();
            let mut question = match last.next_question(&mut delegate) {
                Some(question) => question,
                None => break,
            };

            match nested
                .iter_mut()
                .rev()
                .try_for_each(|layer| layer.modify_question(&mut question))
            {
                ControlFlow::Continue(()) => {
                    return builder.resume_question();
                }

                ControlFlow::Break(()) => {}
            }

            layers = nested;
        }

        None
    }

    fn next_answer<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<RecordBuilder<'b>> {
        let mut layers = self;
        while let [ref mut nested @ .., ref mut last] = layers {
            let mut delegate = builder.reborrow();
            let mut answer = match last.next_answer(&mut delegate) {
                Some(answer) => answer,
                None => break,
            };

            match nested
                .iter_mut()
                .rev()
                .try_for_each(|layer| layer.modify_answer(&mut answer))
            {
                ControlFlow::Continue(()) => {
                    core::mem::drop(answer);
                    return builder.resume_answer();
                }

                ControlFlow::Break(()) => {}
            }

            layers = nested;
        }

        None
    }

    fn next_authority<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<RecordBuilder<'b>> {
        let mut layers = self;
        while let [ref mut nested @ .., ref mut last] = layers {
            let mut delegate = builder.reborrow();
            let mut authority = match last.next_authority(&mut delegate) {
                Some(authority) => authority,
                None => break,
            };

            match nested
                .iter_mut()
                .rev()
                .try_for_each(|layer| layer.modify_authority(&mut authority))
            {
                ControlFlow::Continue(()) => {
                    core::mem::drop(authority);
                    return builder.resume_authority();
                }

                ControlFlow::Break(()) => {}
            }

            layers = nested;
        }

        None
    }

    fn next_additional<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<RecordBuilder<'b>> {
        let mut layers = self;
        while let [ref mut nested @ .., ref mut last] = layers {
            let mut delegate = builder.reborrow();
            let mut additional = match last.next_additional(&mut delegate) {
                Some(additional) => additional,
                None => break,
            };

            match nested.iter_mut().rev().try_for_each(|layer| {
                layer.modify_additional(&mut additional)
            }) {
                ControlFlow::Continue(()) => {
                    core::mem::drop(additional);
                    return builder.resume_additional();
                }

                ControlFlow::Break(()) => {}
            }

            layers = nested;
        }

        None
    }
}

#[cfg(feature = "std")]
impl<T: TransformMessage> ProduceMessage for Vec<T> {
    fn header(&mut self, header: &mut Header) {
        self.as_mut_slice().header(header)
    }

    fn next_question<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<QuestionBuilder<'b>> {
        self.as_mut_slice().next_question(builder)
    }

    fn next_answer<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<RecordBuilder<'b>> {
        self.as_mut_slice().next_answer(builder)
    }

    fn next_authority<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<RecordBuilder<'b>> {
        self.as_mut_slice().next_authority(builder)
    }

    fn next_additional<'b>(
        &mut self,
        builder: &'b mut MessageBuilder<'_>,
    ) -> Option<RecordBuilder<'b>> {
        self.as_mut_slice().next_additional(builder)
    }
}

//----------- TransformMessage -----------------------------------------------

impl<T: ?Sized + TransformMessage> TransformMessage for &mut T {
    fn modify_header(&mut self, header: &mut Header) {
        T::modify_header(self, header);
    }

    fn modify_question(
        &mut self,
        builder: &mut QuestionBuilder<'_>,
    ) -> ControlFlow<()> {
        T::modify_question(self, builder)
    }

    fn modify_answer(
        &mut self,
        builder: &mut RecordBuilder<'_>,
    ) -> ControlFlow<()> {
        T::modify_answer(self, builder)
    }

    fn modify_authority(
        &mut self,
        builder: &mut RecordBuilder<'_>,
    ) -> ControlFlow<()> {
        T::modify_authority(self, builder)
    }

    fn modify_additional(
        &mut self,
        builder: &mut RecordBuilder<'_>,
    ) -> ControlFlow<()> {
        T::modify_additional(self, builder)
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + TransformMessage> TransformMessage for Box<T> {
    fn modify_header(&mut self, header: &mut Header) {
        T::modify_header(self, header);
    }

    fn modify_question(
        &mut self,
        builder: &mut QuestionBuilder<'_>,
    ) -> ControlFlow<()> {
        T::modify_question(self, builder)
    }

    fn modify_answer(
        &mut self,
        builder: &mut RecordBuilder<'_>,
    ) -> ControlFlow<()> {
        T::modify_answer(self, builder)
    }

    fn modify_authority(
        &mut self,
        builder: &mut RecordBuilder<'_>,
    ) -> ControlFlow<()> {
        T::modify_authority(self, builder)
    }

    fn modify_additional(
        &mut self,
        builder: &mut RecordBuilder<'_>,
    ) -> ControlFlow<()> {
        T::modify_additional(self, builder)
    }
}

impl<A, B> TransformMessage for Either<A, B>
where
    A: TransformMessage,
    B: TransformMessage,
{
    fn modify_header(&mut self, header: &mut Header) {
        either::for_both!(self, x => x.modify_header(header));
    }

    fn modify_question(
        &mut self,
        builder: &mut QuestionBuilder<'_>,
    ) -> ControlFlow<()> {
        either::for_both!(self, x => x.modify_question(builder))
    }

    fn modify_answer(
        &mut self,
        builder: &mut RecordBuilder<'_>,
    ) -> ControlFlow<()> {
        either::for_both!(self, x => x.modify_answer(builder))
    }

    fn modify_authority(
        &mut self,
        builder: &mut RecordBuilder<'_>,
    ) -> ControlFlow<()> {
        either::for_both!(self, x => x.modify_authority(builder))
    }

    fn modify_additional(
        &mut self,
        builder: &mut RecordBuilder<'_>,
    ) -> ControlFlow<()> {
        either::for_both!(self, x => x.modify_additional(builder))
    }
}

impl<A, B: ?Sized> TransformMessage for (A, B)
where
    A: TransformMessage,
    B: TransformMessage,
{
    fn modify_header(&mut self, header: &mut Header) {
        self.1.modify_header(header);
        self.0.modify_header(header);
    }

    fn modify_question(
        &mut self,
        builder: &mut QuestionBuilder<'_>,
    ) -> ControlFlow<()> {
        self.1.modify_question(builder)?;
        self.0.modify_question(builder)?;
        ControlFlow::Continue(())
    }

    fn modify_answer(
        &mut self,
        builder: &mut RecordBuilder<'_>,
    ) -> ControlFlow<()> {
        self.1.modify_answer(builder)?;
        self.0.modify_answer(builder)?;
        ControlFlow::Continue(())
    }

    fn modify_authority(
        &mut self,
        builder: &mut RecordBuilder<'_>,
    ) -> ControlFlow<()> {
        self.1.modify_authority(builder)?;
        self.0.modify_authority(builder)?;
        ControlFlow::Continue(())
    }

    fn modify_additional(
        &mut self,
        builder: &mut RecordBuilder<'_>,
    ) -> ControlFlow<()> {
        self.1.modify_additional(builder)?;
        self.0.modify_additional(builder)?;
        ControlFlow::Continue(())
    }
}

macro_rules! impl_transform_message_tuple {
    ($first:ident .. $last:ident: $($middle:ident)*) => {
        impl<$first, $($middle,)* $last: ?Sized>
        TransformMessage for ($first, $($middle,)* $last)
        where
            $first: TransformMessage,
            $($middle: TransformMessage,)*
            $last: TransformMessage,
        {
            fn modify_header(&mut self, header: &mut Header) {
                #[allow(non_snake_case)]
                let ($first, $($middle,)* ref mut $last) = self;
                ($first, ($($middle,)* $last))
                    .modify_header(header)
            }

            fn modify_question(
                &mut self,
                builder: &mut QuestionBuilder<'_>,
            ) -> ControlFlow<()> {
                #[allow(non_snake_case)]
                let ($first, $($middle,)* ref mut $last) = self;
                ($first, ($($middle,)* $last))
                    .modify_question(builder)
            }

            fn modify_answer(
                &mut self,
                builder: &mut RecordBuilder<'_>,
            ) -> ControlFlow<()> {
                #[allow(non_snake_case)]
                let ($first, $($middle,)* ref mut $last) = self;
                ($first, ($($middle,)* $last))
                    .modify_answer(builder)
            }

            fn modify_authority(
                &mut self,
                builder: &mut RecordBuilder<'_>,
            ) -> ControlFlow<()> {
                #[allow(non_snake_case)]
                let ($first, $($middle,)* ref mut $last) = self;
                ($first, ($($middle,)* $last))
                    .modify_authority(builder)
            }

            fn modify_additional(
                &mut self,
                builder: &mut RecordBuilder<'_>,
            ) -> ControlFlow<()> {
                #[allow(non_snake_case)]
                let ($first, $($middle,)* ref mut $last) = self;
                ($first, ($($middle,)* $last))
                    .modify_additional(builder)
            }
        }
    };
}

impl_transform_message_tuple!(A..C: B);
impl_transform_message_tuple!(A..D: B C);
impl_transform_message_tuple!(A..E: B C D);
impl_transform_message_tuple!(A..F: B C D E);
impl_transform_message_tuple!(A..G: B C D E F);
impl_transform_message_tuple!(A..H: B C D E F G);
impl_transform_message_tuple!(A..I: B C D E F G H);
impl_transform_message_tuple!(A..J: B C D E F G H I);
impl_transform_message_tuple!(A..K: B C D E F G H I J);
impl_transform_message_tuple!(A..L: B C D E F G H I J K);

impl<T: TransformMessage> TransformMessage for [T] {
    fn modify_header(&mut self, header: &mut Header) {
        self.iter_mut()
            .rev()
            .for_each(|layer| layer.modify_header(header));
    }

    fn modify_question(
        &mut self,
        builder: &mut QuestionBuilder<'_>,
    ) -> ControlFlow<()> {
        self.iter_mut()
            .rev()
            .try_for_each(|layer| layer.modify_question(builder))
    }

    fn modify_answer(
        &mut self,
        builder: &mut RecordBuilder<'_>,
    ) -> ControlFlow<()> {
        self.iter_mut()
            .rev()
            .try_for_each(|layer| layer.modify_answer(builder))
    }

    fn modify_authority(
        &mut self,
        builder: &mut RecordBuilder<'_>,
    ) -> ControlFlow<()> {
        self.iter_mut()
            .rev()
            .try_for_each(|layer| layer.modify_authority(builder))
    }

    fn modify_additional(
        &mut self,
        builder: &mut RecordBuilder<'_>,
    ) -> ControlFlow<()> {
        self.iter_mut()
            .rev()
            .try_for_each(|layer| layer.modify_additional(builder))
    }
}

#[cfg(feature = "std")]
impl<T: TransformMessage> TransformMessage for Vec<T> {
    fn modify_header(&mut self, header: &mut Header) {
        self.as_mut_slice().modify_header(header)
    }

    fn modify_question(
        &mut self,
        builder: &mut QuestionBuilder<'_>,
    ) -> ControlFlow<()> {
        self.as_mut_slice().modify_question(builder)
    }

    fn modify_answer(
        &mut self,
        builder: &mut RecordBuilder<'_>,
    ) -> ControlFlow<()> {
        self.as_mut_slice().modify_answer(builder)
    }

    fn modify_authority(
        &mut self,
        builder: &mut RecordBuilder<'_>,
    ) -> ControlFlow<()> {
        self.as_mut_slice().modify_authority(builder)
    }

    fn modify_additional(
        &mut self,
        builder: &mut RecordBuilder<'_>,
    ) -> ControlFlow<()> {
        self.as_mut_slice().modify_additional(builder)
    }
}
