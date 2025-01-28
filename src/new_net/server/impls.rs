//! Blanket implementations for service traits.

use core::ops::ControlFlow;

#[cfg(feature = "std")]
use std::{boxed::Box, rc::Rc, sync::Arc, vec::Vec};

use either::Either::{self, Left, Right};

use crate::new_base::{
    build::{MessageBuilder, QuestionBuilder, RecordBuilder},
    Header,
};

use super::{
    LocalService, LocalServiceLayer, ProduceMessage, RequestMessage, Service,
    ServiceLayer, TransformMessage,
};

//----------- impl Service ---------------------------------------------------

impl<T: ?Sized + Service> Service for &T {
    async fn respond(&self, request: &RequestMessage<'_>) -> Self::Producer {
        T::respond(self, request).await
    }
}

impl<T: ?Sized + Service> Service for &mut T {
    async fn respond(&self, request: &RequestMessage<'_>) -> Self::Producer {
        T::respond(self, request).await
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + Service> Service for Box<T> {
    async fn respond(&self, request: &RequestMessage<'_>) -> Self::Producer {
        T::respond(self, request).await
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + Send + Service> Service for Arc<T> {
    async fn respond(&self, request: &RequestMessage<'_>) -> Self::Producer {
        T::respond(self, request).await
    }
}

impl<A, S: ?Sized> Service for (A, S)
where
    A: ServiceLayer,
    S: Service,
{
    async fn respond(&self, request: &RequestMessage<'_>) -> Self::Producer {
        match self.0.respond(request).await {
            ControlFlow::Continue(t) => {
                Right((t, self.1.respond(request).await))
            }
            ControlFlow::Break(p) => Left(p),
        }
    }
}

macro_rules! impl_service_tuple {
    ($($layers:ident)* .. $service:ident) => {
        impl<$($layers,)* $service: ?Sized>
        Service for ($($layers,)* $service,)
        where
            $($layers: ServiceLayer,)*
            $service: Service,
        {
            async fn respond(
                &self,
                request: &RequestMessage<'_>,
            ) -> Self::Producer {
                #[allow(non_snake_case)]
                let ($($layers,)* $service,) = self;
                (($($layers),*,), $service).respond(request).await
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

//----------- impl LocalService ----------------------------------------------

impl<T: ?Sized + LocalService> LocalService for &T {
    type Producer = T::Producer;

    async fn respond_local(
        &self,
        request: &RequestMessage<'_>,
    ) -> Self::Producer {
        T::respond_local(self, request).await
    }
}

impl<T: ?Sized + LocalService> LocalService for &mut T {
    type Producer = T::Producer;

    async fn respond_local(
        &self,
        request: &RequestMessage<'_>,
    ) -> Self::Producer {
        T::respond_local(self, request).await
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + LocalService> LocalService for Box<T> {
    type Producer = T::Producer;

    async fn respond_local(
        &self,
        request: &RequestMessage<'_>,
    ) -> Self::Producer {
        T::respond_local(self, request).await
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + LocalService> LocalService for Rc<T> {
    type Producer = T::Producer;

    async fn respond_local(
        &self,
        request: &RequestMessage<'_>,
    ) -> Self::Producer {
        T::respond_local(self, request).await
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + LocalService> LocalService for Arc<T> {
    type Producer = T::Producer;

    async fn respond_local(
        &self,
        request: &RequestMessage<'_>,
    ) -> Self::Producer {
        T::respond_local(self, request).await
    }
}

impl<A, S: ?Sized> LocalService for (A, S)
where
    A: LocalServiceLayer,
    S: LocalService,
{
    type Producer = Either<A::Producer, (A::Transformer, S::Producer)>;

    async fn respond_local(
        &self,
        request: &RequestMessage<'_>,
    ) -> Self::Producer {
        match self.0.respond_local(request).await {
            ControlFlow::Continue(t) => {
                Right((t, self.1.respond_local(request).await))
            }
            ControlFlow::Break(p) => Left(p),
        }
    }
}

macro_rules! impl_local_service_tuple {
    ($($layers:ident)* .. $service:ident) => {
        impl<$($layers,)* $service: ?Sized>
        LocalService for ($($layers,)* $service,)
        where
            $($layers: LocalServiceLayer,)*
            $service: LocalService,
        {
            type Producer =
                <(($($layers),*,), $service) as LocalService>::Producer;

            async fn respond_local(
                &self,
                request: &RequestMessage<'_>,
            ) -> Self::Producer {
                #[allow(non_snake_case)]
                let ($($layers,)* $service,) = self;
                (($($layers),*,), $service).respond_local(request).await
            }
        }
    };
}

impl_local_service_tuple!(A B..S);
impl_local_service_tuple!(A B C..S);
impl_local_service_tuple!(A B C D..S);
impl_local_service_tuple!(A B C D E..S);
impl_local_service_tuple!(A B C D E F..S);
impl_local_service_tuple!(A B C D E F G..S);
impl_local_service_tuple!(A B C D E F G H..S);
impl_local_service_tuple!(A B C D E F G H I..S);
impl_local_service_tuple!(A B C D E F G H I J..S);
impl_local_service_tuple!(A B C D E F G H I J K..S);

//----------- impl ServiceLayer ----------------------------------------------

impl<T: ?Sized + ServiceLayer> ServiceLayer for &T {
    async fn respond(
        &self,
        request: &RequestMessage<'_>,
    ) -> ControlFlow<Self::Producer, Self::Transformer> {
        T::respond(self, request).await
    }
}

impl<T: ?Sized + ServiceLayer> ServiceLayer for &mut T {
    async fn respond(
        &self,
        request: &RequestMessage<'_>,
    ) -> ControlFlow<Self::Producer, Self::Transformer> {
        T::respond(self, request).await
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + ServiceLayer> ServiceLayer for Box<T> {
    async fn respond(
        &self,
        request: &RequestMessage<'_>,
    ) -> ControlFlow<Self::Producer, Self::Transformer> {
        T::respond(self, request).await
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + ServiceLayer + Send> ServiceLayer for Arc<T> {
    async fn respond(
        &self,
        request: &RequestMessage<'_>,
    ) -> ControlFlow<Self::Producer, Self::Transformer> {
        T::respond(self, request).await
    }
}

impl<A, B: ?Sized> ServiceLayer for (A, B)
where
    A: ServiceLayer,
    B: ServiceLayer,
{
    async fn respond(
        &self,
        request: &RequestMessage<'_>,
    ) -> ControlFlow<Self::Producer, Self::Transformer> {
        let at = match <A as ServiceLayer>::respond(&self.0, request).await {
            ControlFlow::Continue(at) => at,
            ControlFlow::Break(ap) => return ControlFlow::Break(Left(ap)),
        };

        match <B as ServiceLayer>::respond(&self.1, request).await {
            ControlFlow::Continue(bt) => ControlFlow::Continue((at, bt)),
            ControlFlow::Break(bp) => ControlFlow::Break(Right((at, bp))),
        }
    }
}

macro_rules! impl_service_layer_tuple {
    ($first:ident .. $last:ident: $($middle:ident)+) => {
        impl<$first, $($middle,)+ $last: ?Sized>
        ServiceLayer for ($first, $($middle,)+ $last)
        where
            $first: ServiceLayer,
            $($middle: ServiceLayer,)+
            $last: ServiceLayer,
        {
            async fn respond(
                &self,
                request: &RequestMessage<'_>,
            ) -> ControlFlow<Self::Producer, Self::Transformer>
            {
                #[allow(non_snake_case)]
                let ($first, $($middle,)+ ref $last) = self;
                ($first, ($($middle,)+ $last)).respond(request).await
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
impl<T: ServiceLayer> ServiceLayer for [T] {
    async fn respond(
        &self,
        request: &RequestMessage<'_>,
    ) -> ControlFlow<Self::Producer, Self::Transformer> {
        let mut transformers = Vec::new();
        for layer in self {
            match layer.respond(request).await {
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
impl<T: ServiceLayer> ServiceLayer for Vec<T> {
    async fn respond(
        &self,
        request: &RequestMessage<'_>,
    ) -> ControlFlow<Self::Producer, Self::Transformer> {
        self.as_slice().respond(request).await
    }
}

//----------- impl LocalServiceLayer -----------------------------------------

impl<T: ?Sized + LocalServiceLayer> LocalServiceLayer for &T {
    type Producer = T::Producer;

    type Transformer = T::Transformer;

    async fn respond_local(
        &self,
        request: &RequestMessage<'_>,
    ) -> ControlFlow<Self::Producer, Self::Transformer> {
        T::respond_local(self, request).await
    }
}

impl<T: ?Sized + LocalServiceLayer> LocalServiceLayer for &mut T {
    type Producer = T::Producer;

    type Transformer = T::Transformer;

    async fn respond_local(
        &self,
        request: &RequestMessage<'_>,
    ) -> ControlFlow<Self::Producer, Self::Transformer> {
        T::respond_local(self, request).await
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + LocalServiceLayer> LocalServiceLayer for Box<T> {
    type Producer = T::Producer;

    type Transformer = T::Transformer;

    async fn respond_local(
        &self,
        request: &RequestMessage<'_>,
    ) -> ControlFlow<Self::Producer, Self::Transformer> {
        T::respond_local(self, request).await
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + LocalServiceLayer> LocalServiceLayer for Rc<T> {
    type Producer = T::Producer;

    type Transformer = T::Transformer;

    async fn respond_local(
        &self,
        request: &RequestMessage<'_>,
    ) -> ControlFlow<Self::Producer, Self::Transformer> {
        T::respond_local(self, request).await
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + LocalServiceLayer> LocalServiceLayer for Arc<T> {
    type Producer = T::Producer;

    type Transformer = T::Transformer;

    async fn respond_local(
        &self,
        request: &RequestMessage<'_>,
    ) -> ControlFlow<Self::Producer, Self::Transformer> {
        T::respond_local(self, request).await
    }
}

impl<A, B: ?Sized> LocalServiceLayer for (A, B)
where
    A: LocalServiceLayer,
    B: LocalServiceLayer,
{
    type Producer = Either<A::Producer, (A::Transformer, B::Producer)>;

    type Transformer = (A::Transformer, B::Transformer);

    async fn respond_local(
        &self,
        request: &RequestMessage<'_>,
    ) -> ControlFlow<Self::Producer, Self::Transformer> {
        let at = match self.0.respond_local(request).await {
            ControlFlow::Continue(at) => at,
            ControlFlow::Break(ap) => return ControlFlow::Break(Left(ap)),
        };

        match self.1.respond_local(request).await {
            ControlFlow::Continue(bt) => ControlFlow::Continue((at, bt)),
            ControlFlow::Break(bp) => ControlFlow::Break(Right((at, bp))),
        }
    }
}

macro_rules! impl_local_service_layer_tuple {
    ($first:ident .. $last:ident: $($middle:ident)+) => {
        impl<$first, $($middle,)+ $last: ?Sized>
        LocalServiceLayer for ($first, $($middle,)+ $last)
        where
            $first: LocalServiceLayer,
            $($middle: LocalServiceLayer,)+
            $last: LocalServiceLayer,
        {
            type Producer =
                <($first, ($($middle,)+ $last)) as LocalServiceLayer>
                    ::Producer;

            type Transformer =
                <($first, ($($middle,)+ $last)) as LocalServiceLayer>
                    ::Transformer;

            async fn respond_local(
                &self,
                request: &RequestMessage<'_>,
            ) -> ControlFlow<Self::Producer, Self::Transformer>
            {
                #[allow(non_snake_case)]
                let ($first, $($middle,)+ ref $last) = self;
                ($first, ($($middle,)+ $last)).respond_local(request).await
            }
        }
    }
}

impl_local_service_layer_tuple!(A..C: B);
impl_local_service_layer_tuple!(A..D: B C);
impl_local_service_layer_tuple!(A..E: B C D);
impl_local_service_layer_tuple!(A..F: B C D E);
impl_local_service_layer_tuple!(A..G: B C D E F);
impl_local_service_layer_tuple!(A..H: B C D E F G);
impl_local_service_layer_tuple!(A..I: B C D E F G H);
impl_local_service_layer_tuple!(A..J: B C D E F G H I);
impl_local_service_layer_tuple!(A..K: B C D E F G H I J);
impl_local_service_layer_tuple!(A..L: B C D E F G H I J K);

#[cfg(feature = "std")]
impl<T: LocalServiceLayer> LocalServiceLayer for [T] {
    type Producer = (Box<[T::Transformer]>, T::Producer);
    type Transformer = Box<[T::Transformer]>;

    async fn respond_local(
        &self,
        request: &RequestMessage<'_>,
    ) -> ControlFlow<Self::Producer, Self::Transformer> {
        let mut transformers = Vec::new();
        for layer in self {
            match layer.respond_local(request).await {
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
impl<T: LocalServiceLayer> LocalServiceLayer for Vec<T> {
    type Producer = (Box<[T::Transformer]>, T::Producer);
    type Transformer = Box<[T::Transformer]>;

    async fn respond_local(
        &self,
        request: &RequestMessage<'_>,
    ) -> ControlFlow<Self::Producer, Self::Transformer> {
        self.as_slice().respond_local(request).await
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
