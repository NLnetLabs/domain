//! Blanket implementations for service traits.

use core::ops::ControlFlow;

#[cfg(feature = "std")]
use std::{boxed::Box, rc::Rc, sync::Arc, vec::Vec};

use super::{
    exchange::OutgoingResponse, Exchange, LocalService, LocalServiceLayer,
    Service, ServiceLayer,
};

//----------- impl Service ---------------------------------------------------

impl<T: ?Sized + Service> Service for &T {
    async fn respond(&self, exchange: &mut Exchange<'_>) {
        T::respond(self, exchange).await
    }
}

impl<T: ?Sized + Service> Service for &mut T {
    async fn respond(&self, exchange: &mut Exchange<'_>) {
        T::respond(self, exchange).await
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + Service> Service for Box<T> {
    async fn respond(&self, exchange: &mut Exchange<'_>) {
        T::respond(self, exchange).await
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + Send + Service> Service for Arc<T> {
    async fn respond(&self, exchange: &mut Exchange<'_>) {
        T::respond(self, exchange).await
    }
}

impl<A, S: ?Sized> Service for (A, S)
where
    A: ServiceLayer,
    S: Service,
{
    async fn respond(&self, exchange: &mut Exchange<'_>) {
        if self.0.process_incoming(exchange).await.is_continue() {
            self.1.respond(exchange).await;
            let response = OutgoingResponse::new(exchange);
            self.0.process_outgoing(response).await;
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
            async fn respond(&self, exchange: &mut Exchange<'_>) {
                #[allow(non_snake_case)]
                let ($($layers,)* $service,) = self;
                (($($layers),*,), $service).respond(exchange).await
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
    async fn respond_local(&self, exchange: &mut Exchange<'_>) {
        T::respond_local(self, exchange).await
    }
}

impl<T: ?Sized + LocalService> LocalService for &mut T {
    async fn respond_local(&self, exchange: &mut Exchange<'_>) {
        T::respond_local(self, exchange).await
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + LocalService> LocalService for Box<T> {
    async fn respond_local(&self, exchange: &mut Exchange<'_>) {
        T::respond_local(self, exchange).await
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + LocalService> LocalService for Rc<T> {
    async fn respond_local(&self, exchange: &mut Exchange<'_>) {
        T::respond_local(self, exchange).await
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + LocalService> LocalService for Arc<T> {
    async fn respond_local(&self, exchange: &mut Exchange<'_>) {
        T::respond_local(self, exchange).await
    }
}

impl<A, S: ?Sized> LocalService for (A, S)
where
    A: LocalServiceLayer,
    S: LocalService,
{
    async fn respond_local(&self, exchange: &mut Exchange<'_>) {
        if self.0.process_local_incoming(exchange).await.is_continue() {
            self.1.respond_local(exchange).await;
            let response = OutgoingResponse::new(exchange);
            self.0.process_local_outgoing(response).await;
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
            async fn respond_local(&self, exchange: &mut Exchange<'_>) {
                #[allow(non_snake_case)]
                let ($($layers,)* $service,) = self;
                (($($layers),*,), $service).respond_local(exchange).await
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
    async fn process_incoming(
        &self,
        exchange: &mut Exchange<'_>,
    ) -> ControlFlow<()> {
        T::process_incoming(self, exchange).await
    }

    async fn process_outgoing(&self, response: OutgoingResponse<'_, '_>) {
        T::process_outgoing(self, response).await
    }
}

impl<T: ?Sized + ServiceLayer> ServiceLayer for &mut T {
    async fn process_incoming(
        &self,
        exchange: &mut Exchange<'_>,
    ) -> ControlFlow<()> {
        T::process_incoming(self, exchange).await
    }

    async fn process_outgoing(&self, response: OutgoingResponse<'_, '_>) {
        T::process_outgoing(self, response).await
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + ServiceLayer> ServiceLayer for Box<T> {
    async fn process_incoming(
        &self,
        exchange: &mut Exchange<'_>,
    ) -> ControlFlow<()> {
        T::process_incoming(self, exchange).await
    }

    async fn process_outgoing(&self, response: OutgoingResponse<'_, '_>) {
        T::process_outgoing(self, response).await
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + ServiceLayer + Send> ServiceLayer for Arc<T> {
    async fn process_incoming(
        &self,
        exchange: &mut Exchange<'_>,
    ) -> ControlFlow<()> {
        T::process_incoming(self, exchange).await
    }

    async fn process_outgoing(&self, response: OutgoingResponse<'_, '_>) {
        T::process_outgoing(self, response).await
    }
}

impl<A, B: ?Sized> ServiceLayer for (A, B)
where
    A: ServiceLayer,
    B: ServiceLayer,
{
    async fn process_incoming(
        &self,
        exchange: &mut Exchange<'_>,
    ) -> ControlFlow<()> {
        self.0.process_incoming(exchange).await?;
        self.1.process_incoming(exchange).await
    }

    async fn process_outgoing(&self, mut response: OutgoingResponse<'_, '_>) {
        self.1.process_outgoing(response.reborrow()).await;
        self.0.process_outgoing(response.reborrow()).await
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
            async fn process_incoming(
                &self,
                exchange: &mut Exchange<'_>,
            ) -> ControlFlow<()>
            {
                #[allow(non_snake_case)]
                let ($first, $($middle,)+ ref $last) = self;
                $first.process_incoming(exchange).await?;
                $($middle.process_incoming(exchange).await?;)+
                $last.process_incoming(exchange).await
            }

            async fn process_outgoing(
                &self,
                response: OutgoingResponse<'_, '_>,
            ) {
                #[allow(non_snake_case)]
                let ($first, $($middle,)+ ref $last) = self;
                ($first, ($($middle,)+ $last))
                    .process_outgoing(response).await
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
    async fn process_incoming(
        &self,
        exchange: &mut Exchange<'_>,
    ) -> ControlFlow<()> {
        for layer in self {
            layer.process_incoming(exchange).await?;
        }
        ControlFlow::Continue(())
    }

    async fn process_outgoing(&self, mut response: OutgoingResponse<'_, '_>) {
        for layer in self.iter().rev() {
            layer.process_outgoing(response.reborrow()).await;
        }
    }
}

#[cfg(feature = "std")]
impl<T: ServiceLayer> ServiceLayer for Vec<T> {
    async fn process_incoming(
        &self,
        exchange: &mut Exchange<'_>,
    ) -> ControlFlow<()> {
        self.as_slice().process_incoming(exchange).await
    }

    async fn process_outgoing(&self, response: OutgoingResponse<'_, '_>) {
        self.as_slice().process_outgoing(response).await
    }
}

//----------- impl LocalServiceLayer -----------------------------------------

impl<T: ?Sized + LocalServiceLayer> LocalServiceLayer for &T {
    async fn process_local_incoming(
        &self,
        exchange: &mut Exchange<'_>,
    ) -> ControlFlow<()> {
        T::process_local_incoming(self, exchange).await
    }

    async fn process_local_outgoing(
        &self,
        response: OutgoingResponse<'_, '_>,
    ) {
        T::process_local_outgoing(self, response).await
    }
}

impl<T: ?Sized + LocalServiceLayer> LocalServiceLayer for &mut T {
    async fn process_local_incoming(
        &self,
        exchange: &mut Exchange<'_>,
    ) -> ControlFlow<()> {
        T::process_local_incoming(self, exchange).await
    }

    async fn process_local_outgoing(
        &self,
        response: OutgoingResponse<'_, '_>,
    ) {
        T::process_local_outgoing(self, response).await
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + LocalServiceLayer> LocalServiceLayer for Box<T> {
    async fn process_local_incoming(
        &self,
        exchange: &mut Exchange<'_>,
    ) -> ControlFlow<()> {
        T::process_local_incoming(self, exchange).await
    }

    async fn process_local_outgoing(
        &self,
        response: OutgoingResponse<'_, '_>,
    ) {
        T::process_local_outgoing(self, response).await
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + LocalServiceLayer> LocalServiceLayer for Rc<T> {
    async fn process_local_incoming(
        &self,
        exchange: &mut Exchange<'_>,
    ) -> ControlFlow<()> {
        T::process_local_incoming(self, exchange).await
    }

    async fn process_local_outgoing(
        &self,
        response: OutgoingResponse<'_, '_>,
    ) {
        T::process_local_outgoing(self, response).await
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + LocalServiceLayer> LocalServiceLayer for Arc<T> {
    async fn process_local_incoming(
        &self,
        exchange: &mut Exchange<'_>,
    ) -> ControlFlow<()> {
        T::process_local_incoming(self, exchange).await
    }

    async fn process_local_outgoing(
        &self,
        response: OutgoingResponse<'_, '_>,
    ) {
        T::process_local_outgoing(self, response).await
    }
}

impl<A, B: ?Sized> LocalServiceLayer for (A, B)
where
    A: LocalServiceLayer,
    B: LocalServiceLayer,
{
    async fn process_local_incoming(
        &self,
        exchange: &mut Exchange<'_>,
    ) -> ControlFlow<()> {
        self.0.process_local_incoming(exchange).await?;
        self.1.process_local_incoming(exchange).await?;
        ControlFlow::Continue(())
    }

    async fn process_local_outgoing(
        &self,
        mut response: OutgoingResponse<'_, '_>,
    ) {
        self.1.process_local_outgoing(response.reborrow()).await;
        self.0.process_local_outgoing(response.reborrow()).await
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
            async fn process_local_incoming(
                &self,
                exchange: &mut Exchange<'_>
            ) -> ControlFlow<()> {
                #[allow(non_snake_case)]
                let ($first, $($middle,)+ ref $last) = self;
                $first.process_local_incoming(exchange).await?;
                $($middle.process_local_incoming(exchange).await?;)+
                $last.process_local_incoming(exchange).await
            }

            async fn process_local_outgoing(
                &self,
                response: OutgoingResponse<'_, '_>
            ) {
                #[allow(non_snake_case)]
                let ($first, $($middle,)+ ref $last) = self;
                ($first, ($($middle,)+ $last))
                    .process_local_outgoing(response).await
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
    async fn process_local_incoming(
        &self,
        exchange: &mut Exchange<'_>,
    ) -> ControlFlow<()> {
        for layer in self {
            layer.process_local_incoming(exchange).await?;
        }
        ControlFlow::Continue(())
    }

    async fn process_local_outgoing(
        &self,
        mut response: OutgoingResponse<'_, '_>,
    ) {
        for layer in self.iter().rev() {
            layer.process_local_outgoing(response.reborrow()).await;
        }
    }
}

#[cfg(feature = "std")]
impl<T: LocalServiceLayer> LocalServiceLayer for Vec<T> {
    async fn process_local_incoming(
        &self,
        exchange: &mut Exchange<'_>,
    ) -> ControlFlow<()> {
        self.as_slice().process_local_incoming(exchange).await
    }

    async fn process_local_outgoing(
        &self,
        response: OutgoingResponse<'_, '_>,
    ) {
        self.as_slice().process_local_outgoing(response).await
    }
}
