use core::future::{ready, Future};
use core::ops::Deref;
use core::pin::Pin;

use octseq::Octets;

use std::boxed::Box;
use std::vec::Vec;

use crate::base::wire::ParseError;
use crate::base::Serial;
use crate::net::server::message::Request;
use crate::zonetree::types::EmptyZoneDiff;
use crate::zonetree::{Zone, ZoneDiff, ZoneTree};

//------------ XfrDataProviderError -------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum XfrDataProviderError {
    ParseError(ParseError),

    UnknownZone,

    Refused,

    TemporarilyUnavailable,
}

//--- From<ParseError>

impl From<ParseError> for XfrDataProviderError {
    fn from(err: ParseError) -> Self {
        Self::ParseError(err)
    }
}

//------------ XfrData --------------------------------------------------------

/// The data supplied by an [`XfrDataProvider`].
pub struct XfrData<Diff> {
    /// The zone to transfer.
    zone: Zone,

    /// The requested diffs.
    ///
    /// Empty if the requested diff range could not be satisfied.
    diffs: Vec<Diff>,

    /// Should XFR be done in RFC 5936 backward compatible mode?
    ///
    /// See: https://www.rfc-editor.org/rfc/rfc5936#section-7
    compatibility_mode: bool,
}

impl<Diff> XfrData<Diff> {
    pub fn new(
        zone: Zone,
        diffs: Vec<Diff>,
        backward_compatible: bool,
    ) -> Self {
        Self {
            zone,
            diffs,
            compatibility_mode: backward_compatible,
        }
    }

    pub fn zone(&self) -> &Zone {
        &self.zone
    }

    pub fn diffs(&self) -> &[Diff] {
        &self.diffs
    }

    pub fn into_diffs(self) -> Vec<Diff> {
        self.diffs
    }

    pub fn compatibility_mode(&self) -> bool {
        self.compatibility_mode
    }
}

//------------ XfrDataProvider ------------------------------------------------

/// A provider of data needed for responding to XFR requests.
pub trait XfrDataProvider<RequestMeta> {
    type Diff: ZoneDiff + Send + Sync;

    /// Request data needed to respond to an XFR request.
    ///
    /// Returns Ok if the request is allowed and the requested data is
    /// available.
    ///
    /// Returns Err otherwise.
    ///
    /// Pass `Some` zone SOA serial number in the `diff_from` parameter to
    /// request `ZoneDiff`s from the specified serial to the current SOA
    /// serial number of the zone, inclusive, if available.
    #[allow(clippy::type_complexity)]
    fn request<Octs>(
        &self,
        req: &Request<Octs, RequestMeta>,
        diff_from: Option<Serial>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        XfrData<Self::Diff>,
                        XfrDataProviderError,
                    >,
                > + Sync
                + Send
                + '_,
        >,
    >
    where
        Octs: Octets + Send + Sync;
}

//--- impl XfrDataProvider for Deref<XfrDataProvider>

impl<RequestMeta, T, U> XfrDataProvider<RequestMeta> for U
where
    T: XfrDataProvider<RequestMeta> + 'static,
    U: Deref<Target = T>,
{
    type Diff = T::Diff;

    fn request<Octs>(
        &self,
        req: &Request<Octs, RequestMeta>,
        diff_from: Option<Serial>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        XfrData<Self::Diff>,
                        XfrDataProviderError,
                    >,
                > + Sync
                + Send
                + '_,
        >,
    >
    where
        Octs: Octets + Send + Sync,
    {
        (**self).request(req, diff_from)
    }
}

//--- impl XfrDataProvider for Zone

impl<RequestMeta> XfrDataProvider<RequestMeta> for Zone {
    type Diff = EmptyZoneDiff;

    /// Request data needed to respond to an XFR request.
    ///
    /// Returns Ok(Self, vec![]) if the given apex name and class match this
    /// zone, irrespective of the given request or diff range.
    ///
    /// Returns Err if the requested zone is not this zone.
    fn request<Octs>(
        &self,
        req: &Request<Octs, RequestMeta>,
        _diff_from: Option<Serial>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        XfrData<Self::Diff>,
                        XfrDataProviderError,
                    >,
                > + Sync
                + Send,
        >,
    >
    where
        Octs: Octets + Send + Sync,
    {
        let res = req
            .message()
            .sole_question()
            .map_err(XfrDataProviderError::ParseError)
            .and_then(|q| {
                if q.qname() == self.apex_name() && q.qclass() == self.class()
                {
                    Ok(XfrData::new(self.clone(), vec![], false))
                } else {
                    Err(XfrDataProviderError::UnknownZone)
                }
            });

        Box::pin(ready(res))
    }
}

//--- impl XfrDataProvider for ZoneTree

impl<RequestMeta> XfrDataProvider<RequestMeta> for ZoneTree {
    type Diff = EmptyZoneDiff;

    /// Request data needed to respond to an XFR request.
    ///
    /// Returns Ok(zone, vec![]) if the given apex name and class match a zone
    /// in this zone tree, irrespective of the given request or diff range.
    ///
    /// Returns Err if the requested zone is not this zone tree.
    fn request<Octs>(
        &self,
        req: &Request<Octs, RequestMeta>,
        _diff_from: Option<Serial>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        XfrData<Self::Diff>,
                        XfrDataProviderError,
                    >,
                > + Sync
                + Send,
        >,
    >
    where
        Octs: Octets + Send + Sync,
    {
        let res = req
            .message()
            .sole_question()
            .map_err(XfrDataProviderError::ParseError)
            .and_then(|q| {
                if let Some(zone) = self.find_zone(q.qname(), q.qclass()) {
                    Ok(XfrData::new(zone.clone(), vec![], false))
                } else {
                    Err(XfrDataProviderError::UnknownZone)
                }
            });

        Box::pin(ready(res))
    }
}
