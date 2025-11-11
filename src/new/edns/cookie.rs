//! DNS cookies.
//!
//! See [RFC 7873] and [RFC 9018].
//!
//! [RFC 7873]: https://datatracker.ietf.org/doc/html/rfc7873
//! [RFC 9018]: https://datatracker.ietf.org/doc/html/rfc9018

use core::fmt;

#[cfg(feature = "siphasher")]
use core::net::IpAddr;
#[cfg(feature = "siphasher")]
use core::ops::Range;

use crate::{
    new::base::{
        wire::{
            AsBytes, BuildBytes, ParseBytes, ParseBytesZC, SplitBytes,
            SplitBytesZC,
        },
        Serial,
    },
    utils::dst::UnsizedCopy,
};

#[cfg(feature = "siphasher")]
use crate::new::base::wire::TruncationError;

//----------- ClientCookie ---------------------------------------------------

/// A request for a DNS cookie.
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    Hash,
    AsBytes,
    BuildBytes,
    ParseBytes,
    ParseBytesZC,
    SplitBytes,
    SplitBytesZC,
    UnsizedCopy,
)]
#[repr(transparent)]
pub struct ClientCookie {
    /// The octets of the request.
    pub octets: [u8; 8],
}

//--- Construction

impl ClientCookie {
    /// Construct a random [`ClientCookie`].
    #[cfg(feature = "rand")]
    pub fn random() -> Self {
        rand::random::<[u8; 8]>().into()
    }
}

//--- Interaction

impl ClientCookie {
    /// Build a [`Cookie`] in response to this request.
    ///
    /// A 24-byte version-1 interoperable cookie will be generated and written
    /// to the given buffer.  If the buffer is big enough, the remaining part
    /// of the buffer is returned.
    #[cfg(feature = "siphasher")]
    pub fn respond_into<'b>(
        &self,
        addr: IpAddr,
        secret: &[u8; 16],
        mut bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        use core::hash::Hasher;

        use siphasher::sip::SipHasher24;

        use crate::new::base::wire::BuildBytes;

        // Build and hash the cookie simultaneously.
        let mut hasher = SipHasher24::new_with_key(secret);

        bytes = self.build_bytes(bytes)?;
        hasher.write(self.as_bytes());

        // The version number and the reserved octets.
        bytes = [1, 0, 0, 0].build_bytes(bytes)?;
        hasher.write(&[1, 0, 0, 0]);

        let timestamp = Serial::unix_time();
        bytes = timestamp.build_bytes(bytes)?;
        hasher.write(timestamp.as_bytes());

        match addr {
            IpAddr::V4(addr) => hasher.write(&addr.octets()),
            IpAddr::V6(addr) => hasher.write(&addr.octets()),
        }

        let hash = hasher.finish().to_le_bytes();
        bytes = hash.build_bytes(bytes)?;

        Ok(bytes)
    }
}

//--- Conversion to and from octets

impl From<[u8; 8]> for ClientCookie {
    fn from(value: [u8; 8]) -> Self {
        Self { octets: value }
    }
}

impl From<ClientCookie> for [u8; 8] {
    fn from(value: ClientCookie) -> Self {
        value.octets
    }
}

//--- Formatting

impl fmt::Debug for ClientCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClientCookie({})", self)
    }
}

impl fmt::Display for ClientCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016X}", u64::from_be_bytes(self.octets))
    }
}

//----------- Cookie ---------------------------------------------------------

/// A DNS cookie.
#[derive(
    Debug, PartialEq, Eq, Hash, AsBytes, BuildBytes, ParseBytesZC, UnsizedCopy,
)]
#[repr(C)]
pub struct Cookie {
    /// The client's request for this cookie.
    request: ClientCookie,

    /// The version number of this cookie.
    version: u8,

    /// Reserved bytes in the cookie format.
    reserved: [u8; 3],

    /// When this cookie was made.
    timestamp: Serial,

    /// The hash of this cookie.
    hash: [u8],
}

//--- Inspection

impl Cookie {
    /// The underlying cookie request.
    pub fn request(&self) -> &ClientCookie {
        &self.request
    }

    /// The version number of this interoperable cookie.
    ///
    /// Assuming this is an interoperable cookie, as specified by [RFC 9018],
    /// the 1-byte version number of the cookie is returned.  Currently, only
    /// version 1 has been specified.
    ///
    /// [RFC 9018]: https://datatracker.ietf.org/doc/html/rfc9018
    pub fn version(&self) -> u8 {
        self.version
    }

    /// When this interoperable cookie was produced.
    ///
    /// Assuming this is an interoperable cookie, as specified by [RFC 9018],
    /// the 4-byte timestamp of the cookie is returned.
    ///
    /// [RFC 9018]: https://datatracker.ietf.org/doc/html/rfc9018
    pub fn timestamp(&self) -> Serial {
        self.timestamp
    }
}

//--- Interaction

impl Cookie {
    /// Verify this cookie.
    ///
    /// This cookie is verified as a 24-byte version-1 interoperable cookie,
    /// as specified by [RFC 9018].  A 16-byte secret is used to generate a
    /// hash for this cookie, based on its fields and the IP address of the
    /// client which used it.  If the cookie was generated in the given time
    /// period, and the generated hash matches the hash in the cookie, it is
    /// valid.
    ///
    /// [RFC 9018]: https://datatracker.ietf.org/doc/html/rfc9018
    #[cfg(feature = "siphasher")]
    pub fn verify(
        &self,
        addr: IpAddr,
        secret: &[u8; 16],
        validity: Range<Serial>,
    ) -> Result<(), CookieError> {
        use core::hash::Hasher;

        use siphasher::sip::SipHasher24;

        // Check basic features of the cookie.
        if self.version != 1
            || self.hash.len() != 8
            || !validity.contains(&self.timestamp)
        {
            return Err(CookieError);
        }

        // Check the cookie hash.
        let mut hasher = SipHasher24::new_with_key(secret);
        hasher.write(&self.as_bytes()[..16]);
        match addr {
            IpAddr::V4(addr) => hasher.write(&addr.octets()),
            IpAddr::V6(addr) => hasher.write(&addr.octets()),
        }

        if self.hash == hasher.finish().to_le_bytes() {
            Ok(())
        } else {
            Err(CookieError)
        }
    }
}

//--- Cloning

#[cfg(feature = "alloc")]
impl Clone for alloc::boxed::Box<Cookie> {
    fn clone(&self) -> Self {
        (*self).unsized_copy_into()
    }
}

//----------- CookieError ----------------------------------------------------

/// An invalid [`Cookie`] was encountered.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CookieError;

//--- Formatting

impl fmt::Display for CookieError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("A DNS cookie could not be verified")
    }
}
