//! DNS cookies.
//!
//! See [RFC 7873] and [RFC 9018].
//!
//! [RFC 7873]: https://datatracker.ietf.org/doc/html/rfc7873
//! [RFC 9018]: https://datatracker.ietf.org/doc/html/rfc9018

use core::{
    borrow::{Borrow, BorrowMut},
    fmt,
    hash::{Hash, Hasher},
    ops::{Deref, DerefMut},
};

#[cfg(feature = "siphasher")]
use core::{net::IpAddr, ops::Range};

use domain_macros::*;

use crate::new_base::{
    wire::{AsBytes, ParseBytesByRef},
    Serial,
};

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
    ParseBytesByRef,
    SplitBytes,
    SplitBytesByRef,
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
    /// A 24-byte version-1 interoperable cookie will be returned.
    #[cfg(feature = "siphasher")]
    pub fn respond(&self, addr: IpAddr, secret: &[u8; 16]) -> CookieBuf {
        use siphasher::sip::SipHasher24;

        // Construct a buffer to write into.
        let mut bytes = [0u8; 24];

        bytes[0..8].copy_from_slice(self.as_bytes());

        // The version number and the reserved octets.
        bytes[8..12].copy_from_slice(&[1, 0, 0, 0]);

        let timestamp = Serial::unix_time();
        bytes[12..16].copy_from_slice(timestamp.as_bytes());

        // Hash the cookie.
        let mut hasher = SipHasher24::new_with_key(secret);
        hasher.write(&bytes[0..16]);

        match addr {
            IpAddr::V4(addr) => hasher.write(&addr.octets()),
            IpAddr::V6(addr) => hasher.write(&addr.octets()),
        }

        let hash = hasher.finish().to_le_bytes();
        bytes[16..24].copy_from_slice(&hash);

        let cookie = Cookie::parse_bytes_by_ref(&bytes)
            .expect("Any 24-byte string is a valid 'Cookie'");
        CookieBuf::copy_from(cookie)
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
    Debug,
    PartialEq,
    Eq,
    Hash,
    AsBytes,
    BuildBytes,
    ParseBytesByRef,
    UnsizedClone,
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

//----------- CookieBuf ------------------------------------------------------

/// A 41-byte buffer holding a [`Cookie`].
#[derive(Clone)]
pub struct CookieBuf {
    /// The size of the cookie, in bytes.
    ///
    /// This value is between 24 and 40, inclusive.
    size: u8,

    /// The cookie data, as raw bytes.
    data: [u8; 40],
}

//--- Construction

impl CookieBuf {
    /// Copy a [`Cookie`] into a [`CookieBuf`].
    pub fn copy_from(cookie: &Cookie) -> Self {
        let mut data = [0u8; 40];
        let cookie = cookie.as_bytes();
        data[..cookie.len()].copy_from_slice(cookie);
        let size = cookie.len() as u8;
        Self { size, data }
    }
}

//--- Access to the underlying 'Cookie'

impl Deref for CookieBuf {
    type Target = Cookie;

    fn deref(&self) -> &Self::Target {
        let bytes = &self.data[..self.size as usize];
        // SAFETY: A 'CookieBuf' always contains a valid 'Cookie'.
        unsafe { Cookie::parse_bytes_by_ref(bytes).unwrap_unchecked() }
    }
}

impl DerefMut for CookieBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let bytes = &mut self.data[..self.size as usize];
        // SAFETY: A 'CookieBuf' always contains a valid 'Cookie'.
        unsafe { Cookie::parse_bytes_by_mut(bytes).unwrap_unchecked() }
    }
}

impl Borrow<Cookie> for CookieBuf {
    fn borrow(&self) -> &Cookie {
        self
    }
}

impl BorrowMut<Cookie> for CookieBuf {
    fn borrow_mut(&mut self) -> &mut Cookie {
        self
    }
}

impl AsRef<Cookie> for CookieBuf {
    fn as_ref(&self) -> &Cookie {
        self
    }
}

impl AsMut<Cookie> for CookieBuf {
    fn as_mut(&mut self) -> &mut Cookie {
        self
    }
}

//--- Forwarding formatting, equality and hashing

impl fmt::Debug for CookieBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}

impl PartialEq for CookieBuf {
    fn eq(&self, that: &Self) -> bool {
        **self == **that
    }
}

impl Eq for CookieBuf {}

impl Hash for CookieBuf {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (**self).hash(state)
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
