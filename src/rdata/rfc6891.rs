//! Record data from [RFC 6891].
//!
//! This RFC contains the currently valid definition of the OPT resouce
//! record type originally defined in [RFC 2671].
//!
//! There are three types for OPT record data: [`OptSlice`] and [`OptBuf`]
//! for a bytes slice and a bytes vector containing the data, respectively,
//! and [`Opt`] for the actual [`RecordData`] implementation using a cow of
//! the former.
//!
//! Since OPT records actually requisition some of the standard fields of a
//! DNS record for their own purpose, this module also defines
//! [`OptRecord]` for an entire OPT resource record.
//!
//! There are a number of additional types used for specific EDNS options
//! or as friendly helper types.
//!
//! [`Opt`]: struct.Opt.html
//! [`OptBuf`]: struct.OptBuf.html
//! [`OptRecord`]: struct.OptRecord.html
//! [`OptSlice`]: struct.OptSlice.html
//! [RecordData]: ../../bits/rdata/trait.RecordData.html
//! [RFC 2671]: https://tools.ietf.org/html/rfc2671
//! [RFC 6891]: https://tools.ietf.org/html/rfc6891

use std::borrow::{Borrow, Cow};
use std::cmp::min;
use std::fmt;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops;
use bits::{DName, Composable, Composer, ComposeError,
           ComposeResult, DNameSlice, Parser, ParseError, ParseResult,
           ParsedRecordData, Record, RecordData};
use iana::{OptionCode, Rtype, SecAlg};


//------------ Opt ----------------------------------------------------------

/// OPT record data.
///
/// The OPT record is the main facility of the EDNS extension mechanism. It
/// is a pseudo record that carries additional flags and bits as well as an
/// extendable way to add options. Its presence in the additional section of
/// a DNS message marks a EDNS compatible implementation.
///
/// This type is the [`RecordData`] implementation. It is effectively a cow
/// on [`OptSlice`] and derefs into that. The type is more commonly used for
/// looking at existing OPT records. Building normally happens on the fly
/// with a [`MessageBuilder`]. The [`OptRecord::push()`] function can be used
/// for this. It accepts a closure for adding specific options. Functions
/// for use in this closure are associated with the Opt type.
///
/// The OPT record data is currently defined in [RFC 6891] after having been
/// introduced in [RFC 2671].
///
/// [`MessageBuilder`]: ../../bits/message/struct.MessageBuilder.html
/// [`OptRecord::push()`]: struct.OptRecord.html#method.push
/// [`OptSlice`]: struct.OptSlice.html
/// [`RecordData`]: ../../bits/rdata/trait.RecordData.html
/// [RFC 2671]: https://tools.ietf.org/html/rfc2671
/// [RFC 6891]: https://tools.ietf.org/html/rfc6891
#[derive(Clone, Debug, PartialEq)]
pub struct Opt<O: AsRef<OptSlice>> {
    inner: O
}

impl<O: AsRef<OptSlice>> Opt<O> {
    /// Creates a new opt value.
    pub fn new(slice: O) -> Self {
        Opt{inner: slice}
    }

    /// Returns the record type of OPT records.
    pub fn rtype() -> Rtype { Rtype::Opt }
}

/*
/// # Building OPT Records on the Fly
///
/// These associated functions can be used in the closure of
/// [`OptRecord::push()`] for adding options on the fly. For example:
///
/// ```rust
/// use domain::bits::{ComposeMode, MessageBuilder};
/// use domain::rdata::rfc6891::{Opt, OptRecord};
///
/// let mut msg = MessageBuilder::new(ComposeMode::Limited(512),
///                                   true).unwrap();
/// // Add more resource records here ...
/// let mut sec = msg.answer().authority().additional();
/// OptRecord::push(&mut sec, 1280, 0, 0, false, |target| {
///     try!(Opt::push_nsid(target, b"Foo"));
///     Ok(())
/// }).unwrap();
/// ```
///
/// [`OptRecord::push()`]: struct.OptRecord.html#method.push
impl<'a> Opt<'a> {
    /// Pushes a generic option to the end of `target`.
    ///
    /// The option will use the given option code and bytes slice.
    ///
    /// # Panic
    ///
    /// The function panics if `data` is longer than 65535 bytes.
    pub fn push_option<C>(target: &mut C, code: OptionCode, data: &[u8])
                          -> ComposeResult<()>
                       where C: ComposeBytes {
        assert!(data.len() <= 0xFFFF); // Or better return Err?
        try!(target.push_u16(code.into()));
        try!(target.push_u16(data.len() as u16));
        try!(target.push_bytes(data));
        Ok(())
    }

    /// Pushes an NSID option to the end of `target`.
    ///
    /// The ‘name server identifier’ option allows to identify which name
    /// server has answered a query. It can be used for debugging purposes.
    /// A request should contain an empty option, ie., `nsid` should be
    /// `b""`. If a server supports this option and receives a request with
    /// an NSID option, it adds an option with its identifier to its
    /// response. See [RFC 5001] for more details.
    ///
    /// [RFC 5001]: https://tools.ietf.org/html/rfc5001
    pub fn push_nsid<C: ComposeBytes>(target: &mut C, nsid: &[u8])
                                      -> ComposeResult<()> {
        Opt::push_option(target, OptionCode::Nsid, nsid)
    }

    /// Pushes an option with algorithm numbers to the end of `target`.
    ///
    /// # Panic
    ///
    /// The functions panics if the list is longer than 65535 elements.
    fn push_alglist<C: ComposeBytes>(target: &mut C, code: OptionCode,
                                     list: &[SecAlg])
                                     -> ComposeResult<()> {
        assert!(list.len() < 0xFFFF); // Or better return Err?
        try!(target.push_u16(code.into()));
        try!(target.push_u16(list.len() as u16));
        for item in list.iter() {
            try!(target.push_u8(item.to_int()));
        }
        Ok(())
    }

    /// Pushes a DAU option to the end of `target`.
    ///
    /// The ‘DNSSEC algorithm understood’ option can be used by end-system
    /// resolvers validating DNSSEC responses to indicate which DNSSEC
    /// algorithms they understand.
    ///
    /// The `list` argument contains a list with all DNSSEC security
    /// algorithm codes that the system understands.
    ///
    /// See [RFC 6975] for more details.
    ///
    /// # Panic
    ///
    /// The functions panics if the list is longer than 65535 elements.
    ///
    /// [RFC 6975]: https://tools.ietf.org/html/rfc6975
    pub fn push_dau<C: ComposeBytes>(target: &mut C, list: &[SecAlg])
                                     -> ComposeResult<()> {
        Opt::push_alglist(target, OptionCode::Dau, list)
    }

    /// Pushes a DHU option to the end of `target`.
    ///
    /// The ‘DS hash understood’ option can be used by end-system
    /// resolvers validating DNSSEC responses to indicate which DNSSEC
    /// algorithms it supports for the hash of a key in a DS record.
    ///
    /// The `list` argument contains a list with all DNSSEC security
    /// algorithm codes that the system understands.
    ///
    /// See [RFC 6975] for more details.
    ///
    /// # Panic
    ///
    /// The functions panics if the list is longer than 65535 elements.
    ///
    /// [RFC 6975]: https://tools.ietf.org/html/rfc6975
    pub fn push_dhu<C: ComposeBytes>(target: &mut C, list: &[SecAlg])
                                     -> ComposeResult<()> {
        Opt::push_alglist(target, OptionCode::Dhu, list)
    }

    /// Pushes an N3U option to the end of `target`.
    ///
    /// The ‘NSEC3 hash understood’ option can be used by end-system
    /// resolvers validating DNSSEC responses to indicate which DNSSEC
    /// algorithms it supports for the hash in NSEC3 records.
    ///
    /// The `list` argument contains a list with all DNSSEC security
    /// algorithm codes that the system understands.
    ///
    /// See [RFC 6975] for more details.
    ///
    /// # Panic
    ///
    /// The functions panics if the list is longer than 65535 elements.
    ///
    /// [RFC 6975]: https://tools.ietf.org/html/rfc6975
    pub fn push_n3u<C: ComposeBytes>(target: &mut C, list: &[SecAlg])
                                     -> ComposeResult<()> {
        Opt::push_alglist(target, OptionCode::N3u, list)
    }

    /// Pushes an edns-client-subnet option to the end of `target`.
    ///
    /// The EDNS client subnet option can be used by recursive resolvers to
    /// convey the client’s subnet to upstream name servers so they can
    /// return responses tailored for that subnet.
    ///
    /// See [ClientSubnet] for details on the option value or [RFC 7871]
    /// for the full story.
    ///
    /// [ClientSubnet]: struct.ClientSubnet.html
    /// [RFC 7871]: https://tools.ietf.org/html/rfc7871
    pub fn push_client_subnet<C>(target: &mut C, data: &ClientSubnet)
                                 -> ComposeResult<()>
                              where C: ComposeBytes {
        try!(target.push_u16(OptionCode::EdnsClientSubnet.into()));
        try!(target.push_u16(data.compose_len() as u16));
        data.compose(target)
    }

    /// Pushes an EDNS EXPIRE option to the end of `target`.
    ///
    /// The EDNS expire option is used between primary and secondary name
    /// servers to convey the expire time for zone transfers. A secondary
    /// name servers requests the expire option by adding an empty option
    /// value, ie. a `value` of `None` to its request. In its response, the
    /// name server will include the current value of expire field of the
    /// zone’s SOA as the expire option.
    ///
    /// See [RFC 7314] for details.
    ///
    /// [RFC 7314]: https://tools.ietf.org/html/rfc7314
    pub fn push_expire<C: ComposeBytes>(target: &mut C, value: Option<u32>)
                                        -> ComposeResult<()> {
        try!(target.push_u16(OptionCode::EdnsExpire.into()));
        if let Some(value) = value {
            try!(target.push_u16(4));
            try!(target.push_u32(value));
        }
        else {
            try!(target.push_u16(0));
        }
        Ok(())
    }

    /// Pushes a COOKIE option to the end of `target`.
    ///
    /// The COOKIE option provides limited protection against off-path
    /// attacks by adding transaction cookies to messages exchanged between
    /// client and server.
    ///
    /// See [Cookie] for the content of the option and [RFC 7873] for
    /// details.
    ///
    /// [Cookie]: struct.Cookie.html
    /// [RFC 7873]: https://tools.ietf.org/html/rfc7873
    pub fn push_cookie<C: ComposeBytes>(target: &mut C, cookie: Cookie)
                                        -> ComposeResult<()> {
        try!(target.push_u16(OptionCode::Cookie.into()));
        try!(target.push_u16(cookie.compose_len() as u16));
        try!(cookie.compose(target));
        Ok(())
    }

    /// Pushes the edns-tcp-keepalive option to the end of `target`.
    ///
    /// The EDNS client keepalive option allows clients and resolvers to
    /// use long-lived TCP connections when talking to name servers. When
    /// sending a request, the client includes an empty timeout, ie., `None`,
    /// to indicate support for this option. If the server supports the
    /// option, too, it includes the time the client should keep the TCP
    /// connection open, given in units of 100 milliseconds.
    ///
    /// See [RFC 7828] for details.
    ///
    /// [RFC 7828]: https://tools.ietf.org/html/rfc7828
    pub fn push_tcp_keepalive<C>(target: &mut C, timeout: Option<u16>)
                                 -> ComposeResult<()>
                              where C: ComposeBytes {
        try!(target.push_u16(OptionCode::EdnsTcpKeepalive.into()));
        if let Some(timeout) = timeout {
            try!(target.push_u16(2));
            try!(target.push_u16(timeout));
        }
        else {
            try!(target.push_u16(0));
        }
        Ok(())
    }

    /// Pushes a Padding option to the end of `target`.
    ///
    /// The Padding option can be used to add extra data to a DNS message.
    /// This can be useful with encrypted DNS to make it harder to derive
    /// information from the message size.
    /// The option is defined in [RFC 7830].
    ///
    /// This function adds the content of `padding` as padding. The RFC
    /// specifies that you should prefer using [Opt::push_zero_padding()]
    /// which adds padding of a given length using zeros. This alternative
    /// method is suggested if there is concerns that zeros may get gobbled
    /// up by a compression mechanism.
    ///
    /// # Panic
    ///
    /// The function panics if `padding` is longer than 65535 bytes.
    ///
    /// [Opt::push_zero_padding()]: #method.push_zero_padding
    /// [RFC 7830]: https://tools.ietf.org/html/rfc7830
    pub fn push_padding<C: ComposeBytes>(target: &mut C, padding: &[u8])
                                         -> ComposeResult<()> {
        Opt::push_option(target, OptionCode::Padding, padding)
    }

    /// Pushes a Padding option to the end of `target`.
    ///
    /// The Padding option can be used to add extra data to a DNS message.
    /// This can be useful with encrypted DNS to make it harder to derive
    /// information from the message size. The option is defined in
    /// [RFC 7830].
    ///
    /// This function adds `len` zero bytes as padding. This is specified
    /// by the RFC as the method that should be used. However, if messages
    /// are compressed, a sequence of zeroes may be taken out again, so in
    /// this case, alternative padding can be specified using the
    /// [Opt::push_padding()] function.
    ///
    /// [Opt::push_padding()]: #method.push_padding
    /// [RFC 7830]: https://tools.ietf.org/html/rfc7830
    pub fn push_zero_padding<C: ComposeBytes>(target: &mut C, len: u16)
                                              -> ComposeResult<()> {
        try!(target.push_u16(OptionCode::Padding.into()));
        try!(target.push_u16(len));
        for _ in 0 .. len {
            try!(target.push_u8(0));
        }
        Ok(())
    }

    /// Pushes a CHAIN option to the end of `target`.
    ///
    /// The CHAIN option is used by a stub resolver to signal to an upstream
    /// recursive resolver to include all DNSSEC resource records necessary
    /// to validate the result. The option’s content specifies the domain 
    /// name from where on these records need to be included.
    ///
    /// See [RFC 7901] for details.
    ///
    /// [RFC 7901]: https://tools.ietf.org/html/rfc7901
    pub fn push_chain<C, N>(target: &mut C, n: &N) -> ComposeResult<()>
                      where C: ComposeBytes, N: AsDName {
        let name = try!(n.as_dname().into_cow());
        Opt::push_option(target, OptionCode::Chain, name.as_bytes())
    }
}
*/


//--- RecordData and ParsedRecordData

impl<O: AsRef<OptSlice>> RecordData for Opt<O> {
    fn rtype(&self) -> Rtype { 
        Opt::rtype()
    }

    fn compose<C: AsMut<Composer>>(&self, mut target: C) -> ComposeResult<()> {
        self.inner.as_ref().as_bytes().compose(target.as_mut())
    }
}

impl<'a> ParsedRecordData<'a> for Opt<&'a OptSlice> {
    fn parse(rtype: Rtype, parser: &mut Parser<'a>)
             -> ParseResult<Option<Self>> {
        if rtype == Rtype::Opt {
            OptSlice::parse(parser).map(|x| Some(Opt::new(x)))
        }
        else { Ok(None) }
    }
}


//--- Deref, Borrow, AsRef

impl<B: AsRef<OptSlice>> ops::Deref for Opt<B> {
    type Target = OptSlice;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<B: AsRef<OptSlice>> Borrow<OptSlice> for Opt<B> {
    fn borrow(&self) -> &OptSlice {
        self
    }
}

impl<B: AsRef<OptSlice>> AsRef<OptSlice> for Opt<B> {
    fn as_ref(&self) -> &OptSlice {
        self
    }
}


//--- Display

impl<B: AsRef<OptSlice>> fmt::Display for Opt<B> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        "...".fmt(f) // XXX Use the generic format here.
    }
}


//------------ OptSlice -----------------------------------------------------

/// OPT record data atop a bytes slice.
///
/// The bytes slice contains the raw record data upon which this type
/// implements methods to access its contents. The record data is a
/// sequence of EDNS options. You can get an iterator over the raw options
/// via the [`iter()`](#method.iter) method. More likely, though, you will
/// want to get to [the individual options](#access-to-specific-options).
///
/// This is an unsized type, so you have to always use it behind a reference
/// or a box. For an owned OPT record, see [`OptBuf`]. The actual record data
/// is based on a cow, see [`Opt`].
///
/// [`Opt`]: struct.Opt.html
/// [`OptBuf`]: struct.OptBuf.html
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct OptSlice([u8]);

impl OptSlice {
    /// Creates an opt slice from a bytes slice.
    ///
    /// The function ensures that bytes slice actually contains valid opt
    /// record data, hence returns a [ParseResult].
    ///
    /// [ParseResult]: ../../bits/error/type.ParseResult.html
    pub fn from_bytes(bytes: &[u8]) -> ParseResult<&Self> {
        let mut parser = Parser::new(bytes);
        loop {
            if parser.left() == 0 { break }
            try!(parser.skip(2));
            let len = try!(parser.parse_u16()) as usize;
            try!(parser.skip(len));
        }
        Ok(unsafe { OptSlice::from_bytes_unsafe(bytes) })
    }

    /// Creates an opt slice from a bytes slice without checking.
    unsafe fn from_bytes_unsafe(bytes: &[u8]) -> &Self {
        mem::transmute(bytes)
    }

    /// Parses an opt slice.
    ///
    /// Assumes that the entire data left in the parser is the opt slice.
    /// This is because the length of the record data is explicitely given
    /// in a record. After reading the length, you should create a subparser
    /// with the given length, using [ParseBytes::parse_sub()].
    ///
    /// [ParseBytes::parse_sub()]: ../../bits/parse/trait.ParseBytes.html#tymethod.parse_sub
    fn parse<'a>(rtype: Rtype, parser: &mut Parser<'a>)
             -> ParseResult<Option<&'a Self>> {
        let len = parser.remaining();
        OptSlice::from_bytes(try!(parser.parse_bytes(len)))
    }

    /// Returns the underlying bytes slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

}


/// # Access to Specific Options
///
impl OptSlice {
    /// Parses the first option of the given option code.
    ///
    /// This function iterates over the options. If it encounters an option
    /// with `code`, it creates a parser on the option data, passes that to
    /// the provided closure and returns its result as `Some()`. If no
    /// option with `code` exists, returns `None`.
    ///
    /// This function is useful for disecting option data with more complex
    /// format. If the format is basically just a bytes slice, use
    /// `get_option()` instead.
    fn parse_option<'a, R, F>(&'a self, code: OptionCode, f: F) -> Option<R>
                    where F: FnOnce(&mut Parser<'a>) -> R {
        for option in self.iter() {
            if option.code != code { continue }
            let mut parser = Parser::new(option.data);
            return Some(f(&mut parser));
        }
        None
    }

    /// Converts the first option of the given code.
    ///
    /// This function iterates over the options. If it encounters an option
    /// with `code`, it passes the option data to the provided closure and
    /// returns its result as `Some()`. If no option with `code` exists,
    /// returns `None`.
    ///
    /// This function is useful if the option uses the option data pretty
    /// much as is. If it has a more complex format, it may be more
    /// convenient to use `parse_option()` instead.
    fn get_option<'a, R, F>(&'a self, code: OptionCode, f: F) -> Option<R>
                  where F: FnOnce(&'a [u8]) -> R {
        for option in self.iter() {
            if option.code != code { return Some(f(option.data)) }
        }
        None
    }

    /// Returns the content of the NSID option if present.
    ///
    /// The ‘name server identifier’ option allows to identify which name
    /// server has answered a query. It can be used for debugging purposes.
    /// In a request, an empty option, ie., `Some(b"")`, will mark the desire
    /// to receive this identifier in a response. In a response, the
    /// identifier may be present. A return value of `None` means the option
    /// was not present.
    ///
    /// See [RFC 5001] for more details.
    ///
    /// [RFC 5001]: https://tools.ietf.org/html/rfc5001
    pub fn nsid(&self) -> Option<&[u8]> {
        self.get_option(OptionCode::Nsid, |x| x)
    }

    /// Returns the content of the DAU option if present.
    ///
    /// The ‘DNSSEC algorithm understood’ option can be used by end-system
    /// resolvers validating DNSSEC responses to indicate which DNSSEC
    /// algorithms they understand. If this option is present, the method
    /// will return an iterator over the numbers of the algorithms supported
    /// by the sender. If the option is not present, returns `None`.
    ///
    /// See [RFC 6975] for more details.
    ///
    /// [RFC 6975]: https://tools.ietf.org/html/rfc6975
    pub fn dau(&self) -> Option<SecAlgIter> {
        self.get_option(OptionCode::Dau, SecAlgIter::new)
    }

    /// Returns the content of the DHU option if present.
    ///
    /// The ‘DS hash understood’ option can be used by end-system
    /// resolvers validating DNSSEC responses to indicate which DNSSEC
    /// algorithms it supports for the hash of a key in a DS record.
    /// If this option is present, the method
    /// will return an iterator over the numbers of the algorithms supported
    /// by the sender. If the option is not present, returns `None`.
    ///
    /// See [RFC 6975] for more details.
    ///
    /// [RFC 6975]: https://tools.ietf.org/html/rfc6975
    pub fn dhu(&self) -> Option<SecAlgIter> {
        self.get_option(OptionCode::Dhu, SecAlgIter::new)
    }

    /// Returns the content of the N3U option if present.
    ///
    /// The ‘NSEC3 hash understood’ option can be used by end-system
    /// resolvers validating DNSSEC responses to indicate which DNSSEC
    /// algorithms it supports for the hash in NSEC3 records.
    /// If this option is present, the method
    /// will return an iterator over the numbers of the algorithms supported
    /// by the sender. If the option is not present, returns `None`.
    ///
    /// See [RFC 6975] for more details.
    ///
    /// [RFC 6975]: https://tools.ietf.org/html/rfc6975
    pub fn n3u(&self) -> Option<SecAlgIter> {
        self.get_option(OptionCode::N3u, SecAlgIter::new)
    }

    /// Returns the content of the edns-client-subnet option if present.
    ///
    /// The EDNS client subnet option can be used by recursive resolvers to
    /// convey the client’s subnet to upstream name servers so they can
    /// return responses tailored for that subnet.
    ///
    /// If the option is present and correctly formated, the function
    /// returns `Some(Ok(_))`. See [ClientSubnet] for information on the
    /// content of the option. If the option is present but parsing failed,
    /// returns `Some(Err(_))`. Finally, if the option is not present,
    /// returns `None`.
    ///
    /// See [RFC 7871] for details on the option.
    ///
    /// [ClientSubnet]: struct.ClientSubnet.html
    /// [RFC 7871]: https://tools.ietf.org/html/rfc7871
    pub fn client_subnet(&self) -> Option<ParseResult<ClientSubnet>> {
        self.parse_option(OptionCode::EdnsClientSubnet, ClientSubnet::parse)
    }

    /// Returns the content of the EDNS EXPIRE option if present.
    ///
    /// The EDNS expire option is used between primary and secondary name
    /// servers to convey the expire time for zone transfers. When used in
    /// a request, the option should be empty, ie., the return value will be 
    /// `Some(Ok(None))`. In a response, the option includes the current
    /// value of the expire field of the zone’s SOA record. In this case,
    /// the return value will be `Some(Ok(Some(_)))`. If anything else is
    /// included in the option data, the result will be `Some(Err(_))`. If
    /// the option is not present, the result will be `None`.
    pub fn expire(&self) -> Option<ParseResult<Option<u32>>> {
        self.parse_option(OptionCode::EdnsExpire, |parser| {
            if parser.left() == 0 { Ok(None) }
            else if parser.left() == 4 {
                parser.parse_u32().map(Some)
            }
            else { Err(ParseError::FormErr) }
        })
    }

    /// Returns the content of the COOKIE option if present.
    ///
    /// The COOKIE option provides limited protection against off-path
    /// attacks by adding transaction cookies to messages exchanged between
    /// client and server.
    ///
    /// If the option is present and correctly formated, the function
    /// returns `Some(Ok(_))`. See [Cookie] for information on the
    /// content of the option. If the option is present but parsing failed,
    /// returns `Some(Err(_))`. Finally, if the option is not present,
    /// returns `None`.
    ///
    /// See [RFC 7873] for more information on DNS cookies.
    ///
    /// [Cookie]: struct.Cookie.html
    /// [RFC 7873]: https://tools.ietf.org/html/rfc7873
    pub fn cookie(&self) -> Option<ParseResult<Cookie>> {
        self.parse_option(OptionCode::Cookie, Cookie::parse)
    }

    /// Returns the content of the edns-tcp-keepalive option if present.
    ///
    /// The EDNS client keepalive option allows clients and resolvers to
    /// use long-lived TCP connections when talking to name servers. In a
    /// request, an empty option value, returned as `Some(Ok(None))`,
    /// signals the senders interest in the keepalive option. In a response,
    /// an option value, now `Some(Ok(Some(_)))`, contains the suggested
    /// connection timeout in units of 100 milliseconds. If the option is
    /// present but missformed, the function returns `Some(Err(_))`, if it
    /// is missing, `None`.
    ///
    /// See [RFC 7828] for details.
    ///
    /// [RFC 7828]: https://tools.ietf.org/html/rfc7828
    pub fn tcp_timeout(&self) -> Option<ParseResult<Option<u16>>> {
        self.parse_option(OptionCode::EdnsTcpKeepalive, |parser| {
            if parser.left() == 0 { Ok(None) }
            else if parser.left() != 2 { Err(ParseError::FormErr) }
            else { parser.parse_u16().map(Some) }
        })
    }

    /// Returns the content of the CHAIN option if present.
    ///
    /// The CHAIN option is used by a stub resolver to signal to an upstream
    /// recursive resolver to include all DNSSEC resource records necessary
    /// to validate the result. The option’s content specifies the domain 
    /// name from where on these records need to be included. If the option
    /// is present and correctly formed, the function returns `Some(Ok(_))`, 
    /// if it is present and malformed, `Some(Err(_))`, and if it is missing,
    /// `None`.
    ///
    /// See [RFC 7901] for details.
    ///
    /// [RFC 7901]: https://tools.ietf.org/html/rfc7901
    pub fn chain(&self) -> Option<ParseResult<&DNameSlice>> {
        self.get_option(OptionCode::Chain, DNameSlice::from_bytes)
    }
}


/// # Iteration over raw options.
///
impl OptSlice {
    /// Returns an iterator over the raw options of the record data.
    ///
    /// The iterator’s items are of type [OptOption], which is a simple
    /// composite type containing the options’s code in a public `code`
    /// attribute and its data as a bytes slice in a public `data`
    /// attribute.
    ///
    /// [OptOption]: struct.OptOption.html
    pub fn iter(&self) -> OptionIter {
        OptionIter::new(&self.0)
    }
}


//--- AsRef

impl AsRef<OptSlice> for OptSlice {
    fn as_ref(&self) -> &OptSlice { self }
}


//--- ToOwned

impl ToOwned for OptSlice {
    type Owned = OptBuf;

    fn to_owned(&self) -> Self::Owned {
        OptBuf::from(self)
    }
}


//------------ OptBuf -------------------------------------------------------

/// Owned OPT record data atop a bytes vector.
///
/// This is the owned companion to [`OptSlice`] and derefs to that type in
/// order to give access to all its methods. In addition, it provides a
/// number of methods to add additional options to the data.
///
/// [`OptSlice`]: struct.OptSlice.html
#[derive(Clone, Debug)]
pub struct OptBuf(Vec<u8>);

/// # Creation and Conversion
///
impl OptBuf {
    /// Creates a new opt buf consuming the given vector.
    ///
    /// This function checks that the vector’s content contains valid OPT
    /// record data and thus returns a [ParseResult].
    ///
    /// [ParseResult]: ../../bits/error/type.ParseResult.html
    pub fn from_vec(vec: Vec<u8>) -> ParseResult<Self> {
        let _ = try!(OptSlice::from_bytes(&vec));
        Ok(OptBuf(ComposeBuf::from_vec(vec, ComposeMode::Unlimited, false)))
    }

    /// Creates a new, empty opt buf.
    pub fn new() -> OptBuf {
        OptBuf(ComposeBuf::new(ComposeMode::Unlimited, false))
    }

    /// Returns a reference to data as an opt slice.
    pub fn as_slice(&self) -> &OptSlice {
        unsafe { OptSlice::from_bytes_unsafe(self.as_bytes()) }
    }
}


/// # Manipulation
///
impl OptBuf {
    /// Appends a raw EDNS option to the end of the data.
    ///
    /// This adds a new option with the given `code` and `data` to the end
    /// of the opt data without any regard for whether the added data is
    /// well-formed in any way.
    ///
    /// # Panics
    ///
    /// The function panics if `data` is longer than 65535 bytes.
    pub fn push(&mut self, code: OptionCode, data: &[u8]) {
        Opt::push_option(&mut self.0, code, data).unwrap();
    }

    /// Appends an NSID option to the end of the data.
    ///
    /// The ‘name server identifier’ option allows to identify which name
    /// server has answered a query. It can be used for debugging purposes.
    /// A request should contain an empty option, ie., `nsid` should be
    /// `b""`. If a server supports this option and receives a request with
    /// an NSID option, it adds an option with its identifier to its
    /// response. See [RFC 5001] for more details.
    ///
    /// [RFC 5001]: https://tools.ietf.org/html/rfc5001
    pub fn push_nsid(&mut self, nsid: &[u8]) {
        Opt::push_nsid(&mut self.0, nsid).unwrap();
    }

    /// Appends a DAU option to the end of the data.
    ///
    /// The ‘DNSSEC algorithm understood’ option can be used by end-system
    /// resolvers validating DNSSEC responses to indicate which DNSSEC
    /// algorithms they understand.
    ///
    /// The `list` argument contains a list with all DNSSEC security
    /// algorithm codes that the system understands.
    ///
    /// See [RFC 6975] for more details.
    ///
    /// # Panic
    ///
    /// The functions panics if the list is longer than 65535 elements.
    ///
    /// [RFC 6975]: https://tools.ietf.org/html/rfc6975
    pub fn push_dau(&mut self, dau: &[SecAlg]) {
        Opt::push_dau(&mut self.0, dau).unwrap();
    }

    /// Appends a DHU option to the end of the data.
    ///
    /// The ‘DS hash understood’ option can be used by end-system
    /// resolvers validating DNSSEC responses to indicate which DNSSEC
    /// algorithms it supports for the hash of a key in a DS record.
    ///
    /// The `list` argument contains a list with all DNSSEC security
    /// algorithm codes that the system understands.
    ///
    /// See [RFC 6975] for more details.
    ///
    /// # Panic
    ///
    /// The functions panics if the list is longer than 65535 elements.
    ///
    /// [RFC 6975]: https://tools.ietf.org/html/rfc6975
    pub fn push_dhu(&mut self, dhu: &[SecAlg]) {
        Opt::push_dhu(&mut self.0, dhu).unwrap();
    }

    /// Appends an N3U option to the end of the data.
    ///
    /// The ‘NSEC3 hash understood’ option can be used by end-system
    /// resolvers validating DNSSEC responses to indicate which DNSSEC
    /// algorithms it supports for the hash in NSEC3 records.
    ///
    /// The `list` argument contains a list with all DNSSEC security
    /// algorithm codes that the system understands.
    ///
    /// See [RFC 6975] for more details.
    ///
    /// # Panic
    ///
    /// The functions panics if the list is longer than 65535 elements.
    ///
    /// [RFC 6975]: https://tools.ietf.org/html/rfc6975
    pub fn push_n3u(&mut self, n3u: &[SecAlg]) {
        Opt::push_n3u(&mut self.0, n3u).unwrap();
    }

    /// Appends an edns-client-subnet option to the end of the data.
    ///
    /// The EDNS client subnet option can be used by recursive resolvers to
    /// convey the client’s subnet to upstream name servers so they can
    /// return responses tailored for that subnet.
    ///
    /// See [ClientSubnet] for details on the option value or [RFC 7871]
    /// for the full story.
    ///
    /// [ClientSubnet]: struct.ClientSubnet.html
    /// [RFC 7871]: https://tools.ietf.org/html/rfc7871
    pub fn push_client_subnet(&mut self, data: &ClientSubnet) {
        Opt::push_client_subnet(&mut self.0, data).unwrap();
    }

    /// Appends an EDNS EXPIRE option to the end of the data.
    ///
    /// The EDNS expire option is used between primary and secondary name
    /// servers to convey the expire time for zone transfers. A secondary
    /// name servers requests the expire option by adding an empty option
    /// value, ie. a `value` of `None` to its request. In its response, the
    /// name server will include the current value of expire field of the
    /// zone’s SOA as the expire option.
    ///
    /// See [RFC 7314] for details.
    ///
    /// [RFC 7314]: https://tools.ietf.org/html/rfc7314
    pub fn push_expire(&mut self, value: Option<u32>) {
        Opt::push_expire(&mut self.0, value).unwrap();
    }

    /// Appends a COOKIE option to the end of the data.
    ///
    /// The COOKIE option provides limited protection against off-path
    /// attacks by adding transaction cookies to messages exchanged between
    /// client and server.
    ///
    /// See [Cookie] for the content of the option and [RFC 7873] for
    /// details.
    ///
    /// [Cookie]: struct.Cookie.html
    /// [RFC 7873]: https://tools.ietf.org/html/rfc7873
    pub fn push_cookie(&mut self, cookie: Cookie) {
        Opt::push_cookie(&mut self.0, cookie).unwrap();
    }

    /// Appends the edns-tcp-keepalive option to the end of the data.
    ///
    /// The EDNS client keepalive option allows clients and resolvers to
    /// use long-lived TCP connections when talking to name servers. When
    /// sending a request, the client includes an empty timeout, ie., `None`,
    /// to indicate support for this option. If the server supports the
    /// option, too, it includes the time the client should keep the TCP
    /// connection open, given in units of 100 milliseconds.
    ///
    /// See [RFC 7828] for details.
    ///
    /// [RFC 7828]: https://tools.ietf.org/html/rfc7828
    pub fn push_tcp_keepalive(&mut self, timeout: Option<u16>) {
        Opt::push_tcp_keepalive(&mut self.0, timeout).unwrap();
    }

    /// Appends a Padding option to the end of the data.
    ///
    /// The Padding option can be used to add extra data to a DNS message.
    /// This can be useful with encrypted DNS to make it harder to derive
    /// information from the message size.
    /// The option is defined in [RFC 7830].
    ///
    /// This function adds the content of `padding` as padding. The RFC
    /// specifies that you should prefer using [Opt::push_zero_padding()]
    /// which adds padding of a given length using zeros. This alternative
    /// method is suggested if there is concerns that zeros may get gobbled
    /// up by a compression mechanism.
    ///
    /// # Panic
    ///
    /// The function panics if `padding` is longer than 65535 bytes.
    ///
    /// [Opt::push_zero_padding()]: #method.push_zero_padding
    /// [RFC 7830]: https://tools.ietf.org/html/rfc7830
    pub fn push_padding(&mut self, padding: &[u8]) {
        Opt::push_padding(&mut self.0, padding).unwrap();
    }

    /// Appends a Padding option to the end of the data.
    ///
    /// The Padding option can be used to add extra data to a DNS message.
    /// This can be useful with encrypted DNS to make it harder to derive
    /// information from the message size. The option is defined in
    /// [RFC 7830].
    ///
    /// This function adds `len` zero bytes as padding. This is specified
    /// by the RFC as the method that should be used. However, if messages
    /// are compressed, a sequence of zeroes may be taken out again, so in
    /// this case, alternative padding can be specified using the
    /// [Opt::push_padding()] function.
    ///
    /// [Opt::push_padding()]: #method.push_padding
    /// [RFC 7830]: https://tools.ietf.org/html/rfc7830
    pub fn push_zero_padding(&mut self, len: u16) {
        Opt::push_zero_padding(&mut self.0, len).unwrap();
    }

    /// Appends a CHAIN option to the end of the data.
    ///
    /// The CHAIN option is used by a stub resolver to signal to an upstream
    /// recursive resolver to include all DNSSEC resource records necessary
    /// to validate the result. The option’s content specifies the domain 
    /// name from where on these records need to be included.
    ///
    /// See [RFC 7901] for details.
    ///
    /// [RFC 7901]: https://tools.ietf.org/html/rfc7901
    pub fn push_chain<N: DName>(&mut self, n: &N) {
        Opt::push_chain(&mut self.0, n).unwrap()
    }
}


//--- Default

impl Default for OptBuf {
    fn default() -> Self {
        Self::new()
    }
}


//--- From

impl<'a> From<&'a OptSlice> for OptBuf {
    fn from(slice: &'a OptSlice) -> OptBuf {
        OptBuf(ComposeBuf::from_vec(Vec::from(slice.as_bytes()),
                                    ComposeMode::Unlimited, false))
    }
}


//--- Deref, Borrow, and AsRef

impl Deref for OptBuf {
    type Target = OptSlice;

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl Borrow<OptSlice> for OptBuf {
    fn borrow(&self) -> &OptSlice {
        self.as_slice()
    }
}

impl AsRef<OptSlice> for OptBuf {
    fn as_ref(&self) -> &OptSlice {
        self.as_slice()
    }
}


//------------ OptRecord ----------------------------------------------------

/// An OPT pseudo-resource record.
///
/// The OPT record differs from regular records in that it reuses parts of
/// the common fields for its own nefarious purposes. This type reflects
/// these differences and represents an OPT record.
///
/// You can create a new OPT record from its parts using the [new()] function.
/// The type also implements the `From` trait for converting a regular
/// record with [Opt] record data.
///
/// [new()]: #method.new
/// [Opt]: struct.Opt.html
pub struct OptRecord<'a> {
    /// The requestor’s UDP payload size.
    ///
    /// Stored in what would be the class in regular records.
    udp_size: u16,

    /// The upper eight bits of the extended rcode.
    ///
    /// This is stored in the first byte of what would be the TTL in
    /// regular records.
    extended_rcode: u8,

    /// The EDNS version.
    ///
    /// This is stored in the second byte of what would be the TTL in
    /// regular records.
    version: u8,

    /// The extra flags.
    ///
    /// This is stored in the two last bytes of what would be the TTL in
    /// regular records. Only the topmost bit is in use as the DO flag.
    flags: u16,

    /// The OPT record data.
    data: Opt<'a>
}


/// # Creation and Conversion
///
impl<'a> OptRecord<'a> {
    /// Creates a new record from its components.
    ///
    /// See the methods with the same name for more details on the meaning
    /// of the arguments.
    pub fn new(udp_size: u16, extended_rcode: u8, version: u8, dop: bool,
               data: Opt<'a>) -> Self {
        OptRecord {
            udp_size: udp_size,
            extended_rcode: extended_rcode,
            version: version,
            flags: if dop { 0x8000 } else { 0 },
            data: data
        }
    }
}

impl<'a> OptRecord<'a> {
    /// Returns the maximum UDP payload size the sender can process.
    ///
    /// See [RFC 6891, section 6.2.3] and [6.2.4][RFC 6891, section 6.2.4]
    /// for details.
    ///
    /// [RFC 6891, section 6.2.3]: https://tools.ietf.org/html/rfc6891#section-6.2.3
    /// [RFC 6891, section 6.2.4]: https://tools.ietf.org/html/rfc6891#section-6.2.4
    pub fn udp_size(&self) -> u16 {
        self.udp_size
    }

    /// Sets the maximum UDP payload size.
    ///
    /// See [RFC 6891, section 6.2.3] and [6.2.4][RFC 6891, section 6.2.4]
    /// for details.
    ///
    /// [RFC 6891, section 6.2.3]: https://tools.ietf.org/html/rfc6891#section-6.2.3
    /// [RFC 6891, section 6.2.4]: https://tools.ietf.org/html/rfc6891#section-6.2.4
    pub fn set_udp_size(&mut self, size: u16) {
        self.udp_size = size;
    }

    /// Returns the upper eight bits of the extended rcode.
    ///
    /// The full extended rcode is 12 bits long with the lower four bits
    /// taken from the rcode of the message.
    pub fn extended_rcode(&self) -> u8 {
        self.extended_rcode
    }

    /// Sets the upper eight bits of the extended rcode.
    pub fn set_extended_rcode(&mut self, value: u8) {
        self.extended_rcode = value
    }

    /// Returns the EDNS version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Sets the EDNS version.
    pub fn set_version(&mut self, version: u8) {
        self.version = version
    }

    /// Returns whether the DNSSEC OK bit is set.
    ///
    /// This bit is known as the DO flag. But since that is a reserved name
    /// in Rust, we us `dok` instead. The flag is defined in [RFC 3225]. In
    /// a query, the DO bit indicates whether the sender is able to accept
    /// DNSSEC security resource records. Only if the bit is set should a
    /// server include these records in its answer.
    ///
    /// [RFC 3225]: https://tools.ietf.org/html/rfc3225
    pub fn dok(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    /// Sets or resets the DNSSEC OK bit.
    pub fn set_dok(&mut self, dok: bool) {
        if dok { self.flags = 0x8000 }
        else { self.flags = 0 }
    }

    /// Return a reference to the OPT record data.
    pub fn rdata(&self) -> &'a Opt {
        &self.data
    }

    /// Returns a mutable reference to the OPT record data.
    pub fn rdata_mut(&mut self) -> &'a mut Opt {
        &mut self.data
    }
}

/// # Building OPT Records on the Fly
///
impl<'a> OptRecord<'a> {
    /// Adds an OPT record to `target`.
    ///
    /// The OPT record should be added to the additional section of a DNS
    /// message. Using this function, it can be added directly into that
    /// section.
    ///
    /// The `udp_size` argument should be set to the maximum UDP payload
    /// size the sender can process. The `extended_rcode` argument should
    /// contain the upper eight bits of the extended rcode. The `version`
    /// argument contains the EDNS version, currently always 0. The `dok`
    /// argument contains whether the DO bit should be set.
    ///
    /// The `options` closure will be called to add the desired options
    /// to the message. The [Opt] type has a number of
    /// [associated functions][opt-on-the-fly] for this purpose.
    ///
    /// # Example
    ///
    /// Here is an example of adding an OPT record to a message that
    /// contains a single NSID option:
    ///
    /// ```rust
    /// use domain::bits::{ComposeMode, MessageBuilder};
    /// use domain::rdata::rfc6891::{Opt, OptRecord};
    ///
    /// let mut msg = MessageBuilder::new(ComposeMode::Limited(512),
    ///                                   true).unwrap();
    /// // Add more resource records here ...
    /// let mut sec = msg.answer().authority().additional();
    /// OptRecord::push(&mut sec, 1280, 0, 0, false, |target| {
    ///     try!(Opt::push_nsid(target, b"Foo"));
    ///     Ok(())
    /// }).unwrap();
    /// ```
    ///
    /// [Opt]: struct.Opt.html
    /// [opt-on-the-fly]: struct.Opt.html#building-opt-records-on-the-fly
    pub fn push<C, T, F>(target: &mut T, udp_size: u16, extended_rcode: u8,
                         version: u8, dok: bool, options: F)
                         -> ComposeResult<()>
                where C: ComposeBytes, T: RecordTarget<C>,
                      F: Fn(&mut C) -> ComposeResult<()> {
        target.compose(|target| {
            try!(target.push_u8(0));
            try!(target.push_u16(Rtype::Opt.into()));
            try!(target.push_u16(udp_size));
            try!(target.push_u8(extended_rcode));
            try!(target.push_u8(version));
            if dok { try!(target.push_u16(0x8000)); }
            else { try!(target.push_u16(0)); }
            let pos = target.pos();
            try!(target.push_u16(0));
            try!(options(target));
            let delta = target.delta(pos) - 2;
            if delta > (::std::u16::MAX as usize) {
                return Err(ComposeError::Overflow)
            }
            target.update_u16(pos, delta as u16)
        })
    }
}


//--- From<Record<..>>

impl<'a> From<Record<'a, Opt<'a>>> for OptRecord<'a> {
    fn from(record: Record<'a, Opt<'a>>) -> Self {
        OptRecord {
            udp_size: record.class().into(),
            extended_rcode: (record.ttl() >> 24) as u8,
            version: (record.ttl() >> 16) as u8,
            flags: record.ttl() as u16,
            data: record.into_rdata()
        }
    }
}



//------------ OptionIter----------------------------------------------------

/// An iterator over the options in OPT record data.
///
/// The item of this iterator is the [`OptOption`] type. You can acquire an
/// iterator using the [`OptSlice::iter()`] method.
///
/// [`OptOption`]: struct.OptOption.html
/// [`OptSlice::iter()`]: struct.OptSlice.html#method.iter
pub struct OptionIter<'a>(Parser<'a>);

impl<'a> OptionIter<'a> {
    /// Creates a new iterator from a bytes slice.
    fn new(slice: &'a [u8]) -> Self {
        OptionIter(Parser::new(slice))
    }

    /// Tries parsing the next option.
    ///
    /// Returns either the option or an error if parsing fails or we run out
    /// of data.
    ///
    /// This method mostly exists so we can use `try!()`.
    fn try_next(&mut self) -> ParseResult<OptOption<'a>> {
        let code = OptionCode::from_int(try!(self.0.parse_u16()));
        let len = try!(self.0.parse_u16()) as usize;
        let data = try!(self.0.parse_bytes(len));
        Ok(OptOption { code: code, data: data })
    }
}

impl<'a> Iterator for OptionIter<'a> {
    type Item = OptOption<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.try_next().ok()
    }
}


//------------ OptOption ----------------------------------------------------

/// A single option of OPT record data.
///
/// This is really only a dumb composite type without any further function.
pub struct OptOption<'a> {
    /// The option code for this option.
    pub code: OptionCode,

    /// A bytes slice with the data of this option.
    pub data: &'a [u8]
}


//------------ SecAlgIter ---------------------------------------------------

/// An iterator over security algorithms.
pub struct SecAlgIter<'a>(&'a [u8]);

impl<'a> SecAlgIter<'a> {
    /// Creates a new iterator from the given bytes slice.
    fn new(slice: &'a [u8]) -> Self {
        SecAlgIter(slice)
    }
}

impl<'a> Iterator for SecAlgIter<'a> {
    type Item = SecAlg;

    fn next(&mut self) -> Option<SecAlg> {
        if self.0.is_empty() { None }
        else {
            let res = SecAlg::from_int(self.0[0]);
            self.0 = &self.0[1..];
            Some(res)
        }
    }
}


//------------ ClientSubnet -------------------------------------------------

/// A EDNS Client Subnet option value.
///
/// The EDNS Client Subnet option allows a recursive resolver to submit the
/// subnet a query originated from to upstream name servers. This is useful
/// in cases where name servers create different responses depending on the
/// origin of the query.
///
/// In order to protect the innocent as well as allow cashing, the option
/// doesn’t operate on addresses but on subnets. When the client includes
/// the option in a query, it specifies the length of the prefix of an
/// address it wishes the server to consider. This is called the source
/// prefix length. In its response, the server states the length of the
/// prefix it actually used. This is the scope prefix length.
///
/// For details on the actual encoding of the option as well as information
/// on expected behavior, see RFC 7871.
///
/// [RFC 7871]: https://tools.ietf.org/html/rfc7871
#[derive(Clone, Debug)]
pub struct ClientSubnet {
    /// The address.
    ///
    /// Unlike in the encoded option, this is always a full address.
    addr: IpAddr,

    /// The source prefix length.
    source: u8,

    /// The scope prefix length.
    scope: u8,
}

impl ClientSubnet {
    /// Creates a new client subnet value from the given components.
    ///
    /// See the methods with the same name for the meaning of the components.
    pub fn new(addr: IpAddr, source: u8, scope: u8) -> Self {
        // XXX Make sure all components are valid here already and either
        //     fix them or panic. In particular, make sure unused bits in
        //     addr are 0 as otherwise the option may be rejected by picky
        //     servers.
        ClientSubnet { addr: addr, source: source, scope: scope }
    }

    /// Returns the source prefix length.
    ///
    /// This value specifies the leftmost number of bits of the address that
    /// are to be used in the lookup.
    pub fn source(&self) -> u8 {
        self.source
    }

    /// Returns the scope prefix length.
    ///
    /// This value specifies the leftmost number of bits ot the address the
    /// server considered or would have considered when creating the answer.
    /// In a query, this value must be 0.
    pub fn scope(&self) -> u8 {
        self.scope
    }

    /// Returns the address from which the subnet can be determined.
    ///
    /// This is either an IPv4 or IPv6 address. The subnet is determined
    /// by only considering the [source()] number of leftmost bits.
    ///
    /// [source()]: #method.source
    pub fn addr(&self) -> IpAddr {
        self.addr
    }
}


/// # Parsing and Composing
///
impl ClientSubnet {
    /// Parses a client subnet value.
    #[allow(needless_lifetimes)]
    pub fn parse<'a, P: ParseBytes<'a>>(parser: &mut P) -> ParseResult<Self> {
        let family = try!(parser.parse_u16());
        let source = try!(parser.parse_u8());
        let scope = try!(parser.parse_u8());
        let addr_len = addr_len(source);
        let addr_bytes = try!(parser.parse_bytes(addr_len));

        let addr = match family {
            1 => {
                // Ipv4
                if source > 32 || scope > 32 {
                    return Err(ParseError::FormErr)
                }
                IpAddr::V4(
                    Ipv4Addr::new(
                        if addr_len > 0 { addr_bytes[0] } else { 0 },
                        if addr_len > 1 { addr_bytes[1] } else { 0 },
                        if addr_len > 2 { addr_bytes[2] } else { 0 },
                        if addr_len > 3 { addr_bytes[3] } else { 0 }
                    )
                )
            }
            2 => {
                // Ipv6
                if source > 128 || scope > 128 {
                    return Err(ParseError::FormErr)
                }
                IpAddr::V6(
                    Ipv6Addr::new(
                        u16_from_slice(addr_bytes, 0),
                        u16_from_slice(addr_bytes, 2),
                        u16_from_slice(addr_bytes, 4),
                        u16_from_slice(addr_bytes, 6),
                        u16_from_slice(addr_bytes, 8),
                        u16_from_slice(addr_bytes, 10),
                        u16_from_slice(addr_bytes, 12),
                        u16_from_slice(addr_bytes, 14)
                    )
                )
            }
            _ => return Err(ParseError::FormErr)
        };

        Ok(ClientSubnet { addr: addr, source: source, scope: scope })
    }

    /// Returns the length of the encoded client subnet value in bytes.
    pub fn compose_len(&self) -> usize {
        let mut addr_len = addr_len(self.source);
        match self.addr {
            IpAddr::V4(_) => addr_len = min(addr_len, 4),
            IpAddr::V6(_) => addr_len = min(addr_len, 16)
        };
        addr_len + 4
    }

    /// Pushes the client subnet value to the end of `target`.
    pub fn compose<C: ComposeBytes>(&self, target: &mut C)
                                    -> ComposeResult<()> {
        let mut addr_len = addr_len(self.source);
        match self.addr {
            IpAddr::V4(addr) => {
                addr_len = min(addr_len, 4);
                try!(target.push_u16(1));
                try!(target.push_u8(self.source));
                try!(target.push_u8(self.scope));
                try!(target.push_bytes(&addr.octets()[..addr_len]));
            }
            IpAddr::V6(addr) => {
                addr_len = min(addr_len, 16);
                try!(target.push_u16(2));
                try!(target.push_u8(self.source));
                try!(target.push_u8(self.scope));
                try!(target.push_bytes(&v6_octets(addr)[..addr_len]));
            }
        }
        Ok(())
    }
}


//------------ Cookie -------------------------------------------------------

/// A DNS Cookie.
///
/// DNS cookies are a lightweight security mechanism to protect agains
/// off-path attackers. The details are described in [RFC 7873].
///
/// A DNS cookie value as represented by this type consists of two parts:
/// a client cookie and a server cookie. The client cookie is always eight
/// bytes long and chosen by the client. The server cookie `is between eight
/// and 32 bytes long and chosen by the server in such a way that a query
/// by the same client results in the same server cookie.
///
/// When a client contacts a certain server for the first time and doesn’t
/// know the server cookie yet, it leaves it out. Once it received the first
/// response from the server, it will include it in any subsequent query.
///
/// Todo: Implement the example algorithms from appendixes A and B of the
///       RFC.
///
/// [RFC 7873]: https://tools.ietf.org/html/rfc7873
#[derive(Clone, Copy)]
pub struct Cookie<'a> {
    client: &'a [u8],
    server: Option<&'a [u8]>
}

impl<'a> Cookie<'a> {
    /// Creates a new cookie value from the client and server cookies.
    pub fn new(client: &'a [u8], server: Option<&'a [u8]>) -> Self {
        Cookie { client: client, server: server }
    }

    /// Returns a reference to the client cookie.
    pub fn client(&self) -> &[u8] {
        self.client
    }

    /// Returns a reference to the server cookie if present.
    pub fn server(&self) -> Option<&[u8]> {
        self.server
    }
}


/// # Parsing and Composing
///
impl<'a> Cookie<'a> {
    #[allow(if_same_then_else)]
    pub fn parse<P: ParseBytes<'a>>(parser: &mut P) -> ParseResult<Self> {
        if parser.left() < 8 {
            Err(ParseError::FormErr)
        }
        else if parser.left() == 8 {
            Ok(Cookie { client: try!(parser.parse_bytes(8)), server: None })
        }
        else if parser.left() < 16 || parser.left() > 40 {
            Err(ParseError::FormErr)
        }
        else {
            Ok(Cookie { client: try!(parser.parse_bytes(8)),
                        server: Some(try!(parser.parse_left())) })
        }
    }

    /// Returns the length of the cookie option value.
    pub fn compose_len(&self) -> usize {
        if let Some(server) = self.server {
            self.client.len() + server.len()
        }
        else {
            self.client.len()
        }
    }

    /// Pushes the cookie option to the end of `target`.
    pub fn compose<C: ComposeBytes>(&self, target: &mut C)
                                    -> ComposeResult<()> {
        try!(target.push_bytes(&self.client));
        if let Some(server) = self.server {
            try!(target.push_bytes(&server));
        }
        Ok(())
    }
}


//------------ Helper Functions ---------------------------------------------

/// Returns the number of bytes necessary to store `source` bits.
fn addr_len(source: u8) -> usize {
    (if source & 0x07 != 0 { (source >> 3) + 1 }
    else { source >> 3 }) as usize
}

/// Returns the host-order u16 starting at `pos` in `slice` in network order.
///
/// Assumes an infinitely long slice filled up with zeroes.
fn u16_from_slice(slice: &[u8], pos: usize) -> u16 {
    if slice.len() > pos + 1 {
        (slice[pos] as u16) << 8 | (slice[pos + 1] as u16)
    }
    else if slice.len() > pos {
        (slice[pos] as u16) << 8
    }
    else {
        0
    }
}

/// Returns the octets of a V6 address as a bytes slice.
///
/// XXX Replace this once `Ipv6Addr.octets()` is stable.
fn v6_octets(addr: Ipv6Addr) -> [u8; 16] {
    let mut res = [0u8; 16];
    for (i, v) in addr.segments().iter().enumerate() {
        res[2 * i] = (*v >> 8) as u8;
        res[2 * i + 1] = *v as u8;
    }
    res
}

