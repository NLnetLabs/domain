//! Resolver configuration
//!
//! There are two parts to this module: Query options that allow you to
//! modify the behaviour of the resolver on a query by query basis and
//! the global resolver configuration (normally read from the system’s
//! `/etc/resolv.conf`) that contains things like the name servers to query
//! and a set of default options.
//!
//! Both parts are modeled along the lines of glibc’s resolver.

use std::{convert, error, fmt, fs, io, ops};
use std::default::Default;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::str::{self, FromStr, SplitWhitespace};
use std::time::Duration;
use domain_core::bits::name::{self, Dname};


//------------ ResolvOptions ------------------------------------------------

/// Options for the resolver configuration.
///
/// This type contains a lot of options that influence the resolver
/// configuration. It collects all server-indpendent options that glibc’s
/// resolver supports. Not all of them are currently supported by this
/// implementation.
#[derive(Clone, Debug)]
pub struct ResolvOptions {
    /// Search list for host-name lookup.
    pub search: SearchList,

    /// TODO Sortlist
    /// sortlist: ??

    /// Number of dots before an initial absolute query is made.
    pub ndots: usize,

    /// Timeout to wait for a response.
    pub timeout: Duration,

    /// Number of retries before giving up.
    pub attempts: usize,

    /// Accept authoritative answers only.
    ///
    /// Only responses with the AA bit set will be considered. If there
    /// aren’t any, the query will fail.
    ///
    /// This option is not currently implemented. It is likely to be
    /// eventually implemented by the query.
    pub aa_only: bool,
    
    /// Always use TCP.
    ///
    /// This option is implemented by the query.
    pub use_vc: bool,

    /// Query primary name servers only.
    ///
    /// This option is not currently implemented. It is unclear what exactly
    /// it is supposed to mean.
    pub primary: bool,

    /// Ignore trunactions errors, don’t retry with TCP.
    ///
    /// This option is implemented by the query.
    pub ign_tc: bool,

    /// Set the recursion desired bit in queries.
    ///
    /// Enabled by default.
    ///
    /// Implemented by the query request.
    pub recurse: bool,

    /// Append the default domain name to single component names.
    ///
    /// Enabled by default.
    ///
    /// This is not currently implemented. Instead, the resolver config’s
    /// `search` and `ndots` fields govern resolution of relative names of
    /// all kinds.
    pub default_names: bool,

    /// Keep TCP connections open between queries.
    ///
    /// This is not currently implemented.
    pub stay_open: bool,

    /// Search hostnames in the current domain and parent domains.
    ///
    /// Enabled by default.
    ///
    /// This options is not currently implemented. Instead, the resolver
    /// config’s `search` and `ndots` fields govern resolution of relative
    /// names.
    pub dn_search: bool,

    /// Try AAAA query before A query and map IPv4 responses to tunnel form.
    ///
    /// This option is not currently implemented. It is only relevant for
    /// `lookup_host`.
    pub use_inet6: bool,

    /// Use round-robin selection of name servers.
    ///
    /// This option is implemented by the query.
    pub rotate: bool,

    /// Disable checking of incoming hostname and mail names.
    ///
    /// This is not currently implemented. Or rather, this is currently
    /// always on—there is no name checking as yet.
    pub no_check_name: bool,

    /// Do not strip TSIG records.
    ///
    /// This is not currently implemented. Or rather, no records are stripped
    /// at all.
    pub keep_tsig: bool,

    /// Send each query simultaneously to all name servers.
    ///
    /// This is not currently implemented. It would be a query option.
    pub blast: bool,

    /// Use bit-label format for IPv6 reverse lookups.
    ///
    /// Bit labels have been deprecated and consequently, this option is not
    /// implemented.
    pub use_bstring: bool,

    /// Use ip6.int instead of the recommended ip6.arpa.
    ///
    /// (This option is the reverse of glibc’s `RES_NOIP6DOTINT` option).
    ///
    /// This option is only relevant for `lookup_addr()` and is implemented
    /// there already.
    pub use_ip6dotint: bool,

    /// Use EDNS0.
    ///
    /// EDNS is not yet supported.
    pub use_edns0: bool,

    /// Perform IPv4 and IPv6 lookups sequentially instead of in parallel.
    ///
    /// This is not yet implemented but would be an option for
    /// `lookup_host()`.
    pub single_request: bool,

    /// Open a new socket for each request.
    ///
    /// This is not currently implemented.
    pub single_request_reopen: bool,

    /// Don’t look up unqualified names as top-level-domain.
    ///
    /// This is not currently implemented. Instead, the resolver config’s
    /// `search` and `ndots` fields govern resolution of relative names of
    /// all kinds.
    pub no_tld_query: bool,
}

impl Default for ResolvOptions {
    fn default() -> Self {
        ResolvOptions {
            // non-flags:
            search: SearchList::new(),
            //sortlist,
            ndots: 1,
            timeout: Duration::new(5,0),
            attempts: 2,

            // enabled by default:
            recurse: true, default_names: true, dn_search: true,

            // everthing else is not:
            aa_only: false, use_vc: false, primary: false, ign_tc: false,
            stay_open: false, use_inet6: false, rotate: false,
            no_check_name: false, keep_tsig: false, blast: false,
            use_bstring: false, use_ip6dotint: false, use_edns0: false,
            single_request: false, single_request_reopen: false,
            no_tld_query: false
        }
    }
}


//------------ Transport -----------------------------------------------------

/// The transport protocol to be used for a server.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Transport {
    /// Unencrypted UDP transport.
    Udp,

    /// Unencrypted TCP transport.
    Tcp,
}

impl Transport {
    /// Returns whether the transport is a preferred transport.
    ///
    /// Only preferred transports are considered initially. Only if a
    /// truncated answer comes back will we consider streaming protocols
    /// instead.
    pub fn is_preferred(self) -> bool {
        match self {
            Transport::Udp => true,
            Transport::Tcp => false,
        }
    }

    /// Returns whether the transport is a streaming protocol.
    pub fn is_stream(self) -> bool {
        match self {
            Transport::Udp => false,
            Transport::Tcp => true,
        }
    }
}


//------------ ServerConf ----------------------------------------------------

/// Configuration for one upstream DNS server.
///
/// The server is identified by a socket address, ie., an address/port pair.
/// For each server you can set how it should operate on all supported
/// transport protocols, including not at all, and two timeouts for each
/// request and sockets. The timeouts are used for all transports. If you
/// need different timeouts for, say, UDP and TCP, you can always use two
/// server entries with the same address.
#[derive(Clone, Debug)]
pub struct ServerConf {
    /// Server address.
    pub addr: SocketAddr,

    /// Transport protocol.
    pub transport: Transport,

    /// How long to wait for a response before returning a timeout error.
    pub request_timeout: Duration,

    /// Size of the message receive buffer in bytes.
    ///
    /// This is used for datagram transports only.
    pub recv_size: usize,
}

impl ServerConf {
    /// Returns a new default server config for the given address.
    pub fn new(addr: SocketAddr, transport: Transport) -> Self {
        ServerConf {
            addr,
            transport,
            request_timeout: Duration::from_secs(2),
            // Maximum non-fragmenting payload sizes from RFC 6891, 6.2.3.
            // 
            // XXX We use those only for now, even though RFC 6891, 6.2.5.
            //     recommends to start with 4096 and decrease on failure.
            //     We’ll add a mechanism to scale down, later.
            recv_size: match addr {
                SocketAddr::V4(_) => 1280,
                SocketAddr::V6(_) => 1410,
            }
        }
    }
}


//------------ ResolvConf ---------------------------------------------------

/// Resolver configuration.
///
/// This type collects all information necessary to configure how a stub
/// resolver talks to its upstream resolvers.
///
/// The type follows the builder pattern. After creating a value with
/// `ResolvConf::new()` you can manipulate the members. Once you are happy
/// with them, you call `finalize()` to make sure the configuration is valid.
/// It mostly just fixes the `servers`.
///
/// Additionally, the type can parse a glibc-style configuration file,
/// commonly known as `/etc/resolv.conf` through the `parse()` and
/// `parse_file()` methods. You still need to call `finalize()` after
/// parsing.
///
/// The easiest way, however, to get the system resolver configuration is
/// through `ResolvConf::default()`. This will parse the configuration file
/// or return a default configuration if that fails.
///
#[derive(Clone, Debug)]
pub struct ResolvConf {
    /// Addresses of servers to query.
    pub servers: Vec<ServerConf>,

    /// Default options.
    pub options: ResolvOptions,
}


/// # Management
///
impl ResolvConf {
    /// Creates a new, empty configuration.
    ///
    /// Using an empty configuration will fail since it does not contain
    /// any name servers. Call `self.finalize()` to make it usable.
    pub fn new() -> Self {
        ResolvConf {
            servers: Vec::new(),
            options: ResolvOptions::default()
        }
    }

    /// Finalizes the configuration for actual use.
    ///
    /// The function does two things. If `servers` is empty, it adds
    /// `127.0.0.1:53`. This is exactly what glibc does. If `search` is
    /// empty, it adds the root domain `"."`. This differs from what
    /// glibc does which considers the machine’s host name.
    pub fn finalize(&mut self) {
        if self.servers.is_empty() {
            // glibc just simply uses 127.0.0.1:53. Let's do that, too,
            // and claim it is for compatibility.
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                                       53);
            self.servers.push(ServerConf::new(addr, Transport::Udp));
            self.servers.push(ServerConf::new(addr, Transport::Tcp));
        }
        if self.options.search.is_empty() {
            self.options.search.push(Dname::root())
        }
        for server in &mut self.servers {
            server.request_timeout = self.options.timeout
        }
    }

    /// Creates a default configuration for this system.
    ///
    /// XXX This currently only works for Unix-y systems.
    pub fn default() -> Self {
        let mut res = ResolvConf::new();
        let _ = res.parse_file("/etc/resolv.conf");
        res.finalize();
        res
    }
}


/// # Parsing Configuration File
///
impl ResolvConf {
    /// Parses the configuration from a file.
    pub fn parse_file<P: AsRef<Path>>(
        &mut self, path: P
    ) -> Result<(), Error> {
        let mut file = fs::File::open(path)?;
        self.parse(&mut file)
    }

    /// Parses the configuration from a reader.
    ///
    /// The format is that of the /etc/resolv.conf file.
    pub fn parse<R: Read>(&mut self, reader: &mut R) -> Result<(), Error> {
        use std::io::BufRead;

        for line in io::BufReader::new(reader).lines() {
            let line = line?;
            let line = line.trim_end();

            if line.is_empty() || line.starts_with(';') ||
                                  line.starts_with('#') {
                continue
            }
            
            let mut words = line.split_whitespace();
            let keyword = words.next();
            match keyword {
                Some("nameserver") => self.parse_nameserver(words)?,
                Some("domain") => self.parse_domain(words)?,
                Some("search") => self.parse_search(words)?,
                Some("sortlist") => self.parse_sortlist(words)?,
                Some("options") => self.parse_options(words)?,
                _ => return Err(Error::ParseError)
            }
        }
        Ok(())
    }

    fn parse_nameserver(
        &mut self,
        mut words: SplitWhitespace
    ) -> Result<(), Error> {
        use std::net::ToSocketAddrs;
        
        for addr in (next_word(&mut words)?, 53).to_socket_addrs()?
        {
            self.servers.push(ServerConf::new(addr, Transport::Udp));
            self.servers.push(ServerConf::new(addr, Transport::Tcp));
        }
        no_more_words(words)
    }

    fn parse_domain(
        &mut self,
        mut words: SplitWhitespace
    ) -> Result<(), Error> {
        let domain = Dname::from_str(next_word(&mut words)?)?;
        self.options.search = domain.into();
        no_more_words(words)
    }

    fn parse_search(&mut self, words: SplitWhitespace) -> Result<(), Error> {
        let mut search = SearchList::new();
        for word in words {
            let name = Dname::from_str(word)?;
            search.push(name)
        }
        self.options.search = search;
        Ok(())
    }

    fn parse_sortlist(
        &mut self,
        words: SplitWhitespace
    ) -> Result<(), Error> {
        // XXX TODO
        let _ = words; 
        Ok(())
    }
 
    #[allow(match_same_arms)]
    fn parse_options(&mut self, words: SplitWhitespace) -> Result<(), Error> {
        for word in words {
            match split_arg(word)? {
                ("debug", None) => { }
                ("ndots", Some(n)) => {
                    self.options.ndots = n
                }
                ("timeout", Some(n)) => {
                    self.options.timeout = Duration::new(n as u64, 0)
                }
                ("attempts", Some(n)) => {
                    self.options.attempts = n
                }
                ("rotate", None) => {
                    self.options.rotate = true
                }
                ("no-check-names", None) => {
                    self.options.no_check_name = true
                }
                ("inet6", None) => {
                    self.options.use_inet6 = true
                }
                ("ip6-bytestring", None) => {
                    self.options.use_bstring = true
                }
                ("ip6-dotint", None) => {
                    self.options.use_ip6dotint = true
                }
                ("no-ip6-dotint", None) => {
                    self.options.use_ip6dotint = false
                }
                ("edns0", None) => {
                    self.options.use_edns0 = true
                }
                ("single-request", None) => {
                    self.options.single_request = true
                }
                ("single-request-reopen", None) => {
                    self.options.single_request_reopen = true
                }
                ("no-tld-query", None) => {
                    self.options.no_tld_query = true
                }
                ("use-vc", None) => {
                    self.options.use_vc = true
                }
                // Ignore unknown or misformated options.
                _ => { }
            }
        }
        Ok(())
    }
}


//--- Default

impl Default for ResolvConf {
    fn default() -> Self {
        Self::new()
    }
}


//--- Display

impl fmt::Display for ResolvConf {
    #[allow(cyclomatic_complexity)]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for server in &self.servers {
            let server = server.addr;
            f.write_str("nameserver ")?;
            if server.port() == 53 { server.ip().fmt(f)?; }
            else { server.fmt(f)?; }
            "\n".fmt(f)?;
        }
        if self.options.search.len() == 1 {
            write!(f, "domain {}\n", self.options.search[0])?;
        }
        else if self.options.search.len() > 1 {
            "search".fmt(f)?;
            for name in self.options.search.as_slice() {
                write!(f, " {}", name)?;
            }
            "\n".fmt(f)?;
        }

        // Collect options so we only print them if there are any non-default
        // ones.
        let mut options = Vec::new();
        
        if self.options.ndots != 1 {
            options.push(format!("ndots:{}", self.options.ndots));
        }
        if self.options.timeout != Duration::new(5,0) {
            // XXX This ignores fractional seconds.
            options.push(
                format!("timeout:{}", self.options.timeout.as_secs())
            );
        }
        if self.options.attempts != 2 {
            options.push(format!("attempts:{}", self.options.attempts));
        }
        if self.options.aa_only { options.push("aa-only".into()) }
        if self.options.use_vc { options.push("use-vc".into()) }
        if self.options.primary { options.push("primary".into()) }
        if self.options.ign_tc { options.push("ign-tc".into()) }
        if !self.options.recurse { options.push("no-recurse".into()) }
        if !self.options.default_names {
            options.push("no-default-names".into())
        }
        if self.options.stay_open { options.push("stay-open".into()) }
        if !self.options.dn_search { options.push("no-dn-search".into()) }
        if self.options.use_inet6 { options.push("use-inet6".into()) }
        if self.options.rotate { options.push("rotate".into()) }
        if self.options.no_check_name { options.push("no-check-name".into()) }
        if self.options.keep_tsig { options.push("keep-tsig".into()) }
        if self.options.blast { options.push("blast".into()) }
        if self.options.use_bstring { options.push("use-bstring".into()) }
        if self.options.use_ip6dotint { options.push("ip6dotint".into()) }
        if self.options.use_edns0 { options.push("use-edns0".into()) }
        if self.options.single_request {
            options.push("single-request".into())
        }
        if self.options.single_request_reopen {
            options.push("single-request-reopen".into())
        }
        if self.options.no_tld_query { options.push("no-tld-query".into()) }

        if !options.is_empty() {
            "options".fmt(f)?;
            for option in options {
                write!(f, " {}", option)?;
            }
            "\n".fmt(f)?;
        }

        Ok(())
    }
}


//------------ SearchList ----------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct SearchList {
    search: Vec<Dname>,
}

impl SearchList {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, name: Dname) {
        self.search.push(name)
    }

    pub fn push_root(&mut self) {
        self.search.push(Dname::root())
    }

    pub fn get(&self, pos: usize) -> Option<&Dname> {
        self.search.get(pos)
    }

    pub fn as_slice(&self) -> &[Dname] {
        self.as_ref()
    }
}

impl From<Dname> for SearchList {
    fn from(name: Dname) -> Self {
        let mut res = Self::new();
        res.push(name);
        res
    }
}


//--- AsRef and Deref

impl AsRef<[Dname]> for SearchList {
    fn as_ref(&self) -> &[Dname] {
        self.search.as_ref()
    }
}

impl ops::Deref for SearchList {
    type Target = [Dname];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}


//------------ Private Helpers -----------------------------------------------
//
// These are here to wrap stuff into Results.

/// Returns a reference to the next word or an error.
fn next_word<'a>(
    words: &'a mut str::SplitWhitespace
) -> Result<&'a str, Error> {
    match words.next() {
        Some(word) => Ok(word),
        None => Err(Error::ParseError)
    }
}

/// Returns nothing but errors out if there are words left.
fn no_more_words(mut words: str::SplitWhitespace) -> Result<(), Error> {
    match words.next() {
        Some(..) => Err(Error::ParseError),
        None => Ok(())
    }
}

/// Splits the name and argument from an option with arguments.
///
/// These options consist of a name followed by a colon followed by a
/// value, which so far is only `usize`, so we do that.
fn split_arg(s: &str) -> Result<(&str, Option<usize>), Error> {
    match s.find(':') {
        Some(idx) => {
            let (left, right) = s.split_at(idx);
            Ok((left, Some(usize::from_str_radix(&right[1..], 10)?)))
        }
        None => Ok((s, None))
    }
}


//------------ Error --------------------------------------------------------

/// The error that can happen when parsing `resolv.conf`.
#[derive(Debug)]
pub enum Error {
    /// The file is not a proper file.
    ParseError,

    /// Something happend while reading.
    Io(io::Error),
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::ParseError => "error parsing configuration",
            Error::Io(ref e) => e.description(),
        }
    }
}

impl convert::From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Error::Io(error)
    }
}

impl convert::From<name::FromStrError> for Error {
    fn from(_: name::FromStrError) -> Error {
        Error::ParseError
    }
}

impl convert::From<::std::num::ParseIntError> for Error {
    fn from(_: ::std::num::ParseIntError) -> Error {
        Error::ParseError
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use std::error::Error;

        self.description().fmt(f)
    }
}


//============ Testing ======================================================

#[cfg(test)]
mod test {
    use std::io;
    use super::*;

    #[test]
    fn parse_resolv_conf() {
        let mut conf = ResolvConf::new();
        let data = "nameserver 192.0.2.0\n\
                    nameserver 192.0.2.1\n\
                    options use-vc ndots:122\n".to_string();
        assert!(conf.parse(&mut io::Cursor::new(data)).is_ok());
        assert!(conf.options.use_vc);
        assert_eq!(conf.options.ndots, 122);
    }
}

