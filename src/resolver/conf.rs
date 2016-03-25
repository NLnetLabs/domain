//! Resolver configuration
//!
//! There are two parts to this module: Query options that allow you to
//! modify the behaviour of the resolver on a query by query basis and
//! the global resolver configuration (normally read from the system’s
//! `/etc/resolv.conf`) that contains things like the name servers to query
//! and a set of default options.
//!
//! Both parts are modeled along the lines of glibc’s resolver.

use std::convert;
use std::default::Default;
use std::error;
use std::fmt;
use std::fs; 
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::str::{self, FromStr, SplitWhitespace};
use std::result;
use std::time::Duration;
use ::bits::error::FromStrError;
use ::bits::name::OwnedDName;


//------------ ResolvOptions ------------------------------------------------

#[derive(Clone, Debug)]
pub struct ResolvOptions {
    /// Accept authoritative answers only.
    pub aa_only: bool,
    
    /// Always use TCP.
    pub use_vc: bool,

    /// Query primary name servers only.
    pub primary: bool,

    /// Ignore trunactions errors, don’t retry with TCP.
    pub ign_tc: bool,

    /// Set the recursion desired bit in queries.
    ///
    /// Enabled by default.
    pub recurse: bool,

    /// Append the default domain name to single component names.
    ///
    /// Enabled by default.
    pub default_names: bool,

    /// Keep TCP connections open between queries.
    pub stay_open: bool,

    /// Search hostnames in the current domain and parent domains.
    ///
    /// Enabled by default.
    pub dn_search: bool,

    /// Try AAAA query before A query and map IPv4 responses to tunnel form.
    pub use_inet6: bool,

    /// Use round-robin selection of name servers.
    pub rotate: bool,

    /// Disable checking of incoming hostname and mail names.
    pub no_check_name: bool,

    /// Do not strip TSIG records.
    pub keep_tsig: bool,

    /// Send each query simultaneously to all name servers.
    pub blast: bool,

    /// Use bit-label format for IPv6 reverse lookups.
    pub use_bstring: bool,

    /// Use ip6.int instead of the recommended ip6.arpa.
    ///
    /// (This option is the reverse of glibc’s `RES_NOIP6DOTINT` option).
    pub use_ip6dotint: bool,

    /// Use EDNS0.
    pub use_edns0: bool,

    /// Perform IPv4 and IPv6 lookups sequentially instead of in parallel.
    pub single_request: bool,

    /// Open a new socket for each request.
    pub single_request_reopen: bool,

    /// Don’t look up unqualified names as top-level-domain.
    pub no_tld_query: bool,
}

impl Default for ResolvOptions {
    fn default() -> Self {
        ResolvOptions {
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


//------------ ResolvConf ---------------------------------------------------

/// Resolver configuration
#[derive(Clone, Debug)]
pub struct ResolvConf {
    /// Addresses of servers to query.
    pub servers: Vec<SocketAddr>,

    /// Search list for host-name lookup.
    pub search: Vec<OwnedDName>,

    /// TODO Sortlist
    /// sortlist: ??

    /// Number of dots before an initial absolute query is made.
    pub ndots: usize,

    /// Timeout to wait for a response.
    pub timeout: Duration,

    /// Number of retries before giving up.
    pub attempts: usize,

    /// Default options.
    pub options: ResolvOptions
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
            search: Vec::new(),
            //sortlist,
            ndots: 1,
            timeout: Duration::new(5,0),
            attempts: 2,
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
            let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
            self.servers.push(SocketAddr::new(addr, 53));
        }
        if self.search.is_empty() {
            self.search.push(OwnedDName::root())
        }
    }
}


/// # Parsing Configuration File
///
impl ResolvConf {
    /// Parses the configuration from a file.
    pub fn parse_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let mut file = try!(fs::File::open(path));
        self.parse(&mut file)
    }

    /// Parses the configuration from a reader.
    ///
    /// The format is that of the /etc/resolv.conf file.
    pub fn parse<R: Read>(&mut self, reader: &mut R) -> Result<()> {
        use std::io::BufRead;

        for line in io::BufReader::new(reader).lines() {
            let line = try!(line);
            let line = line.trim_right();

            if line.is_empty() || line.starts_with(';') ||
                                  line.starts_with('#') {
                continue
            }
            
            let mut words = line.split_whitespace();
            let keyword = words.next();
            match keyword {
                Some("nameserver") => try!(self.parse_nameserver(words)),
                Some("domain") => try!(self.parse_domain(words)),
                Some("search") => try!(self.parse_search(words)),
                Some("sortlist") => try!(self.parse_sortlist(words)),
                Some("options") => try!(self.parse_options(words)),
                _ => return Err(Error::ParseError)
            }
        }
        Ok(())
    }

    fn parse_nameserver(&mut self, mut words: SplitWhitespace) -> Result<()> {
        use std::net::ToSocketAddrs;
        
        for addr in try!((try!(next_word(&mut words)), 53).to_socket_addrs())
        {
            self.servers.push(addr)
        }
        no_more_words(words)
    }

    fn parse_domain(&mut self, mut words: SplitWhitespace) -> Result<()> {
        let domain = try!(OwnedDName::from_str(try!(next_word(&mut words))));
        self.search = Vec::new();
        self.search.push(domain);
        no_more_words(words)
    }

    fn parse_search(&mut self, words: SplitWhitespace) -> Result<()> {
        let mut search = Vec::new();
        for word in words {
            search.push(try!(OwnedDName::from_str(word)))
        }
        self.search = search;
        Ok(())
    }

    fn parse_sortlist(&mut self, words: SplitWhitespace) -> Result<()> {
        // XXX TODO
        let _ = words; 
        Ok(())
    }
    
    fn parse_options(&mut self, words: SplitWhitespace) -> Result<()> {
        for word in words {
            match try!(split_arg(word)) {
                ("debug", None) => { }
                ("ndots", Some(n)) => {
                    self.ndots = n
                }
                ("timeout", Some(n)) => {
                    self.timeout = Duration::new(n as u64, 0)
                }
                ("attempts", Some(n)) => {
                    self.attempts = n
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


//------------ Private Helpers ----------------------------------------------

fn next_word<'a>(words: &'a mut str::SplitWhitespace) -> Result<&'a str> {
    match words.next() {
        Some(word) => Ok(word),
        None => Err(Error::ParseError)
    }
}

fn no_more_words(mut words: str::SplitWhitespace) -> Result<()> {
    match words.next() {
        Some(..) => Err(Error::ParseError),
        None => Ok(())
    }
}

fn split_arg<'a>(s: &'a str) -> Result<(&'a str, Option<usize>)> {
    match s.find(':') {
        Some(idx) => {
            let (left, right) = s.split_at(idx);
            Ok((left, Some(try!(usize::from_str_radix(right, 10)))))
        }
        None => Ok((s, None))
    }
}


//------------ Error and Result ---------------------------------------------

#[derive(Debug)]
pub enum Error {
    ParseError,
    IoError(io::Error),
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::ParseError => "error parsing configuration",
            Error::IoError(ref e) => e.description(),
        }
    }
}

impl convert::From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Error::IoError(error)
    }
}

impl convert::From<FromStrError> for Error {
    fn from(_: FromStrError) -> Error {
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

pub type Result<T> = result::Result<T, Error>;


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
                    options use-vc".to_string();
        assert!(conf.parse(&mut io::Cursor::new(data)).is_ok());
        assert!(conf.options.use_vc);
    }
}
