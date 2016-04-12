//! Static host table

use std::collections::HashMap;
use std::convert;
use std::error;
use std::fmt;
use std::fs;
use std::io;
use std::net::{self, IpAddr};
use std::path::Path;
use std::str::FromStr;
use std::result;
use bits::error::FromStrError;
use bits::name::{DNameSlice, OwnedDName};


//------------ Hosts --------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Hosts {
    forward: HashMap<OwnedDName, IpAddr>,
    reverse: HashMap<IpAddr, OwnedDName>,
}


/// # Creation and Manipulation
///
impl Hosts {
    /// Creates a new, empty host table.
    pub fn new() -> Self {
        Hosts {
            forward: HashMap::new(),
            reverse: HashMap::new()
        }
    }

    /// Creates a default hosts table for this system.
    /// 
    /// XXX This currently only works for Unix-y systems.
    pub fn default() -> Self {
        let mut res = Hosts::new();
        let _ = res.parse_file("/etc/hosts");
        res
    }
 
    /// Adds a host to IP mapping.
    pub fn add_forward(&mut self, name: OwnedDName, addr: IpAddr) {
        self.forward.insert(name, addr);
    }

    /// Adds a IP to host mapping.
    pub fn add_reverse(&mut self, addr: IpAddr, name: OwnedDName) {
        self.reverse.insert(addr, name);
    }
}


/// # Lookups
///
impl Hosts {
    /// Looks up the address of a host.
    pub fn lookup_host<N: AsRef<DNameSlice>>(&self, name: N) -> Option<IpAddr> {
        self._lookup_host(name.as_ref())
    }

    fn _lookup_host(&self, name: &DNameSlice) -> Option<IpAddr> {
        self.forward.get(name).map(|addr| addr.clone())
    }

    /// Looks up the hostname of an address.
    pub fn lookup_addr(&self, addr: &IpAddr) -> Option<&OwnedDName> {
        self.reverse.get(addr)
    }
}


/// # Parsing Hosts File
///
impl Hosts {
    /// Adds the hosts listed in a file.
    pub fn parse_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let mut file = try!(fs::File::open(path));
        self.parse(&mut file)
    }

    /// Reads hosts from a reader and adds them.
    ///
    /// The format is that of the /etc/hosts file.
    pub fn parse<R: io::Read>(&mut self, reader: &mut R) -> Result<()> {
        use std::io::BufRead;

        for line in io::BufReader::new(reader).lines() {
            let _ = self.parse_line(try!(line));
        }
        Ok(())
    }

    /// Parses a single line.
    ///
    /// Returns a result only so we can use `try!()`.
    fn parse_line(&mut self, line: String) -> Result<()> {
        let line: &str = match line.find('#') {
            Some(pos) => line.split_at(pos).0,
            None => &line
        };
        let line = line.trim();
        if line.is_empty() { return Ok(()) }
        let mut words = line.split_whitespace();

        let addr = try!(words.next().ok_or(Error::ParseError));
        let addr = try!(IpAddr::from_str(addr));

        let cname = try!(words.next().ok_or(Error::ParseError));
        let cname = try!(OwnedDName::from_str(cname));

        self.forward.insert(cname.clone(), addr.clone());
        self.reverse.insert(addr.clone(), cname);

        for name in words {
            let name = try!(OwnedDName::from_str(name));
            self.forward.insert(name, addr.clone());
        }
        Ok(())
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

impl convert::From<net::AddrParseError> for Error {
    fn from(_: net::AddrParseError) -> Error {
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



