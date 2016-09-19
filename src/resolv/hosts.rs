//! Static host table.
//!
//! This module implements `Hosts` representing the static host table
//! commonly stored in `/etc/hosts`.

use std::collections::HashMap;
use std::convert;
use std::error;
use std::fmt;
use std::fs;
use std::io;
use std::net::{self, IpAddr};
use std::path::Path;
use std::slice;
use std::str::FromStr;
use std::result;
use bits::FromStrError;
use bits::name::{DNameSlice, DNameBuf};


//------------ Hosts --------------------------------------------------------

/// A type for the static host table.
///
/// The static host table maps host names to IP addresses. It is used to
/// either give names to addresses that do not appear in DNS or to overide
/// address information from DNS.
///
/// The type implements two lookup functions: `lookup_host()` takes a host
/// name and returns an iterator over the IP addresses assigned to it, and
/// `lookup_addr()` takes an IP address and returns an iterator over the
/// host names for that address.
///
/// You can create an empty host map to start with using `Hosts::new()`,
/// create one by parsing a hosts file with `Hosts::parse()` or
/// `Hosts::parse_file()`, or start with the system’s configure map by
/// calling `Hosts::default()`.
///
/// You then can add entries using `add_forward()` and `add_reverse()`. Note
/// that these calls don’t have to add matching information but rather
/// the forward (host name to address) and reverse (address to host name)
/// are independent.
#[derive(Clone, Debug, Default)]
pub struct Hosts {
    forward: HashMap<DNameBuf, Vec<IpAddr>>,
    reverse: HashMap<IpAddr, Vec<DNameBuf>>,
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
    pub fn add_forward(&mut self, name: &DNameBuf, addr: IpAddr) {
        if let Some(ref mut vec) = self.forward.get_mut(name) {
            vec.push(addr);
            return;
        }
        
        self.forward.insert(name.clone(), vec!(addr));
    }

    /// Adds an IP to host mapping.
    pub fn add_reverse(&mut self, addr: IpAddr, name: DNameBuf) {
        if let Some(ref mut vec) = self.reverse.get_mut(&addr) {
            vec.push(name);
            return;
        }

        self.reverse.insert(addr, vec!(name));
    }
}


/// # Lookups
///
impl Hosts {
    /// Looks up the address of a host.
    pub fn lookup_host<N: AsRef<DNameSlice>>(&self, name: N)
                                             -> Option<slice::Iter<IpAddr>> {
        self._lookup_host(name.as_ref())
    }

    fn _lookup_host(&self, name: &DNameSlice) -> Option<slice::Iter<IpAddr>> {
        self.forward.get(name).map(|vec| vec.iter())
    }

    /// Looks up the hostname of an address.
    pub fn lookup_addr(&self, addr: IpAddr) -> Option<slice::Iter<DNameBuf>> {
        self.reverse.get(&addr).map(|vec| vec.iter())
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
        let cname = try!(DNameBuf::from_str(cname));

        self.add_forward(&cname, addr);
        self.add_reverse(addr, cname);

        for name in words {
            let name = try!(DNameBuf::from_str(name));
            self.add_forward(&name, addr);
        }
        Ok(())
    }
}


//------------ Error and Result ---------------------------------------------

/// An error happend during parsing a hosts file.
#[derive(Debug)]
pub enum Error {
    /// The host file is kaputt.
    ParseError,

    /// Reading failed.
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



