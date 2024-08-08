//! Configuring and running NSD.

use std::fs::File;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::string::String;
use std::vec::Vec;
use std::{fmt, io};

use bytes::Bytes;
use domain::utils::base64;

//------------ Config --------------------------------------------------------

/// NSD configuration.
///
/// This type contains a subset of the options available in NSD’s
/// configuration file. In order to configure an NSD instance, you create and
/// manipulate a value of this type and, once you are happy with it, save if
/// to disk via the `save` method.
///
/// Note that we include here whatever we need for our tests. This isn’t meant
/// as a complete NSD configuration generator at all. That said, feel free to
/// add new options if you do need them. Remember to also add them to the
/// `write` method which writes out the actual config data.
#[derive(Clone, Debug, Default)]
pub struct Config {
    pub ip_address: Vec<SocketAddr>,
    pub port: Option<u16>,
    pub database: Option<PathBuf>,
    pub zonelistfile: Option<PathBuf>,
    pub logfile: Option<PathBuf>,
    pub pidfile: Option<PathBuf>,
    pub username: Option<String>,
    pub zonesdir: Option<PathBuf>,
    pub xfrdfile: Option<PathBuf>,
    pub xfrdir: Option<PathBuf>,
    pub verbosity: Option<u8>,

    pub zones: Vec<ZoneConfig>,
    pub keys: Vec<KeyConfig>,
}

impl Config {
    /// Creates a configuration that keeps all NSD data in a directory.
    pub fn all_in<P: AsRef<Path>>(path: P) -> Self {
        let path = path.as_ref();
        Config {
            database: Some(path.join("nsd.nsd")),
            zonelistfile: Some(path.join("zone.list")),
            pidfile: Some(path.join("nsd.pid")),
            username: Some("\"\"".into()),
            zonesdir: Some(path.into()),
            xfrdfile: Some(path.join("nsd.xfrd.state")),
            xfrdir: Some(path.into()),
            ..Default::default()
        }
    }

    /// Writes the configuration to a file.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), io::Error> {
        let mut file = File::create(path)?;
        self.write(&mut file)
    }

    /// Writes the configuration to something writable.
    pub fn write<W: io::Write>(
        &self,
        target: &mut W,
    ) -> Result<(), io::Error> {
        // server: clause
        writeln!(target, "server:")?;
        for addr in &self.ip_address {
            writeln!(target, "    ip-address: {}@{}", addr.ip(), addr.port())?
        }
        if let Some(port) = self.port {
            writeln!(target, "    port: {}", port)?
        }
        if let Some(path) = self.database.as_ref() {
            writeln!(target, "    database: {}", path.display())?
        }
        if let Some(path) = self.zonelistfile.as_ref() {
            writeln!(target, "    zonelistfile: {}", path.display())?
        }
        if let Some(path) = self.logfile.as_ref() {
            writeln!(target, "    logfile: {}", path.display())?
        }
        if let Some(path) = self.pidfile.as_ref() {
            writeln!(target, "    pidfile: {}", path.display())?
        }
        if let Some(name) = self.username.as_ref() {
            writeln!(target, "    username: {}", name)?
        }
        if let Some(path) = self.zonesdir.as_ref() {
            writeln!(target, "    zonesdir: {}", path.display())?
        }
        if let Some(path) = self.xfrdfile.as_ref() {
            writeln!(target, "    xfrdfile: {}", path.display())?
        }
        if let Some(path) = self.xfrdir.as_ref() {
            writeln!(target, "    xfrdir: {}", path.display())?
        }
        if let Some(value) = self.verbosity {
            writeln!(target, "    verbosity: {}", value)?
        }

        // zone: clauses
        for zone in &self.zones {
            zone.write(target)?
        }

        // key: clauses
        for key in &self.keys {
            key.write(target)?
        }

        Ok(())
    }
}

//------------ KeyConfig -----------------------------------------------------

/// A single `key:` clause fo the NSD configuration.
#[derive(Clone, Debug, Default)]
pub struct KeyConfig {
    pub name: String,
    pub algorithm: String,
    pub secret: Bytes,
}

impl KeyConfig {
    pub fn new<S: Into<String>, V: Into<Bytes>>(
        name: S,
        algorithm: S,
        secret: V,
    ) -> Self {
        KeyConfig {
            name: name.into(),
            algorithm: algorithm.into(),
            secret: secret.into(),
        }
    }

    pub fn write<W: io::Write>(
        &self,
        target: &mut W,
    ) -> Result<(), io::Error> {
        writeln!(target, "key:")?;
        writeln!(target, "    name: {}", self.name)?;
        writeln!(target, "    algorithm: {}", self.algorithm)?;
        let mut secret = String::new();
        base64::display(&self.secret, &mut secret).unwrap();
        writeln!(target, "    secret: {}", secret)?;
        Ok(())
    }
}

//------------ ZoneConfig ----------------------------------------------------

/// A single `zone:` clause of the NSD configuration.
#[derive(Clone, Debug, Default)]
pub struct ZoneConfig {
    pub name: String,
    pub zonefile: PathBuf,
    pub provide_xfr: Vec<Acl>,
}

impl ZoneConfig {
    pub fn new<S: Into<String>, P: Into<PathBuf>>(
        name: S,
        zonefile: P,
        provide_xfr: Vec<Acl>,
    ) -> Self {
        ZoneConfig {
            name: name.into(),
            zonefile: zonefile.into(),
            provide_xfr,
        }
    }

    pub fn write<W: io::Write>(
        &self,
        target: &mut W,
    ) -> Result<(), io::Error> {
        writeln!(target, "zone:")?;
        writeln!(target, "    name: {}", self.name)?;
        writeln!(target, "    zonefile: {}", self.zonefile.display())?;
        for acl in &self.provide_xfr {
            writeln!(target, "    provide-xfr: {}", acl)?;
        }
        writeln!(target, "remote-control:\n    control-enable: no")?;
        Ok(())
    }
}

//------------ Acl -----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Acl {
    /// The IP address
    pub ip_addr: IpAddr,

    /// Optional prefix length for `ip_addr`.
    pub ip_net: Option<u8>,

    /// Optional remote port.
    pub ip_port: Option<u16>,

    /// Name of TSIG key.
    key: Option<String>,
}

impl Acl {
    pub fn new(
        ip_addr: IpAddr,
        ip_net: Option<u8>,
        ip_port: Option<u16>,
        key: Option<String>,
    ) -> Self {
        Acl {
            ip_addr,
            ip_net,
            ip_port,
            key,
        }
    }
}

impl fmt::Display for Acl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.ip_addr)?;
        if let Some(net) = self.ip_net {
            write!(f, "/{}", net)?;
        }
        if let Some(port) = self.ip_port {
            write!(f, "@{}", port)?;
        }
        match self.key {
            Some(ref key) => write!(f, " {}", key)?,
            None => write!(f, " NOKEY")?,
        }
        Ok(())
    }
}
