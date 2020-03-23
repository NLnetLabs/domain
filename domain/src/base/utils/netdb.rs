//! The network database.
//!
//! This module provides a placeholder implementation for some of the
//! functions included in POSIX’s (?) network database.
//!
//! For the moment, implementations here are functional in the sense that
//! they simulate an empty database. Since we are only using this for
//! parsing WKS records for the moment, this seems to be a reasonably
//! shortcut.
//!
//! Furthermore, if this gets implemented for real, it should be considered
//! whether giving out clones of the entities is really necessary.


//------------ ProtoEnt -----------------------------------------------------

pub struct ProtoEnt {
    pub name: String,
    pub aliases: Vec<String>,
    pub proto: u8,
}

impl ProtoEnt {
    pub fn by_name(name: &str) -> Option<Self> {
        let _ = name;
        None
    }

    pub fn by_number(number: u8) -> Option<Self> {
        let _ = number;
        None
    }

    pub fn iter() -> ProtoIter {
        ProtoIter
    }
}


//------------ ProtoIter ----------------------------------------------------

pub struct ProtoIter;

impl Iterator for ProtoIter {
    type Item = ProtoEnt;

    fn next(&mut self) -> Option<ProtoEnt> {
        None
    }
}
    

//------------ ServEnt ------------------------------------------------------

pub struct ServEnt {
    pub name: String,
    pub aliases: Vec<String>,
    pub port: u16,
    pub proto: String
}

impl ServEnt {
    pub fn by_name(name: &str) -> Option<Self> {
        let _ = name;
        None
    }

    pub fn by_port(port: u16) -> Option<Self> {
        let _ = port;
        None
    }

    pub fn iter() -> ServIter {
        ServIter
    }
}


//------------ ServIter ------------------------------------------------------

pub struct ServIter;

impl Iterator for ServIter {
    type Item = ServEnt;

    fn next(&mut self) -> Option<ServEnt> {
        None
    }
}

