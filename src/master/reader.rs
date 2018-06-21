
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use ::bits::name::Dname;
use ::iana::Class;
use super::entry::{Entry, MasterRecord};
use super::scan::{CharSource, Pos, ScanError, Scanner};
use super::source::Utf8File;


pub struct Reader<C: CharSource> {
    scanner: Option<Scanner<C>>,
    ttl: Option<u32>,
    last: Option<(Dname, Class)>,
}

impl<C: CharSource> Reader<C> {
    pub fn new(source: C) -> Self {
        Reader {
            scanner: Some(Scanner::new(source)),
            ttl: None,
            last: None
        }
    }
}

impl Reader<Utf8File> {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, io::Error> {
        Utf8File::open(path).map(Self::new)
    }
}

impl<C: CharSource> Reader<C> {
    #[allow(match_same_arms)]
    pub fn next_record(&mut self) -> Result<Option<ReaderItem>, ScanError> {
        loop {
            match self.next_entry() {
                Ok(Some(Entry::Origin(origin))) => self.set_origin(origin),
                Ok(Some(Entry::Include{ path, origin })) => {
                    return Ok(Some(ReaderItem::Include { path, origin }))
                }
                Ok(Some(Entry::Ttl(ttl))) => self.ttl = Some(ttl),
                Ok(Some(Entry::Control{ name, start })) => {
                    return Ok(Some(ReaderItem::Control { name, start }))
                }
                Ok(Some(Entry::Record(record))) => {
                    self.last = Some((record.owner().clone(),
                                      record.class()));
                    return Ok(Some(ReaderItem::Record(record)))
                }
                Ok(Some(Entry::Blank)) => { }
                Ok(None) => return Ok(None),
                Err(err) => {
                    self.scanner = None;
                    return Err(err)
                }
            }
        }
    }

    fn next_entry(&mut self) -> Result<Option<Entry>, ScanError> {
        // The borrow checker doesn’t like a ref mut of self.scanner and a
        // ref of self.last at the same time, unless created at the same
        // time. Some shenenigans are necessary to get that done.
        let (scanner, owner, class) = match (&mut self.scanner, &self.last) {
            (&mut Some(ref mut scanner), &Some((ref owner, class))) => {
                (scanner, Some(owner), Some(class))
            }
            (&mut Some(ref mut scanner), _) => {
                (scanner, None, None)
            }
            (&mut None, _) => {
                return Ok(None)
            }
        };
        Entry::scan(scanner, owner, class, self.ttl)
    }

    fn set_origin(&mut self, origin: Dname) {
        if let Some(ref mut scanner) = self.scanner {
            scanner.set_origin(Some(origin))
        }
    }
}

impl<C: CharSource> Iterator for Reader<C> {
    type Item = Result<ReaderItem, ScanError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_record() {
            Ok(Some(res)) => Some(Ok(res)),
            Ok(None) => None,
            Err(err) => Some(Err(err))
        }
    }
}


#[derive(Clone, Debug)]
pub enum ReaderItem {
    Record(MasterRecord),
    Include { path: PathBuf, origin: Option<Dname> },
    Control { name: String, start: Pos },
}

impl fmt::Display for ReaderItem {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ReaderItem::Record(ref record) => write!(f, "{}", record),
            ReaderItem::Include { ref path, ref origin } => {
                try!(write!(f, "$INCLUDE {}", path.display()));
                if let Some(ref origin) = *origin {
                    try!(write!(f, " {}", origin));
                }
                Ok(())
            }
            ReaderItem::Control { ref name, .. } => {
                write!(f, "{}", name)
            }
        }
    }
}


//============ Test ==========================================================

#[cfg(test)]
mod test {
    use super::*;
    use ::master::scan::ScanError;

    #[test]
    fn print() {
        let reader = Reader::new(&"$ORIGIN ISI.EDU.
$TTL 86400
@   IN  SOA     VENERA      Action\\.domains (
                                 20     ; SERIAL
                                 7200   ; REFRESH
                                 600    ; RETRY
                                 3600000; EXPIRE
                                 60)    ; MINIMUM

        NS      A.ISI.EDU.
        NS      VENERA
        NS      VAXA
        MX      10      VENERA
        MX      20      VAXA
   
A       A       26.3.0.103

VENERA  A       10.1.0.52
        A       128.9.0.32

VAXA    A       10.2.0.27
        A       128.9.0.33


$INCLUDE <SUBSYS>ISI-MAILBOXES.TXT"[..]);

        for item in reader {
            match item {
                Ok(item) => println!("{}", item),
                Err(ScanError::Syntax(err, pos)) => {
                    panic!("{}:{}:  {:?}", pos.line(), pos.col(), err);
                }
                Err(err) => panic!("{:?}", err)
            }
        }
    }
}

