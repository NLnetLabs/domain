
use std::fmt;
use std::fs::File;
use std::io;
use std::path::Path;
use std::rc::Rc;
use ::bits::name::DNameBuf;
use ::iana::Class;
use ::master::entry::Entry;
use ::master::error::ScanResult;
use ::master::record::MasterRecord;
use ::master::scanner::Scanner;


pub struct Reader<S: Scanner> {
    scanner: Option<S>,
    origin: Option<Rc<DNameBuf>>,
    ttl: Option<u32>,
    last: Option<(Rc<DNameBuf>, Class)>,
}

/*
impl<R: io::Read> Reader<R> {
    pub fn new(reader: R) -> Self {
        Reader {
            stream: Some(Stream::new(reader)),
            origin: None,
            ttl: None,
            last: None
        }
    }
}

impl Reader<File> {
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        Ok(Reader::new(try!(File::open(path))))
    }
}

impl<T: AsRef<[u8]>> Reader<io::Cursor<T>> {
    pub fn create(t: T) -> Self {
        Reader::new(io::Cursor::new(t))
    }
}
*/

impl<S: Scanner> Reader<S> {
    fn last_owner(&self) -> Option<Rc<DNameBuf>> {
        match &self.last {
            &Some((ref name, _)) => Some(name.clone()),
            &None => None
        }
    }

    fn last_class(&self) -> Option<Class> {
        match &self.last {
            &Some((_, class)) => Some(class),
            &None => None
        }
    }

    fn next_entry(&mut self) -> ScanResult<Option<Entry>> {
        let last_owner = self.last_owner();
        let last_class = self.last_class();
        if let Some(ref mut scanner) = self.scanner {
            Entry::scan(scanner, last_owner, last_class, &self.origin,
                        self.ttl)
        }
        else {
            Ok(None)
        }
    }

    pub fn next_record(&mut self) -> ScanResult<Option<ReaderItem>> {
        loop {
            match self.next_entry() {
                Ok(Some(Entry::Origin(origin))) => self.origin = Some(origin),
                Ok(Some(Entry::Include{path, origin})) => {
                    return Ok(Some(ReaderItem::Include { path: path,
                                                         origin: origin }))
                }
                Ok(Some(Entry::Ttl(ttl))) => self.ttl = Some(ttl),
                Ok(Some(Entry::Control{..})) => { },
                Ok(Some(Entry::Record(record))) => {
                    self.last = Some((record.owner.clone(), record.class));
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
}

impl<S: Scanner> Iterator for Reader<S> {
    type Item = ScanResult<ReaderItem>;

    fn next(&mut self) -> Option<ScanResult<ReaderItem>> {
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
    Include { path: Vec<u8>, origin: Option<Rc<DNameBuf>> }
}

impl fmt::Display for ReaderItem {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ReaderItem::Record(ref record) => write!(f, "{}", record),
            ReaderItem::Include{ref path, ref origin} => {
                try!(write!(f, "$INCLUDE {}", String::from_utf8_lossy(path)));
                if let Some(ref origin) = *origin {
                    try!(write!(f, " {}", origin));
                }
                Ok(())
            }
        }
    }
}


//============ Test ==========================================================

#[cfg(test)]
mod test {
    use super::*;
    use ::master::error::Error;

    #[test]
    fn print() {
        let reader = Reader::create(&b"$ORIGIN ISI.EDU.
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
                Err(Error::Syntax(err, pos)) => {
                    println!("{}:{}:  {:?}", pos.line(), pos.col(), err);
                }
                Err(err) => println!("{:?}", err)
            }
        }
    }
}

