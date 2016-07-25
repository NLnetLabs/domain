
use std::io;
use std::rc::Rc;
use ::bits::name::DNameBuf;
use ::iana::Class;
use ::master::entry::Entry;
use ::master::error::Result;
use ::master::record::MasterRecord;
use ::master::stream::Stream;


pub struct Reader<R: io::Read> {
    stream: Stream<R>,
    origin: Option<Rc<DNameBuf>>,
    ttl: Option<u32>,
    last: Option<(Rc<DNameBuf>, Class)>,
}

impl<R: io::Read> Reader<R> {
    pub fn new(reader: R) -> Self {
        Reader {
            stream: Stream::new(reader),
            origin: None,
            ttl: None,
            last: None
        }
    }

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

    pub fn next_record(&mut self) -> Result<Option<ReaderItem>> {
        loop {
            let last_owner = self.last_owner();
            let last_class = self.last_class();
            match try!(Entry::scan(&mut self.stream, last_owner,
                                   last_class, &self.origin, self.ttl)) {
                Some(Entry::Origin(origin)) => self.origin = Some(origin),
                Some(Entry::Include{path, origin}) => {
                    return Ok(Some(ReaderItem::Include { path: path,
                                                         origin: origin }))
                }
                Some(Entry::Ttl(ttl)) => self.ttl = Some(ttl),
                Some(Entry::Control{..}) => { },
                Some(Entry::Record(record)) => {
                    return Ok(Some(ReaderItem::Record(record)))
                }
                None => return Ok(None)
            }
        }
     }
}

impl<R: io::Read> Iterator for Reader<R> {
    type Item = Result<ReaderItem>;

    fn next(&mut self) -> Option<Result<ReaderItem>> {
        match self.next_record() {
            Ok(Some(res)) => Some(Ok(res)),
            Ok(None) => None,
            Err(err) => Some(Err(err))
        }
    }
}


pub enum ReaderItem {
    Record(MasterRecord),
    Include { path: Vec<u8>, origin: Option<Rc<DNameBuf>> }
}
