//! Modelled roughly after `std::fmt::Display`

use core::fmt;
use std::string::String;

pub struct ZoneFileFormatter<'a> {
    buf: &'a mut (dyn fmt::Write + 'a),
}

/// Prints its field in a zonefile format when [`Display`](fmt::Display)ed
/// 
/// This type is typically constructed by calling [`ZoneFileFormat::zone_file`].
/// 
/// ```
/// use std::fmt::Write;
/// use domain::rdata::rfc1035::A;
/// use domain::base::iana::Class;
/// use domain::base::{Record, Ttl, Name};
/// use domain::zonefile::present::ZoneFileFormat;
/// use std::str::FromStr;
/// 
/// let name: Name<Vec<u8>> = Name::from_str("nlnetlabs.nl").unwrap();
/// let record = Record::new(
///     name,
///     Class::IN,
///     Ttl::from_secs(3600),
///     A::new("128.140.76.106".parse().unwrap()),
/// );
/// 
/// let mut s = String::new();
/// write!(s, "{}", record.display_zone_file());
/// assert_eq!(s, "nlnetlabs.nl. 3600 IN A 128.140.76.106")
/// ```
pub struct Display<'a, T: ?Sized>(&'a T);

impl<'a, T: ZoneFileFormat> fmt::Display for Display<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.write_presentation(f)
    }
}

/// Print as presentation (i.e. zonefile) format
/// 
/// This trait resembles the standard [`std::fmt::Display`] trait.
pub trait ZoneFileFormat {
    /// Write `self` to the `ZoneFileFormatter`
    fn present(&self, w: &mut ZoneFileFormatter) -> fmt::Result;

    fn write_presentation<W: fmt::Write>(&self, mut w: W) -> fmt::Result {
        let mut formatter = ZoneFileFormatter {
            buf: &mut w,
        };
        self.present(&mut formatter)
    }

    fn to_presentation_string(&self) -> String {
        let mut s = String::new();
        self.write_presentation(&mut s).unwrap();
        s
    }

    /// Wrap the value so that it will be displayed in zone file format
    fn display_zone_file(&self) -> Display<'_, Self> {
        Display(self)
    }
}

impl ZoneFileFormatter<'_> {
    pub fn format<P: ZoneFileFormat>(&mut self, item: &P) -> fmt::Result {
        item.present(self)
    }

    pub fn write_bytes(&mut self, b: &[u8]) -> fmt::Result {
        for byte in b {
            self.write_char(*byte as char)?;
        }
        Ok(())
    }

    pub fn write_str(&mut self, s: &str) -> fmt::Result {
        self.buf.write_str(s)
    }

    pub fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> fmt::Result {
        self.buf.write_fmt(args)
    }

    pub fn write_char(&mut self, c: char) -> fmt::Result {
        self.buf.write_char(c)
    }
}

impl fmt::Write for ZoneFileFormatter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.buf.write_str(s)
    }

    fn write_char(&mut self, c: char) -> fmt::Result {
        self.buf.write_char(c)
    }

    fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> fmt::Result {
        self.buf.write_fmt(args)
    }
}
