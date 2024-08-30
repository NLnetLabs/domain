//! Modelled roughly after `std::fmt::Display`

use core::fmt::{self, Write};
use std::string::String;

pub struct ZoneFileFormatter<'a> {
    buf: &'a mut (dyn Write + 'a),
}

pub struct Error;

/// Print as presentation format
pub trait Present {
    fn present(&self, w: &mut ZoneFileFormatter) -> fmt::Result;

    fn write_presentation<W: Write>(&self, mut w: W) -> fmt::Result {
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
}

impl ZoneFileFormatter<'_> {
    pub fn format<P: Present>(&mut self, item: &P) -> fmt::Result {
        item.present(self)
    }

    pub fn write_bytes(&mut self, b: &[u8]) -> fmt::Result {
        for byte in b {
            self.write_char(*byte as char)?;
        }
        Ok(())
    }
}

impl Write for ZoneFileFormatter<'_> {
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
