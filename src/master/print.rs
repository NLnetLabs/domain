//! Master file printing.

use std::io;
use std::ascii::AsciiExt;
use std::io::Write;
use std::net::Ipv4Addr;


//------------ Printer -------------------------------------------------------

pub struct Printer<W: io::Write> {
    writer: W,
}

impl<W: io::Write> Printer<W> {
    pub fn item(&mut self) -> Result<PrintItem<W>, io::Error> {
        self.writer.write_all(b" ")?;
        Ok(PrintItem { printer: self })
    }

    pub fn end_entry(&mut self) -> Result<(), io::Error> {
        self.writer.write_all(b"\n")
    }
}


//------------ PrintItem -----------------------------------------------------

pub struct PrintItem<'a, W: io::Write + 'a> {
    printer: &'a mut Printer<W>,
}

impl<'a, W: io::Write + 'a> PrintItem<'a, W> {
    pub fn print_byte(&mut self, byte: u8) -> Result<(), io::Error> {
        match byte {
            b'.' | b'"' | b';' => write!(self, "\\{}", byte),
            ch if ch.is_ascii() => write!(self, "{}", ch),
            ch => write!(self, "{:03x}", ch),
        }
    }
}


impl<'a, W: io::Write + 'a> io::Write for PrintItem<'a, W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        self.printer.writer.write(buf)
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        self.printer.writer.flush()
    }
}


//------------ Print ---------------------------------------------------------

pub trait Print {
    fn print<W: io::Write>(&self, printer: &mut Printer<W>)
                           -> Result<(), io::Error>;
}

impl Print for u8 {
    fn print<W: io::Write>(&self, printer: &mut Printer<W>)
                           -> Result<(), io::Error> {
        write!(printer.item()?, "{}", self)
    }
}

impl Print for u16 {
    fn print<W: io::Write>(&self, printer: &mut Printer<W>)
                           -> Result<(), io::Error> {
        write!(printer.item()?, "{}", self)
    }
}

impl Print for u32 {
    fn print<W: io::Write>(&self, printer: &mut Printer<W>)
                           -> Result<(), io::Error> {
        write!(printer.item()?, "{}", self)
    }
}

impl Print for Ipv4Addr {
    fn print<W: io::Write>(&self, printer: &mut Printer<W>)
                           -> Result<(), io::Error> {
        write!(printer.item()?, "{}", self)
    }
}
