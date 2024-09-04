//! Modelled roughly after `std::fmt::Display`

use core::fmt;

#[derive(Clone, Copy, Debug)]
pub struct Error;

impl From<std::fmt::Error> for Error {
    fn from(value: std::fmt::Error) -> Self {
        Self
    }
}

pub type Result = std::result::Result<(), Error>;

pub trait Show {
    fn show(&self, p: &mut Presenter<'_>) -> Result;

    fn display_zonefile(&self) -> impl fmt::Display {
        struct ZoneFileDisplay<'a, T: ?Sized> {
            inner: &'a T,
        }

        impl<T: Show + ?Sized> fmt::Display for ZoneFileDisplay<'_, T> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.inner.show(&mut Presenter {
                    writer: &mut SimplePresentationWriter::new(f)
                }).map_err(|_| fmt::Error)
            }
        }

        ZoneFileDisplay {
            inner: self
        }
    }
}

impl<T: Show> Show for &T {
    fn show(&self, p: &mut Presenter<'_>) -> Result {
        T::show(self, p)
    }
} 

pub trait PresentationWriter {
    fn fmt_token(&mut self, args: std::fmt::Arguments<'_>) -> Result;
    fn begin_block(&mut self) -> Result;
    fn end_block(&mut self) -> Result;
    fn fmt_comment(&mut self, args: std::fmt::Arguments<'_>) -> Result;
    fn newline(&mut self) -> Result;
}

struct SimplePresentationWriter<'a> {
    first: bool,
    writer: &'a mut (dyn std::fmt::Write + 'a),
}

impl<'a> SimplePresentationWriter<'a> {
    fn new(writer: &'a mut dyn fmt::Write) -> Self {
        Self {
            first: true,
            writer,
        }
    }
}

impl PresentationWriter for SimplePresentationWriter<'_> {
    fn fmt_token(&mut self, args: std::fmt::Arguments<'_>) -> Result {
        if !self.first {
            self.writer.write_char(' ')?;
        }
        self.first = false;
        self.writer.write_fmt(args)?;
        Ok(())
    }

    fn begin_block(&mut self) -> Result {
        Ok(())
    }

    fn end_block(&mut self) -> Result {
        Ok(())
    }

    fn fmt_comment(&mut self, _args: std::fmt::Arguments<'_>) -> Result {
        Ok(())
    }

    fn newline(&mut self) -> Result {
        self.writer.write_char('\n');
        self.first = true;
        Ok(())
    }
}

pub struct Presenter<'a> {
    writer: &'a mut (dyn PresentationWriter + 'a),
}

impl<'a> Presenter<'a> {
    pub fn block<'b>(&'b mut self) -> Block<'a, 'b> {
        let result = self.writer.begin_block();
        Block {
            presenter: self,
            result,
        }
    }

    pub fn write_token(&mut self, token: impl std::fmt::Display) -> Result {
        self.writer.fmt_token(format_args!("{token}"))
    }
}

#[must_use]
pub struct Block<'a, 'b> {
    presenter: &'b mut Presenter<'a>,
    result: Result,
}

impl<'a, 'b> Block<'a, 'b> {
    pub fn write_token(&mut self, token: impl std::fmt::Display) -> &mut Self {
        self.result = self
            .result
            .and_then(|_| self.presenter.write_token(token));
        self
    }

    pub fn write_show(&mut self, token: impl Show) -> &mut Self {
        self.result = self
            .result
            .and_then(|_| token.show(self.presenter));
        self
    }

    pub fn write_comment(&mut self, s: impl std::fmt::Display) -> &mut Self {
        self.result = self
            .result
            .and_then(|_| self.presenter.writer.fmt_comment(format_args!("{s}")));
        self
    }

    pub fn finish(&mut self) -> Result {
        self.result.and_then(|_| self.presenter.writer.end_block())
    }
}

#[cfg(test)]
mod test {
    use crate::base::show::Show;
    use crate::base::{Record, Name, Ttl};
    use crate::rdata::A;
    use crate::base::iana::Class;

    #[test]
    fn a_record() {
        let name = Name::from_slice(b"\x07example\x03com\x00").unwrap();
        let record = Record::new(
            name,
            Class::IN,
            Ttl::from_secs(3600),
            A::new("128.140.76.106".parse().unwrap()),
        );
        eprintln!("{}", record.display_zonefile());
        panic!()
    }
}