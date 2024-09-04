use core::fmt;

#[derive(Clone, Copy, Debug)]
pub struct Error;

impl From<fmt::Error> for Error {
    fn from(_: fmt::Error) -> Self {
        Self
    }
}

pub type Result = std::result::Result<(), Error>;

/// Show a value as zonefile format
pub trait Show {
    fn show(&self, p: &mut Presenter<'_>) -> Result;

    fn display_zonefile(&self) -> impl fmt::Display {
        struct ZoneFileDisplay<'a, T: ?Sized> {
            inner: &'a T,
        }

        impl<T: Show + ?Sized> fmt::Display for ZoneFileDisplay<'_, T> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.inner
                    .show(&mut Presenter {
                        writer: &mut SimplePresentationWriter::new(f),
                    })
                    .map_err(|_| fmt::Error)
            }
        }

        ZoneFileDisplay { inner: self }
    }
}

impl<T: Show> Show for &T {
    fn show(&self, p: &mut Presenter<'_>) -> Result {
        T::show(self, p)
    }
}

/// Determines how a zonefile is formatted
pub trait PresentationWriter {
    /// Push a token to the zonefile
    fn fmt_token(&mut self, args: std::fmt::Arguments<'_>) -> Result;

    /// Start a block of grouped tokens
    /// 
    /// This might push `'('` to the zonefile, but may be ignored by the
    /// `PresentationWriter`.
    fn begin_block(&mut self) -> Result;

    /// End a block of grouped tokens
    /// 
    /// This might push `'('` to the zonefile, but may be ignored by the
    /// `PresentationWriter`.
    fn end_block(&mut self) -> Result;

    /// Write a comment
    /// 
    /// This may be ignored.
    fn fmt_comment(&mut self, args: std::fmt::Arguments<'_>) -> Result;

    /// End the current record and start a new line
    fn newline(&mut self) -> Result;
}

/// The simplest possible zonefile writer
/// 
/// This writer does not do any alignment, comments and squeezes each record
/// onto a single line.
struct SimplePresentationWriter<'a> {
    first: bool,
    writer: &'a mut (dyn fmt::Write + 'a),
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
    fn fmt_token(&mut self, args: fmt::Arguments<'_>) -> Result {
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

    fn fmt_comment(&mut self, _args: fmt::Arguments<'_>) -> Result {
        Ok(())
    }

    fn newline(&mut self) -> Result {
        self.writer.write_char('\n')?;
        self.first = true;
        Ok(())
    }
}

/// A more structured wrapper around a [`PresentationWriter`]
/// 
/// Writing comments is not allowed with this type because comments can only
/// appear when a token is surrounded by parentheses.
pub struct Presenter<'a> {
    writer: &'a mut (dyn PresentationWriter + 'a),
}

impl<'a> Presenter<'a> {
    /// Start a sequence of grouped tokens
    /// 
    /// The block might be surrounded by `(` and `)` in a multiline format.
    pub fn block<'b>(&'b mut self) -> Block<'a, 'b> {
        let result = self.writer.begin_block();
        Block {
            presenter: self,
            result,
        }
    }

    /// Push a token
    pub fn write_token(&mut self, token: impl fmt::Display) -> Result {
        self.writer.fmt_token(format_args!("{token}"))
    }
}

#[must_use]
pub struct Block<'a, 'b> {
    presenter: &'b mut Presenter<'a>,
    result: Result,
}

impl<'a, 'b> Block<'a, 'b> {
    /// Push a token
    pub fn write_token(
        &mut self,
        token: impl std::fmt::Display,
    ) -> &mut Self {
        self.result =
            self.result.and_then(|_| self.presenter.write_token(token));
        self
    }

    /// Push the sequence of tokens generated by the [`Show`] implementation
    /// of the `token`
    pub fn write_show(&mut self, token: impl Show) -> &mut Self {
        self.result = self.result.and_then(|_| token.show(self.presenter));
        self
    }

    /// Write a comment
    /// 
    /// This may be ignored.
    pub fn write_comment(&mut self, s: impl fmt::Display) -> &mut Self {
        self.result = self.result.and_then(|_| {
            self.presenter.writer.fmt_comment(format_args!("{s}"))
        });
        self
    }

    /// Finish the block.
    /// 
    /// This _must_ be called before the `Block` is dropped.
    pub fn finish(&mut self) -> Result {
        self.result.and_then(|_| self.presenter.writer.end_block())
    }
}

#[cfg(all(test, feature = "std"))]
mod test {
    use std::string::ToString as _;
    use std::vec::Vec;

    use crate::base::iana::{Class, DigestAlg, SecAlg};
    use crate::base::show::Show;
    use crate::base::{Name, Record, Ttl};
    use crate::rdata::{Cds, Cname, Ds, Mx, Txt, A};

    fn create_record<Data>(data: Data) -> Record<&'static Name<[u8]>, Data> {
        let name = Name::from_slice(b"\x07example\x03com\x00").unwrap();
        Record::new(name, Class::IN, Ttl::from_secs(3600), data)
    }

    #[test]
    fn a_record() {
        let record = create_record(A::new("128.140.76.106".parse().unwrap()));
        assert_eq!(
            "example.com. 3600 IN A 128.140.76.106",
            record.display_zonefile().to_string()
        );
    }

    #[test]
    fn cname_record() {
        let record = create_record(Cname::new(
            Name::from_slice(b"\x07example\x03com\x00").unwrap(),
        ));
        assert_eq!(
            "example.com. 3600 IN CNAME example.com.",
            record.display_zonefile().to_string()
        );
    }

    #[test]
    fn ds_key_record() {
        let record = create_record(
            Ds::new(
                5414,
                SecAlg::ED25519,
                DigestAlg::SHA256,
                &[0xDE, 0xAD, 0xBE, 0xEF],
            )
            .unwrap(),
        );
        assert_eq!(
            "example.com. 3600 IN DS 5414 15 2 DEADBEEF",
            record.display_zonefile().to_string()
        );
    }

    #[test]
    fn cds_record() {
        let record = create_record(
            Cds::new(
                5414,
                SecAlg::ED25519,
                DigestAlg::SHA256,
                &[0xDE, 0xAD, 0xBE, 0xEF],
            )
            .unwrap(),
        );
        assert_eq!(
            "example.com. 3600 IN CDS 5414 15 2 DEADBEEF",
            record.display_zonefile().to_string()
        );
    }

    #[test]
    fn mx_record() {
        let record = create_record(Mx::new(
            20,
            Name::from_slice(b"\x07example\x03com\x00").unwrap(),
        ));
        assert_eq!(
            "example.com. 3600 IN MX 20 example.com.",
            record.display_zonefile().to_string()
        );
    }

    #[test]
    fn txt_record() {
        let record = create_record(Txt::<Vec<u8>>::build_from_slice(
            b"this is a string that is longer than 255 characters if I just \
            type a little bit more to pad this test out and then write some \
            more like a silly monkey with a typewriter accidentally writing \
            some shakespeare along the way but it feels like I have to type \
            even longer to hit that limit!\
        ").unwrap());
        assert_eq!(
            "example.com. 3600 IN TXT \
            \"this is a string that is longer than 255 characters if I just \
            type a little bit more to pad this test out and then write some \
            more like a silly monkey with a typewriter accidentally writing \
            some shakespeare along the way but it feels like I have to type \
            e\" \"ven longer to hit that limit!\"",
            record.display_zonefile().to_string()
        );
    }
}