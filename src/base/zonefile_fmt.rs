use core::fmt;

#[derive(Clone, Copy, Debug)]
pub struct Error;

impl From<fmt::Error> for Error {
    fn from(_: fmt::Error) -> Self {
        Self
    }
}

pub type Result = core::result::Result<(), Error>;

pub struct ZoneFileDisplay<'a, T: ?Sized> {
    inner: &'a T,
    pretty: bool,
}

impl<T: ZonefileFmt + ?Sized> fmt::Display for ZoneFileDisplay<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.pretty {
            self.inner
                .show(&mut Presenter {
                    writer: &mut MultiLineWriter::new(f),
                })
                .map_err(|_| fmt::Error)
        } else {
            self.inner
                .show(&mut Presenter {
                    writer: &mut SimpleWriter::new(f),
                })
                .map_err(|_| fmt::Error)
        }
    }
}

/// Show a value as zonefile format
pub trait ZonefileFmt {
    fn show(&self, p: &mut Presenter<'_>) -> Result;

    fn display_zonefile(&self, pretty: bool) -> ZoneFileDisplay<'_, Self> {
        ZoneFileDisplay {
            inner: self,
            pretty,
        }
    }
}

impl<T: ZonefileFmt> ZonefileFmt for &T {
    fn show(&self, p: &mut Presenter<'_>) -> Result {
        T::show(self, p)
    }
}

/// Determines how a zonefile is formatted
pub trait PresentationWriter {
    /// Push a token to the zonefile
    fn fmt_token(&mut self, args: fmt::Arguments<'_>) -> Result;

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
    fn fmt_comment(&mut self, args: fmt::Arguments<'_>) -> Result;

    /// End the current record and start a new line
    fn newline(&mut self) -> Result;
}

/// The simplest possible zonefile writer
///
/// This writer does not do any alignment, comments and squeezes each record
/// onto a single line.
struct SimpleWriter<'a> {
    first: bool,
    writer: &'a mut (dyn fmt::Write + 'a),
}

impl<'a> SimpleWriter<'a> {
    fn new(writer: &'a mut dyn fmt::Write) -> Self {
        Self {
            first: true,
            writer,
        }
    }
}

impl PresentationWriter for SimpleWriter<'_> {
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

struct MultiLineWriter<'a> {
    current_column: usize,
    block_indent: Option<usize>,
    first: bool,
    writer: &'a mut (dyn fmt::Write + 'a),
}

impl<'a> MultiLineWriter<'a> {
    fn new(writer: &'a mut dyn fmt::Write) -> Self {
        Self {
            first: true,
            current_column: 0,
            block_indent: None,
            writer,
        }
    }
}

impl PresentationWriter for MultiLineWriter<'_> {
    fn fmt_token(&mut self, args: fmt::Arguments<'_>) -> Result {
        use fmt::Write;
        if !self.first {
            self.write_str(" ")?;
        }
        self.first = false;
        self.write_fmt(args)?;
        Ok(())
    }

    fn begin_block(&mut self) -> Result {
        self.fmt_token(format_args!("("))?;
        self.block_indent = Some(self.current_column + 1);
        Ok(())
    }

    fn end_block(&mut self) -> Result {
        self.block_indent = None;
        self.fmt_token(format_args!(")"))
    }

    fn fmt_comment(&mut self, args: fmt::Arguments<'_>) -> Result {
        if self.block_indent.is_some() {
            self.writer.write_fmt(format_args!("\t; {}", args))?;
            self.newline()
        } else {
            // a comment should not have been allowed
            // so ignore it
            Ok(())
        }
    }

    fn newline(&mut self) -> Result {
        use fmt::Write;
        self.writer.write_char('\n')?;
        self.current_column = 0;
        if let Some(x) = self.block_indent {
            for _ in 0..x {
                self.write_str(" ")?;
            }
        }
        self.first = true;
        Ok(())
    }
}

impl fmt::Write for MultiLineWriter<'_> {
    fn write_str(&mut self, x: &str) -> fmt::Result {
        self.current_column += x.len();
        self.writer.write_str(x)
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
    pub fn block(&mut self, f: impl Fn(&mut Self) -> Result) -> Result {
        self.writer.begin_block()?;
        f(self)?;
        self.writer.end_block()
    }

    /// Push a token
    pub fn write_token(&mut self, token: impl fmt::Display) -> Result {
        self.writer.fmt_token(format_args!("{token}"))
    }

    /// Call the `show` method on `item` with this `Presenter`
    pub fn write_show(&mut self, item: impl ZonefileFmt) -> Result {
        item.show(self)
    }

    /// Write a comment
    ///
    /// This may be ignored.
    pub fn write_comment(&mut self, s: impl fmt::Display) -> Result {
        self.writer.fmt_comment(format_args!("{s}"))
    }
}

#[cfg(all(test, feature = "std"))]
mod test {
    use std::string::ToString as _;
    use std::vec::Vec;

    use crate::base::iana::{Class, DigestAlg, SecAlg};
    use crate::base::zonefile_fmt::ZonefileFmt;
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
            record.display_zonefile(false).to_string()
        );
    }

    #[test]
    fn cname_record() {
        let record = create_record(Cname::new(
            Name::from_slice(b"\x07example\x03com\x00").unwrap(),
        ));
        assert_eq!(
            "example.com. 3600 IN CNAME example.com.",
            record.display_zonefile(false).to_string()
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
            record.display_zonefile(false).to_string()
        );
        assert_eq!(
            [
                "example.com. 3600 IN DS ( 5414\t; key tag",
                "                          15\t; algorithm: 15(ED25519)",
                "                          2\t; digest type: 2(SHA-256)",
                "                          DEADBEEF )",
            ]
            .join("\n"),
            record.display_zonefile(true).to_string()
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
            record.display_zonefile(false).to_string()
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
            record.display_zonefile(false).to_string()
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
            record.display_zonefile(false).to_string()
        );
    }
}
