use core::fmt;

#[derive(Clone, Copy, Debug)]
pub struct Error;

impl From<fmt::Error> for Error {
    fn from(_: fmt::Error) -> Self {
        Self
    }
}

pub type Result = core::result::Result<(), Error>;

pub enum DisplayKind {
    Simple,
    Tabbed,
    Multiline,
}

pub struct ZoneFileDisplay<'a, T: ?Sized> {
    inner: &'a T,
    kind: DisplayKind,
}

impl<T: ZonefileFmt + ?Sized> fmt::Display for ZoneFileDisplay<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            DisplayKind::Simple => self
                .inner
                .fmt(&mut SimpleWriter::new(f))
                .map_err(|_| fmt::Error),
            DisplayKind::Tabbed => self
                .inner
                .fmt(&mut TabbedWriter::new(f))
                .map_err(|_| fmt::Error),
            DisplayKind::Multiline => self
                .inner
                .fmt(&mut MultiLineWriter::new(f))
                .map_err(|_| fmt::Error),
        }
    }
}

/// Show a value as zonefile format
pub trait ZonefileFmt {
    /// Format the item as zonefile fmt into a [`fmt::Formatter`]
    ///
    /// This method is meant for use in a `fmt::Display` implementation.
    fn fmt(&self, p: &mut impl Formatter) -> Result;

    /// Display the item as a zonefile
    ///
    /// The returned object will be displayed as zonefile when printed or
    /// written using `fmt::Display`.
    fn display_zonefile(
        &self,
        display_kind: DisplayKind,
    ) -> ZoneFileDisplay<'_, Self> {
        ZoneFileDisplay {
            inner: self,
            kind: display_kind,
        }
    }
}

impl<T: ZonefileFmt> ZonefileFmt for &T {
    fn fmt(&self, p: &mut impl Formatter) -> Result {
        T::fmt(self, p)
    }
}

/// Determines how a zonefile is formatted
pub trait FormatWriter: Sized {
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
struct SimpleWriter<W> {
    first: bool,
    writer: W,
}

impl<W: fmt::Write> SimpleWriter<W> {
    fn new(writer: W) -> Self {
        Self {
            first: true,
            writer,
        }
    }
}

impl<W: fmt::Write> FormatWriter for SimpleWriter<W> {
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

/// A single line writer that puts tabs between ungrouped tokens
struct TabbedWriter<W> {
    first: bool,
    first_block: bool,
    blocks: usize,
    writer: W,
}

impl<W> TabbedWriter<W> {
    fn new(writer: W) -> Self {
        Self {
            first: true,
            first_block: true,
            blocks: 0,
            writer,
        }
    }
}

impl<W: fmt::Write> FormatWriter for TabbedWriter<W> {
    fn fmt_token(&mut self, args: fmt::Arguments<'_>) -> Result {
        if !self.first {
            let c = if self.blocks == 0 {
                '\t'
            } else if self.first_block {
                self.first_block = false;
                '\t'
            } else {
                ' '
            };
            self.writer.write_char(c)?;
        }
        self.first = false;
        self.first_block = false;
        self.writer.write_fmt(args)?;
        Ok(())
    }

    fn begin_block(&mut self) -> Result {
        self.blocks += 1;

        // If we enter the first level of blocks, we do 1 more tab
        if self.blocks == 1 {
            self.first_block = true;
        }

        Ok(())
    }

    fn end_block(&mut self) -> Result {
        self.blocks -= 1;
        Ok(())
    }

    fn fmt_comment(&mut self, _args: fmt::Arguments<'_>) -> Result {
        Ok(())
    }

    fn newline(&mut self) -> Result {
        self.writer.write_char('\n')?;
        self.first = true;
        self.first_block = true;

        debug_assert_eq!(self.blocks, 0);

        Ok(())
    }
}

struct MultiLineWriter<W> {
    current_column: usize,
    block_indent: Option<usize>,
    first: bool,
    writer: W,
}

impl<W> MultiLineWriter<W> {
    fn new(writer: W) -> Self {
        Self {
            first: true,
            current_column: 0,
            block_indent: None,
            writer,
        }
    }
}

impl<W: fmt::Write> FormatWriter for MultiLineWriter<W> {
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
            write!(self.writer, "\t; {}", args)?;
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

impl<W: fmt::Write> fmt::Write for MultiLineWriter<W> {
    fn write_str(&mut self, x: &str) -> fmt::Result {
        self.current_column += x.len();
        self.writer.write_str(x)
    }
}

/// A more structured wrapper around a [`PresentationWriter`]
pub trait Formatter: FormatWriter {
    /// Start a sequence of grouped tokens
    ///
    /// The block might be surrounded by `(` and `)` in a multiline format.
    fn block(&mut self, f: impl Fn(&mut Self) -> Result) -> Result {
        self.begin_block()?;
        f(self)?;
        self.end_block()
    }

    /// Push a token
    fn write_token(&mut self, token: impl fmt::Display) -> Result {
        self.fmt_token(format_args!("{token}"))
    }

    /// Call the `show` method on `item` with this `Presenter`
    fn write_show(&mut self, item: impl ZonefileFmt) -> Result {
        item.fmt(self)
    }

    /// Write a comment
    ///
    /// This may be ignored.
    fn write_comment(&mut self, s: impl fmt::Display) -> Result {
        self.fmt_comment(format_args!("{s}"))
    }
}

impl<T: FormatWriter> Formatter for T {}

#[cfg(all(test, feature = "std"))]
mod test {
    use std::string::ToString as _;
    use std::vec::Vec;

    use crate::base::iana::{Class, DigestAlgorithm, SecurityAlgorithm};
    use crate::base::zonefile_fmt::{DisplayKind, ZonefileFmt};
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
            record.display_zonefile(DisplayKind::Simple).to_string()
        );
    }

    #[test]
    fn cname_record() {
        let record = create_record(Cname::new(
            Name::from_slice(b"\x07example\x03com\x00").unwrap(),
        ));
        assert_eq!(
            "example.com. 3600 IN CNAME example.com.",
            record.display_zonefile(DisplayKind::Simple).to_string()
        );
    }

    #[test]
    fn ds_key_record() {
        let record = create_record(
            Ds::new(
                5414,
                SecurityAlgorithm::ED25519,
                DigestAlgorithm::SHA256,
                &[0xDE, 0xAD, 0xBE, 0xEF],
            )
            .unwrap(),
        );
        assert_eq!(
            "example.com. 3600 IN DS 5414 15 2 DEADBEEF",
            record.display_zonefile(DisplayKind::Simple).to_string()
        );
        assert_eq!(
            "example.com.\t3600\tIN\tDS\t5414 15 2 DEADBEEF",
            record.display_zonefile(DisplayKind::Tabbed).to_string()
        );
        assert_eq!(
            [
                "example.com. 3600 IN DS ( 5414\t; key tag",
                "                          15\t; algorithm: ED25519",
                "                          2\t; digest type: SHA-256",
                "                          DEADBEEF )",
            ]
            .join("\n"),
            record.display_zonefile(DisplayKind::Multiline).to_string()
        );
    }

    #[test]
    fn only_ds_data() {
        let rdata = Ds::new(
            5414,
            SecurityAlgorithm::ED25519,
            DigestAlgorithm::SHA256,
            &[0xDE, 0xAD, 0xBE, 0xEF],
        )
        .unwrap();

        // No tabs because it is a single block
        assert_eq!(
            "5414 15 2 DEADBEEF",
            rdata.display_zonefile(DisplayKind::Tabbed).to_string()
        );
    }

    #[test]
    fn cds_record() {
        let record = create_record(
            Cds::new(
                5414,
                SecurityAlgorithm::ED25519,
                DigestAlgorithm::SHA256,
                &[0xDE, 0xAD, 0xBE, 0xEF],
            )
            .unwrap(),
        );
        assert_eq!(
            "example.com. 3600 IN CDS 5414 15 2 DEADBEEF",
            record.display_zonefile(DisplayKind::Simple).to_string()
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
            record.display_zonefile(DisplayKind::Simple).to_string()
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
            record.display_zonefile(DisplayKind::Simple).to_string()
        );
    }

    #[test]
    fn hinfo_record() {
        use crate::rdata::Hinfo;
        let record = create_record(Hinfo::<Vec<u8>>::new(
            "Windows".parse().unwrap(),
            "Windows Server".parse().unwrap(),
        ));
        assert_eq!(
            "example.com. 3600 IN HINFO \"Windows\" \"Windows Server\"",
            record.display_zonefile(DisplayKind::Simple).to_string()
        );
    }

    #[test]
    fn naptr_record() {
        use crate::rdata::Naptr;
        let record = create_record(Naptr::<Vec<u8>, &Name<[u8]>>::new(
            100,
            50,
            "a".parse().unwrap(),
            "z3950+N2L+N2C".parse().unwrap(),
            r#"!^urn:cid:.+@([^\\.]+\\.)(.*)$!\\2!i"#.parse().unwrap(),
            Name::from_slice(b"\x09cidserver\x07example\x03com\x00").unwrap(),
        ));
        assert_eq!(
            r#"example.com. 3600 IN NAPTR 100 50 "a" "z3950+N2L+N2C" "!^urn:cid:.+@([^\\.]+\\.)(.*)$!\\2!i" cidserver.example.com."#,
            record.display_zonefile(DisplayKind::Simple).to_string()
        );
    }

    #[test]
    fn tabbed() {
        let record = create_record(
            Cds::new(
                5414,
                SecurityAlgorithm::ED25519,
                DigestAlgorithm::SHA256,
                &[0xDE, 0xAD, 0xBE, 0xEF],
            )
            .unwrap(),
        );

        // The name, ttl, class and rtype should be separated by \t, but the
        // rdata shouldn't.
        assert_eq!(
            "example.com.\t3600\tIN\tCDS\t5414 15 2 DEADBEEF",
            record.display_zonefile(DisplayKind::Tabbed).to_string()
        );
    }

    #[test]
    fn caa_record() {
        use crate::rdata::Caa;
        let record = create_record(Caa::new(
            0,
            "issue".parse().unwrap(),
            "ca.example.net".as_bytes().to_vec(),
        ));
        assert_eq!(
            "example.com. 3600 IN CAA 0 issue \"ca.example.net\"",
            record.display_zonefile(DisplayKind::Simple).to_string()
        );
    }
}
