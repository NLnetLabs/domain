//! Decoding for common binary-to-text formats.

#[cfg(feature = "std")]
use std::vec::Vec;

//----------- Base16Dec ------------------------------------------------------

/// A Base16 decoder.
#[derive(Default)]
pub struct Base16Dec {
    /// Carry-over bytes.
    carry: [u8; 2],
}

impl Base16Dec {
    /// Prepare for Base16 decoding.
    pub const fn new() -> Self {
        Self { carry: [0; 2] }
    }

    /// The necessary buffer size for decoded Base16 content.
    ///
    /// This returns the minimum size of the destination buffer for a call to
    /// [`decode()`], accounting for any carry-over data currently saved.
    ///
    /// [`decode()`]: Self::decode()
    pub const fn decoded_len(&self, encoded_len: usize) -> usize {
        (self.carry[1] as usize + encoded_len) / 2
    }

    /// Decode some bytes into Base16.
    ///
    /// A partial byte, if any, will be saved for a future call to
    /// [`decode()`] -- or [`finish()`] if there is no more data left.
    ///
    /// [`decode()`]: Self::decode()
    /// [`finish()`]: Self::finish()
    ///
    /// # Panics
    ///
    /// Panics if `decoded` is too small to fit the decoded data; call
    /// [`decoded_len()`] to determine how big it should be.
    ///
    /// [`decoded_len()`]: Self::decoded_len()
    pub fn decode<'e>(
        &mut self,
        mut encoded: &[u8],
        decoded: &'e mut [u8],
    ) -> Result<&'e [u8], DecodeError> {
        assert!(decoded.len() >= self.decoded_len(encoded.len()));

        if self.decoded_len(encoded.len()) == 0 {
            // We're not expecting to write any bytes.
            // Append any encoded bytes to the carry and stop.

            let off = self.carry[1] as usize;
            self.carry[off..][..encoded.len()].copy_from_slice(encoded);
            self.carry[1] += encoded.len() as u8;
            return Ok(&[]);
        }

        // The offset into 'decoded'.
        let mut dec = 0;

        // Empty the carry first.
        if self.carry[1] != 0 {
            let off = self.carry[1] as usize;
            self.carry[off..].copy_from_slice(&encoded[..2 - off]);
            decoded[dec] = Self::decode_block(self.carry)?;
            self.carry.fill(0);
            encoded = &encoded[2 - off..];
            dec += 1;
        }

        // Process as many blocks from 'encoded' as possible.
        // TODO (feature(array_chunks)): Use 'slice::array_chunks()'.
        let mut chunks = encoded.chunks_exact(2);
        for chunk in &mut chunks {
            let chunk: [u8; 2] = chunk.try_into().unwrap();
            decoded[dec] = Self::decode_block(chunk)?;
            dec += 1;
        }

        // Save any leftover carry.
        let leftover = chunks.remainder().len();
        self.carry[..leftover].copy_from_slice(chunks.remainder());
        self.carry[1] = leftover as u8;

        Ok(&decoded[..dec])
    }

    /// Decode bytes into a [`Vec`].
    #[cfg(feature = "std")]
    pub fn decode_to_vec<'e>(
        &mut self,
        mut encoded: &[u8],
        decoded: &'e mut Vec<u8>,
    ) -> Result<&'e [u8], DecodeError> {
        if self.decoded_len(encoded.len()) == 0 {
            // We're not expecting to write any bytes.
            // Append any encoded bytes to the carry and stop.

            let off = self.carry[1] as usize;
            self.carry[off..][..encoded.len()].copy_from_slice(encoded);
            self.carry[1] += encoded.len() as u8;
            return Ok(&[]);
        }

        // The start of the decoded data.
        let start = decoded.len();

        // Empty the carry first.
        if self.carry[1] != 0 {
            let off = self.carry[1] as usize;
            self.carry[off..].copy_from_slice(&encoded[..2 - off]);
            decoded.push(Self::decode_block(self.carry)?);
            self.carry.fill(0);

            encoded = &encoded[2 - off..];
        }

        // Process as many blocks from 'encoded' as possible.
        // TODO (feature(array_chunks)): Use 'slice::array_chunks()'.
        let mut chunks = encoded.chunks_exact(2);
        for chunk in &mut chunks {
            let chunk: [u8; 2] = chunk.try_into().unwrap();
            decoded.push(Self::decode_block(chunk)?);
        }

        // Save any leftover carry.
        let leftover = chunks.remainder().len();
        self.carry[..leftover].copy_from_slice(chunks.remainder());
        self.carry[1] = leftover as u8;

        Ok(&decoded[start..])
    }

    /// Finish decoding any leftover data.
    pub fn finish(&mut self) -> Result<(), DecodeError> {
        if self.carry[1] == 0 {
            Ok(())
        } else {
            Err(DecodeError)
        }
    }

    /// Decode a single block of data.
    fn decode_block(mut encoded: [u8; 2]) -> Result<u8, DecodeError> {
        // Decode each character.
        for c in &mut encoded {
            *c = match *c {
                b'0'..=b'9' => *c - b'0',
                b'A'..=b'F' => *c - b'A' + 10,
                b'a'..=b'f' => *c - b'a' + 10,
                _ => return Err(DecodeError),
            }
        }

        Ok((encoded[0] << 4) + encoded[1])
    }
}

impl Base16Dec {
    pub fn all_decoded_len(encoded_len: usize) -> usize {
        encoded_len / 2
    }

    /// Decode all the given data statelessly.
    pub fn decode_all<'e>(
        encoded: &[u8],
        decoded: &'e mut [u8],
    ) -> Result<&'e [u8], DecodeError> {
        assert!(decoded.len() >= Self::all_decoded_len(encoded.len()));

        let mut this = Self::new();
        let mut dec = 0;
        dec += this.decode(encoded, decoded)?.len();
        this.finish()?;

        Ok(&decoded[..dec])
    }

    /// Decode all the given data statelessly into a [`Vec`].
    #[cfg(feature = "std")]
    pub fn decode_all_to_vec<'e>(
        encoded: &[u8],
        decoded: &'e mut Vec<u8>,
    ) -> Result<&'e [u8], DecodeError> {
        let mut this = Self::new();
        let start = decoded.len();
        this.decode_to_vec(encoded, decoded)?;
        this.finish()?;

        Ok(&decoded[start..])
    }
}

//----------- impl_base_dec --------------------------------------------------

/// Define a decoder for a Base32-like format.
macro_rules! impl_base_dec {
    (
        $(#[$attr:meta])*
        $vis:vis struct $name:ident;
    ) => {
        $(#[$attr])*
        $vis struct $name {
            /// Carry-over bytes.
            carry: [u8; Self::ENCODED_BLOCK_SIZE],
        }

        impl $name {
            /// Initialize a new encoder.
            pub const fn new() -> Self {
                Self { carry: [0; Self::ENCODED_BLOCK_SIZE] }
            }
        }

        impl $name {
            /// The amount of carry.
            const fn carry(&self) -> usize {
                self.carry[Self::ENCODED_BLOCK_SIZE - 1] as usize
            }
        }

        impl $name {
            /// The minimum buffer size for calling [`decode()`].
            ///
            /// [`decode()`] must be called with a destination buffer that is
            /// at least as big as the returned size (in bytes).
            ///
            /// [`decode()`]: Self::decode()
            pub const fn decoded_len(&self, encoded_len: usize) -> usize {
                let encoded = self.carry() + encoded_len;
                let blocks = encoded / Self::ENCODED_BLOCK_SIZE;
                blocks * Self::DECODED_BLOCK_SIZE
            }

            /// Decode some bytes.
            ///
            /// A partial block of encoded bytes, if any, will be saved and
            /// used for a later call to [`decode()`] or [`finish()`].
            ///
            /// # Panics
            ///
            /// Panics if `decoded` is too small to fit the decoded data; call
            /// [`decoded_len()`] to determine how big it should be.
            ///
            /// [`decode()`]: Self::decode()
            /// [`finish()`]: Self::finish()
            /// [`decoded_len()`]: Self::decoded_len()
            pub fn decode<'e>(
                &mut self,
                mut encoded: &[u8],
                decoded: &'e mut [u8],
            ) -> Result<&'e [u8], DecodeError> {
                let output_len = self.decoded_len(encoded.len());
                assert!(decoded.len() >= output_len);

                if output_len == 0 {
                    // We're not expecting to write any bytes.
                    // Append any encoded bytes to the carry and stop.

                    let off = self.carry();
                    let carry = &mut self.carry[off..];
                    carry[..encoded.len()].copy_from_slice(encoded);
                    carry[Self::ENCODED_BLOCK_SIZE - 1]
                        += encoded.len() as u8;
                    return Ok(&[]);
                }

                // The offset to write in `decoded` at.
                let mut dec = 0;

                // Empty the carry first.
                if self.carry() != 0 {
                    let off = self.carry();
                    let carry = &mut self.carry[off..];
                    let remaining = carry.len();

                    carry.copy_from_slice(&encoded[..remaining]);
                    dec += decoded[dec..]
                        .iter_mut()
                        .zip(Self::decode_block(self.carry)?)
                        .map(|(d, b)| *d = b)
                        .count();

                    self.carry.fill(0);
                    encoded = &encoded[remaining..];
                }

                // Process as many blocks from 'encoded' as possible.
                // TODO (feature(array_chunks)): Use 'slice::array_chunks()'.
                let mut input = encoded
                    .chunks_exact(Self::ENCODED_BLOCK_SIZE);
                for block in &mut input {
                    let block = block.try_into().unwrap();
                    dec += decoded[dec..]
                        .iter_mut()
                        .zip(Self::decode_block(block)?)
                        .map(|(d, b)| *d = b)
                        .count();
                }

                // Save any leftover carry.
                let leftover = input.remainder().len();
                self.carry[..leftover].copy_from_slice(input.remainder());
                self.carry[Self::ENCODED_BLOCK_SIZE - 1] = leftover as u8;

                Ok(&decoded[..dec])
            }

            /// Decode bytes into a [`Vec`].
            ///
            /// The bytes will be decoded and appended to the [`Vec`].  The
            /// appended bytes will be returned as a string.  A partial block
            /// of encoded bytes, if any, will be saved and used for a later
            /// call to [`decode()`] or [`finish()`].
            ///
            /// [`decode()`]: Self::decode()
            /// [`finish()`]: Self::finish()
            #[cfg(feature = "std")]
            pub fn decode_to_vec<'e>(
                &mut self,
                mut encoded: &[u8],
                decoded: &'e mut Vec<u8>,
            ) -> Result<&'e [u8], DecodeError> {
                if self.decoded_len(encoded.len()) == 0 {
                    // We're not expecting to write any bytes.
                    // Append any encoded bytes to the carry and stop.

                    let off = self.carry();
                    let carry = &mut self.carry[off..];
                    carry[..encoded.len()].copy_from_slice(encoded);
                    carry[Self::ENCODED_BLOCK_SIZE - 1]
                        += encoded.len() as u8;
                    return Ok(&[]);
                }

                // The start of the decoded data.
                let start = decoded.len();

                // Empty the carry first.
                if self.carry() != 0 {
                    let off = self.carry();
                    let carry = &mut self.carry[off..];
                    let remaining = carry.len();

                    carry.copy_from_slice(&encoded[..remaining]);
                    decoded.extend(Self::decode_block(self.carry)?);

                    self.carry.fill(0);
                    encoded = &encoded[remaining..];
                }

                // Process as many blocks from 'encoded' as possible.
                // TODO (feature(array_chunks)): Use 'slice::array_chunks()'.
                let mut input = encoded
                    .chunks_exact(Self::ENCODED_BLOCK_SIZE);
                for chunk in &mut input {
                    let chunk = chunk.try_into().unwrap();
                    decoded.extend(Self::decode_block(chunk)?);
                }

                // Save any leftover carry.
                let leftover = input.remainder().len();
                self.carry[..leftover].copy_from_slice(input.remainder());
                self.carry[Self::ENCODED_BLOCK_SIZE - 1] = leftover as u8;

                Ok(&decoded[start..])
            }

            /// The minimum buffer size for calling [`finish()`].
            ///
            /// [`finish()`] must be called with a destination buffer that is
            /// at least as big as the returned size (in bytes).
            ///
            /// [`finish()`]: Self::finish()
            pub fn finished_len(&self, partial: bool) -> usize {
                if partial {
                    (self.carry() * Self::DECODED_BLOCK_SIZE)
                        / Self::ENCODED_BLOCK_SIZE
                } else {
                    0
                }
            }

            /// Finish decoding.
            ///
            /// If some encoded bytes were left over from previous calls to
            /// [`decode()`], and partial decoding is allowed, they will be
            /// decoded and written to the given slice.
            ///
            /// # Panics
            ///
            /// Panics if `decoded` is too small to fit the decoded data; call
            /// [`finished_len()`] to determine how big it should be.
            ///
            /// [`decode()`]: Self::decode()
            /// [`finished_len()`]: Self::finished_len()
            pub fn finish<'e>(
                &mut self,
                decoded: &'e mut [u8],
                partial: bool,
            ) -> Result<&'e [u8], DecodeError> {
                let output_len = self.finished_len(partial);
                assert!(decoded.len() >= output_len);
                let decoded = &mut decoded[..output_len];

                if self.carry() == 0 {
                    return Ok(&[]);
                } else if !partial {
                    return Err(DecodeError);
                }

                let len = self.carry();
                self.carry[len..].fill(Self::PADDING);
                decoded.iter_mut()
                    .zip(Self::decode_block(self.carry)?)
                    .for_each(|(d, b)| *d = b);
                self.carry.fill(0);

                Ok(decoded)
            }

            /// Finish decoding.
            ///
            /// If some encoded bytes were left over from previous calls to
            /// [`decode()`], they will be decoded (and possibly padded) and
            /// appended to the given [`Vec`].
            ///
            /// [`decode()`]: Self::decode()
            #[cfg(feature = "std")]
            pub fn finish_to_vec<'e>(
                &mut self,
                decoded: &'e mut Vec<u8>,
                partial: bool,
            ) -> Result<&'e [u8], DecodeError> {
                let start = decoded.len();

                if self.carry() == 0 {
                    return Ok(&[]);
                } else if !partial {
                    return Err(DecodeError);
                }

                let len = self.carry();
                self.carry[len..].fill(Self::PADDING);
                decoded.extend(Self::decode_block(self.carry)?);
                self.carry.fill(0);

                // Write padding if necessary.
                Ok(&decoded[start..])
            }
        }

        impl $name {
            /// The minimum buffer size for calling [`decode_all()`].
            ///
            /// [`decode_all()`] must be called with a destination buffer that
            /// is at least as big as the returned size (in bytes).
            ///
            /// [`decode_all()`]: Self::decode_all()
            pub fn all_decoded_len(
                encoded_len: usize,
                partial: bool,
            ) -> usize {
                if partial {
                    (encoded_len * Self::DECODED_BLOCK_SIZE)
                        .div_ceil(Self::ENCODED_BLOCK_SIZE)
                } else {
                    (encoded_len / Self::ENCODED_BLOCK_SIZE)
                        * Self::DECODED_BLOCK_SIZE
                }
            }

            /// Decode bytes statelessly.
            ///
            /// This is a convenidece function for calling [`decode()`] and
            /// [`finish()`] with a single slice of input.
            ///
            /// # Panics
            ///
            /// Panics if `decoded` is too small to fit the decoded data; call
            /// [`all_decoded_len()`] to determine how big it should be.
            ///
            /// [`decode()`]: Self::decode()
            /// [`finish()`]: Self::finish()
            /// [`all_decoded_len()`]: Self::all_decoded_len()
            pub fn decode_all<'e>(
                encoded: &[u8],
                decoded: &'e mut [u8],
                partial: bool,
            ) -> Result<&'e [u8], DecodeError> {
                let len = Self::all_decoded_len(encoded.len(), partial);
                assert!(decoded.len() >= len);

                let mut this = Self::new();
                let mut dec = 0;
                dec += this.decode(encoded, decoded)?.len();
                dec += this.finish(&mut decoded[dec..], partial)?.len();

                Ok(&decoded[..dec])
            }

            /// Decode bytes into a [`Vec`] statelessly.
            ///
            /// This is a convenidece function for calling [`decode_to_vec()`]
            /// and [`finish_to_vec()`] with a single slice of input.
            ///
            /// [`decode_to_vec()`]: Self::decode_to_vec()
            /// [`finish_to_vec()`]: Self::finish_to_vec()
            #[cfg(feature = "std")]
            pub fn decode_all_to_vec<'e>(
                encoded: &[u8],
                decoded: &'e mut Vec<u8>,
                partial: bool,
            ) -> Result<&'e [u8], DecodeError> {
                let start = decoded.len();

                let mut this = Self::new();
                this.decode_to_vec(encoded, decoded)?;
                this.finish_to_vec(decoded, partial)?;

                Ok(&decoded[start..])
            }
        }
    };
}

//----------- Base32Dec ------------------------------------------------------

impl_base_dec! {
    /// A Base32 decoder.
    #[derive(Default)]
    pub struct Base32Dec;
}

impl Base32Dec {
    /// The size of a decoded block.
    const DECODED_BLOCK_SIZE: usize = 5;

    /// The size of an encoded block.
    const ENCODED_BLOCK_SIZE: usize = 8;

    /// An encoded padding character.
    const PADDING: u8 = b'=';

    /// Decode a single block of data.
    fn decode_block(
        mut encoded: [u8; 8],
    ) -> Result<impl ExactSizeIterator<Item = u8>, DecodeError> {
        // Check for padding.
        let non_padding = encoded
            .iter()
            .position(|&c| c == b'=')
            .unwrap_or(encoded.len());
        let len = match non_padding {
            8 => 5,
            7 => 4,
            5 => 3,
            4 => 2,
            2 => 1,
            _ => return Err(DecodeError),
        };

        // Check for mixed padding and non-padding characters.
        if encoded[non_padding..].iter().any(|&c| c != b'=') {
            return Err(DecodeError);
        }

        // Overwrite the padding characters to encoded zeros.
        encoded[non_padding..].fill(b'A');

        // Decode each character.
        for c in &mut encoded {
            *c = match *c {
                b'A'..=b'Z' => *c - b'A',
                b'a'..=b'z' => *c - b'a',
                b'2'..=b'7' => *c - b'2' + 26,
                _ => return Err(DecodeError),
            }
        }

        // Use 64-bit arithmetic to rearrange the bits efficiently.
        let mut block = u64::from_be_bytes(encoded);
        // 000X XXXX 000X XXXX 000X XXXX 000X XXXX
        // 000X XXXX 000X XXXX 000X XXXX 000X XXXX
        block = ((block & 0x1F00_1F00_1F00_1F00) >> 3)
            | (block & 0x001F_001F_001F_001F);
        // 0000 00XX XXXX XXXX 0000 00XX XXXX XXXX
        // 0000 00XX XXXX XXXX 0000 00XX XXXX XXXX
        block = ((block & 0x03FF0000_03FF0000) >> 6)
            | (block & 0x000003FF_000003FF);
        // 0000 0000 0000 XXXX XXXX XXXX XXXX XXXX
        // 0000 0000 0000 XXXX XXXX XXXX XXXX XXXX
        block = ((block & 0x000FFFFF00000000) >> 12)
            | (block & 0x00000000000FFFFF);
        // 0000 0000 0000 0000 0000 0000 XXXX XXXX
        // XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX
        let block = (block << 24).to_be_bytes();
        Ok(block.into_iter().take(len))
    }
}

//----------- Base32Dec ------------------------------------------------------

impl_base_dec! {
    /// A Base32 decoder using the `base32hex` alphabet.
    #[derive(Default)]
    pub struct Base32HexDec;
}

impl Base32HexDec {
    /// The size of a decoded block.
    const DECODED_BLOCK_SIZE: usize = 5;

    /// The size of an encoded block.
    const ENCODED_BLOCK_SIZE: usize = 8;

    /// An encoded padding character.
    const PADDING: u8 = b'=';

    /// Decode a single block of data.
    fn decode_block(
        mut encoded: [u8; 8],
    ) -> Result<impl ExactSizeIterator<Item = u8>, DecodeError> {
        // Check for padding.
        let non_padding = encoded
            .iter()
            .position(|&c| c == b'=')
            .unwrap_or(encoded.len());
        let len = match non_padding {
            8 => 5,
            7 => 4,
            5 => 3,
            4 => 2,
            2 => 1,
            _ => return Err(DecodeError),
        };

        // Check for mixed padding and non-padding characters.
        if encoded[non_padding..].iter().any(|&c| c != b'=') {
            return Err(DecodeError);
        }

        // Overwrite the padding characters to encoded zeros.
        encoded[non_padding..].fill(b'0');

        // Decode each character.
        for c in &mut encoded {
            *c = match *c {
                b'0'..=b'9' => *c - b'0',
                b'A'..=b'V' => *c - b'A' + 10,
                b'a'..=b'v' => *c - b'a' + 10,
                _ => return Err(DecodeError),
            }
        }

        // Use 64-bit arithmetic to rearrange the bits efficiently.
        let mut block = u64::from_be_bytes(encoded);
        // 000X XXXX 000X XXXX 000X XXXX 000X XXXX
        // 000X XXXX 000X XXXX 000X XXXX 000X XXXX
        block = ((block & 0x1F00_1F00_1F00_1F00) >> 3)
            | (block & 0x001F_001F_001F_001F);
        // 0000 00XX XXXX XXXX 0000 00XX XXXX XXXX
        // 0000 00XX XXXX XXXX 0000 00XX XXXX XXXX
        block = ((block & 0x03FF0000_03FF0000) >> 6)
            | (block & 0x000003FF_000003FF);
        // 0000 0000 0000 XXXX XXXX XXXX XXXX XXXX
        // 0000 0000 0000 XXXX XXXX XXXX XXXX XXXX
        block = ((block & 0x000FFFFF00000000) >> 12)
            | (block & 0x00000000000FFFFF);
        // 0000 0000 0000 0000 0000 0000 XXXX XXXX
        // XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX
        let block = (block << 24).to_be_bytes();
        Ok(block.into_iter().take(len))
    }
}

//----------- Base64Dec ------------------------------------------------------

impl_base_dec! {
    /// A Base64 decoder.
    #[derive(Default)]
    pub struct Base64Dec;
}

impl Base64Dec {
    /// The size of a decoded block.
    const DECODED_BLOCK_SIZE: usize = 3;

    /// The size of an encoded block.
    const ENCODED_BLOCK_SIZE: usize = 4;

    /// An encoded padding character.
    const PADDING: u8 = b'=';

    /// Decode a single block of data.
    fn decode_block(
        mut encoded: [u8; 4],
    ) -> Result<impl ExactSizeIterator<Item = u8>, DecodeError> {
        // Check for padding.
        let len = match encoded {
            [_, _, b'=', b'='] => {
                encoded[2..].fill(b'A');
                1
            }
            [_, _, _, b'='] => {
                encoded[3..].fill(b'A');
                2
            }
            _ => 3,
        };

        // Decode each character.
        for c in &mut encoded {
            *c = match *c {
                b'A'..=b'Z' => *c - b'A',
                b'a'..=b'z' => *c - b'a' + 26,
                b'0'..=b'9' => *c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => return Err(DecodeError),
            }
        }

        // Use 32-bit arithmetic to rearrange the bits efficiently.
        let mut block = u32::from_be_bytes(encoded);
        // 00XX XXXX 00XX XXXX 00XX XXXX 00XX XXXX
        block = ((block & 0x3F003F00) >> 2) | (block & 0x003F003F);
        // 0000 XXXX XXXX XXXX 0000 XXXX XXXX XXXX
        block = ((block & 0x0FFF0000) >> 4) | (block & 0x00000FFF);
        // 0000 0000 XXXX XXXX XXXX XXXX XXXX XXXX
        let block = (block << 8).to_be_bytes();
        Ok(block.into_iter().take(len))
    }
}

//----------- DecodeError ----------------------------------------------------

/// An error when decoding Base32/Base64/etc.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeError;

//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use super::{Base16Dec, Base32Dec, Base32HexDec, Base64Dec};

    #[test]
    fn base16() {
        const CASES: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "66"),
            (b"fo", "666F"),
            (b"foo", "666F6F"),
            (b"foob", "666F6F62"),
            (b"fooba", "666F6F6261"),
            (b"foobar", "666F6F626172"),
        ];

        for &(output, input) in CASES {
            let mut buffer = [0u8; 12];
            assert_eq!(
                Base16Dec::decode_all(input.as_bytes(), &mut buffer),
                Ok(output)
            );
        }
    }

    #[test]
    fn base32() {
        const CASES: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "MY======"),
            (b"fo", "MZXQ===="),
            (b"foo", "MZXW6==="),
            (b"foo\n", "MZXW6CQ="),
            (b"foo\nb", "MZXW6CTC"),
            (b"foo\nba", "MZXW6CTCME======"),
            (b"foo\nbar", "MZXW6CTCMFZA===="),
        ];

        for &(output, input) in CASES {
            let mut buffer = [0u8; 16];
            assert_eq!(
                Base32Dec::decode_all(input.as_bytes(), &mut buffer, false),
                Ok(output)
            );
            assert_eq!(
                Base32Dec::decode_all(input.as_bytes(), &mut buffer, true),
                Ok(output)
            );
            assert_eq!(
                Base32Dec::decode_all(
                    input.trim_end_matches('=').as_bytes(),
                    &mut buffer,
                    true
                ),
                Ok(output)
            );
        }
    }

    #[test]
    fn base32hex() {
        const CASES: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "CO======"),
            (b"fo", "CPNG===="),
            (b"foo", "CPNMU==="),
            (b"foo\n", "CPNMU2G="),
            (b"foo\nb", "CPNMU2J2"),
            (b"foo\nba", "CPNMU2J2C4======"),
            (b"foo\nbar", "CPNMU2J2C5P0===="),
        ];

        for &(output, input) in CASES {
            let mut buffer = [0u8; 16];
            assert_eq!(
                Base32HexDec::decode_all(
                    input.as_bytes(),
                    &mut buffer,
                    false
                ),
                Ok(output)
            );
            assert_eq!(
                Base32HexDec::decode_all(input.as_bytes(), &mut buffer, true),
                Ok(output)
            );
            assert_eq!(
                Base32HexDec::decode_all(
                    input.trim_end_matches('=').as_bytes(),
                    &mut buffer,
                    true
                ),
                Ok(output)
            );
        }
    }

    #[test]
    fn base64() {
        const CASES: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"fo~", "Zm9+"),
            (b"fo~b", "Zm9+Yg=="),
            (b"fo~ba", "Zm9+YmE="),
            (b"fo~ba\xFF", "Zm9+YmH/"),
        ];

        for &(output, input) in CASES {
            let mut buffer = [0u8; 12];
            assert_eq!(
                Base64Dec::decode_all(input.as_bytes(), &mut buffer, false),
                Ok(output)
            );
            assert_eq!(
                Base64Dec::decode_all(input.as_bytes(), &mut buffer, true),
                Ok(output)
            );
            assert_eq!(
                Base64Dec::decode_all(
                    input.trim_end_matches('=').as_bytes(),
                    &mut buffer,
                    true
                ),
                Ok(output)
            );
        }
    }
}
