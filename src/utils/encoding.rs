//! Encoding for common binary-to-text formats.

#[cfg(feature = "std")]
use std::vec::Vec;

//----------- Base16Enc ------------------------------------------------------

/// A Base16 encoder.
#[derive(Default)]
pub struct Base16Enc;

impl Base16Enc {
    /// Prepare for Base16 encoding.
    pub const fn new() -> Self {
        Self
    }

    /// The necessary buffer size for encoded Base16 content.
    ///
    /// This returns the minimum size of the destination buffer for a call to
    /// [`encode()`], accounting for any carry-over data currently saved.
    ///
    /// [`encode()`]: Self::encode()
    pub const fn encoded_len(&self, decoded_len: usize) -> usize {
        decoded_len * 2
    }

    /// Encode some bytes into Base16.
    ///
    /// Only whole blocks (groups of 2 characters) will be output.
    ///
    /// # Panics
    ///
    /// Panics if `encoded` is too small to fit the encoded data; call
    /// [`encoded_len()`] to determine how big it should be.
    ///
    /// [`encoded_len()`]: Self::encoded_len()
    pub fn encode<'e>(
        &mut self,
        decoded: &[u8],
        encoded: &'e mut [u8],
    ) -> &'e str {
        assert!(encoded.len() >= self.encoded_len(decoded.len()));

        // The offset into 'encoded'.
        let mut enc = 0;

        // Process as many blocks from 'decoded' as possible.
        for &byte in decoded {
            encoded[enc..][..2].copy_from_slice(&Self::encode_block(byte));
            enc += 2;
        }

        // SAFETY: 'encode_block()' only outputs ASCII characters, and the
        // first 'enc' bytes of 'encoded' have been written with them.
        unsafe { core::str::from_utf8_unchecked(&encoded[..enc]) }
    }

    /// Encode bytes into a [`Vec`].
    #[cfg(feature = "std")]
    pub fn encode_to_vec<'e>(
        &mut self,
        decoded: &[u8],
        encoded: &'e mut Vec<u8>,
    ) -> &'e str {
        // The start of the encoded data.
        let start = encoded.len();

        // Process as many blocks from 'decoded' as possible.
        for &byte in decoded {
            encoded.extend_from_slice(&Self::encode_block(byte));
        }

        // SAFETY: 'encode_block()' only outputs ASCII characters, and the
        // first 'enc' bytes of 'encoded' have been written with them.
        unsafe { core::str::from_utf8_unchecked(&encoded[start..]) }
    }

    /// Encode a single block of data.
    fn encode_block(decoded: u8) -> [u8; 2] {
        let block = [decoded >> 4, decoded & 15];
        block.map(|c| match c {
            0..=9 => b'0' + c,
            10..=15 => b'A' + c - 10,
            _ => unreachable!(),
        })
    }
}

//----------- impl_base_enc --------------------------------------------------

/// Define an encoder for a Base32-like format.
macro_rules! impl_base_enc {
    (
        $(#[$attr:meta])*
        $vis:vis struct $name:ident;
    ) => {
        $(#[$attr])*
        $vis struct $name {
            /// Carry-over bytes.
            carry: [u8; Self::DECODED_BLOCK_SIZE],
        }

        impl $name {
            /// Initialize a new encoder.
            pub const fn new() -> Self {
                Self { carry: [0; Self::DECODED_BLOCK_SIZE] }
            }
        }

        impl $name {
            /// The amount of carry.
            const fn carry(&self) -> usize {
                self.carry[Self::DECODED_BLOCK_SIZE - 1] as usize
            }
        }

        impl $name {
            /// The minimum buffer size for calling [`encode()`].
            ///
            /// [`encode()`] must be called with a destination buffer that is
            /// at least as big as the returned size (in bytes).
            ///
            /// [`encode()`]: Self::encode()
            pub const fn encoded_len(&self, decoded_len: usize) -> usize {
                let decoded = self.carry() + decoded_len;
                let blocks = decoded / Self::DECODED_BLOCK_SIZE;
                blocks * Self::ENCODED_BLOCK_SIZE
            }

            /// Encode some bytes.
            ///
            /// A partial block of decoded bytes, if any, will be saved and
            /// used for a later call to [`encode()`] or [`finish()`].
            ///
            /// # Panics
            ///
            /// Panics if `encoded` is too small to fit the encoded data; call
            /// [`encoded_len()`] to determine how big it should be.
            ///
            /// [`encode()`]: Self::encode()
            /// [`finish()`]: Self::finish()
            /// [`encoded_len()`]: Self::encoded_len()
            pub fn encode<'e>(
                &mut self,
                mut decoded: &[u8],
                encoded: &'e mut [u8],
            ) -> &'e str {
                let output_len = self.encoded_len(decoded.len());
                assert!(encoded.len() >= output_len);

                if output_len == 0 {
                    // We're not expecting to write any bytes.
                    // Append any decoded bytes to the carry and stop.

                    let off = self.carry();
                    let carry = &mut self.carry[off..];
                    carry[..decoded.len()].copy_from_slice(decoded);
                    carry[Self::DECODED_BLOCK_SIZE - 1]
                        += decoded.len() as u8;
                    return "";
                }

                // The chunks of output to be written.
                let encoded = &mut encoded[..output_len];
                let mut output = encoded
                    .chunks_exact_mut(Self::ENCODED_BLOCK_SIZE);

                // Empty the carry first.
                if self.carry() != 0 {
                    let off = self.carry();
                    let carry = &mut self.carry[off..];
                    let remaining = carry.len();

                    carry.copy_from_slice(&decoded[..remaining]);
                    let block = Self::encode_block(self.carry);
                    self.carry.fill(0);

                    output.next().unwrap().copy_from_slice(&block);
                    decoded = &decoded[remaining..];
                }

                // Process as many blocks from 'decoded' as possible.
                // TODO (feature(array_chunks)): Use 'slice::array_chunks()'.
                let mut input = decoded.chunks_exact(Self::DECODED_BLOCK_SIZE);
                for (dst, src) in output.zip(&mut input) {
                    let block = src.try_into().unwrap();
                    let block = Self::encode_block(block);
                    dst.copy_from_slice(&block);
                }

                // Save any leftover carry.
                let leftover = input.remainder().len();
                self.carry[..leftover].copy_from_slice(input.remainder());
                self.carry[Self::DECODED_BLOCK_SIZE - 1] = leftover as u8;

                // SAFETY: 'encode_block()' only outputs ASCII characters, and
                // 'encoded' has been completely overwritten with it.
                unsafe { core::str::from_utf8_unchecked(encoded) }
            }

            /// Encode bytes into a [`Vec`].
            ///
            /// The bytes will be encoded and appended to the [`Vec`].  The
            /// appended bytes will be returned as a string.  A partial block
            /// of decoded bytes, if any, will be saved and used for a later
            /// call to [`encode()`] or [`finish()`].
            ///
            /// [`encode()`]: Self::encode()
            /// [`finish()`]: Self::finish()
            #[cfg(feature = "std")]
            pub fn encode_to_vec<'e>(
                &mut self,
                mut decoded: &[u8],
                encoded: &'e mut Vec<u8>,
            ) -> &'e str {
                if self.encoded_len(decoded.len()) == 0 {
                    // We're not expecting to write any bytes.
                    // Append any decoded bytes to the carry and stop.

                    let off = self.carry();
                    let carry = &mut self.carry[off..];
                    carry[..decoded.len()].copy_from_slice(decoded);
                    carry[Self::DECODED_BLOCK_SIZE - 1]
                        += decoded.len() as u8;
                    return "";
                }

                // The start of the encoded data.
                let start = encoded.len();

                // Empty the carry first.
                if self.carry() != 0 {
                    let off = self.carry();
                    let carry = &mut self.carry[off..];
                    let remaining = carry.len();

                    carry.copy_from_slice(&decoded[..remaining]);
                    let block = Self::encode_block(self.carry);
                    self.carry.fill(0);

                    encoded.extend_from_slice(&block);
                    decoded = &decoded[remaining..];
                }

                // Process as many blocks from 'decoded' as possible.
                // TODO (feature(array_chunks)): Use 'slice::array_chunks()'.
                let mut input = decoded
                    .chunks_exact(Self::DECODED_BLOCK_SIZE);
                for chunk in &mut input {
                    let chunk = chunk.try_into().unwrap();
                    encoded.extend_from_slice(&Self::encode_block(chunk));
                }

                // Save any leftover carry.
                let leftover = input.remainder().len();
                self.carry[..leftover].copy_from_slice(input.remainder());
                self.carry[Self::DECODED_BLOCK_SIZE - 1] = leftover as u8;

                // SAFETY: 'encode_block()' only outputs ASCII characters, and
                // 'encoded[start..]' was written with them.
                unsafe { core::str::from_utf8_unchecked(&encoded[start..]) }
            }

            /// The minimum buffer size for calling [`finish()`].
            ///
            /// [`finish()`] must be called with a destination buffer that is
            /// at least as big as the returned size (in bytes).
            ///
            /// [`finish()`]: Self::finish()
            pub fn finished_len(&self, padded: bool) -> usize {
                match (self.carry(), padded) {
                    (0, _) => 0,
                    (_, true) => Self::ENCODED_BLOCK_SIZE,
                    (n, false) => {
                        (n * Self::ENCODED_BLOCK_SIZE)
                            .div_ceil(Self::DECODED_BLOCK_SIZE)
                    }
                }
            }

            /// Finish encoding.
            ///
            /// If some decoded bytes were left over from previous calls to
            /// [`encode()`], they will be encoded (and possibly padded) and
            /// written to the given slice.
            ///
            /// # Panics
            ///
            /// Panics if `encoded` is too small to fit the encoded data; call
            /// [`finished_len()`] to determine how big it should be.
            ///
            /// [`encode()`]: Self::encode()
            /// [`finished_len()`]: Self::finished_len()
            pub fn finish<'e>(
                &mut self,
                encoded: &'e mut [u8],
                padded: bool,
            ) -> &'e str {
                let output_len = self.finished_len(padded);
                let unpadded_len = self.finished_len(false);
                assert!(encoded.len() >= output_len);
                let encoded = &mut encoded[..output_len];

                let len = self.carry();
                self.carry[len..].fill(0);
                let mut block = Self::encode_block(self.carry);
                self.carry.fill(0);

                // Write padding if necessary.
                match (len, padded) {
                    (0, _) => return "",
                    (_, true) => {
                        block[unpadded_len..].fill(b'=');
                    }
                    _ => {}
                };

                // SAFETY: 'encode_block()' only outputs ASCII characters.
                encoded.copy_from_slice(&block[..output_len]);
                unsafe { core::str::from_utf8_unchecked(encoded) }
            }

            /// Finish encoding.
            ///
            /// If some decoded bytes were left over from previous calls to
            /// [`encode()`], they will be encoded (and possibly padded) and
            /// appended to the given [`Vec`].
            ///
            /// [`encode()`]: Self::encode()
            #[cfg(feature = "std")]
            pub fn finish_to_vec<'e>(
                &mut self,
                encoded: &'e mut Vec<u8>,
                padded: bool,
            ) -> &'e str {
                let output_len = self.finished_len(padded);
                let unpadded_len = self.finished_len(false);
                let start = encoded.len();

                let len = self.carry();
                self.carry[len..].fill(0);
                let mut block = Self::encode_block(self.carry);
                self.carry.fill(0);

                // Write padding if necessary.
                match (len, padded) {
                    (0, _) => return "",
                    (_, true) => {
                        block[unpadded_len..].fill(b'=');
                    }
                    _ => {}
                };

                // SAFETY: 'encode_block()' only outputs ASCII characters.
                encoded.extend_from_slice(&block[..output_len]);
                unsafe { core::str::from_utf8_unchecked(&encoded[start..]) }
            }
        }

        impl $name {
            /// The minimum buffer size for calling [`encode_all()`].
            ///
            /// [`encode_all()`] must be called with a destination buffer that
            /// is at least as big as the returned size (in bytes).
            ///
            /// [`encode_all()`]: Self::encode_all()
            pub fn all_encoded_len(
                decoded_len: usize,
                padded: bool
            ) -> usize {
                if padded {
                    decoded_len.div_ceil(Self::DECODED_BLOCK_SIZE)
                        * Self::ENCODED_BLOCK_SIZE
                } else {
                    (decoded_len * Self::ENCODED_BLOCK_SIZE)
                        .div_ceil(Self::DECODED_BLOCK_SIZE)
                }
            }

            /// Encode bytes statelessly.
            ///
            /// This is a convenience function for calling [`encode()`] and
            /// [`finish()`] with a single slice of input.
            ///
            /// # Panics
            ///
            /// Panics if `encoded` is too small to fit the encoded data; call
            /// [`all_encoded_len()`] to determine how big it should be.
            ///
            /// [`encode()`]: Self::encode()
            /// [`finish()`]: Self::finish()
            /// [`all_encoded_len()`]: Self::all_encoded_len()
            pub fn encode_all<'e>(
                decoded: &[u8],
                encoded: &'e mut [u8],
                padded: bool,
            ) -> &'e str {
                let len = Self::all_encoded_len(decoded.len(), padded);
                assert!(encoded.len() >= len);

                let mut this = Self::new();
                let enc = this.encode(decoded, encoded).len();
                let _ = this.finish(&mut encoded[enc..], padded);

                // SAFETY: 'Self' only outputs ASCII characters.
                unsafe { core::str::from_utf8_unchecked(&encoded[..len]) }
            }

            /// Encode bytes into a [`Vec`] statelessly.
            ///
            /// This is a convenience function for calling [`encode_to_vec()`]
            /// and [`finish_to_vec()`] with a single slice of input.
            ///
            /// [`encode_to_vec()`]: Self::encode_to_vec()
            /// [`finish_to_vec()`]: Self::finish_to_vec()
            #[cfg(feature = "std")]
            pub fn encode_all_to_vec<'e>(
                decoded: &[u8],
                encoded: &'e mut Vec<u8>,
                padded: bool,
            ) -> &'e str {
                let start = encoded.len();

                let mut this = Self::new();
                let _ = this.encode_to_vec(decoded, encoded);
                let _ = this.finish_to_vec(encoded, padded);

                // SAFETY: 'Self' only outputs ASCII characters.
                unsafe { core::str::from_utf8_unchecked(&encoded[start..]) }
            }
        }
    };
}

//----------- Base32Enc ------------------------------------------------------

impl_base_enc! {
    /// A Base32 encoder.
    #[derive(Default)]
    pub struct Base32Enc;
}

impl Base32Enc {
    /// The size of a decoded block.
    const DECODED_BLOCK_SIZE: usize = 5;

    /// The size of an encoded block.
    const ENCODED_BLOCK_SIZE: usize = 8;

    /// Encode a single block of data.
    fn encode_block(decoded: [u8; 5]) -> [u8; 8] {
        let mut block = [0u8; 8];
        block[3..8].copy_from_slice(&decoded);
        // Use 64-bit arithmetic to rearrange the bits efficiently.
        let mut block = u64::from_be_bytes(block);
        // 0000 0000 0000 0000 0000 0000 XXXX XXXX
        // XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX
        block = ((block & 0x000000FFFFF00000) << 12)
            | (block & 0x00000000000FFFFF);
        // 0000 0000 0000 XXXX XXXX XXXX XXXX XXXX
        // 0000 0000 0000 XXXX XXXX XXXX XXXX XXXX
        block = ((block & 0x000FFC00_000FFC00) << 6)
            | (block & 0x000003FF_000003FF);
        // 0000 00XX XXXX XXXX 0000 00XX XXXX XXXX
        // 0000 00XX XXXX XXXX 0000 00XX XXXX XXXX
        block = ((block & 0x03E0_03E0_03E0_03E0) << 3)
            | (block & 0x001F_001F_001F_001F);
        // 000X XXXX 000X XXXX 000X XXXX 000X XXXX
        // 000X XXXX 000X XXXX 000X XXXX 000X XXXX
        let block = block.to_be_bytes();
        block.map(|c| match c {
            0..=25 => b'A' + c,
            26..=31 => b'2' + c - 26,
            _ => unreachable!(),
        })
    }
}

//----------- Base32HexEnc ---------------------------------------------------

impl_base_enc! {
    /// A Base32 encoder using the `base32hex` alphabet.
    #[derive(Default)]
    pub struct Base32HexEnc;
}

impl Base32HexEnc {
    /// The size of a decoded block.
    const DECODED_BLOCK_SIZE: usize = 5;

    /// The size of an encoded block.
    const ENCODED_BLOCK_SIZE: usize = 8;

    /// Encode a single block of data.
    fn encode_block(decoded: [u8; 5]) -> [u8; 8] {
        let mut block = [0u8; 8];
        block[3..8].copy_from_slice(&decoded);
        // Use 64-bit arithmetic to rearrange the bits efficiently.
        let mut block = u64::from_be_bytes(block);
        // 0000 0000 0000 0000 0000 0000 XXXX XXXX
        // XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX
        block = ((block & 0x000000FFFFF00000) << 12)
            | (block & 0x00000000000FFFFF);
        // 0000 0000 0000 XXXX XXXX XXXX XXXX XXXX
        // 0000 0000 0000 XXXX XXXX XXXX XXXX XXXX
        block = ((block & 0x000FFC00_000FFC00) << 6)
            | (block & 0x000003FF_000003FF);
        // 0000 00XX XXXX XXXX 0000 00XX XXXX XXXX
        // 0000 00XX XXXX XXXX 0000 00XX XXXX XXXX
        block = ((block & 0x03E0_03E0_03E0_03E0) << 3)
            | (block & 0x001F_001F_001F_001F);
        // 000X XXXX 000X XXXX 000X XXXX 000X XXXX
        // 000X XXXX 000X XXXX 000X XXXX 000X XXXX
        let block = block.to_be_bytes();
        block.map(|c| match c {
            0..=9 => b'0' + c,
            10..=31 => b'A' + c - 10,
            _ => unreachable!(),
        })
    }
}

//----------- Base64Enc ------------------------------------------------------

impl_base_enc! {
    /// A Base64 encoder.
    #[derive(Default)]
    pub struct Base64Enc;
}

impl Base64Enc {
    /// The size of a decoded block.
    const DECODED_BLOCK_SIZE: usize = 3;

    /// The size of an encoded block.
    const ENCODED_BLOCK_SIZE: usize = 4;

    /// Encode a single block of data.
    fn encode_block(decoded: [u8; 3]) -> [u8; 4] {
        let mut block = [0u8; 4];
        block[1..4].copy_from_slice(&decoded);
        // Use 32-bit arithmetic to rearrange the bits efficiently.
        let mut block = u32::from_be_bytes(block);
        // 0000 0000 XXXX XXXX XXXX XXXX XXXX XXXX
        block = ((block & 0x00FFF000) << 4) | (block & 0x00000FFF);
        // 0000 XXXX XXXX XXXX 0000 XXXX XXXX XXXX
        block = ((block & 0x0FC00FC0) << 2) | (block & 0x003F003F);
        // 00XX XXXX 00XX XXXX 00XX XXXX 00XX XXXX
        let block = block.to_be_bytes();
        block.map(|c| match c {
            0..=25 => b'A' + c,
            26..=51 => b'a' + c - 26,
            52..=61 => b'0' + c - 52,
            62 => b'+',
            63 => b'/',
            _ => unreachable!(),
        })
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use super::{Base16Enc, Base32Enc, Base32HexEnc, Base64Enc};

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

        for &(input, output) in CASES {
            let mut buffer = [0u8; 12];
            assert_eq!(Base16Enc.encode(input, &mut buffer), output);
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

        for &(input, output) in CASES {
            let mut buffer = [0u8; 16];
            assert_eq!(
                Base32Enc::encode_all(input, &mut buffer, false),
                output.trim_end_matches('='),
            );
            assert_eq!(
                Base32Enc::encode_all(input, &mut buffer, true),
                output
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

        for &(input, output) in CASES {
            let mut buffer = [0u8; 16];
            assert_eq!(
                Base32HexEnc::encode_all(input, &mut buffer, false),
                output.trim_end_matches('='),
            );
            assert_eq!(
                Base32HexEnc::encode_all(input, &mut buffer, true),
                output
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

        for &(input, output) in CASES {
            let mut buffer = [0u8; 12];
            assert_eq!(
                Base64Enc::encode_all(input, &mut buffer, false),
                output.trim_end_matches('='),
            );
            assert_eq!(
                Base64Enc::encode_all(input, &mut buffer, true),
                output,
            );
        }
    }
}
