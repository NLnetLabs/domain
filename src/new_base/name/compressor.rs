//! Name compression.

use crate::new_base::name::{Label, LabelIter};

use super::{Name, RevName};

/// A domain name compressor.
///
/// This struct provides name compression functionality when building DNS
/// messages.  It compares domain names to those already in the message, and
/// if a shared suffix is found, the newly-inserted name will point at the
/// existing instance of the suffix.
///
/// This struct stores the positions of domain names already present in the
/// DNS message, as it is otherwise impossible to differentiate domain names
/// from other bytes.  Only recently-inserted domain names are stored, and
/// only from the first 16KiB of the message (as compressed names cannot point
/// any further).  This is good enough for building small and large messages.
#[repr(align(64))] // align to a typical cache line
pub struct NameCompressor {
    /// The last use position of every entry.
    ///
    /// Every time an entry is used (directly or indirectly), its last use
    /// position is updated so that more stale entries are evicted before it.
    ///
    /// The last use position is calculated somewhat approximately; it would
    /// most appropriately be '(number of children, position of inserted
    /// name)', but it is approximated as 'position of inserted name + offset
    /// into the name if it were uncompressed'.  In either formula, the entry
    /// with the minimum value would be evicted first.
    ///
    /// Both formulae guarantee that entries will be evicted before any of
    /// their dependencies.  The former formula requires at least 19 bits of
    /// storage, while the latter requires less than 15 bits.  The latter can
    /// prioritize a deeply-nested name suffix over a slightly more recently
    /// used name that is less nested, but this should be quite rare.
    ///
    /// Valid values:
    /// - Initialized entries: `[1, 16383+253]`.
    /// - Uninitialized entries: 0.
    last_use: [u16; 32],

    /// The position of each entry.
    ///
    /// This is a byte offset from the message contents (zero represents the
    /// first byte after the 12-byte message header).
    ///
    /// Valid values:
    /// - Initialized entries: `[0, 16383]`.
    /// - Uninitialized entries: 0.
    pos: [u16; 32],

    /// The length of the relative domain name in each entry.
    ///
    /// This is the length of the domain name each entry represents, up to
    /// (but excluding) the root label or compression pointer.  It is used to
    /// quickly find the end of the domain name for matching suffixes.
    ///
    /// Valid values:
    /// - Initialized entries: `[2, 253]`.
    /// - Uninitialized entries: 0.
    len: [u8; 32],

    /// The parent of this entry, if any.
    ///
    /// If this entry represents a compressed domain name, this value stores
    /// the index of that entry.
    ///
    /// Valid values:
    /// - Initialized entries with parents: `[32, 63]`.
    /// - Initialized entries without parents: 64.
    /// - Uninitialized entries: 0.
    parent: [u8; 32],

    /// A 16-bit hash of the entry's last label.
    ///
    /// An existing entry will be used for compressing a new domain name when
    /// the last label in both of them is identical.  This field stores a hash
    /// over the last label in every entry, to speed up lookups.
    ///
    /// Valid values:
    /// - Initialized entries: `[0, 65535]`.
    /// - Uninitialized entries: 0.
    hash: [u16; 32],
}

impl NameCompressor {
    /// Construct an empty [`NameCompressor`].
    pub const fn new() -> Self {
        Self {
            last_use: [0u16; 32],
            pos: [0u16; 32],
            len: [0u8; 32],
            parent: [0u8; 32],
            hash: [0u16; 32],
        }
    }

    /// Compress a [`RevName`].
    ///
    /// This is a low-level function; use [`RevName::build_in_message()`] to
    /// write a [`RevName`] into a DNS message.
    ///
    /// Given the contents of the DNS message, determine how to compress the
    /// given domain name.  If a suitable compression for the name could be
    /// found, this function returns the length of the uncompressed suffix as
    /// well as the address of the compressed prefix.
    ///
    /// The contents slice should begin immediately after the 12-byte message
    /// header.  It must end at the position the name will be inserted.  It is
    /// assumed that the domain names inserted in these contents still exist
    /// from previous calls to [`compress_name()`] and related methods.  If
    /// this is not true, panics or silently invalid results may occur.
    ///
    /// The compressor's state will be updated to assume the provided name was
    /// inserted into the message.
    pub fn compress_revname<'n>(
        &mut self,
        contents: &[u8],
        name: &'n RevName,
    ) -> Option<(&'n [u8], u16)> {
        // Treat the name as a byte sequence without the root label.
        let mut name = &name.as_bytes()[1..];

        if name.is_empty() {
            // Root names are never compressed.
            return None;
        }

        let mut parent = 64u8;
        let mut parent_offset = None;

        // Repeatedly look up entries that could be used for compression.
        while !name.is_empty() {
            match self.lookup_entry_for_revname(contents, name, parent) {
                Some(entry) => {
                    let tmp;
                    (parent, name, tmp) = entry;
                    parent_offset = Some(tmp);

                    // This entry was successfully used for compression.
                    // Record its use at this (approximate) position.
                    let use_pos = contents.len() + name.len();
                    let use_pos = use_pos.max(1);
                    if use_pos < 16383 + 253 {
                        self.last_use[parent as usize] = use_pos as u16;
                    }
                }
                None => break,
            }
        }

        // If there is a non-empty uncompressed prefix, register it as a new
        // entry here.
        if !name.is_empty() && contents.len() < 16384 {
            // SAFETY: 'name' is a non-empty sequence of labels.
            let first = unsafe {
                LabelIter::new_unchecked(name).next().unwrap_unchecked()
            };

            // Pick the entry that was least recently used (or uninitialized).
            //
            // By the invariants of 'last_use', it is guaranteed that this
            // entry is not the parent of any others.
            let index = (0usize..32)
                .min_by_key(|&i| self.last_use[i])
                .expect("the iterator has 32 elements");

            self.last_use[index] = contents.len() as u16;
            self.pos[index] = contents.len() as u16;
            self.len[index] = name.len() as u8;
            self.parent[index] = parent;
            self.hash[index] = Self::hash_label(first);
        }

        // If 'parent_offset' is 'Some', then at least one entry was found,
        // and so the name was compressed.
        parent_offset.map(|offset| (name, offset))
    }

    /// Look up entries which share a suffix with the given reversed name.
    ///
    /// At most one entry ends with a complete label matching the given name.
    /// We will match suffixes using a linear-time algorithm.
    ///
    /// On success, the entry's index, the remainder of the name, and the
    /// offset of the referenced domain name are returned.
    fn lookup_entry_for_revname<'n>(
        &self,
        contents: &[u8],
        name: &'n [u8],
        parent: u8,
    ) -> Option<(u8, &'n [u8], u16)> {
        // SAFETY: 'name' is a sequence of labels.
        let mut name_labels = unsafe { LabelIter::new_unchecked(name) };
        // SAFETY: 'name' is non-empty.
        let first = unsafe { name_labels.next().unwrap_unchecked() };
        let hash = Self::hash_label(first);

        // Search for an entry with a matching hash and parent.
        for i in 0..32 {
            // Check the hash first, as it's less likely to match.  It's also
            // okay if both checks are performed unconditionally.
            if self.hash[i] != hash || self.parent[i] != parent {
                continue;
            };

            // Look up the entry in the message contents.
            let (pos, len) = (self.pos[i] as usize, self.len[i] as usize);
            debug_assert_ne!(len, 0);
            let mut entry = contents.get(pos..pos + len)
                .unwrap_or_else(|| panic!("'contents' did not correspond to the name compressor state"));

            // Find a shared suffix between the entry and the name.
            //
            // Comparing a 'Name' to a 'RevName' properly is difficult.  We're
            // just going for the lazy and not-pedantically-correct version,
            // where we blindly match 'RevName' labels against the end of the
            // 'Name'.  The bytes are definitely correct, but there's a small
            // chance that we aren't consistent with label boundaries.

            // TODO(1.80): Use 'slice::split_at_checked()'.
            if entry.len() < first.as_bytes().len()
                || !entry[entry.len() - first.as_bytes().len()..]
                    .eq_ignore_ascii_case(first.as_bytes())
            {
                continue;
            }
            entry = &entry[..entry.len() - first.as_bytes().len()];

            for label in name_labels.clone() {
                if entry.len() < label.as_bytes().len()
                    || !entry[entry.len() - label.as_bytes().len()..]
                        .eq_ignore_ascii_case(label.as_bytes())
                {
                    break;
                }
                entry = &entry[..entry.len() - label.as_bytes().len()];
            }

            // Suffixes from 'entry' that were also in 'name' have been
            // removed.  The remainder of 'entry' does not match with 'name'.
            // 'name' can be compressed using this entry.
            let rest = name_labels.remaining();
            let pos = pos + entry.len();
            return Some((i as u8, rest, pos as u16));
        }

        None
    }

    /// Compress a [`Name`].
    ///
    /// This is a low-level function; use [`Name::build_in_message()`] to
    /// write a [`Name`] into a DNS message.
    ///
    /// Given the contents of the DNS message, determine how to compress the
    /// given domain name.  If a suitable compression for the name could be
    /// found, this function returns the length of the uncompressed prefix as
    /// well as the address of the suffix.
    ///
    /// The contents slice should begin immediately after the 12-byte message
    /// header.  It must end at the position the name will be inserted.  It is
    /// assumed that the domain names inserted in these contents still exist
    /// from previous calls to [`compress_name()`] and related methods.  If
    /// this is not true, panics or silently invalid results may occur.
    ///
    /// The compressor's state will be updated to assume the provided name was
    /// inserted into the message.
    pub fn compress_name<'n>(
        &mut self,
        contents: &[u8],
        name: &'n Name,
    ) -> Option<(&'n [u8], u16)> {
        // Treat the name as a byte sequence without the root label.
        let mut name = &name.as_bytes()[..name.len() - 1];

        if name.is_empty() {
            // Root names are never compressed.
            return None;
        }

        let mut hash = Self::hash_label(Self::last_label(name));
        let mut parent = 64u8;
        let mut parent_offset = None;

        // Repeatedly look up entries that could be used for compression.
        while !name.is_empty() {
            match self.lookup_entry_for_name(contents, name, parent, hash) {
                Some(entry) => {
                    let tmp;
                    (parent, name, hash, tmp) = entry;
                    parent_offset = Some(tmp);

                    // This entry was successfully used for compression.
                    // Record its use at this (approximate) position.
                    let use_pos = contents.len() + name.len();
                    let use_pos = use_pos.max(1);
                    if use_pos < 16383 + 253 {
                        self.last_use[parent as usize] = use_pos as u16;
                    }
                }
                None => break,
            }
        }

        // If there is a non-empty uncompressed prefix, register it as a new
        // entry here.  We already know what the hash of its last label is.
        if !name.is_empty() && contents.len() < 16384 {
            // Pick the entry that was least recently used (or uninitialized).
            //
            // By the invariants of 'last_use', it is guaranteed that this
            // entry is not the parent of any others.
            let index = (0usize..32)
                .min_by_key(|&i| self.last_use[i])
                .expect("the iterator has 32 elements");

            self.last_use[index] = contents.len() as u16;
            self.pos[index] = contents.len() as u16;
            self.len[index] = name.len() as u8;
            self.parent[index] = parent;
            self.hash[index] = hash;
        }

        // If 'parent_offset' is 'Some', then at least one entry was found,
        // and so the name was compressed.
        parent_offset.map(|offset| (name, offset))
    }

    /// Look up entries which share a suffix with the given name.
    ///
    /// At most one entry ends with a complete label matching the given name.
    /// We will carefully match suffixes using a linear-time algorithm.
    ///
    /// On success, the entry's index, the remainder of the name, the hash of
    /// the last label in the remainder of the name (if any), and the offset
    /// of the referenced domain name are returned.
    fn lookup_entry_for_name<'n>(
        &self,
        contents: &[u8],
        name: &'n [u8],
        parent: u8,
        hash: u16,
    ) -> Option<(u8, &'n [u8], u16, u16)> {
        // SAFETY: 'name' is a non-empty sequence of labels.
        let name_labels = unsafe { LabelIter::new_unchecked(name) };

        // Search for an entry with a matching hash and parent.
        for i in 0..32 {
            // Check the hash first, as it's less likely to match.  It's also
            // okay if both checks are performed unconditionally.
            if self.hash[i] != hash || self.parent[i] != parent {
                continue;
            };

            // Look up the entry in the message contents.
            let (pos, len) = (self.pos[i] as usize, self.len[i] as usize);
            debug_assert_ne!(len, 0);
            let entry = contents.get(pos..pos + len)
                .unwrap_or_else(|| panic!("'contents' did not correspond to the name compressor state"));

            // Find a shared suffix between the entry and the name.
            //
            // We're going to use a not-pendantically-correct implementation
            // where we blindly match the ends of the names.  The bytes are
            // definitely correct, but there's a small chance we aren't
            // consistent with label boundaries.

            let suffix_len = core::iter::zip(
                name.iter().rev().map(u8::to_ascii_lowercase),
                entry.iter().rev().map(u8::to_ascii_lowercase),
            )
            .position(|(a, b)| a != b);

            let Some(suffix_len) = suffix_len else {
                // 'iter::zip()' simply ignores unequal iterators, stopping
                // when either iterator finishes.  Even though the two names
                // had no mismatching bytes, one could be longer than the
                // other.
                if name.len() > entry.len() {
                    // 'entry' is a proper suffix of 'name'.  'name' can be
                    // compressed using 'entry', and will have at least one
                    // more label before it.  This label needs to be found and
                    // hashed.

                    let rest = &name[..name.len() - entry.len()];
                    let hash = Self::hash_label(Self::last_label(rest));
                    return Some((i as u8, rest, hash, pos as u16));
                } else {
                    // 'name' is a suffix of 'entry'.  'name' can be
                    // compressed using 'entry', and no labels will be left.
                    let rest = &name[..0];
                    let hash = 0u16;
                    let pos = pos + len - name.len();
                    return Some((i as u8, rest, hash, pos as u16));
                }
            };

            // Walk 'name' until we reach the shared suffix region.

            // NOTE:
            // - 'suffix_len < min(name.len(), entry.len())'.
            // - 'name_labels.remaining.len() == name.len()'.
            // - Thus 'suffix_len < name_labels.remaining.len()'.
            // - Thus we can move the first statement of the loop here.
            // SAFETY:
            // - 'name' and 'entry' have a corresponding but unequal byte.
            // - Thus 'name' has at least one byte.
            // - Thus 'name' has at least one label.
            let mut name_labels = name_labels.clone();
            let mut prev_in_name =
                unsafe { name_labels.next().unwrap_unchecked() };
            while name_labels.remaining().len() > suffix_len {
                // SAFETY:
                // - 'LabelIter' is only empty once 'remaining' is empty.
                // - 'remaining > suffix_len >= 0'.
                prev_in_name =
                    unsafe { name_labels.next().unwrap_unchecked() };
            }

            // 'entry' and 'name' share zero or more labels, and this shared
            // suffix is equal to 'name_labels'.  The 'name_label' bytes might
            // not lie on the correct label boundaries in 'entry', but this is
            // not problematic.  If 'name_labels' is non-empty, 'name' can be
            // compressed using this entry.

            let suffix_len = name_labels.remaining().len();
            if suffix_len == 0 {
                continue;
            }

            let rest = &name[..name.len() - suffix_len];
            let hash = Self::hash_label(prev_in_name);
            let pos = pos + len - suffix_len;
            return Some((i as u8, rest, hash, pos as u16));
        }

        None
    }

    /// Find the last label of a domain name.
    ///
    /// The name must be a valid non-empty sequence of labels.
    fn last_label(name: &[u8]) -> &Label {
        // The last label begins with a length octet and is followed by
        // the corresponding number of bytes.  While the length octet
        // could look like a valid ASCII character, it would have to be
        // 45 (ASCII '-') or above; most labels are not that long.
        //
        // We will search backwards for a byte that could be the length
        // octet of the last label.  It is highly likely that exactly one
        // match will be found; this is guaranteed to be the right result.
        // If more than one match is found, we will fall back to searching
        // from the beginning.
        //
        // It is possible (although unlikely) for LLVM to vectorize this
        // process, since it performs 64 unconditional byte comparisons
        // over a fixed array.  A manually vectorized implementation would
        // generate a 64-byte mask for the valid bytes in 'name', load all
        // 64 bytes blindly, then do a masked comparison against iota.

        name.iter()
            // Take the last 64 bytes of the name.
            .rev()
            .take(64)
            // Compare those bytes against valid length octets.
            .enumerate()
            .filter_map(|(i, &b)| (i == b as usize).then_some(b))
            // Look for a single valid length octet.
            .try_fold(None, |acc, len| match acc {
                None => Ok(Some(len)),
                Some(_) => Err(()),
            })
            // Unwrap the 'Option' since it's guaranteed to be 'Some'.
            .transpose()
            .unwrap_or_else(|| {
                unreachable!("a valid last label could not be found")
            })
            // Locate the selected bytes.
            .map(|len| {
                let bytes = &name[name.len() - len as usize - 1..];

                // SAFETY: 'name' is a non-empty sequence of labels, and
                // we have correctly selected the last label within it.
                unsafe { Label::from_bytes_unchecked(bytes) }
            })
            // Otherwise, fall back to a forward traversal.
            .unwrap_or_else(|()| {
                // SAFETY: 'name' is a non-empty sequence of labels.
                unsafe { LabelIter::new_unchecked(name) }
                    .last()
                    .expect("'name' is not '.'")
            })
    }

    /// Hash a label.
    fn hash_label(label: &Label) -> u16 {
        // This code is copied from the 'hash_bytes()' function of
        // 'rustc-hash' v2.1.1, with helpers.  The codebase is dual-licensed
        // under Apache-2.0 and MIT, with no explicit copyright statement.
        //
        // 'hash_bytes()' is described as "a wyhash-inspired
        // non-collision-resistant hash for strings/slices designed by Orson
        // Peters, with a focus on small strings and small codesize."
        //
        // While the output of 'hash_bytes()' would pass through an additional
        // multiplication in 'add_to_hash()', manual testing on some sample
        // zonefiles showed that the top 16 bits of the 'hash_bytes()' output
        // was already very uniform.
        //
        // Source: <https://github.com/rust-lang/rustc-hash/blob/dc5c33f1283de2da64d8d7a06401d91aded03ad4/src/lib.rs>

        #[cfg(target_pointer_width = "64")]
        fn multiply_mix(x: u64, y: u64) -> u64 {
            let prod = (x as u128) * (y as u128);
            (prod as u64) ^ ((prod >> 64) as u64)
        }

        #[cfg(target_pointer_width = "32")]
        fn multiply_mix(x: u64, y: u64) -> u64 {
            let a = (x & u32::MAX as u64) * (y >> 32);
            let b = (y & u32::MAX as u64) * (x >> 32);
            a ^ b.rotate_right(32)
        }

        const SEED1: u64 = 0x243f6a8885a308d3;
        const SEED2: u64 = 0x13198a2e03707344;
        const PREVENT_TRIVIAL_ZERO_COLLAPSE: u64 = 0xa4093822299f31d0;

        let bytes = label.as_bytes();
        let len = bytes.len();
        let mut s0 = SEED1;
        let mut s1 = SEED2;

        if len <= 16 {
            // XOR the input into s0, s1.
            if len >= 8 {
                s0 ^= u64::from_le_bytes(bytes[0..8].try_into().unwrap());
                s1 ^=
                    u64::from_le_bytes(bytes[len - 8..].try_into().unwrap());
            } else if len >= 4 {
                s0 ^= u32::from_le_bytes(bytes[0..4].try_into().unwrap())
                    as u64;
                s1 ^= u32::from_le_bytes(bytes[len - 4..].try_into().unwrap())
                    as u64;
            } else if len > 0 {
                let lo = bytes[0];
                let mid = bytes[len / 2];
                let hi = bytes[len - 1];
                s0 ^= lo as u64;
                s1 ^= ((hi as u64) << 8) | mid as u64;
            }
        } else {
            // Handle bulk (can partially overlap with suffix).
            let mut off = 0;
            while off < len - 16 {
                let x = u64::from_le_bytes(
                    bytes[off..off + 8].try_into().unwrap(),
                );
                let y = u64::from_le_bytes(
                    bytes[off + 8..off + 16].try_into().unwrap(),
                );

                // Replace s1 with a mix of s0, x, and y, and s0 with s1.
                // This ensures the compiler can unroll this loop into two
                // independent streams, one operating on s0, the other on s1.
                //
                // Since zeroes are a common input we prevent an immediate
                // trivial collapse of the hash function by XOR'ing a constant
                // with y.
                let t =
                    multiply_mix(s0 ^ x, PREVENT_TRIVIAL_ZERO_COLLAPSE ^ y);
                s0 = s1;
                s1 = t;
                off += 16;
            }

            let suffix = &bytes[len - 16..];
            s0 ^= u64::from_le_bytes(suffix[0..8].try_into().unwrap());
            s1 ^= u64::from_le_bytes(suffix[8..16].try_into().unwrap());
        }

        (multiply_mix(s0, s1) >> 48) as u16
    }
}

impl Default for NameCompressor {
    fn default() -> Self {
        Self::new()
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use crate::new_base::{build::BuildInMessage, name::NameBuf};

    use super::NameCompressor;

    #[test]
    fn no_compression() {
        let mut buffer = [0u8; 26];
        let mut compressor = NameCompressor::new();

        // The TLD is different, so they cannot be compressed together.
        let a: NameBuf = "example.org".parse().unwrap();
        let b: NameBuf = "example.com".parse().unwrap();

        let mut off = 0;
        off = a
            .build_in_message(&mut buffer, off, &mut compressor)
            .unwrap();
        off = b
            .build_in_message(&mut buffer, off, &mut compressor)
            .unwrap();

        assert_eq!(off, buffer.len());
        assert_eq!(
            &buffer,
            b"\
            \x07example\x03org\x00\
            \x07example\x03com\x00"
        );
    }

    #[test]
    fn single_shared_label() {
        let mut buffer = [0u8; 23];
        let mut compressor = NameCompressor::new();

        // Only the TLD will be shared.
        let a: NameBuf = "example.org".parse().unwrap();
        let b: NameBuf = "unequal.org".parse().unwrap();

        let mut off = 0;
        off = a
            .build_in_message(&mut buffer, off, &mut compressor)
            .unwrap();
        off = b
            .build_in_message(&mut buffer, off, &mut compressor)
            .unwrap();

        assert_eq!(off, buffer.len());
        assert_eq!(
            &buffer,
            b"\
            \x07example\x03org\x00\
            \x07unequal\xC0\x14"
        );
    }
}
