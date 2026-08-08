//! Atomic caller-buffer construction for RFC 7541 section 6 representations.

use core::fmt;

use super::integer::{canonical_encoded_len, write_canonical_for_valid_prefix};
use super::representation::HpackLiteralMode;
use super::string::HpackStringLiteralBuildError;

/// Builds an RFC 7541 section 6.1 indexed header field in caller-owned storage.
pub struct HpackIndexedFieldBuilder<'a> {
    destination: &'a mut [u8],
    index: u64,
}

impl<'a> HpackIndexedFieldBuilder<'a> {
    /// Creates a builder for a nonzero static or dynamic table index.
    pub fn new(destination: &'a mut [u8], index: u64) -> Self {
        Self { destination, index }
    }

    /// Validates capacity before atomically writing a canonical indexed field.
    pub fn build(self) -> Result<&'a [u8], HpackRepresentationBuildError> {
        if self.index == 0 {
            return Err(HpackRepresentationBuildError::IndexedFieldZero);
        }
        let required = canonical_encoded_len(self.index, 0x7f);
        check_capacity(self.destination.len(), required)?;
        let representation = &mut self.destination[..required];
        write_integer(representation, 7, 0x7f, 0x80, self.index);
        Ok(&*representation)
    }
}

/// A literal header-field name, either a table index or opaque already encoded bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HpackLiteralName<'a> {
    /// Reuses a nonzero static or dynamic table name index.
    Indexed(u64),
    /// Emits a literal name framed as an HPACK string literal.
    ///
    /// When `huffman` is true, `encoded_bytes` are already Huffman-encoded opaque bytes.
    Literal {
        /// Opaque bytes to frame as the literal name.
        encoded_bytes: &'a [u8],
        /// Whether `encoded_bytes` are already Huffman-encoded.
        huffman: bool,
    },
}

/// Opaque already encoded bytes for a literal header-field value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HpackLiteralValue<'a> {
    encoded_bytes: &'a [u8],
    huffman: bool,
}

impl<'a> HpackLiteralValue<'a> {
    /// Creates a value input around opaque bytes already Huffman-encoded when `huffman` is true.
    ///
    /// This type only preserves the supplied bytes and flag. It does not encode Huffman data;
    /// callers needing Huffman coding should first use [`super::HpackHuffmanEncoder`].
    pub const fn new_encoded(encoded_bytes: &'a [u8], huffman: bool) -> Self {
        Self {
            encoded_bytes,
            huffman,
        }
    }

    /// Returns the opaque bytes that will be framed as the value string literal.
    pub const fn encoded_bytes(self) -> &'a [u8] {
        self.encoded_bytes
    }

    /// Returns whether the supplied opaque bytes are already Huffman-encoded.
    pub const fn is_huffman(self) -> bool {
        self.huffman
    }
}

/// Builds RFC 7541 section 6.2 literal header fields in caller-owned storage.
pub struct HpackLiteralFieldBuilder<'a, 'b> {
    destination: &'a mut [u8],
    mode: HpackLiteralMode,
    name: HpackLiteralName<'b>,
    value: HpackLiteralValue<'b>,
}

impl<'a, 'b> HpackLiteralFieldBuilder<'a, 'b> {
    /// Creates a builder for a literal field with an explicit indexing mode and byte-oriented inputs.
    pub fn new(
        destination: &'a mut [u8],
        mode: HpackLiteralMode,
        name: HpackLiteralName<'b>,
        value: HpackLiteralValue<'b>,
    ) -> Self {
        Self {
            destination,
            mode,
            name,
            value,
        }
    }

    /// Validates every component and total capacity before atomically writing a literal field.
    pub fn build(self) -> Result<&'a [u8], HpackRepresentationBuildError> {
        let (prefix_bits, high_bits) = match self.mode {
            HpackLiteralMode::IncrementalIndexing => (6, 0x40),
            HpackLiteralMode::WithoutIndexing => (4, 0),
            HpackLiteralMode::NeverIndexed => (4, 0x10),
        };
        let name_index = self.name_index();
        if matches!(self.name, HpackLiteralName::Indexed(0)) {
            return Err(HpackRepresentationBuildError::LiteralNameIndexZero);
        }
        let literal_name = self
            .literal_name()
            .map(|name| {
                string_info(name)
                    .map(|info| (name, info))
                    .map_err(HpackRepresentationBuildError::LiteralName)
            })
            .transpose()?;
        let name_index_len = canonical_encoded_len(name_index, prefix_mask(prefix_bits));
        let literal_name_len = literal_name.map_or(0, |(_, (length, _))| length);
        let (value_len, value_encoded_length) =
            string_info(self.value).map_err(HpackRepresentationBuildError::LiteralValue)?;
        let required = name_index_len
            .checked_add(literal_name_len)
            .and_then(|length| length.checked_add(value_len))
            .ok_or(HpackRepresentationBuildError::TotalLengthOverflow)?;
        check_capacity(self.destination.len(), required)?;

        let representation = &mut self.destination[..required];
        let (name_index_destination, after_name_index) =
            representation.split_at_mut(name_index_len);
        write_integer(
            name_index_destination,
            prefix_bits,
            prefix_mask(prefix_bits),
            high_bits,
            name_index,
        );
        let after_name = match literal_name {
            Some((name, (_, encoded_length))) => {
                let (name_destination, remainder) = after_name_index.split_at_mut(literal_name_len);
                write_string(name_destination, name, encoded_length);
                remainder
            }
            None => after_name_index,
        };
        write_string(after_name, self.value, value_encoded_length);
        Ok(&*representation)
    }

    fn name_index(&self) -> u64 {
        match self.name {
            HpackLiteralName::Indexed(index) => index,
            HpackLiteralName::Literal { .. } => 0,
        }
    }

    fn literal_name(&self) -> Option<HpackLiteralValue<'b>> {
        match self.name {
            HpackLiteralName::Indexed(_) => None,
            HpackLiteralName::Literal {
                encoded_bytes,
                huffman,
            } => Some(HpackLiteralValue::new_encoded(encoded_bytes, huffman)),
        }
    }
}

/// Builds an RFC 7541 section 6.3 dynamic table size update in caller-owned storage.
pub struct HpackDynamicTableSizeUpdateBuilder<'a> {
    destination: &'a mut [u8],
    size: u64,
}

impl<'a> HpackDynamicTableSizeUpdateBuilder<'a> {
    /// Creates a builder for a dynamic table size value.
    pub fn new(destination: &'a mut [u8], size: u64) -> Self {
        Self { destination, size }
    }

    /// Validates capacity before atomically writing a canonical size update.
    pub fn build(self) -> Result<&'a [u8], HpackRepresentationBuildError> {
        let required = canonical_encoded_len(self.size, 0x1f);
        check_capacity(self.destination.len(), required)?;
        let representation = &mut self.destination[..required];
        write_integer(representation, 5, 0x1f, 0x20, self.size);
        Ok(&*representation)
    }
}

/// Failure to build an HPACK header-field representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HpackRepresentationBuildError {
    /// An indexed header field used forbidden index zero.
    IndexedFieldZero,

    /// A literal header field selected indexed-name form with forbidden index zero.
    LiteralNameIndexZero,

    /// The literal name string could not be built.
    LiteralName(HpackStringLiteralBuildError),
    /// The literal value string could not be built.
    LiteralValue(HpackStringLiteralBuildError),
    /// The sum of representation component lengths overflows `usize`.
    TotalLengthOverflow,
    /// The caller buffer cannot contain the complete representation.
    BufferTooShort {
        /// Required bytes.
        required: usize,
        /// Available bytes.
        available: usize,
    },
}

impl fmt::Display for HpackRepresentationBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IndexedFieldZero => f.write_str("HPACK indexed field index must not be zero"),
            Self::LiteralNameIndexZero => {
                f.write_str("HPACK literal indexed name must not use index zero")
            }

            Self::LiteralName(error) => write!(f, "could not build HPACK literal name: {error}"),
            Self::LiteralValue(error) => write!(f, "could not build HPACK literal value: {error}"),
            Self::TotalLengthOverflow => f.write_str("HPACK representation length overflows usize"),
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                f,
                "HPACK representation buffer is too short: need {required} bytes, have {available}"
            ),
        }
    }
}

fn check_capacity(available: usize, required: usize) -> Result<(), HpackRepresentationBuildError> {
    if available < required {
        return Err(HpackRepresentationBuildError::BufferTooShort {
            required,
            available,
        });
    }
    Ok(())
}

fn string_info(value: HpackLiteralValue<'_>) -> Result<(usize, u64), HpackStringLiteralBuildError> {
    let encoded_length = u64::try_from(value.encoded_bytes.len()).map_err(|_| {
        HpackStringLiteralBuildError::EncodedLengthNotRepresentable {
            encoded_length: value.encoded_bytes.len(),
        }
    })?;
    let length_length = canonical_encoded_len(encoded_length, 0x7f);
    let total = length_length.checked_add(value.encoded_bytes.len()).ok_or(
        HpackStringLiteralBuildError::TotalLengthOverflow {
            length_length,
            encoded_length: value.encoded_bytes.len(),
        },
    )?;
    Ok((total, encoded_length))
}

fn write_string(destination: &mut [u8], value: HpackLiteralValue<'_>, encoded_length: u64) {
    let length_length = canonical_encoded_len(encoded_length, 0x7f);
    let (length_destination, payload_destination) = destination.split_at_mut(length_length);
    write_integer(
        length_destination,
        7,
        0x7f,
        if value.huffman { 0x80 } else { 0 },
        encoded_length,
    );
    payload_destination.copy_from_slice(value.encoded_bytes);
}

fn write_integer(
    destination: &mut [u8],
    prefix_bits: u8,
    prefix_mask: u8,
    high_bits: u8,
    value: u64,
) {
    write_canonical_for_valid_prefix(destination, prefix_bits, prefix_mask, high_bits, value);
}

const fn prefix_mask(prefix_bits: u8) -> u8 {
    (1 << prefix_bits) - 1
}
