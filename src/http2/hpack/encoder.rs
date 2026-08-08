//! Stateful, allocation-free encoding of HPACK fields and leading size updates.

use core::fmt;

use super::context::PendingSizes;
use super::huffman::{HpackHuffmanEncodeError, HpackHuffmanEncoder};
use super::integer::{canonical_encoded_len, write_canonical_for_valid_prefix};
use super::representation::HpackLiteralMode;
use super::representation_builder::{
    HpackDynamicTableSizeUpdateBuilder, HpackIndexedFieldBuilder, HpackRepresentationBuildError,
};
use super::table::{
    HPACK_STATIC_TABLE_LEN, HpackDynamicTable, HpackDynamicTableError, HpackHeaderFieldRef,
    HpackStaticTable,
};

/// A decoded literal-field name for [`HpackBlockEncoder::encode_literal`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HpackEncodeLiteralName<'a> {
    /// Reuses a static or dynamic table name index after verifying its decoded name.
    Indexed {
        /// The combined static/dynamic table index to emit.
        index: u64,
        /// The decoded opaque name bytes expected at `index`.
        decoded: &'a [u8],
    },
    /// Emits decoded opaque name bytes as a plain literal string.
    Literal(&'a [u8]),
}

/// Explicit Huffman choices for one HPACK literal field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HpackLiteralHuffman(u8);

impl HpackLiteralHuffman {
    /// Encodes neither literal string with Huffman coding.
    pub const NONE: Self = Self(0);
    /// Encodes a literal name with Huffman coding.
    pub const NAME: Self = Self(1);
    /// Encodes the literal value with Huffman coding.
    pub const VALUE: Self = Self(2);
    /// Encodes both emitted literal strings with Huffman coding.
    pub const BOTH: Self = Self(3);

    /// Creates a strategy from independent name and value choices.
    pub const fn new(name: bool, value: bool) -> Self {
        Self((name as u8) | ((value as u8) << 1))
    }

    /// Returns whether a literal name is Huffman encoded.
    pub const fn encodes_name(self) -> bool {
        self.0 & Self::NAME.0 != 0
    }

    /// Returns whether a literal value is Huffman encoded.
    pub const fn encodes_value(self) -> bool {
        self.0 & Self::VALUE.0 != 0
    }
}

/// Failure to construct or advance an HPACK block encoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HpackEncodeError {
    /// The configured allowed maximum exceeds the table's physical capacity.
    AllowedMaximumExceedsCapacity {
        /// The requested policy maximum.
        allowed: usize,
        /// The physical table capacity.
        capacity: usize,
    },
    /// A required leading dynamic-table size update has not been emitted.
    DynamicTableSizeUpdateRequired,
    /// A required leading dynamic-table size update did not match the exact pending value.
    DynamicTableSizeUpdateMismatch {
        /// The exact next required maximum.
        expected: usize,
        /// The requested maximum.
        requested: usize,
    },
    /// A dynamic-table update was requested after a header field.
    DynamicTableSizeUpdateAfterField,
    /// A dynamic-table update exceeds the encoder's configured allowed maximum.
    DynamicTableSizeUpdateExceedsAllowed {
        /// The requested maximum.
        requested: usize,
        /// The encoder policy maximum.
        allowed: usize,
    },
    /// A combined static/dynamic table index cannot be represented on the wire.
    IndexNotRepresentable {
        /// The requested index.
        index: u64,
    },
    /// A combined static/dynamic table index is unavailable.
    UnavailableIndex {
        /// The requested index.
        index: usize,
    },
    /// An indexed literal name did not match the supplied decoded name.
    IndexedLiteralNameMismatch {
        /// The combined static/dynamic table index.
        index: u64,
    },
    /// Huffman name encoding was requested for an indexed name with no emitted name bytes.
    HuffmanNameForIndexedName,
    /// Huffman encoding a literal name failed during preflight.
    HuffmanName(HpackHuffmanEncodeError),
    /// Huffman encoding a literal value failed during preflight.
    HuffmanValue(HpackHuffmanEncodeError),
    /// An encoded string length cannot be represented by the HPACK integer format.
    StringLengthNotRepresentable {
        /// The encoded string length.
        length: usize,
    },
    /// The exact HPACK literal representation length overflows `usize`.
    RepresentationLengthOverflow,
    /// Calculating an incremental-indexing entry size failed before output was written.
    DynamicTableEntrySize(HpackDynamicTableError),
    /// A dynamic-table maximum cannot be represented on the wire.
    MaximumSizeNotRepresentable {
        /// The requested maximum.
        maximum_size: usize,
    },
    /// A representation could not be built in the supplied destination.
    Representation(HpackRepresentationBuildError),
}

impl fmt::Display for HpackEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllowedMaximumExceedsCapacity { allowed, capacity } => write!(
                f,
                "HPACK allowed maximum {allowed} exceeds table capacity {capacity}"
            ),
            Self::DynamicTableSizeUpdateRequired => {
                f.write_str("HPACK dynamic-table size update is required before a header field")
            }
            Self::DynamicTableSizeUpdateMismatch {
                expected,
                requested,
            } => write!(
                f,
                "HPACK dynamic-table update {requested} does not match required update {expected}"
            ),
            Self::DynamicTableSizeUpdateAfterField => {
                f.write_str("HPACK dynamic-table update follows a header field")
            }
            Self::DynamicTableSizeUpdateExceedsAllowed { requested, allowed } => write!(
                f,
                "HPACK dynamic-table update {requested} exceeds allowed maximum {allowed}"
            ),
            Self::IndexNotRepresentable { index } => {
                write!(f, "HPACK index {index} cannot be represented on the wire")
            }
            Self::UnavailableIndex { index } => {
                write!(f, "HPACK index {index} is unavailable")
            }
            Self::IndexedLiteralNameMismatch { index } => {
                write!(
                    f,
                    "HPACK indexed literal name at index {index} does not match"
                )
            }
            Self::HuffmanNameForIndexedName => {
                f.write_str("HPACK Huffman name encoding requires an emitted literal name")
            }
            Self::HuffmanName(error) => {
                write!(f, "could not Huffman encode HPACK literal name: {error}")
            }
            Self::HuffmanValue(error) => {
                write!(f, "could not Huffman encode HPACK literal value: {error}")
            }
            Self::StringLengthNotRepresentable { length } => write!(
                f,
                "HPACK string length {length} cannot be represented on the wire"
            ),
            Self::RepresentationLengthOverflow => {
                f.write_str("HPACK literal representation length overflows usize")
            }
            Self::DynamicTableEntrySize(error) => write!(
                f,
                "could not calculate HPACK dynamic-table entry size: {error:?}"
            ),
            Self::MaximumSizeNotRepresentable { maximum_size } => write!(
                f,
                "HPACK maximum size {maximum_size} cannot be represented on the wire"
            ),
            Self::Representation(error) => {
                write!(f, "could not build HPACK representation: {error}")
            }
        }
    }
}

/// An encoder for one HPACK block borrowing connection-owned dynamic-table state.
pub struct HpackBlockEncoder<'table, 'storage, 'entries> {
    table: &'table mut HpackDynamicTable<'storage, 'entries>,
    pending: &'table mut PendingSizes,
    allowed_maximum_size: usize,
    has_emitted_field: bool,
}

impl<'table, 'storage, 'entries> HpackBlockEncoder<'table, 'storage, 'entries> {
    pub(super) fn from_context(
        table: &'table mut HpackDynamicTable<'storage, 'entries>,
        pending: &'table mut PendingSizes,
        allowed_maximum_size: usize,
    ) -> Self {
        Self {
            table,
            pending,
            allowed_maximum_size,
            has_emitted_field: false,
        }
    }

    /// Returns whether a leading dynamic-table size update must precede a field.
    pub const fn requires_size_update(&self) -> bool {
        self.pending.next().is_some()
    }

    /// Returns whether this block has emitted a header-field representation.
    pub const fn has_emitted_field(&self) -> bool {
        self.has_emitted_field
    }

    /// Encodes one currently resolvable combined static/dynamic table index.
    pub fn encode_indexed<'destination>(
        &mut self,
        destination: &'destination mut [u8],
        index: u64,
    ) -> Result<&'destination [u8], HpackEncodeError> {
        if self.pending.next().is_some() {
            return Err(HpackEncodeError::DynamicTableSizeUpdateRequired);
        }
        self.resolve(index)?;
        let output = HpackIndexedFieldBuilder::new(destination, index)
            .build()
            .map_err(HpackEncodeError::Representation)?;
        self.has_emitted_field = true;
        Ok(output)
    }

    /// Encodes one plain literal field and inserts it only for incremental indexing.
    ///
    /// Inputs are decoded opaque bytes. This convenience method always emits non-Huffman strings.
    pub fn encode_literal<'destination>(
        &mut self,
        destination: &'destination mut [u8],
        mode: HpackLiteralMode,
        name: HpackEncodeLiteralName<'_>,
        value: &[u8],
    ) -> Result<&'destination [u8], HpackEncodeError> {
        self.encode_literal_with_huffman(destination, mode, name, value, HpackLiteralHuffman::NONE)
    }

    /// Encodes one literal field with explicit Huffman choices for emitted strings.
    ///
    /// Inputs and any incremental-indexing table entry remain decoded opaque bytes.
    pub fn encode_literal_with_huffman<'destination>(
        &mut self,
        destination: &'destination mut [u8],
        mode: HpackLiteralMode,
        name: HpackEncodeLiteralName<'_>,
        value: &[u8],
        strategy: HpackLiteralHuffman,
    ) -> Result<&'destination [u8], HpackEncodeError> {
        if self.pending.next().is_some() {
            return Err(HpackEncodeError::DynamicTableSizeUpdateRequired);
        }

        let (decoded_name, name_index, literal_name) = match name {
            HpackEncodeLiteralName::Indexed { index, decoded } => {
                if strategy.encodes_name() {
                    return Err(HpackEncodeError::HuffmanNameForIndexedName);
                }
                let resolved = self.resolve(index)?;
                if resolved.name() != decoded {
                    return Err(HpackEncodeError::IndexedLiteralNameMismatch { index });
                }
                (decoded, index, None)
            }
            HpackEncodeLiteralName::Literal(decoded) => (decoded, 0, Some(decoded)),
        };
        let entry_size = if mode == HpackLiteralMode::IncrementalIndexing {
            Some(
                HpackDynamicTable::entry_size(decoded_name, value)
                    .map_err(HpackEncodeError::DynamicTableEntrySize)?,
            )
        } else {
            None
        };
        let name_encoded_len = match literal_name {
            Some(decoded) if strategy.encodes_name() => {
                HpackHuffmanEncoder::required_encoded_len(decoded)
                    .map_err(HpackEncodeError::HuffmanName)?
            }
            Some(decoded) => decoded.len(),
            None => 0,
        };
        let value_encoded_len = if strategy.encodes_value() {
            HpackHuffmanEncoder::required_encoded_len(value)
                .map_err(HpackEncodeError::HuffmanValue)?
        } else {
            value.len()
        };
        let name_string_len = literal_name
            .map(|_| string_len(name_encoded_len))
            .transpose()?;
        let value_string_len = string_len(value_encoded_len)?;
        let required = canonical_encoded_len(name_index, prefix_mask(mode))
            .checked_add(name_string_len.unwrap_or(0))
            .and_then(|length| length.checked_add(value_string_len))
            .ok_or(HpackEncodeError::RepresentationLengthOverflow)?;
        if destination.len() < required {
            return Err(HpackEncodeError::Representation(
                HpackRepresentationBuildError::BufferTooShort {
                    required,
                    available: destination.len(),
                },
            ));
        }

        let representation = &mut destination[..required];
        let name_index_len = canonical_encoded_len(name_index, prefix_mask(mode));
        let (name_index_destination, remainder) = representation.split_at_mut(name_index_len);
        write_canonical_for_valid_prefix(
            name_index_destination,
            prefix_bits(mode),
            prefix_mask(mode),
            high_bits(mode),
            name_index,
        );
        let remainder = if let Some(decoded) = literal_name {
            let encoded_len = name_encoded_len;
            let string_len = name_string_len.unwrap_or(0);
            let (string_destination, remainder) = remainder.split_at_mut(string_len);
            write_string(
                string_destination,
                decoded,
                encoded_len,
                strategy.encodes_name(),
            );
            remainder
        } else {
            remainder
        };
        write_string(
            remainder,
            value,
            value_encoded_len,
            strategy.encodes_value(),
        );

        if let Some(entry_size) = entry_size {
            self.table
                .insert_prevalidated(decoded_name, value, entry_size);
        }
        self.has_emitted_field = true;
        Ok(&*representation)
    }

    /// Encodes and applies one leading RFC dynamic-table maximum update.
    pub fn encode_dynamic_table_size_update<'destination>(
        &mut self,
        destination: &'destination mut [u8],
        maximum_size: usize,
    ) -> Result<&'destination [u8], HpackEncodeError> {
        if self.has_emitted_field {
            return Err(HpackEncodeError::DynamicTableSizeUpdateAfterField);
        }
        if let Some(expected) = self.pending.next()
            && maximum_size != expected
        {
            return Err(HpackEncodeError::DynamicTableSizeUpdateMismatch {
                expected,
                requested: maximum_size,
            });
        }
        let permitted_maximum_size = self.allowed_maximum_size.min(self.table.capacity());
        if maximum_size > permitted_maximum_size {
            return Err(HpackEncodeError::DynamicTableSizeUpdateExceedsAllowed {
                requested: maximum_size,
                allowed: permitted_maximum_size,
            });
        }
        let maximum_size_u64 = u64::try_from(maximum_size)
            .map_err(|_| HpackEncodeError::MaximumSizeNotRepresentable { maximum_size })?;
        let required = canonical_encoded_len(maximum_size_u64, 0x1f);
        if destination.len() < required {
            return Err(HpackEncodeError::Representation(
                HpackRepresentationBuildError::BufferTooShort {
                    required,
                    available: destination.len(),
                },
            ));
        }
        let output = HpackDynamicTableSizeUpdateBuilder::new(destination, maximum_size_u64)
            .build()
            .map_err(HpackEncodeError::Representation)?;
        self.table.set_maximum_size_prevalidated(maximum_size);
        if self.pending.next().is_some() {
            self.pending.advance();
        }
        Ok(output)
    }

    /// Establishes successful semantic completion of this HPACK block.
    pub fn finish(self) -> Result<(), HpackEncodeError> {
        if self.pending.next().is_some() {
            Err(HpackEncodeError::DynamicTableSizeUpdateRequired)
        } else {
            Ok(())
        }
    }

    fn resolve(&self, index: u64) -> Result<HpackHeaderFieldRef<'_>, HpackEncodeError> {
        let index = usize::try_from(index)
            .map_err(|_| HpackEncodeError::IndexNotRepresentable { index })?;
        if index == 0 {
            return Err(HpackEncodeError::UnavailableIndex { index });
        }
        if index <= HPACK_STATIC_TABLE_LEN {
            return HpackStaticTable::get(index)
                .ok_or(HpackEncodeError::UnavailableIndex { index });
        }
        self.table
            .get(index - HPACK_STATIC_TABLE_LEN)
            .ok_or(HpackEncodeError::UnavailableIndex { index })
    }
}

fn prefix_bits(mode: HpackLiteralMode) -> u8 {
    match mode {
        HpackLiteralMode::IncrementalIndexing => 6,
        HpackLiteralMode::WithoutIndexing | HpackLiteralMode::NeverIndexed => 4,
    }
}

fn prefix_mask(mode: HpackLiteralMode) -> u8 {
    (1 << prefix_bits(mode)) - 1
}

fn high_bits(mode: HpackLiteralMode) -> u8 {
    match mode {
        HpackLiteralMode::IncrementalIndexing => 0x40,
        HpackLiteralMode::WithoutIndexing => 0,
        HpackLiteralMode::NeverIndexed => 0x10,
    }
}

fn string_len(encoded_len: usize) -> Result<usize, HpackEncodeError> {
    let encoded_len_u64 =
        u64::try_from(encoded_len).map_err(|_| HpackEncodeError::StringLengthNotRepresentable {
            length: encoded_len,
        })?;
    canonical_encoded_len(encoded_len_u64, 0x7f)
        .checked_add(encoded_len)
        .ok_or(HpackEncodeError::RepresentationLengthOverflow)
}

fn write_string(destination: &mut [u8], decoded: &[u8], encoded_len: usize, huffman: bool) {
    let encoded_len_u64 = encoded_len as u64;
    let length_len = canonical_encoded_len(encoded_len_u64, 0x7f);
    let (length_destination, payload_destination) = destination.split_at_mut(length_len);
    write_canonical_for_valid_prefix(
        length_destination,
        7,
        0x7f,
        if huffman { 0x80 } else { 0 },
        encoded_len_u64,
    );
    if huffman {
        HpackHuffmanEncoder::encode_prevalidated(decoded, payload_destination);
    } else {
        payload_destination.copy_from_slice(decoded);
    }
}
