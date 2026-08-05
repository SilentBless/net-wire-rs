//! Stateful, allocation-free decoding of complete HPACK header blocks.

use core::fmt;

use super::context::PendingSizes;
use super::{
    HpackDynamicTable, HpackDynamicTableError, HpackHuffmanDecodeError, HpackHuffmanDecoder,
    HpackLiteralMode, HpackRepresentation, HpackRepresentationParseError, HpackStaticTable,
    HpackStringLiteral,
};

/// The indexing semantics of a decoded HPACK header field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HpackDecodedFieldMode {
    /// The field was selected by an indexed representation.
    Indexed,
    /// The literal field was inserted into the dynamic table.
    IncrementalIndexing,
    /// The literal field was not inserted into the dynamic table.
    WithoutIndexing,
    /// The literal field was not inserted and is marked sensitive.
    NeverIndexed,
}

/// A decoded byte-oriented header field backed entirely by the caller output buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HpackDecodedField<'a> {
    name: &'a [u8],
    value: &'a [u8],
    mode: HpackDecodedFieldMode,
}

impl<'a> HpackDecodedField<'a> {
    /// Returns the decoded opaque header name.
    pub const fn name(self) -> &'a [u8] {
        self.name
    }

    /// Returns the decoded opaque header value.
    pub const fn value(self) -> &'a [u8] {
        self.value
    }

    /// Returns the representation's indexing semantics.
    pub const fn mode(self) -> HpackDecodedFieldMode {
        self.mode
    }
}

/// One explicit result of advancing an HPACK header-block decoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HpackDecodeStep<'a> {
    /// A header field was decoded into caller-owned output.
    Field(HpackDecodedField<'a>),
    /// A leading dynamic-table maximum update was applied.
    DynamicTableSizeUpdate {
        /// The requested and applied RFC dynamic-table maximum.
        maximum_size: usize,
    },
    /// The supplied block has no remaining representations.
    Complete,
}

/// Failure to construct or advance an HPACK block decoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HpackDecodeError {
    /// A representation could not be parsed.
    Representation(HpackRepresentationParseError),
    /// A combined static/dynamic table index cannot be represented as `usize`.
    IndexNotRepresentable {
        /// The wire index.
        index: u64,
    },
    /// A combined static/dynamic table index is unavailable.
    UnavailableIndex {
        /// The wire index.
        index: u64,
    },
    /// A dynamic-table update cannot be represented as `usize`.
    MaximumSizeNotRepresentable {
        /// The wire maximum size.
        maximum_size: u64,
    },
    /// The configured allowed maximum exceeds the table's physical capacity.
    AllowedMaximumExceedsCapacity {
        /// The requested policy maximum.
        allowed: usize,
        /// The physical table capacity.
        capacity: usize,
    },
    /// A required leading dynamic-table size update has not been received.
    DynamicTableSizeUpdateRequired,
    /// A leading dynamic-table update did not match the exact pending value.
    DynamicTableSizeUpdateMismatch {
        /// The exact next required maximum.
        expected: usize,
        /// The wire-requested maximum.
        requested: usize,
    },
    /// A dynamic-table update appeared after a header field.
    DynamicTableSizeUpdateAfterField,
    /// A dynamic-table update exceeds the decoder's configured allowed maximum.
    DynamicTableSizeUpdateExceedsAllowed {
        /// The wire-requested maximum.
        requested: usize,
        /// The decoder policy maximum.
        allowed: usize,
    },
    /// Applying a dynamic-table update failed.
    DynamicTableSizeUpdate(HpackDynamicTableError),
    /// Decoding a literal name's Huffman bytes failed.
    HuffmanName(HpackHuffmanDecodeError),
    /// Decoding a literal value's Huffman bytes failed.
    HuffmanValue(HpackHuffmanDecodeError),
    /// Name and value lengths cannot be added as `usize`.
    DecodedLengthOverflow,
    /// The RFC dynamic-table entry-size calculation overflowed `usize`.
    EntrySizeOverflow,
    /// The caller output cannot contain the complete decoded field.
    OutputTooShort {
        /// Bytes required for the complete field.
        required: usize,
        /// Bytes supplied by the caller.
        available: usize,
    },
}

impl fmt::Display for HpackDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Representation(error) => write!(f, "invalid HPACK representation: {error}"),
            Self::IndexNotRepresentable { index } => {
                write!(f, "HPACK index {index} cannot be represented as usize")
            }
            Self::UnavailableIndex { index } => write!(f, "HPACK index {index} is unavailable"),
            Self::MaximumSizeNotRepresentable { maximum_size } => write!(
                f,
                "HPACK maximum size {maximum_size} cannot be represented as usize"
            ),
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
            Self::DynamicTableSizeUpdate(error) => {
                write!(f, "HPACK dynamic-table update failed: {error:?}")
            }
            Self::HuffmanName(error) => write!(f, "invalid HPACK Huffman name: {error}"),
            Self::HuffmanValue(error) => write!(f, "invalid HPACK Huffman value: {error}"),
            Self::DecodedLengthOverflow => {
                f.write_str("HPACK decoded field length overflows usize")
            }
            Self::EntrySizeOverflow => {
                f.write_str("HPACK dynamic-table entry size overflows usize")
            }
            Self::OutputTooShort {
                required,
                available,
            } => write!(
                f,
                "HPACK output is too short: need {required} bytes, have {available}"
            ),
        }
    }
}

/// A bounded decoder for one complete HPACK block borrowing connection-owned table state.
pub struct HpackBlockDecoder<'block, 'table, 'storage, 'entries> {
    remaining: &'block [u8],
    table: &'table mut HpackDynamicTable<'storage, 'entries>,
    pending: &'table mut PendingSizes,
    allowed_maximum_size: usize,
    saw_field: bool,
}

impl<'block, 'table, 'storage, 'entries> HpackBlockDecoder<'block, 'table, 'storage, 'entries> {
    pub(super) fn from_context(
        block: &'block [u8],
        table: &'table mut HpackDynamicTable<'storage, 'entries>,
        pending: &'table mut PendingSizes,
        allowed_maximum_size: usize,
    ) -> Self {
        Self {
            remaining: block,
            table,
            pending,
            allowed_maximum_size,
            saw_field: false,
        }
    }

    /// Returns the representation bytes not yet consumed.
    pub const fn remaining(&self) -> &'block [u8] {
        self.remaining
    }

    /// Returns whether every representation in this block has been consumed.
    ///
    /// This does not establish semantic success when a required leading size update is absent;
    /// call [`Self::decode_next`] and receive [`HpackDecodeStep::Complete`] to validate that case.
    pub const fn is_complete(&self) -> bool {
        self.remaining.is_empty()
    }

    /// Decodes or applies exactly one representation without partial caller-visible effects.
    pub fn decode_next<'output>(
        &mut self,
        output: &'output mut [u8],
    ) -> Result<HpackDecodeStep<'output>, HpackDecodeError> {
        if self.remaining.is_empty() {
            if self.pending.next().is_some() {
                return Err(HpackDecodeError::DynamicTableSizeUpdateRequired);
            }
            return Ok(HpackDecodeStep::Complete);
        }
        let representation =
            HpackRepresentation::parse(self.remaining).map_err(HpackDecodeError::Representation)?;
        match representation {
            HpackRepresentation::DynamicTableSizeUpdate(update) => {
                if self.saw_field {
                    return Err(HpackDecodeError::DynamicTableSizeUpdateAfterField);
                }
                let maximum_size = usize::try_from(update.size_value()).map_err(|_| {
                    HpackDecodeError::MaximumSizeNotRepresentable {
                        maximum_size: update.size_value(),
                    }
                })?;
                if let Some(expected) = self.pending.next()
                    && maximum_size != expected
                {
                    return Err(HpackDecodeError::DynamicTableSizeUpdateMismatch {
                        expected,
                        requested: maximum_size,
                    });
                }
                if maximum_size > self.allowed_maximum_size {
                    return Err(HpackDecodeError::DynamicTableSizeUpdateExceedsAllowed {
                        requested: maximum_size,
                        allowed: self.allowed_maximum_size,
                    });
                }
                self.table
                    .set_maximum_size(maximum_size)
                    .map_err(HpackDecodeError::DynamicTableSizeUpdate)?;
                self.remaining = &self.remaining[update.as_bytes().len()..];
                if self.pending.next().is_some() {
                    self.pending.advance();
                }
                Ok(HpackDecodeStep::DynamicTableSizeUpdate { maximum_size })
            }
            HpackRepresentation::Indexed(indexed) => {
                if self.pending.next().is_some() {
                    return Err(HpackDecodeError::DynamicTableSizeUpdateRequired);
                }
                let consumed = indexed.as_bytes().len();
                let (name_len, required) = {
                    let field = self.resolve(indexed.index_value())?;
                    let name_len = field.name().len();
                    let required = name_len
                        .checked_add(field.value().len())
                        .ok_or(HpackDecodeError::DecodedLengthOverflow)?;
                    if output.len() < required {
                        return Err(HpackDecodeError::OutputTooShort {
                            required,
                            available: output.len(),
                        });
                    }
                    output[..name_len].copy_from_slice(field.name());
                    output[name_len..required].copy_from_slice(field.value());
                    (name_len, required)
                };
                self.remaining = &self.remaining[consumed..];
                self.saw_field = true;
                Ok(HpackDecodeStep::Field(HpackDecodedField {
                    name: &output[..name_len],
                    value: &output[name_len..required],
                    mode: HpackDecodedFieldMode::Indexed,
                }))
            }
            HpackRepresentation::Literal(literal) => {
                if self.pending.next().is_some() {
                    return Err(HpackDecodeError::DynamicTableSizeUpdateRequired);
                }
                let mode = match literal.mode() {
                    HpackLiteralMode::IncrementalIndexing => {
                        HpackDecodedFieldMode::IncrementalIndexing
                    }
                    HpackLiteralMode::WithoutIndexing => HpackDecodedFieldMode::WithoutIndexing,
                    HpackLiteralMode::NeverIndexed => HpackDecodedFieldMode::NeverIndexed,
                };
                let name = match literal.name() {
                    Some(name) => NameSource::Literal(name),
                    None => NameSource::Borrowed(self.resolve(literal.name_index_value())?.name()),
                };
                let value = literal.value();
                let name_len = name.required_len()?;
                let value_len = literal_len(value, false)?;
                let required = name_len
                    .checked_add(value_len)
                    .ok_or(HpackDecodeError::DecodedLengthOverflow)?;
                if output.len() < required {
                    return Err(HpackDecodeError::OutputTooShort {
                        required,
                        available: output.len(),
                    });
                }
                let entry_size = (mode == HpackDecodedFieldMode::IncrementalIndexing)
                    .then(|| {
                        HpackDynamicTable::entry_size(
                            &output[..name_len],
                            &output[name_len..required],
                        )
                    })
                    .transpose()
                    .map_err(|_| HpackDecodeError::EntrySizeOverflow)?;
                write_name(name, &mut output[..name_len])?;
                write_literal(value, &mut output[name_len..required], false)?;
                if let Some(entry_size) = entry_size {
                    self.table.insert_prevalidated(
                        &output[..name_len],
                        &output[name_len..required],
                        entry_size,
                    );
                }
                self.remaining = &self.remaining[literal.as_bytes().len()..];
                self.saw_field = true;
                Ok(HpackDecodeStep::Field(HpackDecodedField {
                    name: &output[..name_len],
                    value: &output[name_len..required],
                    mode,
                }))
            }
        }
    }

    fn resolve(&self, index: u64) -> Result<super::HpackHeaderFieldRef<'_>, HpackDecodeError> {
        let index = usize::try_from(index)
            .map_err(|_| HpackDecodeError::IndexNotRepresentable { index })?;
        if index == 0 {
            return Err(HpackDecodeError::UnavailableIndex { index: 0 });
        }
        if index <= super::HPACK_STATIC_TABLE_LEN {
            return HpackStaticTable::get(index).ok_or(HpackDecodeError::UnavailableIndex {
                index: index as u64,
            });
        }
        let dynamic = index - super::HPACK_STATIC_TABLE_LEN;
        self.table
            .get(dynamic)
            .ok_or(HpackDecodeError::UnavailableIndex {
                index: index as u64,
            })
    }
}

#[derive(Clone, Copy)]
enum NameSource<'a> {
    Borrowed(&'a [u8]),
    Literal(HpackStringLiteral<'a>),
}

impl NameSource<'_> {
    fn required_len(self) -> Result<usize, HpackDecodeError> {
        match self {
            Self::Borrowed(bytes) => Ok(bytes.len()),
            Self::Literal(literal) => literal_len(literal, true),
        }
    }
}

fn literal_len(literal: HpackStringLiteral<'_>, name: bool) -> Result<usize, HpackDecodeError> {
    if literal.is_huffman() {
        HpackHuffmanDecoder::required_decoded_len(literal.encoded_bytes()).map_err(|error| {
            if name {
                HpackDecodeError::HuffmanName(error)
            } else {
                HpackDecodeError::HuffmanValue(error)
            }
        })
    } else {
        Ok(literal.encoded_bytes().len())
    }
}

fn write_name(source: NameSource<'_>, output: &mut [u8]) -> Result<(), HpackDecodeError> {
    match source {
        NameSource::Borrowed(bytes) => output.copy_from_slice(bytes),
        NameSource::Literal(literal) => write_literal(literal, output, true)?,
    }
    Ok(())
}

fn write_literal(
    literal: HpackStringLiteral<'_>,
    output: &mut [u8],
    name: bool,
) -> Result<(), HpackDecodeError> {
    if literal.is_huffman() {
        HpackHuffmanDecoder::new(literal.encoded_bytes(), output)
            .decode()
            .map_err(|error| {
                if name {
                    HpackDecodeError::HuffmanName(error)
                } else {
                    HpackDecodeError::HuffmanValue(error)
                }
            })?;
    } else {
        output.copy_from_slice(literal.encoded_bytes());
    }
    Ok(())
}
