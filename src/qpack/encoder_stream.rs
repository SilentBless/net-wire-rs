//! Application of parsed RFC 9204 encoder-stream instructions.

use core::fmt;

use super::{
    QPACK_STATIC_TABLE_LEN, QpackDynamicTable, QpackDynamicTableError, QpackEncoderInstruction,
    QpackEncoderInstructions, QpackEncoderInstructionsParseError, QpackHuffmanDecodeError,
    QpackHuffmanDecoder, QpackStaticTable, QpackStringLiteral,
};

/// Applies one parsed QPACK encoder-stream instruction to a dynamic table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackEncoderInstructionApplier {
    maximum_dynamic_table_capacity: u64,
}

impl QpackEncoderInstructionApplier {
    /// Creates an applier with the locally advertised maximum dynamic-table capacity.
    pub const fn new(maximum_dynamic_table_capacity: u64) -> Self {
        Self {
            maximum_dynamic_table_capacity,
        }
    }

    /// Returns the locally advertised maximum permitted dynamic-table capacity.
    pub const fn maximum_dynamic_table_capacity(self) -> u64 {
        self.maximum_dynamic_table_capacity
    }

    /// Applies one instruction using caller-owned scratch storage for decoded or copied bytes.
    ///
    /// Scratch is unchanged when preflight fails. Once staging starts, a later rejected eviction
    /// policy may leave scratch clobbered, while the table remains unchanged on every error.
    /// Effects observed by `evictable` cannot be rolled back.
    pub fn apply<F>(
        &self,
        table: &mut QpackDynamicTable<'_, '_>,
        instruction: QpackEncoderInstruction<'_>,
        scratch: &mut [u8],
        evictable: F,
    ) -> Result<QpackEncoderInstructionApplyOutcome, QpackEncoderInstructionApplyError>
    where
        F: FnMut(u64) -> bool,
    {
        match instruction {
            QpackEncoderInstruction::SetDynamicTableCapacity(instruction) => {
                let requested = instruction.capacity().value();
                if requested > self.maximum_dynamic_table_capacity {
                    return Err(QpackEncoderInstructionApplyError::CapacityExceedsMaximum {
                        requested,
                        maximum: self.maximum_dynamic_table_capacity,
                    });
                }
                let capacity = usize::try_from(requested).map_err(|_| {
                    QpackEncoderInstructionApplyError::CapacityNotRepresentable { value: requested }
                })?;
                table
                    .set_capacity(capacity, evictable)
                    .map_err(QpackEncoderInstructionApplyError::CapacityChange)?;
                Ok(QpackEncoderInstructionApplyOutcome::CapacityUpdated { capacity })
            }
            QpackEncoderInstruction::InsertWithNameReference(instruction) => {
                let value = instruction.value();
                if instruction.is_static() {
                    let index = instruction.name_index().value();
                    if index >= QPACK_STATIC_TABLE_LEN as u64 {
                        return Err(
                            QpackEncoderInstructionApplyError::StaticNameIndexOutOfRange { index },
                        );
                    }
                    let name = QpackStaticTable::get(index as usize)
                        .ok_or(
                            QpackEncoderInstructionApplyError::StaticNameIndexOutOfRange { index },
                        )?
                        .name();
                    let value_len = decoded_len(value, false)?;
                    let required = if value.is_huffman() { value_len } else { 0 };
                    preflight_insert(table, name.len(), value_len, required, scratch.len())?;
                    let value = if value.is_huffman() {
                        decode(value, &mut scratch[..value_len], false)?
                    } else {
                        value.encoded_payload()
                    };
                    insert(table, name, value, evictable)
                } else {
                    let relative = instruction.name_index().value();
                    let name_len = table
                        .get_encoder_relative(relative)
                        .map_err(QpackEncoderInstructionApplyError::DynamicNameReference)?
                        .name()
                        .len();
                    let value_len = decoded_len(value, false)?;
                    let required =
                        checked_sum(name_len, if value.is_huffman() { value_len } else { 0 })?;
                    preflight_insert(table, name_len, value_len, required, scratch.len())?;
                    let (name_destination, value_destination) =
                        scratch[..required].split_at_mut(name_len);
                    let source = table
                        .get_encoder_relative(relative)
                        .map_err(QpackEncoderInstructionApplyError::DynamicNameReference)?;
                    name_destination.copy_from_slice(source.name());
                    let value = if value.is_huffman() {
                        decode(value, value_destination, false)?
                    } else {
                        value.encoded_payload()
                    };
                    insert(table, name_destination, value, evictable)
                }
            }
            QpackEncoderInstruction::InsertWithLiteralName(instruction) => {
                let name_literal = instruction.name();
                let value_literal = instruction.value();
                let name_len = decoded_len(name_literal, true)?;
                let value_len = decoded_len(value_literal, false)?;
                let name_scratch = if name_literal.is_huffman() {
                    name_len
                } else {
                    0
                };
                let value_scratch = if value_literal.is_huffman() {
                    value_len
                } else {
                    0
                };
                let required = checked_sum(name_scratch, value_scratch)?;
                preflight_insert(table, name_len, value_len, required, scratch.len())?;
                let (name_destination, value_destination) =
                    scratch[..required].split_at_mut(name_scratch);
                let name = if name_literal.is_huffman() {
                    decode(name_literal, name_destination, true)?
                } else {
                    name_literal.encoded_payload()
                };
                let value = if value_literal.is_huffman() {
                    decode(value_literal, value_destination, false)?
                } else {
                    value_literal.encoded_payload()
                };
                insert(table, name, value, evictable)
            }
            QpackEncoderInstruction::Duplicate(instruction) => {
                let relative = instruction.index().value();
                let source = table
                    .get_encoder_relative(relative)
                    .map_err(QpackEncoderInstructionApplyError::DuplicateReference)?;
                let name_len = source.name().len();
                let value_len = source.value().len();
                let required = checked_sum(name_len, value_len)?;
                preflight_insert(table, name_len, value_len, required, scratch.len())?;
                let source = table
                    .get_encoder_relative(relative)
                    .map_err(QpackEncoderInstructionApplyError::DuplicateReference)?;
                let (name, value) = scratch[..required].split_at_mut(name_len);
                name.copy_from_slice(source.name());
                value.copy_from_slice(source.value());
                insert(table, name, value, evictable)
            }
        }
    }

    /// Validates and applies a complete unframed encoder-stream instruction sequence.
    ///
    /// The complete sequence is validated before any instruction is applied. On an application
    /// failure, earlier successful instructions remain applied and later instructions are not
    /// attempted. Scratch and `evictable` retain the per-instruction effects documented by
    /// [`Self::apply`].
    pub fn apply_sequence<F>(
        &self,
        table: &mut QpackDynamicTable<'_, '_>,
        bytes: &[u8],
        scratch: &mut [u8],
        mut evictable: F,
    ) -> Result<(), QpackEncoderInstructionsApplyError>
    where
        F: FnMut(u64) -> bool,
    {
        let instructions = QpackEncoderInstructions::parse(bytes)
            .map_err(QpackEncoderInstructionsApplyError::Parse)?;
        let mut offset = 0usize;

        for instruction in instructions.iter() {
            let instruction = instruction.map_err(QpackEncoderInstructionsApplyError::Parse)?;
            self.apply(table, instruction, scratch, &mut evictable)
                .map_err(|error| QpackEncoderInstructionsApplyError::Apply { offset, error })?;
            offset += instruction.as_bytes().len();
        }

        Ok(())
    }
}

/// The successful result of applying one encoder-stream instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackEncoderInstructionApplyOutcome {
    /// The dynamic-table capacity changed.
    CapacityUpdated {
        /// The new RFC dynamic-table capacity.
        capacity: usize,
    },
    /// A field was inserted into the dynamic table.
    Inserted {
        /// The new entry's zero-based absolute index.
        absolute_index: u64,
    },
}

/// Failure to apply one QPACK encoder-stream instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackEncoderInstructionApplyError {
    /// A capacity instruction exceeds the configured locally advertised maximum.
    CapacityExceedsMaximum {
        /// The requested capacity.
        requested: u64,
        /// The configured maximum capacity.
        maximum: u64,
    },
    /// A capacity cannot be represented by this target's `usize`.
    CapacityNotRepresentable {
        /// The unrepresentable capacity value.
        value: u64,
    },
    /// Updating dynamic-table capacity failed.
    CapacityChange(QpackDynamicTableError),
    /// A static name-reference index is outside the static table.
    StaticNameIndexOutOfRange {
        /// The invalid static-table index.
        index: u64,
    },
    /// Resolving a dynamic name reference failed.
    DynamicNameReference(QpackDynamicTableError),
    /// Resolving a Duplicate reference failed.
    DuplicateReference(QpackDynamicTableError),
    /// Decoding a literal name failed.
    LiteralNameHuffman(QpackHuffmanDecodeError),
    /// Decoding a value failed.
    ValueHuffman(QpackHuffmanDecodeError),
    /// Computing the required scratch length overflowed `usize`.
    ScratchLengthOverflow,
    /// Caller scratch storage cannot contain all required staged bytes.
    ScratchTooShort {
        /// Staging bytes required.
        required: usize,
        /// Caller bytes available.
        available: usize,
    },
    /// Inserting the preflighted field failed.
    Insert(QpackDynamicTableError),
}

impl QpackEncoderInstructionApplyError {
    /// Returns whether this failure is an RFC QPACK encoder-stream error.
    pub const fn is_encoder_stream_error(self) -> bool {
        match self {
            Self::CapacityExceedsMaximum { .. }
            | Self::StaticNameIndexOutOfRange { .. }
            | Self::DynamicNameReference(_)
            | Self::DuplicateReference(_) => true,
            Self::LiteralNameHuffman(
                QpackHuffmanDecodeError::EosSymbol
                | QpackHuffmanDecodeError::InvalidHuffmanCode
                | QpackHuffmanDecodeError::InvalidPadding,
            )
            | Self::ValueHuffman(
                QpackHuffmanDecodeError::EosSymbol
                | QpackHuffmanDecodeError::InvalidHuffmanCode
                | QpackHuffmanDecodeError::InvalidPadding,
            ) => true,
            Self::CapacityChange(QpackDynamicTableError::EvictionBlocked { .. }) => true,
            Self::Insert(QpackDynamicTableError::EntryLargerThanCapacity { .. })
            | Self::Insert(QpackDynamicTableError::EvictionBlocked { .. }) => true,
            Self::CapacityNotRepresentable { .. }
            | Self::CapacityChange(_)
            | Self::LiteralNameHuffman(_)
            | Self::ValueHuffman(_)
            | Self::ScratchLengthOverflow
            | Self::ScratchTooShort { .. }
            | Self::Insert(_) => false,
        }
    }
}

impl fmt::Display for QpackEncoderInstructionApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityExceedsMaximum { requested, maximum } => {
                write!(f, "QPACK capacity {requested} exceeds maximum {maximum}")
            }
            Self::CapacityNotRepresentable { value } => {
                write!(f, "QPACK capacity cannot be represented: {value}")
            }
            Self::CapacityChange(error) => write!(f, "QPACK capacity change failed: {error}"),
            Self::StaticNameIndexOutOfRange { index } => {
                write!(f, "QPACK static name index is out of range: {index}")
            }
            Self::DynamicNameReference(error) => {
                write!(f, "QPACK dynamic name reference failed: {error}")
            }
            Self::DuplicateReference(error) => {
                write!(f, "QPACK Duplicate reference failed: {error}")
            }
            Self::LiteralNameHuffman(error) => {
                write!(f, "QPACK literal name Huffman decode failed: {error}")
            }
            Self::ValueHuffman(error) => write!(f, "QPACK value Huffman decode failed: {error}"),
            Self::ScratchLengthOverflow => f.write_str("QPACK scratch length overflows usize"),
            Self::ScratchTooShort {
                required,
                available,
            } => write!(
                f,
                "QPACK scratch is too short: need {required} bytes, have {available}"
            ),
            Self::Insert(error) => write!(f, "QPACK insertion failed: {error}"),
        }
    }
}

impl core::error::Error for QpackEncoderInstructionApplyError {}

/// Failure to validate or apply a QPACK encoder-stream instruction sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackEncoderInstructionsApplyError {
    /// The complete sequence is malformed before application begins.
    Parse(QpackEncoderInstructionsParseError),
    /// Applying one validated instruction failed at this absolute byte offset.
    Apply {
        /// Absolute byte offset of the instruction that failed to apply.
        offset: usize,
        /// The instruction application failure.
        error: QpackEncoderInstructionApplyError,
    },
}

impl QpackEncoderInstructionsApplyError {
    /// Returns whether this failure is an RFC QPACK encoder-stream error.
    pub const fn is_encoder_stream_error(self) -> bool {
        match self {
            Self::Parse(_) => true,
            Self::Apply { error, .. } => error.is_encoder_stream_error(),
        }
    }
}

impl fmt::Display for QpackEncoderInstructionsApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => {
                write!(f, "QPACK encoder instruction sequence is invalid: {error}")
            }
            Self::Apply { offset, error } => {
                write!(
                    f,
                    "QPACK encoder instruction application failed at byte {offset}: {error}"
                )
            }
        }
    }
}

impl core::error::Error for QpackEncoderInstructionsApplyError {}

fn decoded_len(
    literal: QpackStringLiteral<'_>,
    name: bool,
) -> Result<usize, QpackEncoderInstructionApplyError> {
    if literal.is_huffman() {
        QpackHuffmanDecoder::required_decoded_len(literal.encoded_payload()).map_err(|error| {
            if name {
                QpackEncoderInstructionApplyError::LiteralNameHuffman(error)
            } else {
                QpackEncoderInstructionApplyError::ValueHuffman(error)
            }
        })
    } else {
        Ok(literal.encoded_payload().len())
    }
}

fn decode<'a>(
    literal: QpackStringLiteral<'_>,
    destination: &'a mut [u8],
    name: bool,
) -> Result<&'a [u8], QpackEncoderInstructionApplyError> {
    QpackHuffmanDecoder::new(literal.encoded_payload(), destination)
        .decode()
        .map_err(|error| {
            if name {
                QpackEncoderInstructionApplyError::LiteralNameHuffman(error)
            } else {
                QpackEncoderInstructionApplyError::ValueHuffman(error)
            }
        })
}

fn checked_sum(left: usize, right: usize) -> Result<usize, QpackEncoderInstructionApplyError> {
    left.checked_add(right)
        .ok_or(QpackEncoderInstructionApplyError::ScratchLengthOverflow)
}

fn preflight_insert(
    table: &QpackDynamicTable<'_, '_>,
    name_len: usize,
    value_len: usize,
    required: usize,
    available: usize,
) -> Result<(), QpackEncoderInstructionApplyError> {
    let entry_size = name_len
        .checked_add(value_len)
        .and_then(|length| length.checked_add(32))
        .ok_or(QpackEncoderInstructionApplyError::Insert(
            QpackDynamicTableError::EntrySizeOverflow,
        ))?;
    if entry_size > table.capacity() {
        return Err(QpackEncoderInstructionApplyError::Insert(
            QpackDynamicTableError::EntryLargerThanCapacity {
                entry_size,
                capacity: table.capacity(),
            },
        ));
    }
    if table.insert_count() == u64::MAX {
        return Err(QpackEncoderInstructionApplyError::Insert(
            QpackDynamicTableError::InsertCountOverflow,
        ));
    }
    if available < required {
        return Err(QpackEncoderInstructionApplyError::ScratchTooShort {
            required,
            available,
        });
    }
    Ok(())
}

fn insert<F>(
    table: &mut QpackDynamicTable<'_, '_>,
    name: &[u8],
    value: &[u8],
    evictable: F,
) -> Result<QpackEncoderInstructionApplyOutcome, QpackEncoderInstructionApplyError>
where
    F: FnMut(u64) -> bool,
{
    table
        .insert(name, value, evictable)
        .map(|absolute_index| QpackEncoderInstructionApplyOutcome::Inserted { absolute_index })
        .map_err(QpackEncoderInstructionApplyError::Insert)
}
