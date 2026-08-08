//! Checked construction of QPACK encoder-stream instructions.

use core::fmt;

use super::{
    QpackDuplicate, QpackInsertWithLiteralName, QpackInsertWithNameReference,
    QpackSetDynamicTableCapacity,
};
use crate::qpack::integer::{
    QPACK_INTEGER_MAX, QpackIntegerBuildError, canonical_encoded_len, integer_from_prevalidated,
    write_canonical_prevalidated,
};
use crate::qpack::string::{
    QpackStringLiteralBuildError, string_from_prevalidated, string_plan, write_string_prevalidated,
};

/// Failure to build a QPACK encoder-stream instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackEncoderInstructionBuildError {
    /// The Set Dynamic Table Capacity value is invalid.
    SetDynamicTableCapacity(#[doc = "The nested capacity-integer failure."] QpackIntegerBuildError),
    /// The Insert With Name Reference name index is invalid.
    InsertWithNameReferenceNameIndex(
        #[doc = "The nested name-index failure."] QpackIntegerBuildError,
    ),
    /// The Insert With Name Reference value is invalid.
    InsertWithNameReferenceValue(
        #[doc = "The nested value-string failure."] QpackStringLiteralBuildError,
    ),
    /// The Insert With Literal Name name is invalid.
    InsertWithLiteralNameName(
        #[doc = "The nested name-string failure."] QpackStringLiteralBuildError,
    ),
    /// The Insert With Literal Name value is invalid.
    InsertWithLiteralNameValue(
        #[doc = "The nested value-string failure."] QpackStringLiteralBuildError,
    ),
    /// The Duplicate index is invalid.
    DuplicateIndex(#[doc = "The nested duplicate-index failure."] QpackIntegerBuildError),
    /// Computing the total instruction length overflowed `usize`.
    RequiredLengthOverflow,
    /// The caller destination cannot contain the complete instruction.
    BufferTooShort {
        /// Bytes required.
        required: usize,
        /// Bytes available.
        available: usize,
    },
}

impl fmt::Display for QpackEncoderInstructionBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SetDynamicTableCapacity(error) => {
                write!(
                    f,
                    "QPACK Set Dynamic Table Capacity cannot be built: {error}"
                )
            }
            Self::InsertWithNameReferenceNameIndex(error) => {
                write!(
                    f,
                    "QPACK Insert With Name Reference name index cannot be built: {error}"
                )
            }
            Self::InsertWithNameReferenceValue(error) => {
                write!(
                    f,
                    "QPACK Insert With Name Reference value cannot be built: {error}"
                )
            }
            Self::InsertWithLiteralNameName(error) => {
                write!(
                    f,
                    "QPACK Insert With Literal Name name cannot be built: {error}"
                )
            }
            Self::InsertWithLiteralNameValue(error) => {
                write!(
                    f,
                    "QPACK Insert With Literal Name value cannot be built: {error}"
                )
            }
            Self::DuplicateIndex(error) => {
                write!(f, "QPACK Duplicate index cannot be built: {error}")
            }
            Self::RequiredLengthOverflow => {
                f.write_str("QPACK encoder instruction required length overflows usize")
            }
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                f,
                "QPACK encoder instruction buffer is too short: need {required} bytes, have {available}"
            ),
        }
    }
}

/// Builds a canonical Set Dynamic Table Capacity instruction in caller-owned storage.
pub struct QpackSetDynamicTableCapacityBuilder<'a> {
    destination: &'a mut [u8],
    capacity: u64,
}

impl<'a> QpackSetDynamicTableCapacityBuilder<'a> {
    /// Creates a builder for the supplied decoded capacity.
    pub fn new(destination: &'a mut [u8], capacity: u64) -> Self {
        Self {
            destination,
            capacity,
        }
    }

    /// Validates all inputs and capacity before atomically writing the instruction.
    pub fn build(
        self,
    ) -> Result<QpackSetDynamicTableCapacity<'a>, QpackEncoderInstructionBuildError> {
        let length = integer_length(self.capacity, 5)
            .map_err(QpackEncoderInstructionBuildError::SetDynamicTableCapacity)?;
        ensure_capacity(self.destination, length)?;
        write_canonical_prevalidated(&mut self.destination[..length], 5, 0x20, self.capacity);
        let bytes = &self.destination[..length];
        Ok(QpackSetDynamicTableCapacity {
            bytes,
            capacity: integer_from_prevalidated(bytes, 5, 0x20, self.capacity),
        })
    }
}

/// Builds a canonical Insert With Name Reference instruction in caller-owned storage.
pub struct QpackInsertWithNameReferenceBuilder<'a, 'value> {
    destination: &'a mut [u8],
    is_static: bool,
    name_index: u64,
    value_huffman: bool,
    encoded_value: &'value [u8],
}

impl<'a, 'value> QpackInsertWithNameReferenceBuilder<'a, 'value> {
    /// Creates a builder around an opaque, already-encoded value payload.
    pub fn new(
        destination: &'a mut [u8],
        is_static: bool,
        name_index: u64,
        value_huffman: bool,
        encoded_value: &'value [u8],
    ) -> Self {
        Self {
            destination,
            is_static,
            name_index,
            value_huffman,
            encoded_value,
        }
    }

    /// Validates all inputs and capacity before atomically writing the instruction.
    pub fn build(
        self,
    ) -> Result<QpackInsertWithNameReference<'a>, QpackEncoderInstructionBuildError> {
        let name_length = integer_length(self.name_index, 6)
            .map_err(QpackEncoderInstructionBuildError::InsertWithNameReferenceNameIndex)?;
        let value_plan = string_plan(8, 0, self.value_huffman, self.encoded_value)
            .map_err(QpackEncoderInstructionBuildError::InsertWithNameReferenceValue)?;
        let required = checked_sum(name_length, value_plan.required())?;
        ensure_capacity(self.destination, required)?;
        let name_high_bits = 0x80 | if self.is_static { 0x40 } else { 0 };
        let (name_destination, value_destination) =
            self.destination[..required].split_at_mut(name_length);
        write_canonical_prevalidated(name_destination, 6, name_high_bits, self.name_index);
        write_string_prevalidated(value_destination, value_plan);
        let bytes = &self.destination[..required];
        let value = string_from_prevalidated(&bytes[name_length..], value_plan);
        Ok(QpackInsertWithNameReference {
            bytes,
            is_static: self.is_static,
            name_index: integer_from_prevalidated(
                &bytes[..name_length],
                6,
                name_high_bits,
                self.name_index,
            ),
            value,
        })
    }
}

/// Builds a canonical Insert With Literal Name instruction in caller-owned storage.
pub struct QpackInsertWithLiteralNameBuilder<'a, 'name, 'value> {
    destination: &'a mut [u8],
    name_huffman: bool,
    encoded_name: &'name [u8],
    value_huffman: bool,
    encoded_value: &'value [u8],
}

impl<'a, 'name, 'value> QpackInsertWithLiteralNameBuilder<'a, 'name, 'value> {
    /// Creates a builder around opaque, already-encoded name and value payloads.
    pub fn new(
        destination: &'a mut [u8],
        name_huffman: bool,
        encoded_name: &'name [u8],
        value_huffman: bool,
        encoded_value: &'value [u8],
    ) -> Self {
        Self {
            destination,
            name_huffman,
            encoded_name,
            value_huffman,
            encoded_value,
        }
    }

    /// Validates all inputs and capacity before atomically writing the instruction.
    pub fn build(
        self,
    ) -> Result<QpackInsertWithLiteralName<'a>, QpackEncoderInstructionBuildError> {
        let name_plan = string_plan(6, 0x40, self.name_huffman, self.encoded_name)
            .map_err(QpackEncoderInstructionBuildError::InsertWithLiteralNameName)?;
        let value_plan = string_plan(8, 0, self.value_huffman, self.encoded_value)
            .map_err(QpackEncoderInstructionBuildError::InsertWithLiteralNameValue)?;
        let required = checked_sum(name_plan.required(), value_plan.required())?;
        ensure_capacity(self.destination, required)?;
        let (name_destination, value_destination) =
            self.destination[..required].split_at_mut(name_plan.required());
        write_string_prevalidated(name_destination, name_plan);
        write_string_prevalidated(value_destination, value_plan);
        let bytes = &self.destination[..required];
        let name = string_from_prevalidated(&bytes[..name_plan.required()], name_plan);
        let value = string_from_prevalidated(&bytes[name_plan.required()..], value_plan);
        Ok(QpackInsertWithLiteralName { bytes, name, value })
    }
}

/// Builds a canonical Duplicate instruction in caller-owned storage.
pub struct QpackDuplicateBuilder<'a> {
    destination: &'a mut [u8],
    index: u64,
}

impl<'a> QpackDuplicateBuilder<'a> {
    /// Creates a builder for the supplied decoded dynamic-relative index.
    pub fn new(destination: &'a mut [u8], index: u64) -> Self {
        Self { destination, index }
    }

    /// Validates all inputs and capacity before atomically writing the instruction.
    pub fn build(self) -> Result<QpackDuplicate<'a>, QpackEncoderInstructionBuildError> {
        let length = integer_length(self.index, 5)
            .map_err(QpackEncoderInstructionBuildError::DuplicateIndex)?;
        ensure_capacity(self.destination, length)?;
        write_canonical_prevalidated(&mut self.destination[..length], 5, 0, self.index);
        let bytes = &self.destination[..length];
        Ok(QpackDuplicate {
            bytes,
            index: integer_from_prevalidated(bytes, 5, 0, self.index),
        })
    }
}

fn integer_length(value: u64, prefix_bits: u8) -> Result<usize, QpackIntegerBuildError> {
    if value > QPACK_INTEGER_MAX {
        return Err(QpackIntegerBuildError::ValueTooLarge { value });
    }
    Ok(canonical_encoded_len(value, prefix_bits))
}

fn checked_sum(left: usize, right: usize) -> Result<usize, QpackEncoderInstructionBuildError> {
    left.checked_add(right)
        .ok_or(QpackEncoderInstructionBuildError::RequiredLengthOverflow)
}

fn ensure_capacity(
    destination: &[u8],
    required: usize,
) -> Result<(), QpackEncoderInstructionBuildError> {
    if destination.len() < required {
        return Err(QpackEncoderInstructionBuildError::BufferTooShort {
            required,
            available: destination.len(),
        });
    }
    Ok(())
}
