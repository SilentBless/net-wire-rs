//! Atomic canonical builders for QPACK field-line representations.

use core::fmt;

use super::{
    QpackIndexedFieldLine, QpackIndexedPostBaseFieldLine, QpackLiteralNameFieldLine,
    QpackLiteralNameReferenceFieldLine, QpackLiteralPostBaseNameReferenceFieldLine,
};
use crate::qpack::integer::{
    QPACK_INTEGER_MAX, QpackIntegerBuildError, canonical_encoded_len, integer_from_prevalidated,
    write_canonical_prevalidated,
};
use crate::qpack::string::{
    QpackStringLiteralBuildError, QpackStringLiteralPlan, string_from_prevalidated, string_plan,
    write_string_prevalidated,
};

/// Failure to build a QPACK field line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackFieldLineBuildError {
    /// The indexed field-line index is invalid.
    IndexedIndex(#[doc = "The nested integer failure."] QpackIntegerBuildError),
    /// The indexed post-base field-line index is invalid.
    IndexedPostBaseIndex(#[doc = "The nested integer failure."] QpackIntegerBuildError),
    /// The literal name-reference field-line name index is invalid.
    LiteralNameReferenceNameIndex(#[doc = "The nested integer failure."] QpackIntegerBuildError),
    /// The literal name-reference field-line value is invalid.
    LiteralNameReferenceValue(
        #[doc = "The nested string-literal failure."] QpackStringLiteralBuildError,
    ),
    /// The literal post-base name-reference field-line name index is invalid.
    LiteralPostBaseNameReferenceNameIndex(
        #[doc = "The nested integer failure."] QpackIntegerBuildError,
    ),
    /// The literal post-base name-reference field-line value is invalid.
    LiteralPostBaseNameReferenceValue(
        #[doc = "The nested string-literal failure."] QpackStringLiteralBuildError,
    ),
    /// The literal-name field-line name is invalid.
    LiteralNameName(#[doc = "The nested string-literal failure."] QpackStringLiteralBuildError),
    /// The literal-name field-line value is invalid.
    LiteralNameValue(#[doc = "The nested string-literal failure."] QpackStringLiteralBuildError),
    /// The complete field-line length cannot be represented as `usize`.
    RequiredLengthOverflow,
    /// The caller buffer cannot contain the complete field line.
    BufferTooShort {
        /// Bytes required for the complete field line.
        required: usize,
        /// Bytes available in the caller buffer.
        available: usize,
    },
}

impl fmt::Display for QpackFieldLineBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IndexedIndex(error) => {
                write!(f, "QPACK Indexed Field Line index cannot be built: {error}")
            }
            Self::IndexedPostBaseIndex(error) => write!(
                f,
                "QPACK Indexed Field Line With Post-Base Index cannot be built: {error}"
            ),
            Self::LiteralNameReferenceNameIndex(error) => write!(
                f,
                "QPACK Literal Field Line With Name Reference name index cannot be built: {error}"
            ),
            Self::LiteralNameReferenceValue(error) => write!(
                f,
                "QPACK Literal Field Line With Name Reference value cannot be built: {error}"
            ),
            Self::LiteralPostBaseNameReferenceNameIndex(error) => write!(
                f,
                "QPACK Literal Field Line With Post-Base Name Reference name index cannot be built: {error}"
            ),
            Self::LiteralPostBaseNameReferenceValue(error) => write!(
                f,
                "QPACK Literal Field Line With Post-Base Name Reference value cannot be built: {error}"
            ),
            Self::LiteralNameName(error) => write!(
                f,
                "QPACK Literal Field Line With Literal Name name cannot be built: {error}"
            ),
            Self::LiteralNameValue(error) => write!(
                f,
                "QPACK Literal Field Line With Literal Name value cannot be built: {error}"
            ),
            Self::RequiredLengthOverflow => {
                f.write_str("QPACK field-line required length overflows usize")
            }
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                f,
                "QPACK field-line buffer is too short: need {required} bytes, have {available}"
            ),
        }
    }
}

/// Input to the prevalidated field-line writer.
///
/// Dynamic indices have already been converted to the wire-relative form required
/// by their representation. Payloads are opaque encoded bytes; their Huffman flags
/// only control the corresponding wire bits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QpackFieldLinePlanInput<'a> {
    IndexedStatic {
        index: u64,
    },
    IndexedDynamicPreBase {
        relative_index: u64,
    },
    IndexedDynamicPostBase {
        post_base_index: u64,
    },
    LiteralStaticNameReference {
        never_indexed: bool,
        index: u64,
        value_huffman: bool,
        encoded_value: &'a [u8],
    },
    LiteralDynamicPreBaseNameReference {
        never_indexed: bool,
        relative_index: u64,
        value_huffman: bool,
        encoded_value: &'a [u8],
    },
    LiteralDynamicPostBaseNameReference {
        never_indexed: bool,
        post_base_index: u64,
        value_huffman: bool,
        encoded_value: &'a [u8],
    },
    LiteralName {
        never_indexed: bool,
        name_huffman: bool,
        encoded_name: &'a [u8],
        value_huffman: bool,
        encoded_value: &'a [u8],
    },
}

/// A fully validated, allocation-free field-line write plan.
#[derive(Clone, Copy)]
pub(crate) struct QpackFieldLinePlan<'a> {
    kind: QpackFieldLinePlanKind<'a>,
    encoded_len: usize,
}

#[derive(Clone, Copy)]
enum QpackFieldLinePlanKind<'a> {
    Integer {
        prefix_bits: u8,
        high_bits: u8,
        value: u64,
    },
    NameReference {
        prefix_bits: u8,
        high_bits: u8,
        index: u64,
        index_len: usize,
        value: QpackStringLiteralPlan<'a>,
    },
    LiteralName {
        name: QpackStringLiteralPlan<'a>,
        value: QpackStringLiteralPlan<'a>,
    },
}

impl QpackFieldLinePlan<'_> {
    /// Returns a harmless canonical plan for opaque caller scratch initialization.
    pub(crate) const fn empty() -> Self {
        Self {
            kind: QpackFieldLinePlanKind::Integer {
                prefix_bits: 6,
                high_bits: 0xc0,
                value: 0,
            },
            encoded_len: 1,
        }
    }

    /// Returns the exact number of bytes this plan writes.
    pub(crate) const fn encoded_len(self) -> usize {
        self.encoded_len
    }

    /// Writes this plan into its exact preallocated output region.
    ///
    /// A mismatched region is untouched rather than partially written. The type is
    /// crate-private so the field-section commit path can pass only the region it
    /// preflighted; with that contract, every split handed to the prevalidated
    /// integer and string writers has its exact validated length.
    pub(crate) fn write(self, destination: &mut [u8]) {
        if destination.len() != self.encoded_len {
            return;
        }

        match self.kind {
            QpackFieldLinePlanKind::Integer {
                prefix_bits,
                high_bits,
                value,
            } => write_canonical_prevalidated(destination, prefix_bits, high_bits, value),
            QpackFieldLinePlanKind::NameReference {
                prefix_bits,
                high_bits,
                index,
                index_len,
                value,
            } => {
                let (index_destination, value_destination) = destination.split_at_mut(index_len);
                write_canonical_prevalidated(index_destination, prefix_bits, high_bits, index);
                write_string_prevalidated(value_destination, value);
            }
            QpackFieldLinePlanKind::LiteralName { name, value } => {
                let (name_destination, value_destination) =
                    destination.split_at_mut(name.required());
                write_string_prevalidated(name_destination, name);
                write_string_prevalidated(value_destination, value);
            }
        }
    }
}

/// Validates one field-line emission without mutating output storage.
pub(crate) fn plan_field_line(
    input: QpackFieldLinePlanInput<'_>,
) -> Result<QpackFieldLinePlan<'_>, QpackFieldLineBuildError> {
    match input {
        QpackFieldLinePlanInput::IndexedStatic { index } => {
            plan_integer(index, 6, 0xc0, QpackFieldLineBuildError::IndexedIndex)
        }
        QpackFieldLinePlanInput::IndexedDynamicPreBase { relative_index } => plan_integer(
            relative_index,
            6,
            0x80,
            QpackFieldLineBuildError::IndexedIndex,
        ),
        QpackFieldLinePlanInput::IndexedDynamicPostBase { post_base_index } => plan_integer(
            post_base_index,
            4,
            0x10,
            QpackFieldLineBuildError::IndexedPostBaseIndex,
        ),
        QpackFieldLinePlanInput::LiteralStaticNameReference {
            never_indexed,
            index,
            value_huffman,
            encoded_value,
        } => plan_name_reference(
            index,
            4,
            0x50 | if never_indexed { 0x20 } else { 0 },
            value_huffman,
            encoded_value,
            QpackFieldLineBuildError::LiteralNameReferenceNameIndex,
            QpackFieldLineBuildError::LiteralNameReferenceValue,
        ),
        QpackFieldLinePlanInput::LiteralDynamicPreBaseNameReference {
            never_indexed,
            relative_index,
            value_huffman,
            encoded_value,
        } => plan_name_reference(
            relative_index,
            4,
            0x40 | if never_indexed { 0x20 } else { 0 },
            value_huffman,
            encoded_value,
            QpackFieldLineBuildError::LiteralNameReferenceNameIndex,
            QpackFieldLineBuildError::LiteralNameReferenceValue,
        ),
        QpackFieldLinePlanInput::LiteralDynamicPostBaseNameReference {
            never_indexed,
            post_base_index,
            value_huffman,
            encoded_value,
        } => plan_name_reference(
            post_base_index,
            3,
            if never_indexed { 0x08 } else { 0 },
            value_huffman,
            encoded_value,
            QpackFieldLineBuildError::LiteralPostBaseNameReferenceNameIndex,
            QpackFieldLineBuildError::LiteralPostBaseNameReferenceValue,
        ),
        QpackFieldLinePlanInput::LiteralName {
            never_indexed,
            name_huffman,
            encoded_name,
            value_huffman,
            encoded_value,
        } => {
            let name = string_plan(
                4,
                0x20 | if never_indexed { 0x10 } else { 0 },
                name_huffman,
                encoded_name,
            )
            .map_err(QpackFieldLineBuildError::LiteralNameName)?;
            let value = string_plan(8, 0, value_huffman, encoded_value)
                .map_err(QpackFieldLineBuildError::LiteralNameValue)?;
            let encoded_len = checked_sum(name.required(), value.required())?;
            Ok(QpackFieldLinePlan {
                kind: QpackFieldLinePlanKind::LiteralName { name, value },
                encoded_len,
            })
        }
    }
}

fn plan_integer(
    value: u64,
    prefix_bits: u8,
    high_bits: u8,
    error: fn(QpackIntegerBuildError) -> QpackFieldLineBuildError,
) -> Result<QpackFieldLinePlan<'static>, QpackFieldLineBuildError> {
    let encoded_len = integer_length(value, prefix_bits).map_err(error)?;
    Ok(QpackFieldLinePlan {
        kind: QpackFieldLinePlanKind::Integer {
            prefix_bits,
            high_bits,
            value,
        },
        encoded_len,
    })
}

fn plan_name_reference<'a>(
    index: u64,
    prefix_bits: u8,
    high_bits: u8,
    value_huffman: bool,
    encoded_value: &'a [u8],
    index_error: fn(QpackIntegerBuildError) -> QpackFieldLineBuildError,
    value_error: fn(QpackStringLiteralBuildError) -> QpackFieldLineBuildError,
) -> Result<QpackFieldLinePlan<'a>, QpackFieldLineBuildError> {
    let index_len = integer_length(index, prefix_bits).map_err(index_error)?;
    let value = string_plan(8, 0, value_huffman, encoded_value).map_err(value_error)?;
    let encoded_len = checked_sum(index_len, value.required())?;
    Ok(QpackFieldLinePlan {
        kind: QpackFieldLinePlanKind::NameReference {
            prefix_bits,
            high_bits,
            index,
            index_len,
            value,
        },
        encoded_len,
    })
}

/// Builds an Indexed Field Line in caller-owned storage.
pub struct QpackIndexedFieldLineBuilder<'buffer> {
    destination: &'buffer mut [u8],
    is_static: bool,
    index: u64,
}

impl<'buffer> QpackIndexedFieldLineBuilder<'buffer> {
    /// Creates a builder for a static- or dynamic-table index.
    pub fn new(destination: &'buffer mut [u8], is_static: bool, index: u64) -> Self {
        Self {
            destination,
            is_static,
            index,
        }
    }

    /// Validates all inputs and capacity before atomically writing the field line.
    pub fn build(self) -> Result<QpackIndexedFieldLine<'buffer>, QpackFieldLineBuildError> {
        let length =
            integer_length(self.index, 6).map_err(QpackFieldLineBuildError::IndexedIndex)?;
        ensure_capacity(self.destination, length)?;
        let high_bits = 0x80 | if self.is_static { 0x40 } else { 0 };
        write_canonical_prevalidated(&mut self.destination[..length], 6, high_bits, self.index);
        let bytes = &self.destination[..length];
        Ok(QpackIndexedFieldLine {
            bytes,
            index: integer_from_prevalidated(bytes, 6, high_bits, self.index),
        })
    }
}

/// Builds an Indexed Field Line With Post-Base Index in caller-owned storage.
pub struct QpackIndexedPostBaseFieldLineBuilder<'buffer> {
    destination: &'buffer mut [u8],
    index: u64,
}

impl<'buffer> QpackIndexedPostBaseFieldLineBuilder<'buffer> {
    /// Creates a builder for the supplied post-base index.
    pub fn new(destination: &'buffer mut [u8], index: u64) -> Self {
        Self { destination, index }
    }

    /// Validates all inputs and capacity before atomically writing the field line.
    pub fn build(self) -> Result<QpackIndexedPostBaseFieldLine<'buffer>, QpackFieldLineBuildError> {
        let length = integer_length(self.index, 4)
            .map_err(QpackFieldLineBuildError::IndexedPostBaseIndex)?;
        ensure_capacity(self.destination, length)?;
        write_canonical_prevalidated(&mut self.destination[..length], 4, 0x10, self.index);
        let bytes = &self.destination[..length];
        Ok(QpackIndexedPostBaseFieldLine {
            bytes,
            index: integer_from_prevalidated(bytes, 4, 0x10, self.index),
        })
    }
}

/// Builds a Literal Field Line With Name Reference in caller-owned storage.
pub struct QpackLiteralNameReferenceFieldLineBuilder<'buffer, 'value> {
    destination: &'buffer mut [u8],
    never_indexed: bool,
    is_static: bool,
    name_index: u64,
    value_huffman: bool,
    encoded_value: &'value [u8],
}

impl<'buffer, 'value> QpackLiteralNameReferenceFieldLineBuilder<'buffer, 'value> {
    /// Creates a builder around an opaque, already-encoded value payload.
    ///
    /// `value_huffman` controls the wire H bit; this builder does not Huffman-encode the payload.
    pub fn new(
        destination: &'buffer mut [u8],
        never_indexed: bool,
        is_static: bool,
        name_index: u64,
        value_huffman: bool,
        encoded_value: &'value [u8],
    ) -> Self {
        Self {
            destination,
            never_indexed,
            is_static,
            name_index,
            value_huffman,
            encoded_value,
        }
    }

    /// Validates all inputs and capacity before atomically writing the field line.
    pub fn build(
        self,
    ) -> Result<QpackLiteralNameReferenceFieldLine<'buffer>, QpackFieldLineBuildError> {
        let name_length = integer_length(self.name_index, 4)
            .map_err(QpackFieldLineBuildError::LiteralNameReferenceNameIndex)?;
        let value_plan = string_plan(8, 0, self.value_huffman, self.encoded_value)
            .map_err(QpackFieldLineBuildError::LiteralNameReferenceValue)?;
        let required = checked_sum(name_length, value_plan.required())?;
        ensure_capacity(self.destination, required)?;
        let high_bits = 0x40
            | if self.never_indexed { 0x20 } else { 0 }
            | if self.is_static { 0x10 } else { 0 };
        let (name_destination, value_destination) =
            self.destination[..required].split_at_mut(name_length);
        write_canonical_prevalidated(name_destination, 4, high_bits, self.name_index);
        write_string_prevalidated(value_destination, value_plan);
        let bytes = &self.destination[..required];
        Ok(QpackLiteralNameReferenceFieldLine {
            bytes,
            name_index: integer_from_prevalidated(
                &bytes[..name_length],
                4,
                high_bits,
                self.name_index,
            ),
            value: string_from_prevalidated(&bytes[name_length..], value_plan),
        })
    }
}

/// Builds a Literal Field Line With Post-Base Name Reference in caller-owned storage.
pub struct QpackLiteralPostBaseNameReferenceFieldLineBuilder<'buffer, 'value> {
    destination: &'buffer mut [u8],
    never_indexed: bool,
    name_index: u64,
    value_huffman: bool,
    encoded_value: &'value [u8],
}

impl<'buffer, 'value> QpackLiteralPostBaseNameReferenceFieldLineBuilder<'buffer, 'value> {
    /// Creates a builder around an opaque, already-encoded value payload.
    ///
    /// `value_huffman` controls the wire H bit; this builder does not Huffman-encode the payload.
    pub fn new(
        destination: &'buffer mut [u8],
        never_indexed: bool,
        name_index: u64,
        value_huffman: bool,
        encoded_value: &'value [u8],
    ) -> Self {
        Self {
            destination,
            never_indexed,
            name_index,
            value_huffman,
            encoded_value,
        }
    }

    /// Validates all inputs and capacity before atomically writing the field line.
    pub fn build(
        self,
    ) -> Result<QpackLiteralPostBaseNameReferenceFieldLine<'buffer>, QpackFieldLineBuildError> {
        let name_length = integer_length(self.name_index, 3)
            .map_err(QpackFieldLineBuildError::LiteralPostBaseNameReferenceNameIndex)?;
        let value_plan = string_plan(8, 0, self.value_huffman, self.encoded_value)
            .map_err(QpackFieldLineBuildError::LiteralPostBaseNameReferenceValue)?;
        let required = checked_sum(name_length, value_plan.required())?;
        ensure_capacity(self.destination, required)?;
        let high_bits = if self.never_indexed { 0x08 } else { 0 };
        let (name_destination, value_destination) =
            self.destination[..required].split_at_mut(name_length);
        write_canonical_prevalidated(name_destination, 3, high_bits, self.name_index);
        write_string_prevalidated(value_destination, value_plan);
        let bytes = &self.destination[..required];
        Ok(QpackLiteralPostBaseNameReferenceFieldLine {
            bytes,
            name_index: integer_from_prevalidated(
                &bytes[..name_length],
                3,
                high_bits,
                self.name_index,
            ),
            value: string_from_prevalidated(&bytes[name_length..], value_plan),
        })
    }
}

/// Builds a Literal Field Line With Literal Name in caller-owned storage.
pub struct QpackLiteralNameFieldLineBuilder<'buffer, 'name, 'value> {
    destination: &'buffer mut [u8],
    never_indexed: bool,
    name_huffman: bool,
    encoded_name: &'name [u8],
    value_huffman: bool,
    encoded_value: &'value [u8],
}

impl<'buffer, 'name, 'value> QpackLiteralNameFieldLineBuilder<'buffer, 'name, 'value> {
    /// Creates a builder around opaque, already-encoded name and value payloads.
    ///
    /// The Huffman flags only control the wire H bits; this builder does not encode either payload.
    pub fn new(
        destination: &'buffer mut [u8],
        never_indexed: bool,
        name_huffman: bool,
        encoded_name: &'name [u8],
        value_huffman: bool,
        encoded_value: &'value [u8],
    ) -> Self {
        Self {
            destination,
            never_indexed,
            name_huffman,
            encoded_name,
            value_huffman,
            encoded_value,
        }
    }

    /// Validates all inputs and capacity before atomically writing the field line.
    pub fn build(self) -> Result<QpackLiteralNameFieldLine<'buffer>, QpackFieldLineBuildError> {
        let name_high_bits = 0x20 | if self.never_indexed { 0x10 } else { 0 };
        let name_plan = string_plan(4, name_high_bits, self.name_huffman, self.encoded_name)
            .map_err(QpackFieldLineBuildError::LiteralNameName)?;
        let value_plan = string_plan(8, 0, self.value_huffman, self.encoded_value)
            .map_err(QpackFieldLineBuildError::LiteralNameValue)?;
        let required = checked_sum(name_plan.required(), value_plan.required())?;
        ensure_capacity(self.destination, required)?;
        let (name_destination, value_destination) =
            self.destination[..required].split_at_mut(name_plan.required());
        write_string_prevalidated(name_destination, name_plan);
        write_string_prevalidated(value_destination, value_plan);
        let bytes = &self.destination[..required];
        Ok(QpackLiteralNameFieldLine {
            bytes,
            name: string_from_prevalidated(&bytes[..name_plan.required()], name_plan),
            value: string_from_prevalidated(&bytes[name_plan.required()..], value_plan),
        })
    }
}

fn integer_length(value: u64, prefix_bits: u8) -> Result<usize, QpackIntegerBuildError> {
    if value > QPACK_INTEGER_MAX {
        return Err(QpackIntegerBuildError::ValueTooLarge { value });
    }
    Ok(canonical_encoded_len(value, prefix_bits))
}

fn checked_sum(left: usize, right: usize) -> Result<usize, QpackFieldLineBuildError> {
    left.checked_add(right)
        .ok_or(QpackFieldLineBuildError::RequiredLengthOverflow)
}

fn ensure_capacity(destination: &[u8], required: usize) -> Result<(), QpackFieldLineBuildError> {
    if destination.len() < required {
        return Err(QpackFieldLineBuildError::BufferTooShort {
            required,
            available: destination.len(),
        });
    }
    Ok(())
}
