//! RFC 9204 sections 4.2 and 4.3 encoder-stream instructions.

use core::fmt;

use crate::qpack::integer::{QpackInteger, QpackIntegerParseError};
use crate::qpack::string::{QpackStringLiteral, QpackStringLiteralParseError};

mod apply;
mod builder;

pub use apply::{
    QpackEncoderInstructionApplier, QpackEncoderInstructionApplyError,
    QpackEncoderInstructionApplyOutcome, QpackEncoderInstructionsApplyError,
};
pub use builder::{
    QpackDuplicateBuilder, QpackEncoderInstructionBuildError, QpackInsertWithLiteralNameBuilder,
    QpackInsertWithNameReferenceBuilder, QpackSetDynamicTableCapacityBuilder,
};

/// A validated, exact borrowed QPACK encoder-stream instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackEncoderInstruction<'a> {
    /// A Set Dynamic Table Capacity instruction.
    SetDynamicTableCapacity(QpackSetDynamicTableCapacity<'a>),
    /// An Insert With Name Reference instruction.
    InsertWithNameReference(QpackInsertWithNameReference<'a>),
    /// An Insert With Literal Name instruction.
    InsertWithLiteralName(QpackInsertWithLiteralName<'a>),
    /// A Duplicate instruction.
    Duplicate(QpackDuplicate<'a>),
}

impl<'a> QpackEncoderInstruction<'a> {
    /// Parses exactly one encoder-stream instruction and excludes following bytes.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, QpackEncoderInstructionParseError> {
        let first = *bytes
            .first()
            .ok_or(QpackEncoderInstructionParseError::DispatchIncomplete)?;
        if first & 0xe0 == 0x20 {
            let capacity = QpackInteger::parse(bytes, 5)
                .map_err(QpackEncoderInstructionParseError::SetDynamicTableCapacity)?;
            return Ok(Self::SetDynamicTableCapacity(
                QpackSetDynamicTableCapacity {
                    bytes: capacity.as_bytes(),
                    capacity,
                },
            ));
        }
        if first & 0x80 != 0 {
            let name_index = QpackInteger::parse(bytes, 6)
                .map_err(QpackEncoderInstructionParseError::InsertWithNameReferenceNameIndex)?;
            let value = QpackStringLiteral::parse(&bytes[name_index.as_bytes().len()..], 8)
                .map_err(QpackEncoderInstructionParseError::InsertWithNameReferenceValue)?;
            let end = name_index.as_bytes().len() + value.as_bytes().len();
            return Ok(Self::InsertWithNameReference(
                QpackInsertWithNameReference {
                    bytes: &bytes[..end],
                    is_static: first & 0x40 != 0,
                    name_index,
                    value,
                },
            ));
        }
        if first & 0xc0 == 0x40 {
            let name = QpackStringLiteral::parse(bytes, 6)
                .map_err(QpackEncoderInstructionParseError::InsertWithLiteralNameName)?;
            let value = QpackStringLiteral::parse(&bytes[name.as_bytes().len()..], 8)
                .map_err(QpackEncoderInstructionParseError::InsertWithLiteralNameValue)?;
            let end = name.as_bytes().len() + value.as_bytes().len();
            return Ok(Self::InsertWithLiteralName(QpackInsertWithLiteralName {
                bytes: &bytes[..end],
                name,
                value,
            }));
        }
        let index = QpackInteger::parse(bytes, 5)
            .map_err(QpackEncoderInstructionParseError::DuplicateIndex)?;
        Ok(Self::Duplicate(QpackDuplicate {
            bytes: index.as_bytes(),
            index,
        }))
    }

    /// Returns the complete exact instruction bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        match self {
            Self::SetDynamicTableCapacity(instruction) => instruction.as_bytes(),
            Self::InsertWithNameReference(instruction) => instruction.as_bytes(),
            Self::InsertWithLiteralName(instruction) => instruction.as_bytes(),
            Self::Duplicate(instruction) => instruction.as_bytes(),
        }
    }
}

/// A Set Dynamic Table Capacity instruction view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackSetDynamicTableCapacity<'a> {
    bytes: &'a [u8],
    capacity: QpackInteger<'a>,
}

impl<'a> QpackSetDynamicTableCapacity<'a> {
    /// Returns the complete exact instruction bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact capacity integer.
    pub const fn capacity(self) -> QpackInteger<'a> {
        self.capacity
    }
}

/// An Insert With Name Reference instruction view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackInsertWithNameReference<'a> {
    bytes: &'a [u8],
    is_static: bool,
    name_index: QpackInteger<'a>,
    value: QpackStringLiteral<'a>,
}

impl<'a> QpackInsertWithNameReference<'a> {
    /// Returns the complete exact instruction bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns whether the name index addresses the static table.
    pub const fn is_static(self) -> bool {
        self.is_static
    }

    /// Returns the exact name-index integer.
    pub const fn name_index(self) -> QpackInteger<'a> {
        self.name_index
    }

    /// Returns the exact opaque value string literal.
    pub const fn value(self) -> QpackStringLiteral<'a> {
        self.value
    }
}

/// An Insert With Literal Name instruction view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackInsertWithLiteralName<'a> {
    bytes: &'a [u8],
    name: QpackStringLiteral<'a>,
    value: QpackStringLiteral<'a>,
}

impl<'a> QpackInsertWithLiteralName<'a> {
    /// Returns the complete exact instruction bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact opaque name string literal.
    pub const fn name(self) -> QpackStringLiteral<'a> {
        self.name
    }

    /// Returns the exact opaque value string literal.
    pub const fn value(self) -> QpackStringLiteral<'a> {
        self.value
    }
}

/// A Duplicate instruction view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackDuplicate<'a> {
    bytes: &'a [u8],
    index: QpackInteger<'a>,
}

impl<'a> QpackDuplicate<'a> {
    /// Returns the complete exact instruction bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact dynamic-relative index integer.
    pub const fn index(self) -> QpackInteger<'a> {
        self.index
    }
}

/// Failure to parse one QPACK encoder-stream instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackEncoderInstructionParseError {
    /// The input contains no first octet to dispatch.
    DispatchIncomplete,
    /// The Set Dynamic Table Capacity integer is invalid.
    SetDynamicTableCapacity(#[doc = "The nested capacity-integer failure."] QpackIntegerParseError),
    /// The Insert With Name Reference name index is invalid.
    InsertWithNameReferenceNameIndex(
        #[doc = "The nested name-index failure."] QpackIntegerParseError,
    ),
    /// The Insert With Name Reference value is invalid.
    InsertWithNameReferenceValue(
        #[doc = "The nested value-string failure."] QpackStringLiteralParseError,
    ),
    /// The Insert With Literal Name name is invalid.
    InsertWithLiteralNameName(
        #[doc = "The nested name-string failure."] QpackStringLiteralParseError,
    ),
    /// The Insert With Literal Name value is invalid.
    InsertWithLiteralNameValue(
        #[doc = "The nested value-string failure."] QpackStringLiteralParseError,
    ),
    /// The Duplicate index is invalid.
    DuplicateIndex(#[doc = "The nested duplicate-index failure."] QpackIntegerParseError),
}

impl fmt::Display for QpackEncoderInstructionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DispatchIncomplete => {
                f.write_str("QPACK encoder instruction input is incomplete")
            }
            Self::SetDynamicTableCapacity(error) => {
                write!(f, "QPACK Set Dynamic Table Capacity is invalid: {error}")
            }
            Self::InsertWithNameReferenceNameIndex(error) => {
                write!(
                    f,
                    "QPACK Insert With Name Reference name index is invalid: {error}"
                )
            }
            Self::InsertWithNameReferenceValue(error) => {
                write!(
                    f,
                    "QPACK Insert With Name Reference value is invalid: {error}"
                )
            }
            Self::InsertWithLiteralNameName(error) => {
                write!(f, "QPACK Insert With Literal Name name is invalid: {error}")
            }
            Self::InsertWithLiteralNameValue(error) => {
                write!(
                    f,
                    "QPACK Insert With Literal Name value is invalid: {error}"
                )
            }
            Self::DuplicateIndex(error) => write!(f, "QPACK Duplicate index is invalid: {error}"),
        }
    }
}

/// A validated complete, unframed QPACK encoder-stream instruction sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackEncoderInstructions<'a> {
    bytes: &'a [u8],
}

impl<'a> QpackEncoderInstructions<'a> {
    /// Validates a complete unframed encoder-stream instruction sequence.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, QpackEncoderInstructionsParseError> {
        let mut offset = 0usize;
        while offset < bytes.len() {
            let instruction = QpackEncoderInstruction::parse(&bytes[offset..])
                .map_err(|error| QpackEncoderInstructionsParseError { offset, error })?;
            offset += instruction.as_bytes().len();
        }
        Ok(Self { bytes })
    }

    /// Returns the complete exact sequence bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns a fallible fused iterator over exact instructions.
    pub const fn iter(self) -> QpackEncoderInstructionIter<'a> {
        QpackEncoderInstructionIter {
            remaining: self.bytes,
            offset: 0,
            failed: false,
        }
    }
}

/// Failure to validate a complete QPACK encoder-stream instruction sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackEncoderInstructionsParseError {
    /// Absolute byte offset of the invalid instruction.
    pub offset: usize,
    /// Local instruction parse failure.
    pub error: QpackEncoderInstructionParseError,
}

impl fmt::Display for QpackEncoderInstructionsParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "QPACK encoder instruction sequence is invalid at byte {}: {}",
            self.offset, self.error
        )
    }
}

/// A fallible fused iterator over QPACK encoder-stream instructions.
#[derive(Clone, Copy, Debug)]
pub struct QpackEncoderInstructionIter<'a> {
    remaining: &'a [u8],
    offset: usize,
    failed: bool,
}

impl<'a> Iterator for QpackEncoderInstructionIter<'a> {
    type Item = Result<QpackEncoderInstruction<'a>, QpackEncoderInstructionsParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.remaining.is_empty() {
            return None;
        }
        match QpackEncoderInstruction::parse(self.remaining) {
            Ok(instruction) => {
                let consumed = instruction.as_bytes().len();
                self.remaining = &self.remaining[consumed..];
                self.offset += consumed;
                Some(Ok(instruction))
            }
            Err(error) => {
                self.failed = true;
                Some(Err(QpackEncoderInstructionsParseError {
                    offset: self.offset,
                    error,
                }))
            }
        }
    }
}

impl core::iter::FusedIterator for QpackEncoderInstructionIter<'_> {}
