//! QPACK field line representations defined by RFC 9204.

mod builder;

use core::fmt;

use crate::qpack::integer::{QpackInteger, QpackIntegerParseError};
use crate::qpack::string::{QpackStringLiteral, QpackStringLiteralParseError};
pub use builder::{
    QpackFieldLineBuildError, QpackIndexedFieldLineBuilder, QpackIndexedPostBaseFieldLineBuilder,
    QpackLiteralNameFieldLineBuilder, QpackLiteralNameReferenceFieldLineBuilder,
    QpackLiteralPostBaseNameReferenceFieldLineBuilder,
};
pub(crate) use builder::{QpackFieldLinePlan, QpackFieldLinePlanInput, plan_field_line};

/// A parsed QPACK field line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackFieldLine<'a> {
    /// An indexed field line.
    Indexed(QpackIndexedFieldLine<'a>),
    /// An indexed post-base field line.
    IndexedPostBase(QpackIndexedPostBaseFieldLine<'a>),
    /// A literal field line with a referenced name.
    LiteralNameReference(QpackLiteralNameReferenceFieldLine<'a>),
    /// A literal field line with a post-base referenced name.
    LiteralPostBaseNameReference(QpackLiteralPostBaseNameReferenceFieldLine<'a>),
    /// A literal field line containing a literal name.
    LiteralName(QpackLiteralNameFieldLine<'a>),
}

impl<'a> QpackFieldLine<'a> {
    /// Parses exactly one QPACK field line from the start of `bytes`.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, QpackFieldLineParseError> {
        let first = *bytes
            .first()
            .ok_or(QpackFieldLineParseError::DispatchIncomplete)?;

        if first & 0x80 != 0 {
            let index =
                QpackInteger::parse(bytes, 6).map_err(QpackFieldLineParseError::IndexedIndex)?;
            return Ok(Self::Indexed(QpackIndexedFieldLine {
                bytes: index.as_bytes(),
                index,
            }));
        }

        if first & 0xc0 == 0x40 {
            let name_index = QpackInteger::parse(bytes, 4)
                .map_err(QpackFieldLineParseError::LiteralNameReferenceNameIndex)?;
            let name_length = name_index.as_bytes().len();
            let value_bytes = bytes
                .get(name_length..)
                .ok_or(QpackFieldLineParseError::RequiredLengthOverflow)?;
            let value = QpackStringLiteral::parse(value_bytes, 8)
                .map_err(QpackFieldLineParseError::LiteralNameReferenceValue)?;
            let length = name_length
                .checked_add(value.as_bytes().len())
                .ok_or(QpackFieldLineParseError::RequiredLengthOverflow)?;
            let line_bytes = bytes
                .get(..length)
                .ok_or(QpackFieldLineParseError::RequiredLengthOverflow)?;
            return Ok(Self::LiteralNameReference(
                QpackLiteralNameReferenceFieldLine {
                    bytes: line_bytes,
                    name_index,
                    value,
                },
            ));
        }

        if first & 0xe0 == 0x20 {
            let name = QpackStringLiteral::parse(bytes, 4)
                .map_err(QpackFieldLineParseError::LiteralNameName)?;
            let name_length = name.as_bytes().len();
            let value_bytes = bytes
                .get(name_length..)
                .ok_or(QpackFieldLineParseError::RequiredLengthOverflow)?;
            let value = QpackStringLiteral::parse(value_bytes, 8)
                .map_err(QpackFieldLineParseError::LiteralNameValue)?;
            let length = name_length
                .checked_add(value.as_bytes().len())
                .ok_or(QpackFieldLineParseError::RequiredLengthOverflow)?;
            let line_bytes = bytes
                .get(..length)
                .ok_or(QpackFieldLineParseError::RequiredLengthOverflow)?;
            return Ok(Self::LiteralName(QpackLiteralNameFieldLine {
                bytes: line_bytes,
                name,
                value,
            }));
        }

        if first & 0xf0 == 0x10 {
            let index = QpackInteger::parse(bytes, 4)
                .map_err(QpackFieldLineParseError::IndexedPostBaseIndex)?;
            return Ok(Self::IndexedPostBase(QpackIndexedPostBaseFieldLine {
                bytes: index.as_bytes(),
                index,
            }));
        }

        let name_index = QpackInteger::parse(bytes, 3)
            .map_err(QpackFieldLineParseError::LiteralPostBaseNameReferenceNameIndex)?;
        let name_length = name_index.as_bytes().len();
        let value_bytes = bytes
            .get(name_length..)
            .ok_or(QpackFieldLineParseError::RequiredLengthOverflow)?;
        let value = QpackStringLiteral::parse(value_bytes, 8)
            .map_err(QpackFieldLineParseError::LiteralPostBaseNameReferenceValue)?;
        let length = name_length
            .checked_add(value.as_bytes().len())
            .ok_or(QpackFieldLineParseError::RequiredLengthOverflow)?;
        let line_bytes = bytes
            .get(..length)
            .ok_or(QpackFieldLineParseError::RequiredLengthOverflow)?;
        Ok(Self::LiteralPostBaseNameReference(
            QpackLiteralPostBaseNameReferenceFieldLine {
                bytes: line_bytes,
                name_index,
                value,
            },
        ))
    }

    /// Returns the exact encoded bytes occupied by this field line.
    pub const fn as_bytes(self) -> &'a [u8] {
        match self {
            Self::Indexed(line) => line.as_bytes(),
            Self::IndexedPostBase(line) => line.as_bytes(),
            Self::LiteralNameReference(line) => line.as_bytes(),
            Self::LiteralPostBaseNameReference(line) => line.as_bytes(),
            Self::LiteralName(line) => line.as_bytes(),
        }
    }
}

/// An indexed QPACK field line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackIndexedFieldLine<'a> {
    bytes: &'a [u8],
    index: QpackInteger<'a>,
}

impl<'a> QpackIndexedFieldLine<'a> {
    /// Returns the exact encoded bytes occupied by this field line.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Returns whether the index refers to the static table.
    pub const fn is_static(self) -> bool {
        self.bytes[0] & 0x40 != 0
    }
    /// Returns the encoded field-line index.
    pub const fn index(self) -> QpackInteger<'a> {
        self.index
    }
}

/// An indexed post-base QPACK field line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackIndexedPostBaseFieldLine<'a> {
    bytes: &'a [u8],
    index: QpackInteger<'a>,
}

impl<'a> QpackIndexedPostBaseFieldLine<'a> {
    /// Returns the exact encoded bytes occupied by this field line.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Returns the encoded post-base index.
    pub const fn index(self) -> QpackInteger<'a> {
        self.index
    }
}

/// A literal QPACK field line with a referenced name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackLiteralNameReferenceFieldLine<'a> {
    bytes: &'a [u8],
    name_index: QpackInteger<'a>,
    value: QpackStringLiteral<'a>,
}

impl<'a> QpackLiteralNameReferenceFieldLine<'a> {
    /// Returns the exact encoded bytes occupied by this field line.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Returns whether intermediaries must not index this field line.
    pub const fn is_never_indexed(self) -> bool {
        self.bytes[0] & 0x20 != 0
    }
    /// Returns whether the name index refers to the static table.
    pub const fn is_static(self) -> bool {
        self.bytes[0] & 0x10 != 0
    }
    /// Returns the encoded referenced-name index.
    pub const fn name_index(self) -> QpackInteger<'a> {
        self.name_index
    }
    /// Returns the encoded field value.
    pub const fn value(self) -> QpackStringLiteral<'a> {
        self.value
    }
}

/// A literal QPACK field line with a post-base referenced name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackLiteralPostBaseNameReferenceFieldLine<'a> {
    bytes: &'a [u8],
    name_index: QpackInteger<'a>,
    value: QpackStringLiteral<'a>,
}

impl<'a> QpackLiteralPostBaseNameReferenceFieldLine<'a> {
    /// Returns the exact encoded bytes occupied by this field line.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Returns whether intermediaries must not index this field line.
    pub const fn is_never_indexed(self) -> bool {
        self.bytes[0] & 0x08 != 0
    }
    /// Returns the encoded post-base name index.
    pub const fn name_index(self) -> QpackInteger<'a> {
        self.name_index
    }
    /// Returns the encoded field value.
    pub const fn value(self) -> QpackStringLiteral<'a> {
        self.value
    }
}

/// A literal QPACK field line containing a literal name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackLiteralNameFieldLine<'a> {
    bytes: &'a [u8],
    name: QpackStringLiteral<'a>,
    value: QpackStringLiteral<'a>,
}

impl<'a> QpackLiteralNameFieldLine<'a> {
    /// Returns the exact encoded bytes occupied by this field line.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Returns whether intermediaries must not index this field line.
    pub const fn is_never_indexed(self) -> bool {
        self.bytes[0] & 0x10 != 0
    }
    /// Returns the encoded literal name.
    pub const fn name(self) -> QpackStringLiteral<'a> {
        self.name
    }
    /// Returns the encoded field value.
    pub const fn value(self) -> QpackStringLiteral<'a> {
        self.value
    }
}

/// An error returned while parsing a QPACK field line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackFieldLineParseError {
    /// The input did not contain a field-line dispatch byte.
    DispatchIncomplete,
    /// The indexed field-line index could not be parsed.
    IndexedIndex(#[doc = "The integer parsing error."] QpackIntegerParseError),
    /// The indexed post-base field-line index could not be parsed.
    IndexedPostBaseIndex(#[doc = "The integer parsing error."] QpackIntegerParseError),
    /// The literal name-reference index could not be parsed.
    LiteralNameReferenceNameIndex(#[doc = "The integer parsing error."] QpackIntegerParseError),
    /// The literal name-reference value could not be parsed.
    LiteralNameReferenceValue(
        #[doc = "The string-literal parsing error."] QpackStringLiteralParseError,
    ),
    /// The literal post-base name-reference index could not be parsed.
    LiteralPostBaseNameReferenceNameIndex(
        #[doc = "The integer parsing error."] QpackIntegerParseError,
    ),
    /// The literal post-base name-reference value could not be parsed.
    LiteralPostBaseNameReferenceValue(
        #[doc = "The string-literal parsing error."] QpackStringLiteralParseError,
    ),
    /// The literal field name could not be parsed.
    LiteralNameName(#[doc = "The string-literal parsing error."] QpackStringLiteralParseError),
    /// The literal field value could not be parsed.
    LiteralNameValue(#[doc = "The string-literal parsing error."] QpackStringLiteralParseError),
    /// The combined component lengths overflowed `usize`.
    RequiredLengthOverflow,
}

impl fmt::Display for QpackFieldLineParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DispatchIncomplete => formatter.write_str("QPACK field line is incomplete"),
            Self::IndexedIndex(error) => {
                write!(formatter, "invalid indexed field line index: {error}")
            }
            Self::IndexedPostBaseIndex(error) => write!(
                formatter,
                "invalid indexed post-base field line index: {error}"
            ),
            Self::LiteralNameReferenceNameIndex(error) => {
                write!(formatter, "invalid literal name-reference index: {error}")
            }
            Self::LiteralNameReferenceValue(error) => {
                write!(formatter, "invalid literal name-reference value: {error}")
            }
            Self::LiteralPostBaseNameReferenceNameIndex(error) => write!(
                formatter,
                "invalid literal post-base name-reference index: {error}"
            ),
            Self::LiteralPostBaseNameReferenceValue(error) => write!(
                formatter,
                "invalid literal post-base name-reference value: {error}"
            ),
            Self::LiteralNameName(error) => {
                write!(formatter, "invalid literal field name: {error}")
            }
            Self::LiteralNameValue(error) => {
                write!(formatter, "invalid literal field value: {error}")
            }
            Self::RequiredLengthOverflow => formatter.write_str("QPACK field line length overflow"),
        }
    }
}

/// A validated sequence of QPACK field lines backed by its encoded bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackFieldLines<'a> {
    bytes: &'a [u8],
}

impl<'a> QpackFieldLines<'a> {
    /// Validates and borrows every field line in `bytes`.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, QpackFieldLinesParseError> {
        let mut remaining = bytes;
        while !remaining.is_empty() {
            let line = match QpackFieldLine::parse(remaining) {
                Ok(line) => line,
                Err(error) => {
                    return Err(QpackFieldLinesParseError {
                        offset: bytes.len() - remaining.len(),
                        error,
                    });
                }
            };
            remaining = &remaining[line.as_bytes().len()..];
        }
        Ok(Self { bytes })
    }

    /// Returns the complete encoded field-line sequence.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Iterates over the field lines in this sequence.
    pub const fn iter(self) -> QpackFieldLineIter<'a> {
        QpackFieldLineIter::new(self.bytes)
    }
}

/// An error encountered while validating a QPACK field-line sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackFieldLinesParseError {
    offset: usize,
    error: QpackFieldLineParseError,
}

impl QpackFieldLinesParseError {
    /// Returns the byte offset at which the invalid field line begins.
    pub const fn offset(self) -> usize {
        self.offset
    }

    /// Returns the error reported for the field line at [`Self::offset`].
    pub const fn error(self) -> QpackFieldLineParseError {
        self.error
    }
}

impl fmt::Display for QpackFieldLinesParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "QPACK field line at offset {}: {}",
            self.offset, self.error
        )
    }
}

/// An iterator over encoded QPACK field lines.
#[derive(Clone, Debug)]
pub struct QpackFieldLineIter<'a> {
    remaining: &'a [u8],
    failed: bool,
}

impl<'a> QpackFieldLineIter<'a> {
    /// Creates a fallible iterator over raw encoded field-line bytes.
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            remaining: bytes,
            failed: false,
        }
    }
}

impl<'a> Iterator for QpackFieldLineIter<'a> {
    type Item = Result<QpackFieldLine<'a>, QpackFieldLineParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.remaining.is_empty() {
            return None;
        }
        match QpackFieldLine::parse(self.remaining) {
            Ok(line) => {
                self.remaining = &self.remaining[line.as_bytes().len()..];
                Some(Ok(line))
            }
            Err(error) => {
                self.remaining = &[];
                self.failed = true;
                Some(Err(error))
            }
        }
    }
}

impl core::iter::FusedIterator for QpackFieldLineIter<'_> {}
