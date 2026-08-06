//! RFC 9204 section 4.4 decoder-stream instructions.

use core::fmt;

use super::{
    QPACK_INTEGER_MAX, QpackInteger, QpackIntegerBuildError, QpackIntegerParseError,
    integer::{canonical_encoded_len, integer_from_prevalidated, write_canonical_prevalidated},
};

/// A validated, exact borrowed QPACK decoder-stream instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackDecoderInstruction<'a> {
    /// A Section Acknowledgment instruction.
    SectionAcknowledgment(QpackSectionAcknowledgment<'a>),
    /// A Stream Cancellation instruction.
    StreamCancellation(QpackStreamCancellation<'a>),
    /// An Insert Count Increment instruction.
    InsertCountIncrement(QpackInsertCountIncrement<'a>),
}

impl<'a> QpackDecoderInstruction<'a> {
    /// Parses exactly one decoder-stream instruction and excludes following bytes.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, QpackDecoderInstructionParseError> {
        let first = *bytes
            .first()
            .ok_or(QpackDecoderInstructionParseError::DispatchIncomplete)?;
        if first & 0x80 != 0 {
            let stream_id = QpackInteger::parse(bytes, 7)
                .map_err(QpackDecoderInstructionParseError::SectionAcknowledgment)?;
            return Ok(Self::SectionAcknowledgment(QpackSectionAcknowledgment {
                bytes: stream_id.as_bytes(),
                stream_id,
            }));
        }
        if first & 0xc0 == 0x40 {
            let stream_id = QpackInteger::parse(bytes, 6)
                .map_err(QpackDecoderInstructionParseError::StreamCancellation)?;
            return Ok(Self::StreamCancellation(QpackStreamCancellation {
                bytes: stream_id.as_bytes(),
                stream_id,
            }));
        }
        let increment = QpackInteger::parse(bytes, 6)
            .map_err(QpackDecoderInstructionParseError::InsertCountIncrement)?;
        Ok(Self::InsertCountIncrement(QpackInsertCountIncrement {
            bytes: increment.as_bytes(),
            increment,
        }))
    }

    /// Returns the complete exact instruction bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        match self {
            Self::SectionAcknowledgment(instruction) => instruction.as_bytes(),
            Self::StreamCancellation(instruction) => instruction.as_bytes(),
            Self::InsertCountIncrement(instruction) => instruction.as_bytes(),
        }
    }
}

/// A Section Acknowledgment instruction view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackSectionAcknowledgment<'a> {
    bytes: &'a [u8],
    stream_id: QpackInteger<'a>,
}

impl<'a> QpackSectionAcknowledgment<'a> {
    /// Returns the complete exact instruction bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact stream-ID integer.
    pub const fn stream_id(self) -> QpackInteger<'a> {
        self.stream_id
    }
}

/// A Stream Cancellation instruction view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackStreamCancellation<'a> {
    bytes: &'a [u8],
    stream_id: QpackInteger<'a>,
}

impl<'a> QpackStreamCancellation<'a> {
    /// Returns the complete exact instruction bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact stream-ID integer.
    pub const fn stream_id(self) -> QpackInteger<'a> {
        self.stream_id
    }
}

/// An Insert Count Increment instruction view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackInsertCountIncrement<'a> {
    bytes: &'a [u8],
    increment: QpackInteger<'a>,
}

impl<'a> QpackInsertCountIncrement<'a> {
    /// Returns the complete exact instruction bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact increment integer.
    pub const fn increment(self) -> QpackInteger<'a> {
        self.increment
    }
}

/// Failure to parse one QPACK decoder-stream instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackDecoderInstructionParseError {
    /// The input contains no first octet to dispatch.
    DispatchIncomplete,
    /// The Section Acknowledgment stream ID is invalid.
    SectionAcknowledgment(#[doc = "The nested stream-ID failure."] QpackIntegerParseError),
    /// The Stream Cancellation stream ID is invalid.
    StreamCancellation(#[doc = "The nested stream-ID failure."] QpackIntegerParseError),
    /// The Insert Count Increment integer is invalid.
    InsertCountIncrement(#[doc = "The nested increment failure."] QpackIntegerParseError),
}

impl fmt::Display for QpackDecoderInstructionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DispatchIncomplete => {
                f.write_str("QPACK decoder instruction input is incomplete")
            }
            Self::SectionAcknowledgment(error) => {
                write!(f, "QPACK Section Acknowledgment is invalid: {error}")
            }
            Self::StreamCancellation(error) => {
                write!(f, "QPACK Stream Cancellation is invalid: {error}")
            }
            Self::InsertCountIncrement(error) => {
                write!(f, "QPACK Insert Count Increment is invalid: {error}")
            }
        }
    }
}

/// A validated complete, unframed QPACK decoder-stream instruction sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackDecoderInstructions<'a> {
    bytes: &'a [u8],
}

impl<'a> QpackDecoderInstructions<'a> {
    /// Validates a complete unframed decoder-stream instruction sequence.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, QpackDecoderInstructionsParseError> {
        let mut offset = 0usize;
        while offset < bytes.len() {
            let instruction = QpackDecoderInstruction::parse(&bytes[offset..])
                .map_err(|error| QpackDecoderInstructionsParseError { offset, error })?;
            offset += instruction.as_bytes().len();
        }
        Ok(Self { bytes })
    }

    /// Returns the complete exact sequence bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns a fallible fused iterator over exact instructions.
    pub const fn iter(self) -> QpackDecoderInstructionIter<'a> {
        QpackDecoderInstructionIter {
            remaining: self.bytes,
            offset: 0,
            failed: false,
        }
    }
}

/// Failure to validate a complete QPACK decoder-stream instruction sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackDecoderInstructionsParseError {
    /// Absolute byte offset of the invalid instruction.
    pub offset: usize,
    /// Local instruction parse failure.
    pub error: QpackDecoderInstructionParseError,
}

impl fmt::Display for QpackDecoderInstructionsParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "QPACK decoder instruction sequence is invalid at byte {}: {}",
            self.offset, self.error
        )
    }
}

/// A fallible fused iterator over QPACK decoder-stream instructions.
#[derive(Clone, Copy, Debug)]
pub struct QpackDecoderInstructionIter<'a> {
    remaining: &'a [u8],
    offset: usize,
    failed: bool,
}

impl<'a> Iterator for QpackDecoderInstructionIter<'a> {
    type Item = Result<QpackDecoderInstruction<'a>, QpackDecoderInstructionsParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.remaining.is_empty() {
            return None;
        }
        match QpackDecoderInstruction::parse(self.remaining) {
            Ok(instruction) => {
                let consumed = instruction.as_bytes().len();
                self.remaining = &self.remaining[consumed..];
                self.offset += consumed;
                Some(Ok(instruction))
            }
            Err(error) => {
                self.failed = true;
                Some(Err(QpackDecoderInstructionsParseError {
                    offset: self.offset,
                    error,
                }))
            }
        }
    }
}

impl core::iter::FusedIterator for QpackDecoderInstructionIter<'_> {}

/// Failure to build a QPACK decoder-stream instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackDecoderInstructionBuildError {
    /// The Section Acknowledgment stream ID is invalid.
    SectionAcknowledgment(#[doc = "The nested stream-ID failure."] QpackIntegerBuildError),
    /// The Stream Cancellation stream ID is invalid.
    StreamCancellation(#[doc = "The nested stream-ID failure."] QpackIntegerBuildError),
    /// The Insert Count Increment value is invalid.
    InsertCountIncrement(#[doc = "The nested increment failure."] QpackIntegerBuildError),
    /// The caller destination cannot contain the complete instruction.
    BufferTooShort {
        /// Bytes required.
        required: usize,
        /// Bytes available.
        available: usize,
    },
}

impl fmt::Display for QpackDecoderInstructionBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SectionAcknowledgment(error) => {
                write!(f, "QPACK Section Acknowledgment cannot be built: {error}")
            }
            Self::StreamCancellation(error) => {
                write!(f, "QPACK Stream Cancellation cannot be built: {error}")
            }
            Self::InsertCountIncrement(error) => {
                write!(f, "QPACK Insert Count Increment cannot be built: {error}")
            }
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                f,
                "QPACK decoder instruction buffer is too short: need {required} bytes, have {available}"
            ),
        }
    }
}

/// Builds a canonical Section Acknowledgment instruction in caller-owned storage.
pub struct QpackSectionAcknowledgmentBuilder<'a> {
    destination: &'a mut [u8],
    stream_id: u64,
}

impl<'a> QpackSectionAcknowledgmentBuilder<'a> {
    /// Creates a builder for the supplied decoded stream ID.
    pub fn new(destination: &'a mut [u8], stream_id: u64) -> Self {
        Self {
            destination,
            stream_id,
        }
    }

    /// Validates all inputs and capacity before atomically writing the instruction.
    pub fn build(
        self,
    ) -> Result<QpackSectionAcknowledgment<'a>, QpackDecoderInstructionBuildError> {
        let length = integer_length(self.stream_id, 7)
            .map_err(QpackDecoderInstructionBuildError::SectionAcknowledgment)?;
        ensure_capacity(self.destination, length)?;
        write_canonical_prevalidated(&mut self.destination[..length], 7, 0x80, self.stream_id);
        let bytes = &self.destination[..length];
        Ok(QpackSectionAcknowledgment {
            bytes,
            stream_id: integer_from_prevalidated(bytes, 7, 0x80, self.stream_id),
        })
    }
}

/// Builds a canonical Stream Cancellation instruction in caller-owned storage.
pub struct QpackStreamCancellationBuilder<'a> {
    destination: &'a mut [u8],
    stream_id: u64,
}

impl<'a> QpackStreamCancellationBuilder<'a> {
    /// Creates a builder for the supplied decoded stream ID.
    pub fn new(destination: &'a mut [u8], stream_id: u64) -> Self {
        Self {
            destination,
            stream_id,
        }
    }

    /// Validates all inputs and capacity before atomically writing the instruction.
    pub fn build(self) -> Result<QpackStreamCancellation<'a>, QpackDecoderInstructionBuildError> {
        let length = integer_length(self.stream_id, 6)
            .map_err(QpackDecoderInstructionBuildError::StreamCancellation)?;
        ensure_capacity(self.destination, length)?;
        write_canonical_prevalidated(&mut self.destination[..length], 6, 0x40, self.stream_id);
        let bytes = &self.destination[..length];
        Ok(QpackStreamCancellation {
            bytes,
            stream_id: integer_from_prevalidated(bytes, 6, 0x40, self.stream_id),
        })
    }
}

/// Builds a canonical Insert Count Increment instruction in caller-owned storage.
pub struct QpackInsertCountIncrementBuilder<'a> {
    destination: &'a mut [u8],
    increment: u64,
}

impl<'a> QpackInsertCountIncrementBuilder<'a> {
    /// Creates a builder for the supplied decoded increment.
    pub fn new(destination: &'a mut [u8], increment: u64) -> Self {
        Self {
            destination,
            increment,
        }
    }

    /// Validates all inputs and capacity before atomically writing the instruction.
    pub fn build(self) -> Result<QpackInsertCountIncrement<'a>, QpackDecoderInstructionBuildError> {
        let length = integer_length(self.increment, 6)
            .map_err(QpackDecoderInstructionBuildError::InsertCountIncrement)?;
        ensure_capacity(self.destination, length)?;
        write_canonical_prevalidated(&mut self.destination[..length], 6, 0, self.increment);
        let bytes = &self.destination[..length];
        Ok(QpackInsertCountIncrement {
            bytes,
            increment: integer_from_prevalidated(bytes, 6, 0, self.increment),
        })
    }
}

fn integer_length(value: u64, prefix_bits: u8) -> Result<usize, QpackIntegerBuildError> {
    if value > QPACK_INTEGER_MAX {
        return Err(QpackIntegerBuildError::ValueTooLarge { value });
    }
    Ok(canonical_encoded_len(value, prefix_bits))
}

fn ensure_capacity(
    destination: &[u8],
    required: usize,
) -> Result<(), QpackDecoderInstructionBuildError> {
    if destination.len() < required {
        return Err(QpackDecoderInstructionBuildError::BufferTooShort {
            required,
            available: destination.len(),
        });
    }
    Ok(())
}
