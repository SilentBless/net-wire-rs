//! Checked construction of QPACK decoder-stream instructions.

use core::fmt;

use super::{QpackInsertCountIncrement, QpackSectionAcknowledgment, QpackStreamCancellation};
use crate::qpack::integer::{
    QPACK_INTEGER_MAX, QpackIntegerBuildError, canonical_encoded_len, integer_from_prevalidated,
    write_canonical_prevalidated,
};

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
