//! QUIC frame parsing diagnostics.

use core::fmt;

use super::super::varint::{QuicVarIntLen, QuicVarIntParseError};

/// Identifies a semantic field in a QUIC frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum QuicFrameField {
    /// The CRYPTO frame's offset field.
    CryptoOffset,
    /// The CRYPTO frame's data-length field.
    CryptoLength,
    /// The CRYPTO frame's opaque data bytes.
    CryptoData,
    /// The frame's token-length field.
    TokenLength,
    /// The frame's opaque token bytes.
    Token,
    /// The frame's stream-ID field.
    StreamId,
    /// The STREAM frame's offset field.
    StreamOffset,
    /// The STREAM frame's data-length field.
    StreamLength,
    /// The STREAM frame's opaque data bytes.
    StreamData,
    /// The frame's maximum-data field.
    MaximumData,
    /// The frame's maximum-stream-data field.
    MaximumStreamData,
    /// The frame's maximum-streams field.
    MaximumStreams,
    /// The frame's application-error-code field.
    ApplicationErrorCode,
    /// The CONNECTION_CLOSE frame's error-code field.
    ConnectionCloseErrorCode,
    /// The transport CONNECTION_CLOSE frame's triggering-frame-type field.
    TriggeringFrameType,
    /// The CONNECTION_CLOSE frame's reason-phrase-length field.
    ReasonPhraseLength,
    /// The CONNECTION_CLOSE frame's opaque reason-phrase bytes.
    ReasonPhrase,
    /// The frame's final-size field.
    FinalSize,
    /// The frame's opaque path-validation data.
    PathData,
    /// The frame's connection-ID sequence-number field.
    SequenceNumber,
    /// The frame's retire-prior-to field.
    RetirePriorTo,
    /// The frame's connection-ID-length field.
    ConnectionIdLength,
    /// The frame's opaque connection-ID bytes.
    ConnectionId,
    /// The frame's stateless-reset-token bytes.
    StatelessResetToken,
    /// The ACK frame's largest-acknowledged field.
    LargestAcknowledged,
    /// The ACK frame's acknowledgment-delay field.
    AckDelay,
    /// The ACK frame's additional-range count field.
    AckRangeCount,
    /// The ACK frame's first acknowledgment-range field.
    FirstAckRange,
    /// An ACK frame's additional-range gap field.
    AckGap,
    /// An ACK frame's additional-range length field.
    AckRangeLength,
    /// The ACK_ECN frame's ECT(0) count field.
    Ect0Count,
    /// The ACK_ECN frame's ECT(1) count field.
    Ect1Count,
    /// The ACK_ECN frame's ECN-CE count field.
    EcnCeCount,
}

/// Failure to parse a QUIC plaintext frame sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicFrameParseError {
    /// The supplied plaintext frame sequence contains no frames.
    EmptySequence,
    /// The frame-type variable integer is incomplete at the indicated sequence offset.
    FrameType {
        /// Absolute byte offset of the frame type from the sequence start.
        offset: usize,
        /// Exact variable-integer parsing failure.
        error: QuicVarIntParseError,
    },
    /// A semantic frame field variable integer is incomplete at the indicated sequence offset.
    Field {
        /// Semantic field whose variable integer could not be parsed.
        field: QuicFrameField,
        /// Absolute byte offset of the field from the sequence start.
        offset: usize,
        /// Exact variable-integer parsing failure.
        error: QuicVarIntParseError,
    },
    /// A semantic frame field exceeds its RFC-defined maximum value.
    FieldValueOutOfRange {
        /// Semantic field whose decoded value exceeds its maximum.
        field: QuicFrameField,
        /// Absolute byte offset of the field from the sequence start.
        offset: usize,
        /// Decoded field value.
        value: u64,
        /// Greatest permitted field value.
        maximum: u64,
    },
    /// A semantic frame field exceeds the decoded value of another field.
    FieldValueExceedsField {
        /// Semantic field whose decoded value is too large.
        field: QuicFrameField,
        /// Absolute byte offset of the field from the sequence start.
        offset: usize,
        /// Decoded field value.
        value: u64,
        /// Semantic field supplying the maximum value.
        maximum_field: QuicFrameField,
        /// Decoded maximum-field value.
        maximum: u64,
    },
    /// A decoded frame byte range exceeds its RFC-defined maximum end offset.
    FieldRangeOutOfRange {
        /// Semantic field encoding the decoded range start.
        field: QuicFrameField,
        /// Absolute byte offset of the encoded range-start field from the sequence start.
        offset: usize,
        /// Decoded range start.
        start: u64,
        /// Decoded range length.
        length: u64,
        /// Greatest permitted decoded range end.
        maximum: u64,
    },
    /// A decoded bounded-byte field length cannot be represented as `usize` on this target.
    LengthNotRepresentable {
        /// Semantic field whose length cannot be represented.
        field: QuicFrameField,
        /// Absolute byte offset of the encoded length from the sequence start.
        offset: usize,
        /// Decoded wire length.
        value: u64,
    },
    /// An implicit bounded-byte field length cannot be represented as `u64`.
    ImplicitLengthNotRepresentable {
        /// Semantic field whose implicit length cannot be represented.
        field: QuicFrameField,
        /// Absolute byte offset of the bounded byte field from the sequence start.
        offset: usize,
        /// Native byte length derived from the supplied slice.
        length: usize,
    },
    /// Computing the end of a bounded-byte field overflows `usize`.
    LengthOverflow {
        /// Semantic bounded-byte field whose end cannot be represented.
        field: QuicFrameField,
        /// Absolute byte offset of the bounded byte field from the sequence start.
        offset: usize,
        /// Representable bounded byte-field length.
        length: usize,
    },
    /// A bounded-byte field is incomplete.
    IncompleteBytes {
        /// Semantic bounded-byte field that is incomplete.
        field: QuicFrameField,
        /// Absolute byte offset of the bounded byte field from the sequence start.
        offset: usize,
        /// Bytes required by the bounded byte field.
        required: usize,
        /// Bytes available for the bounded byte field.
        available: usize,
    },
    /// A semantically required nonempty field is empty.
    EmptyField {
        /// Semantic field that must not be empty.
        field: QuicFrameField,
        /// Absolute byte offset of the field from the sequence start.
        offset: usize,
    },
    /// Computing an ACK range packet number would be negative.
    AckRangeUnderflow {
        /// ACK field whose encoded value caused the underflow.
        field: QuicFrameField,
        /// Absolute byte offset of the encoded field from the sequence start.
        offset: usize,
        /// Packet number before subtracting this field.
        base: u64,
        /// Decoded field value being subtracted.
        value: u64,
        /// Additional fixed adjustment applied after `value`.
        adjustment: u64,
    },
    /// The frame type has no safe boundary without implementing its type-specific layout.
    UnsupportedFrameType {
        /// Decoded raw frame-type value.
        value: u64,
        /// Exact encoded frame-type width.
        length: QuicVarIntLen,
        /// Absolute byte offset of the frame type from the sequence start.
        offset: usize,
    },
}

impl fmt::Display for QuicFrameParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySequence => write!(f, "QUIC plaintext frame sequence is empty"),
            Self::FrameType { offset, error } => write!(
                f,
                "QUIC frame type at offset {offset} cannot be parsed: {error}"
            ),
            Self::Field {
                field,
                offset,
                error,
            } => write!(
                f,
                "QUIC frame {field:?} field at offset {offset} cannot be parsed: {error}"
            ),
            Self::FieldValueOutOfRange {
                field,
                offset,
                value,
                maximum,
            } => write!(
                f,
                "QUIC frame {field:?} field at offset {offset} has value {value}, exceeding maximum {maximum}"
            ),
            Self::FieldValueExceedsField {
                field,
                offset,
                value,
                maximum_field,
                maximum,
            } => write!(
                f,
                "QUIC frame {field:?} field at offset {offset} has value {value}, exceeding {maximum_field:?} value {maximum}"
            ),
            Self::FieldRangeOutOfRange {
                field,
                offset,
                start,
                length,
                maximum,
            } => write!(
                f,
                "QUIC frame {field:?} range at offset {offset} has start {start} plus length {length}, exceeding maximum end {maximum}"
            ),
            Self::LengthNotRepresentable {
                field,
                offset,
                value,
            } => write!(
                f,
                "QUIC frame {field:?} length at offset {offset} has unrepresentable value {value}"
            ),
            Self::ImplicitLengthNotRepresentable {
                field,
                offset,
                length,
            } => write!(
                f,
                "QUIC frame {field:?} implicit length at offset {offset} cannot represent native length {length} as u64"
            ),
            Self::LengthOverflow {
                field,
                offset,
                length,
            } => write!(
                f,
                "QUIC frame {field:?} bounded field at offset {offset} overflows with length {length}"
            ),
            Self::IncompleteBytes {
                field,
                offset,
                required,
                available,
            } => write!(
                f,
                "QUIC frame {field:?} bytes at offset {offset} are incomplete: need {required} bytes, have {available}"
            ),
            Self::EmptyField { field, offset } => write!(
                f,
                "QUIC frame {field:?} field at offset {offset} must be nonempty"
            ),
            Self::AckRangeUnderflow {
                field,
                offset,
                base,
                value,
                adjustment,
            } => write!(
                f,
                "QUIC ACK {field:?} field at offset {offset} underflows: {base} minus {value} minus {adjustment}"
            ),
            Self::UnsupportedFrameType {
                value,
                length,
                offset,
            } => write!(
                f,
                "QUIC frame type {value} at offset {offset} with encoded width {} is unsupported",
                length.byte_len()
            ),
        }
    }
}
