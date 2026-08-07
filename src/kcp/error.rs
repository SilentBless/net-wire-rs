//! KCP segment construction and parsing errors.

use core::fmt;

/// Failure to construct one KCP segment in caller-provided storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KcpSegmentBuildError {
    /// The payload length cannot be represented in KCP's `u32` length field.
    PayloadLengthTooLarge {
        /// Requested payload byte length.
        length: usize,
    },
    /// Adding the fixed header length and payload length overflows `usize`.
    LengthOverflow {
        /// Fixed header byte length.
        header_length: usize,
        /// Requested payload byte length.
        payload_length: usize,
    },
    /// The destination buffer cannot hold the complete segment.
    BufferTooShort {
        /// Complete segment byte length required.
        required: usize,
        /// Bytes available in the destination buffer.
        available: usize,
    },
}

impl fmt::Display for KcpSegmentBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadLengthTooLarge { length } => {
                write!(f, "KCP payload length {length} exceeds u32::MAX")
            }
            Self::LengthOverflow {
                header_length,
                payload_length,
            } => write!(
                f,
                "KCP segment length overflows: header {header_length} plus payload {payload_length}"
            ),
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                f,
                "KCP buffer is too short: need {required} bytes, have {available}"
            ),
        }
    }
}

impl core::error::Error for KcpSegmentBuildError {}

/// Failure to parse one KCP segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KcpSegmentParseError {
    /// The input does not contain KCP's complete fixed-size header.
    HeaderTruncated {
        /// Required header byte length.
        required: usize,
        /// Bytes available in the input.
        available: usize,
    },
    /// The encoded payload length cannot be represented on this target.
    PayloadLengthNotRepresentable {
        /// Encoded little-endian payload length.
        value: u32,
    },
    /// Adding the fixed header length and encoded payload length overflows `usize`.
    LengthOverflow {
        /// Fixed header byte length.
        header_length: usize,
        /// Decoded payload byte length.
        payload_length: usize,
    },
    /// The input does not contain the complete encoded payload.
    PayloadTruncated {
        /// Complete segment byte length required by the header.
        required: usize,
        /// Bytes available in the input.
        available: usize,
    },
}

impl fmt::Display for KcpSegmentParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderTruncated {
                required,
                available,
            } => write!(
                f,
                "KCP segment header is truncated: need {required} bytes, have {available}"
            ),
            Self::PayloadLengthNotRepresentable { value } => write!(
                f,
                "KCP segment payload length {value} cannot be represented on this target"
            ),
            Self::LengthOverflow {
                header_length,
                payload_length,
            } => write!(
                f,
                "KCP segment length overflows: header {header_length} plus payload {payload_length}"
            ),
            Self::PayloadTruncated {
                required,
                available,
            } => write!(
                f,
                "KCP segment payload is truncated: need {required} bytes, have {available}"
            ),
        }
    }
}

impl core::error::Error for KcpSegmentParseError {}

/// Failure to validate a complete concatenated KCP segment sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KcpSegmentsParseError {
    /// The supplied sequence contains no segments.
    EmptySequence,
    /// A segment cannot be parsed at the indicated absolute byte offset.
    Segment {
        /// Absolute byte offset from the sequence start.
        offset: usize,
        /// Exact failure while parsing the segment.
        error: KcpSegmentParseError,
    },
}

impl fmt::Display for KcpSegmentsParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySequence => f.write_str("KCP segment sequence is empty"),
            Self::Segment { offset, error } => {
                write!(
                    f,
                    "KCP segment at offset {offset} cannot be parsed: {error}"
                )
            }
        }
    }
}

impl core::error::Error for KcpSegmentsParseError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Segment { error, .. } => Some(error),
            Self::EmptySequence => None,
        }
    }
}
