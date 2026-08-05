//! HTTP/2 parsing and construction errors.

use core::fmt;

/// Failure to validate a raw HTTP/2 wire layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http2ParseError {
    /// Fewer bytes than a fixed prefix or declared frame payload were supplied.
    Incomplete {
        /// Required bytes.
        required: usize,
        /// Available bytes.
        available: usize,
    },
    /// A byte differs from the required client-preface byte.
    ClientPrefaceMismatch {
        /// Offset of the mismatched byte.
        offset: usize,
        /// Required byte.
        expected: u8,
        /// Supplied byte.
        actual: u8,
    },
    /// A declared frame payload exceeds the caller-provided maximum.
    PayloadTooLarge {
        /// Caller-provided maximum payload length.
        maximum: usize,
        /// Declared payload length.
        actual: usize,
    },
    /// A typed frame view was requested for a different raw frame type.
    WrongFrameType {
        /// Required frame type.
        expected: super::Http2FrameType,
        /// Actual frame type.
        actual: super::Http2FrameType,
    },
    /// A frame that requires a stream has a zero 31-bit stream identifier.
    ZeroStreamId,
    /// A frame that requires the connection stream has a nonzero 31-bit stream identifier.
    ExpectedZeroStreamId,
    /// A fixed-layout frame has an unexpected payload length.
    FrameSizeMismatch {
        /// Required payload length.
        expected: usize,
        /// Actual payload length.
        actual: usize,
    },
    /// A WINDOW_UPDATE frame has a zero 31-bit increment.
    ZeroWindowIncrement,
    /// A SETTINGS payload does not contain a whole number of six-byte parameters.
    SettingsPayloadLength {
        /// Actual payload length.
        actual: usize,
    },
    /// A SETTINGS frame with ACK set has a nonempty payload.
    SettingsAckPayload {
        /// Actual payload length.
        actual: usize,
    },
    /// A SETTINGS parameter has an intrinsically invalid value.
    InvalidSettingValue {
        /// Encoded setting identifier.
        id: super::Http2SettingId,
        /// Encoded setting value.
        value: u32,
    },
    /// A PUSH_PROMISE frame has a zero 31-bit promised stream identifier.
    ZeroPromisedStreamId,
    /// A PADDED frame has no pad-length byte or declares too much padding.
    InvalidPadding {
        /// Encoded padding length, or zero when the pad-length byte is absent.
        padding_length: u8,
        /// Total payload length.
        payload_length: usize,
    },
    /// A required intrinsic payload section is truncated.
    MalformedPayload {
        /// Required bytes in the section.
        required: usize,
        /// Available bytes in the section.
        available: usize,
    },
}

impl fmt::Display for Http2ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete {
                required,
                available,
            } => write!(
                f,
                "HTTP/2 input is incomplete: need {required} bytes, have {available}"
            ),
            Self::ClientPrefaceMismatch {
                offset,
                expected,
                actual,
            } => write!(
                f,
                "HTTP/2 client preface mismatch at byte {offset}: expected {expected}, got {actual}"
            ),
            Self::PayloadTooLarge { maximum, actual } => write!(
                f,
                "HTTP/2 frame payload is too large: maximum {maximum}, got {actual}"
            ),
            Self::WrongFrameType { expected, actual } => write!(
                f,
                "HTTP/2 frame type mismatch: expected {}, got {}",
                expected.raw(),
                actual.raw()
            ),
            Self::ZeroStreamId => f.write_str("HTTP/2 frame requires a nonzero stream identifier"),
            Self::ExpectedZeroStreamId => {
                f.write_str("HTTP/2 frame requires a zero stream identifier")
            }
            Self::FrameSizeMismatch { expected, actual } => write!(
                f,
                "HTTP/2 fixed-layout frame payload length mismatch: expected {expected}, got {actual}"
            ),
            Self::ZeroWindowIncrement => {
                f.write_str("HTTP/2 WINDOW_UPDATE frame requires a nonzero increment")
            }
            Self::SettingsPayloadLength { actual } => write!(
                f,
                "HTTP/2 SETTINGS payload length must be a multiple of 6, got {actual}"
            ),
            Self::SettingsAckPayload { actual } => write!(
                f,
                "HTTP/2 SETTINGS ACK frame must have an empty payload, got {actual} bytes"
            ),
            Self::InvalidSettingValue { id, value } => write!(
                f,
                "HTTP/2 SETTINGS parameter {} has invalid value {value}",
                id.raw()
            ),
            Self::ZeroPromisedStreamId => {
                f.write_str("HTTP/2 PUSH_PROMISE requires a nonzero promised stream identifier")
            }
            Self::InvalidPadding {
                padding_length,
                payload_length,
            } => write!(
                f,
                "HTTP/2 padding length {padding_length} is invalid for payload length {payload_length}"
            ),
            Self::MalformedPayload {
                required,
                available,
            } => write!(
                f,
                "HTTP/2 payload section is truncated: need {required} bytes, have {available}"
            ),
        }
    }
}

/// Failure to create an outgoing HTTP/2 stream identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http2StreamIdError {
    /// The reserved high bit is set.
    ReservedBitSet,
}

impl fmt::Display for Http2StreamIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReservedBitSet => {
                f.write_str("HTTP/2 stream identifier has its reserved bit set")
            }
        }
    }
}

/// Failure to construct an HTTP/2 frame in caller-provided storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http2BuildError {
    /// A frame that requires a stream was given the zero stream identifier.
    ZeroStreamId,
    /// The outgoing stream identifier has its reserved high bit set.
    ReservedStreamId,
    /// A WINDOW_UPDATE frame was given a zero 31-bit increment.
    ZeroWindowIncrement,
    /// The outgoing WINDOW_UPDATE increment has its reserved high bit set.
    ReservedWindowIncrement,
    /// A SETTINGS ACK frame was given one or more settings.
    SettingsAckPayload {
        /// Encoded payload length in bytes.
        actual: usize,
    },
    /// A SETTINGS parameter has an intrinsically invalid value.
    InvalidSettingValue {
        /// Encoded setting identifier.
        id: super::Http2SettingId,
        /// Encoded setting value.
        value: u32,
    },
    /// The outgoing GOAWAY last-stream identifier has its reserved high bit set.
    ReservedLastStreamId,
    /// Caller-supplied DATA flags include PADDED, which is controlled by the padding argument.
    DataPaddedFlagSet,
    /// Caller-supplied HEADERS flags include PADDED, which is controlled by the padding argument.
    HeadersPaddedFlagSet,
    /// Caller-supplied HEADERS flags include PRIORITY, which is controlled by the priority argument.
    HeadersPriorityFlagSet,
    /// Caller-supplied PUSH_PROMISE flags include PADDED, which is controlled by the padding argument.
    PushPromisePaddedFlagSet,
    /// A PUSH_PROMISE frame was given a zero promised stream identifier.
    ZeroPromisedStreamId,
    /// A PUSH_PROMISE frame was given a promised stream identifier with its reserved bit set.
    ReservedPromisedStreamId,
    /// The payload exceeds the caller-provided maximum or HTTP/2's 24-bit length field.
    PayloadTooLarge {
        /// Maximum permitted payload length.
        maximum: usize,
        /// Supplied payload length.
        actual: usize,
    },
    /// The caller buffer cannot contain the complete frame.
    BufferTooShort {
        /// Required bytes.
        required: usize,
        /// Available bytes.
        available: usize,
    },
}

impl fmt::Display for Http2BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroStreamId => {
                f.write_str("outgoing HTTP/2 frame requires a nonzero stream identifier")
            }
            Self::ReservedStreamId => {
                f.write_str("outgoing HTTP/2 stream identifier has its reserved bit set")
            }
            Self::ZeroWindowIncrement => {
                f.write_str("outgoing HTTP/2 WINDOW_UPDATE requires a nonzero increment")
            }
            Self::ReservedWindowIncrement => f.write_str(
                "outgoing HTTP/2 WINDOW_UPDATE increment has its reserved bit set",
            ),
            Self::SettingsAckPayload { actual } => write!(
                f,
                "outgoing HTTP/2 SETTINGS ACK frame must have an empty payload, got {actual} bytes"
            ),
            Self::InvalidSettingValue { id, value } => write!(
                f,
                "outgoing HTTP/2 SETTINGS parameter {} has invalid value {value}",
                id.raw()
            ),
            Self::ReservedLastStreamId => {
                f.write_str("outgoing HTTP/2 GOAWAY last-stream identifier has its reserved bit set")
            }
            Self::DataPaddedFlagSet => f.write_str(
                "outgoing HTTP/2 DATA flags must not include PADDED; use the padding length argument",
            ),
            Self::HeadersPaddedFlagSet => f.write_str(
                "outgoing HTTP/2 HEADERS flags must not include PADDED; use the padding length argument",
            ),
            Self::HeadersPriorityFlagSet => f.write_str(
                "outgoing HTTP/2 HEADERS flags must not include PRIORITY; use the priority argument",
            ),
            Self::PushPromisePaddedFlagSet => f.write_str(
                "outgoing HTTP/2 PUSH_PROMISE flags must not include PADDED; use the padding length argument",
            ),
            Self::ZeroPromisedStreamId => {
                f.write_str("outgoing HTTP/2 PUSH_PROMISE requires a nonzero promised stream identifier")
            }
            Self::ReservedPromisedStreamId => f.write_str(
                "outgoing HTTP/2 PUSH_PROMISE promised stream identifier has its reserved bit set",
            ),
            Self::PayloadTooLarge { maximum, actual } => write!(
                f,
                "HTTP/2 payload is too large: maximum {maximum}, got {actual}"
            ),
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                f,
                "HTTP/2 buffer is too short: need {required} bytes, have {available}"
            ),
        }
    }
}
