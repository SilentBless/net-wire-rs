//! Shared typed HTTP/3 frame payload diagnostics and helpers.

use core::fmt;

use crate::quic::varint::{
    QuicVarInt, QuicVarIntBuildError, QuicVarIntBuilder, QuicVarIntLen, QuicVarIntParseError,
};

use super::envelope::{
    Http3Frame, Http3FrameBuildError, Http3FrameEnvelopePlan, Http3FrameParseError,
};
use crate::http3::codepoints::Http3FrameType;

/// Identifies an HTTP/3 frame payload field whose variable-length integer is malformed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3FramePayloadField {
    /// A Push ID field.
    PushId,
    /// The role-neutral identifier carried by a GOAWAY frame.
    GoawayIdentifier,
    /// A SETTINGS parameter identifier.
    SettingIdentifier,
    /// A SETTINGS parameter value.
    SettingValue,
}

impl fmt::Display for Http3FramePayloadField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PushId => f.write_str("Push ID"),
            Self::GoawayIdentifier => f.write_str("GOAWAY identifier"),
            Self::SettingIdentifier => f.write_str("SETTINGS identifier"),
            Self::SettingValue => f.write_str("SETTINGS value"),
        }
    }
}

/// Failure to parse the intrinsic payload layout of a standard HTTP/3 frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3FramePayloadParseError {
    /// Parsing the raw HTTP/3 frame envelope failed.
    Frame(Http3FrameParseError),
    /// The raw frame type does not match the typed view.
    WrongFrameType {
        /// Frame type required by the typed view.
        expected: Http3FrameType,
        /// Frame type carried by the raw frame.
        actual: Http3FrameType,
    },
    /// A payload variable-length integer is malformed.
    PayloadVarInt {
        /// Field whose variable-length integer could not be parsed.
        field: Http3FramePayloadField,
        /// Byte offset within the frame payload.
        offset: usize,
        /// Underlying QUIC variable-length integer failure.
        error: QuicVarIntParseError,
    },
    /// An exact-layout payload has bytes after its required field.
    TrailingPayload {
        /// Bytes consumed by the required payload fields.
        consumed: usize,
        /// Total payload length in bytes.
        actual: usize,
    },
}

impl fmt::Display for Http3FramePayloadParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(error) => write!(f, "HTTP/3 frame: {error}"),
            Self::WrongFrameType { expected, actual } => write!(
                f,
                "wrong HTTP/3 frame type: expected {}, got {}",
                expected.value(),
                actual.value()
            ),
            Self::PayloadVarInt {
                field,
                offset,
                error,
            } => write!(
                f,
                "HTTP/3 {field} variable-length integer at payload offset {offset}: {error}"
            ),
            Self::TrailingPayload { consumed, actual } => write!(
                f,
                "HTTP/3 frame payload has trailing bytes: consumed {consumed}, got {actual}"
            ),
        }
    }
}

impl core::error::Error for Http3FramePayloadParseError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Frame(error) => Some(error),
            Self::WrongFrameType { .. }
            | Self::PayloadVarInt { .. }
            | Self::TrailingPayload { .. } => None,
        }
    }
}

/// Failure to build an HTTP/3 frame whose payload contains structured fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3FramePayloadBuildError {
    /// Building the raw HTTP/3 frame envelope failed.
    Frame(Http3FrameBuildError),
    /// A payload field cannot be canonically encoded as a QUIC variable-length integer.
    PayloadVarInt {
        /// Field whose value could not be encoded.
        field: Http3FramePayloadField,
        /// Underlying QUIC variable-length integer failure.
        error: QuicVarIntBuildError,
    },
    /// Adding payload components overflowed `usize`.
    PayloadLengthOverflow {
        /// Accumulated payload length before the addition.
        current: usize,
        /// Component length being added.
        addition: usize,
    },
}

impl fmt::Display for Http3FramePayloadBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(error) => write!(f, "HTTP/3 frame: {error}"),
            Self::PayloadVarInt { field, error } => {
                write!(f, "HTTP/3 {field} variable-length integer: {error}")
            }
            Self::PayloadLengthOverflow { current, addition } => write!(
                f,
                "HTTP/3 frame payload length overflows: {current} plus {addition} bytes"
            ),
        }
    }
}

impl core::error::Error for Http3FramePayloadBuildError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Frame(error) => Some(error),
            Self::PayloadVarInt { .. } | Self::PayloadLengthOverflow { .. } => None,
        }
    }
}

pub(in crate::http3) struct EncodedVarInt {
    bytes: [u8; 8],
    pub(super) len: QuicVarIntLen,
}

impl EncodedVarInt {
    pub(in crate::http3) fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len.byte_len()]
    }

    pub(in crate::http3) const fn byte_len(&self) -> usize {
        self.len.byte_len()
    }
}

pub(in crate::http3) fn encode_varint(value: u64) -> Result<EncodedVarInt, QuicVarIntBuildError> {
    let mut bytes = [0; 8];
    let varint = QuicVarIntBuilder::new(&mut bytes, value).build()?;
    let len = varint.encoded_len();
    Ok(EncodedVarInt { bytes, len })
}

pub(super) fn envelope(
    frame_type: Http3FrameType,
    payload_length: usize,
    destination: &mut [u8],
) -> Result<Http3FrameEnvelopePlan, Http3FramePayloadBuildError> {
    Http3FrameEnvelopePlan::new(frame_type, payload_length, destination.len())
        .map_err(Http3FramePayloadBuildError::Frame)
}

pub(super) fn add_payload(current: usize, addition: usize) -> Option<usize> {
    current.checked_add(addition)
}

pub(in crate::http3) fn validate_type(
    frame: Http3Frame<'_>,
    expected: Http3FrameType,
) -> Result<(), Http3FramePayloadParseError> {
    let actual = frame.frame_type();
    if actual != expected {
        return Err(Http3FramePayloadParseError::WrongFrameType { expected, actual });
    }
    Ok(())
}

pub(in crate::http3) fn parse_payload_varint<'a>(
    bytes: &'a [u8],
    field: Http3FramePayloadField,
    offset: usize,
) -> Result<QuicVarInt<'a>, Http3FramePayloadParseError> {
    QuicVarInt::parse(bytes).map_err(|error| Http3FramePayloadParseError::PayloadVarInt {
        field,
        offset,
        error,
    })
}

pub(super) fn parse_exact_varint<'a>(
    payload: &'a [u8],
    field: Http3FramePayloadField,
) -> Result<QuicVarInt<'a>, Http3FramePayloadParseError> {
    let varint = parse_payload_varint(payload, field, 0)?;
    if varint.byte_len() != payload.len() {
        return Err(Http3FramePayloadParseError::TrailingPayload {
            consumed: varint.byte_len(),
            actual: payload.len(),
        });
    }
    Ok(varint)
}
