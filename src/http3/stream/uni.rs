//! Exact borrowed and caller-buffer-built HTTP/3 unidirectional stream headers.

use core::fmt;

use crate::quic::varint::{
    QuicVarInt, QuicVarIntBuildError, QuicVarIntBuilder, QuicVarIntLen, QuicVarIntParseError,
};

use super::super::codepoints::Http3StreamType;
use super::super::enums::stream::Http3UniStreamKind;
use super::super::ids::Http3PushId;

/// Identifies a variable-length integer field in an HTTP/3 unidirectional stream header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3UniStreamField {
    /// The unidirectional stream type.
    StreamType,
    /// The Push ID following a push stream type.
    PushId,
}

impl fmt::Display for Http3UniStreamField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StreamType => f.write_str("stream type"),
            Self::PushId => f.write_str("Push ID"),
        }
    }
}

/// Failure to parse an HTTP/3 unidirectional stream header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3UniStreamParseError {
    /// A required header variable-length integer is incomplete.
    VarInt {
        /// Field whose variable-length integer could not be parsed.
        field: Http3UniStreamField,
        /// Byte offset from the beginning of the stream header.
        offset: usize,
        /// Underlying QUIC variable-length integer failure.
        error: QuicVarIntParseError,
    },
}

impl fmt::Display for Http3UniStreamParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VarInt {
                field,
                offset,
                error,
            } => write!(
                f,
                "HTTP/3 unidirectional stream {field} variable-length integer at offset {offset}: {error}"
            ),
        }
    }
}

impl core::error::Error for Http3UniStreamParseError {}

/// An exact borrowed HTTP/3 unidirectional stream header.
///
/// The view contains the stream-type variable-length integer and, for a push stream, its Push ID.
/// Bytes after this header are intentionally excluded and remain owned by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3UniStreamHeader<'a> {
    bytes: &'a [u8],
    stream_type: QuicVarInt<'a>,
    push_id: Option<QuicVarInt<'a>>,
}

impl<'a> Http3UniStreamHeader<'a> {
    /// Parses one exact unidirectional stream header from the beginning of `bytes`.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Http3UniStreamParseError> {
        let stream_type =
            QuicVarInt::parse(bytes).map_err(|error| Http3UniStreamParseError::VarInt {
                field: Http3UniStreamField::StreamType,
                offset: 0,
                error,
            })?;
        let stream_type_length = stream_type.byte_len();
        let push_id = if stream_type.value() == Http3StreamType::PUSH.value() {
            Some(
                QuicVarInt::parse(&bytes[stream_type_length..]).map_err(|error| {
                    Http3UniStreamParseError::VarInt {
                        field: Http3UniStreamField::PushId,
                        offset: stream_type_length,
                        error,
                    }
                })?,
            )
        } else {
            None
        };
        let header_length = match push_id {
            Some(push_id) => stream_type_length + push_id.byte_len(),
            None => stream_type_length,
        };
        Ok(Self::from_validated(
            &bytes[..header_length],
            stream_type.value(),
            stream_type.encoded_len(),
            push_id.map(|value| (value.value(), value.encoded_len())),
        ))
    }

    /// Returns the semantic stream kind.
    pub const fn kind(self) -> Http3UniStreamKind {
        match self.stream_type.value() {
            0 => Http3UniStreamKind::Control,
            1 => match self.push_id {
                Some(push_id) => Http3UniStreamKind::Push(Http3PushId::new(push_id.value())),
                None => Http3UniStreamKind::Unknown(Http3StreamType::PUSH),
            },
            2 => Http3UniStreamKind::QpackEncoder,
            3 => Http3UniStreamKind::QpackDecoder,
            value => Http3UniStreamKind::Unknown(Http3StreamType::new(value)),
        }
    }

    /// Returns the raw unidirectional stream type.
    pub const fn stream_type(self) -> Http3StreamType {
        Http3StreamType::new(self.stream_type.value())
    }

    /// Returns the exact encoded stream-type variable-length integer.
    pub const fn stream_type_varint(self) -> QuicVarInt<'a> {
        self.stream_type
    }

    /// Returns the Push ID for a push stream.
    pub const fn push_id(self) -> Option<Http3PushId> {
        match self.push_id {
            Some(push_id) => Some(Http3PushId::new(push_id.value())),
            None => None,
        }
    }

    /// Returns the exact encoded Push ID variable-length integer for a push stream.
    pub const fn push_id_varint(self) -> Option<QuicVarInt<'a>> {
        self.push_id
    }

    /// Returns exactly the consumed stream header bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Assembles a header from builder- or parser-validated wire components.
    pub(super) fn from_validated(
        bytes: &'a [u8],
        stream_type_value: u64,
        stream_type_length: QuicVarIntLen,
        push_id: Option<(u64, QuicVarIntLen)>,
    ) -> Self {
        let stream_type_length_bytes = stream_type_length.byte_len();
        let stream_type = QuicVarInt::from_validated(
            &bytes[..stream_type_length_bytes],
            stream_type_value,
            stream_type_length,
        );
        let push_id = push_id.map(|(value, length)| {
            let start = stream_type_length_bytes;
            QuicVarInt::from_validated(&bytes[start..start + length.byte_len()], value, length)
        });
        Self {
            bytes,
            stream_type,
            push_id,
        }
    }
}

/// Failure to build an HTTP/3 unidirectional stream header in caller-provided storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3UniStreamBuildError {
    /// A header variable-length integer cannot be canonically encoded.
    VarInt {
        /// Field whose value could not be encoded.
        field: Http3UniStreamField,
        /// Underlying QUIC variable-length integer failure.
        error: QuicVarIntBuildError,
    },
    /// Adding encoded header field lengths overflowed `usize`.
    LengthOverflow {
        /// First encoded field length in bytes.
        first: usize,
        /// Second encoded field length in bytes.
        second: usize,
    },
    /// The caller buffer cannot contain the complete header.
    BufferTooShort {
        /// Bytes required for the complete header.
        required: usize,
        /// Bytes available in the destination.
        available: usize,
    },
    /// A known stream type was incorrectly supplied as `Unknown`.
    KnownTypeMarkedUnknown {
        /// Known raw stream type value supplied as `Unknown`.
        stream_type: Http3StreamType,
    },
}

impl fmt::Display for Http3UniStreamBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VarInt { field, error } => {
                write!(
                    f,
                    "HTTP/3 unidirectional stream {field} variable-length integer: {error}"
                )
            }
            Self::LengthOverflow { first, second } => write!(
                f,
                "HTTP/3 unidirectional stream header length overflows: {first} plus {second} bytes"
            ),
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                f,
                "HTTP/3 unidirectional stream destination is too short: need {required} bytes, have {available}"
            ),
            Self::KnownTypeMarkedUnknown { stream_type } => write!(
                f,
                "HTTP/3 known unidirectional stream type {} cannot be marked unknown",
                stream_type.value()
            ),
        }
    }
}

impl core::error::Error for Http3UniStreamBuildError {}

/// Builds a canonical HTTP/3 unidirectional stream header in caller-owned storage.
pub struct Http3UniStreamHeaderBuilder<'output> {
    destination: &'output mut [u8],
    kind: Http3UniStreamKind,
}

impl<'output> Http3UniStreamHeaderBuilder<'output> {
    /// Creates a builder for an HTTP/3 unidirectional stream kind.
    pub fn new(destination: &'output mut [u8], kind: Http3UniStreamKind) -> Self {
        Self { destination, kind }
    }

    /// Canonically encodes and atomically writes the exact stream header.
    pub fn build(self) -> Result<Http3UniStreamHeader<'output>, Http3UniStreamBuildError> {
        let (stream_type, push_id) = stream_fields(self.kind)?;
        let stream_type = encode_varint(stream_type.value(), Http3UniStreamField::StreamType)?;
        let push_id = match push_id {
            Some(push_id) => Some(encode_varint(push_id, Http3UniStreamField::PushId)?),
            None => None,
        };
        let required = match push_id {
            Some(push_id) => stream_type
                .length
                .byte_len()
                .checked_add(push_id.length.byte_len())
                .ok_or(Http3UniStreamBuildError::LengthOverflow {
                    first: stream_type.length.byte_len(),
                    second: push_id.length.byte_len(),
                })?,
            None => stream_type.length.byte_len(),
        };
        if self.destination.len() < required {
            return Err(Http3UniStreamBuildError::BufferTooShort {
                required,
                available: self.destination.len(),
            });
        }

        let bytes = &mut self.destination[..required];
        let stream_type_length = stream_type.length.byte_len();
        bytes[..stream_type_length].copy_from_slice(stream_type.bytes());
        if let Some(push_id) = push_id {
            bytes[stream_type_length..].copy_from_slice(push_id.bytes());
        }
        Ok(Http3UniStreamHeader::from_validated(
            bytes,
            stream_type.value,
            stream_type.length,
            push_id.map(|push_id| (push_id.value, push_id.length)),
        ))
    }
}

#[derive(Clone, Copy)]
struct EncodedVarInt {
    bytes: [u8; 8],
    value: u64,
    length: QuicVarIntLen,
}

impl EncodedVarInt {
    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length.byte_len()]
    }
}

fn stream_fields(
    kind: Http3UniStreamKind,
) -> Result<(Http3StreamType, Option<u64>), Http3UniStreamBuildError> {
    match kind {
        Http3UniStreamKind::Control => Ok((Http3StreamType::CONTROL, None)),
        Http3UniStreamKind::Push(push_id) => Ok((Http3StreamType::PUSH, Some(push_id.value()))),
        Http3UniStreamKind::QpackEncoder => Ok((Http3StreamType::QPACK_ENCODER, None)),
        Http3UniStreamKind::QpackDecoder => Ok((Http3StreamType::QPACK_DECODER, None)),
        Http3UniStreamKind::Unknown(stream_type) => {
            if matches!(stream_type.value(), 0..=3) {
                Err(Http3UniStreamBuildError::KnownTypeMarkedUnknown { stream_type })
            } else {
                Ok((stream_type, None))
            }
        }
    }
}

fn encode_varint(
    value: u64,
    field: Http3UniStreamField,
) -> Result<EncodedVarInt, Http3UniStreamBuildError> {
    let mut bytes = [0; 8];
    let varint = QuicVarIntBuilder::new(&mut bytes, value)
        .build()
        .map_err(|error| Http3UniStreamBuildError::VarInt { field, error })?;
    let length = varint.encoded_len();
    Ok(EncodedVarInt {
        bytes,
        value,
        length,
    })
}
