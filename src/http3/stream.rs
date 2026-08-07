//! Exact borrowed HTTP/3 unidirectional stream headers.

use crate::quic::QuicVarInt;

use super::{Http3PushId, Http3StreamType, Http3UniStreamField, Http3UniStreamParseError};

/// Classifies an HTTP/3 unidirectional stream header without discarding extension types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3UniStreamKind {
    /// The HTTP/3 control stream.
    Control,
    /// A server push stream and its Push ID.
    Push(Http3PushId),
    /// The QPACK encoder stream.
    QpackEncoder,
    /// The QPACK decoder stream.
    QpackDecoder,
    /// An extension, unknown, or grease stream type.
    Unknown(Http3StreamType),
}

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
        stream_type_length: crate::quic::QuicVarIntLen,
        push_id: Option<(u64, crate::quic::QuicVarIntLen)>,
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
