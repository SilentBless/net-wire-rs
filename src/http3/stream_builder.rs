//! Atomic caller-buffer construction of HTTP/3 unidirectional stream headers.

use crate::quic::{QuicVarIntBuilder, QuicVarIntLen};

use super::{
    Http3StreamType, Http3UniStreamBuildError, Http3UniStreamField, Http3UniStreamHeader,
    Http3UniStreamKind,
};

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
