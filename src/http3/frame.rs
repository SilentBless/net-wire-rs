//! Exact HTTP/3 frame envelope views.

use crate::quic::{QuicVarInt, QuicVarIntLen};

use super::{Http3FrameParseError, Http3FrameType};

/// A structurally bounded HTTP/3 frame preserving exact variable-integer encodings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3Frame<'a> {
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    payload_length: QuicVarInt<'a>,
}

impl<'a> Http3Frame<'a> {
    pub(super) fn from_validated(
        bytes: &'a [u8],
        frame_type_value: u64,
        frame_type_length: QuicVarIntLen,
        payload_length_value: u64,
        payload_length_length: QuicVarIntLen,
    ) -> Self {
        let type_end = frame_type_length.byte_len();
        let length_end = type_end + payload_length_length.byte_len();
        Self {
            bytes,
            frame_type: QuicVarInt::from_validated(
                &bytes[..type_end],
                frame_type_value,
                frame_type_length,
            ),
            payload_length: QuicVarInt::from_validated(
                &bytes[type_end..length_end],
                payload_length_value,
                payload_length_length,
            ),
        }
    }

    /// Parses the first complete frame, enforcing the caller-provided payload maximum.
    pub fn parse(bytes: &'a [u8], maximum_payload: usize) -> Result<Self, Http3FrameParseError> {
        let frame_type = QuicVarInt::parse(bytes).map_err(Http3FrameParseError::TypeVarInt)?;
        let type_length = frame_type.byte_len();
        let payload_length =
            QuicVarInt::parse(&bytes[type_length..]).map_err(Http3FrameParseError::LengthVarInt)?;
        let total_length = frame_length(
            type_length,
            payload_length.byte_len(),
            payload_length.value(),
            maximum_payload,
            bytes.len(),
        )?;
        Ok(Self {
            bytes: &bytes[..total_length],
            frame_type,
            payload_length,
        })
    }

    /// Returns the raw frame type.
    pub const fn frame_type(&self) -> Http3FrameType {
        Http3FrameType::new(self.frame_type.value())
    }

    /// Returns the exact frame type variable-length integer.
    pub const fn frame_type_varint(&self) -> QuicVarInt<'a> {
        self.frame_type
    }

    /// Returns the exact payload length variable-length integer.
    pub const fn payload_length_varint(&self) -> QuicVarInt<'a> {
        self.payload_length
    }

    /// Returns the declared payload length.
    pub fn payload_length(&self) -> usize {
        self.payload().len()
    }

    /// Returns the exact payload bytes.
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[self.frame_type.byte_len() + self.payload_length.byte_len()..]
    }

    /// Returns the exact represented frame bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

/// A mutable structurally bounded HTTP/3 frame.
#[derive(Debug, Eq, PartialEq)]
pub struct Http3FrameMut<'a> {
    bytes: &'a mut [u8],
    frame_type: Http3FrameType,
    payload_offset: usize,
}

impl<'a> Http3FrameMut<'a> {
    /// Parses the first complete frame, enforcing the caller-provided payload maximum.
    pub fn parse(
        bytes: &'a mut [u8],
        maximum_payload: usize,
    ) -> Result<Self, Http3FrameParseError> {
        let (frame_type, payload_offset, total_length) = frame_layout(bytes, maximum_payload)?;
        Ok(Self {
            bytes: &mut bytes[..total_length],
            frame_type,
            payload_offset,
        })
    }

    /// Returns the raw frame type.
    pub const fn frame_type(&self) -> Http3FrameType {
        self.frame_type
    }

    /// Returns the declared payload length.
    pub fn payload_length(&self) -> usize {
        self.bytes.len() - self.payload_offset
    }

    /// Returns the exact payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.bytes[self.payload_offset..]
    }

    /// Returns the exact payload bytes mutably without changing their encoded length.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[self.payload_offset..]
    }

    /// Returns the exact represented frame bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }
}

fn frame_layout(
    bytes: &[u8],
    maximum_payload: usize,
) -> Result<(Http3FrameType, usize, usize), Http3FrameParseError> {
    let frame_type = QuicVarInt::parse(bytes).map_err(Http3FrameParseError::TypeVarInt)?;
    let type_length = frame_type.byte_len();
    let payload_length =
        QuicVarInt::parse(&bytes[type_length..]).map_err(Http3FrameParseError::LengthVarInt)?;
    let payload_offset = type_length + payload_length.byte_len();
    let total_length = frame_length(
        type_length,
        payload_length.byte_len(),
        payload_length.value(),
        maximum_payload,
        bytes.len(),
    )?;
    Ok((
        Http3FrameType::new(frame_type.value()),
        payload_offset,
        total_length,
    ))
}

fn frame_length(
    type_length: usize,
    length_length: usize,
    payload_length_value: u64,
    maximum_payload: usize,
    available: usize,
) -> Result<usize, Http3FrameParseError> {
    let payload_length = usize::try_from(payload_length_value).map_err(|_| {
        Http3FrameParseError::PayloadLengthNotRepresentable {
            value: payload_length_value,
        }
    })?;
    if payload_length > maximum_payload {
        return Err(Http3FrameParseError::PayloadTooLarge {
            maximum: maximum_payload,
            actual: payload_length,
        });
    }
    let header_length = type_length.checked_add(length_length).ok_or(
        Http3FrameParseError::FrameLengthOverflow {
            type_length,
            length_length,
            payload_length,
        },
    )?;
    let required = header_length.checked_add(payload_length).ok_or(
        Http3FrameParseError::FrameLengthOverflow {
            type_length,
            length_length,
            payload_length,
        },
    )?;
    if available < required {
        return Err(Http3FrameParseError::IncompletePayload {
            required,
            available,
        });
    }
    Ok(required)
}
