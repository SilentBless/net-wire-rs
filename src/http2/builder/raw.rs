//! Atomic caller-buffer construction of raw HTTP/2 frames.

use super::super::error::Http2BuildError;
use super::super::frame::Http2FrameMut;
use super::super::types::{Http2FrameType, Http2StreamId};

pub(super) const FRAME_HEADER_LENGTH: usize = 9;
pub(super) const MAXIMUM_PAYLOAD: usize = 0x00ff_ffff;

pub(super) fn write_frame_envelope(
    buffer: &mut [u8],
    payload_length: usize,
    frame_type: Http2FrameType,
    flags: u8,
    stream_id: Http2StreamId,
    maximum_payload: usize,
) -> Result<&mut [u8], Http2BuildError> {
    let maximum_payload = maximum_payload.min(MAXIMUM_PAYLOAD);
    if payload_length > maximum_payload {
        return Err(Http2BuildError::PayloadTooLarge {
            maximum: maximum_payload,
            actual: payload_length,
        });
    }
    let required = FRAME_HEADER_LENGTH.checked_add(payload_length).ok_or(
        Http2BuildError::PayloadTooLarge {
            maximum: maximum_payload,
            actual: payload_length,
        },
    )?;
    if buffer.len() < required {
        return Err(Http2BuildError::BufferTooShort {
            required,
            available: buffer.len(),
        });
    }

    let bytes = &mut buffer[..required];
    let payload_length = payload_length as u32;
    bytes[0] = (payload_length >> 16) as u8;
    bytes[1] = (payload_length >> 8) as u8;
    bytes[2] = payload_length as u8;
    bytes[3] = frame_type.raw();
    bytes[4] = flags;
    bytes[5..FRAME_HEADER_LENGTH].copy_from_slice(&stream_id.raw().to_be_bytes());
    Ok(bytes)
}

/// Builds a raw HTTP/2 frame in caller-owned storage.
pub struct Http2FrameBuilder<'a, 'b> {
    buffer: &'a mut [u8],
    frame_type: Http2FrameType,
    flags: u8,
    stream_id: Http2StreamId,
    payload: &'b [u8],
}

impl<'a, 'b> Http2FrameBuilder<'a, 'b> {
    /// Creates a builder that copies the supplied raw payload.
    pub fn new(
        buffer: &'a mut [u8],
        frame_type: Http2FrameType,
        flags: u8,
        stream_id: Http2StreamId,
        payload: &'b [u8],
    ) -> Self {
        Self {
            buffer,
            frame_type,
            flags,
            stream_id,
            payload,
        }
    }

    /// Validates HTTP/2's representable payload length and capacity before writing the frame.
    pub fn build(self) -> Result<Http2FrameMut<'a>, Http2BuildError> {
        self.build_with_maximum(MAXIMUM_PAYLOAD)
    }

    /// Validates the caller-provided payload maximum and capacity before writing the frame.
    pub fn build_with_maximum(
        self,
        maximum_payload: usize,
    ) -> Result<Http2FrameMut<'a>, Http2BuildError> {
        if self.stream_id.has_reserved_bit() {
            return Err(Http2BuildError::ReservedStreamId);
        }
        let bytes = write_frame_envelope(
            self.buffer,
            self.payload.len(),
            self.frame_type,
            self.flags,
            self.stream_id,
            maximum_payload,
        )?;
        bytes[FRAME_HEADER_LENGTH..].copy_from_slice(self.payload);
        Ok(Http2FrameMut::from_validated(bytes))
    }
}
