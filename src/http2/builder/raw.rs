//! Atomic caller-buffer construction of raw HTTP/2 frames.

use super::super::error::Http2BuildError;
use super::super::frame::Http2FrameMut;
use super::super::types::{Http2FrameType, Http2StreamId};

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
        self.build_with_maximum(0x00ff_ffff)
    }

    /// Validates the caller-provided payload maximum and capacity before writing the frame.
    pub fn build_with_maximum(
        self,
        maximum_payload: usize,
    ) -> Result<Http2FrameMut<'a>, Http2BuildError> {
        if self.stream_id.has_reserved_bit() {
            return Err(Http2BuildError::ReservedStreamId);
        }
        let maximum_payload = maximum_payload.min(0x00ff_ffff);
        if self.payload.len() > maximum_payload {
            return Err(Http2BuildError::PayloadTooLarge {
                maximum: maximum_payload,
                actual: self.payload.len(),
            });
        }
        let required =
            9usize
                .checked_add(self.payload.len())
                .ok_or(Http2BuildError::PayloadTooLarge {
                    maximum: maximum_payload,
                    actual: self.payload.len(),
                })?;
        if self.buffer.len() < required {
            return Err(Http2BuildError::BufferTooShort {
                required,
                available: self.buffer.len(),
            });
        }

        let bytes = &mut self.buffer[..required];
        let payload_length = self.payload.len() as u32;
        bytes[0] = (payload_length >> 16) as u8;
        bytes[1] = (payload_length >> 8) as u8;
        bytes[2] = payload_length as u8;
        bytes[3] = self.frame_type.raw();
        bytes[4] = self.flags;
        bytes[5..9].copy_from_slice(&self.stream_id.raw().to_be_bytes());
        bytes[9..].copy_from_slice(self.payload);
        Ok(Http2FrameMut::from_validated(bytes))
    }
}
