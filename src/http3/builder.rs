//! Atomic caller-buffer construction of raw HTTP/3 frames.

use crate::quic::{QuicVarIntBuilder, QuicVarIntLen};

use super::{Http3Frame, Http3FrameBuildError, Http3FrameType};

/// A fully validated HTTP/3 frame envelope ready to be written.
pub(crate) struct Http3FrameEnvelopePlan {
    frame_type: Http3FrameType,
    payload_length: u64,
    type_bytes: [u8; 8],
    type_length: QuicVarIntLen,
    length_bytes: [u8; 8],
    length_length: QuicVarIntLen,
    header_length: usize,
    required: usize,
}

impl Http3FrameEnvelopePlan {
    /// Encodes an envelope and verifies that `available` can hold it and its payload.
    pub(crate) fn new(
        frame_type: Http3FrameType,
        payload_length: usize,
        available: usize,
    ) -> Result<Self, Http3FrameBuildError> {
        let payload_length_value = u64::try_from(payload_length).map_err(|_| {
            Http3FrameBuildError::PayloadLengthNotRepresentable {
                length: payload_length,
            }
        })?;
        let mut type_bytes = [0; 8];
        let type_varint = QuicVarIntBuilder::new(&mut type_bytes, frame_type.value())
            .build()
            .map_err(Http3FrameBuildError::TypeVarInt)?;
        let mut length_bytes = [0; 8];
        let length_varint = QuicVarIntBuilder::new(&mut length_bytes, payload_length_value)
            .build()
            .map_err(Http3FrameBuildError::LengthVarInt)?;
        let type_length = type_varint.encoded_len();
        let length_length = length_varint.encoded_len();
        let header_length = type_length
            .byte_len()
            .checked_add(length_length.byte_len())
            .ok_or(Http3FrameBuildError::FrameLengthOverflow {
                type_length: type_length.byte_len(),
                length_length: length_length.byte_len(),
                payload_length,
            })?;
        let required = header_length.checked_add(payload_length).ok_or(
            Http3FrameBuildError::FrameLengthOverflow {
                type_length: type_length.byte_len(),
                length_length: length_length.byte_len(),
                payload_length,
            },
        )?;
        if available < required {
            return Err(Http3FrameBuildError::BufferTooShort {
                required,
                available,
            });
        }
        Ok(Self {
            frame_type,
            payload_length: payload_length_value,
            type_bytes,
            type_length,
            length_bytes,
            length_length,
            header_length,
            required,
        })
    }

    /// Returns the offset immediately following the envelope.
    pub(crate) const fn header_length(&self) -> usize {
        self.header_length
    }

    /// Returns the complete frame length established during planning.
    pub(crate) const fn required(&self) -> usize {
        self.required
    }

    /// Writes the already validated envelope.
    pub(crate) fn write_header(&self, destination: &mut [u8]) {
        let type_length = self.type_length.byte_len();
        destination[..type_length].copy_from_slice(&self.type_bytes[..type_length]);
        destination[type_length..self.header_length]
            .copy_from_slice(&self.length_bytes[..self.length_length.byte_len()]);
    }

    /// Associates an already written frame with this validated envelope.
    pub(crate) fn finish<'output>(self, bytes: &'output mut [u8]) -> Http3Frame<'output> {
        Http3Frame::from_validated(
            bytes,
            self.frame_type.value(),
            self.type_length,
            self.payload_length,
            self.length_length,
        )
    }
}

/// Builds a raw HTTP/3 frame in caller-owned storage.
pub struct Http3FrameBuilder<'output, 'payload> {
    destination: &'output mut [u8],
    frame_type: Http3FrameType,
    payload: &'payload [u8],
}

impl<'output, 'payload> Http3FrameBuilder<'output, 'payload> {
    /// Creates a builder that canonically encodes the type and payload length.
    pub fn new(
        destination: &'output mut [u8],
        frame_type: Http3FrameType,
        payload: &'payload [u8],
    ) -> Self {
        Self {
            destination,
            frame_type,
            payload,
        }
    }

    /// Validates all components and capacity before atomically writing the complete frame.
    pub fn build(self) -> Result<Http3Frame<'output>, Http3FrameBuildError> {
        let plan = Http3FrameEnvelopePlan::new(
            self.frame_type,
            self.payload.len(),
            self.destination.len(),
        )?;
        let required = plan.required();
        let header_length = plan.header_length();
        let bytes = &mut self.destination[..required];
        plan.write_header(bytes);
        bytes[header_length..].copy_from_slice(self.payload);
        Ok(plan.finish(bytes))
    }
}
