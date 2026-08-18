//! Atomic caller-buffer construction of raw HTTP/2 frames.

use super::super::error::Http2BuildError;
use super::super::frame::Http2FrameMut;
use super::super::frame_layout::{
    FRAME_HEADER_LENGTH, Http2FrameLayoutBuilder, Http2FrameLayoutViewMut,
    Http2FrameLayoutWriteError, MAXIMUM_PAYLOAD,
};
use super::super::types::{Http2FrameType, Http2StreamId};

fn representation_error(error: Http2FrameLayoutWriteError) -> Http2BuildError {
    match error {
        Http2FrameLayoutWriteError::FieldPayloadLengthHigh(error)
        | Http2FrameLayoutWriteError::FieldPayloadLengthMiddle(error)
        | Http2FrameLayoutWriteError::FieldPayloadLengthLow(error)
        | Http2FrameLayoutWriteError::FieldFrameType(error)
        | Http2FrameLayoutWriteError::FieldFlags(error)
        | Http2FrameLayoutWriteError::FieldStreamId(error) => match error {},
        Http2FrameLayoutWriteError::OutputTooShort { expected, actual } => {
            Http2BuildError::BufferTooShort {
                required: expected,
                available: actual,
            }
        }
        Http2FrameLayoutWriteError::InvalidPlanLength { .. }
        | Http2FrameLayoutWriteError::MissingContext { .. }
        | Http2FrameLayoutWriteError::InvalidCodecWidth { .. }
        | Http2FrameLayoutWriteError::InvalidRangeSource { .. }
        | Http2FrameLayoutWriteError::ConflictingRangeSources { .. }
        | Http2FrameLayoutWriteError::InvalidPrefixPlanLength { .. }
        | Http2FrameLayoutWriteError::InvalidLayoutExtent { .. }
        | Http2FrameLayoutWriteError::MissingField { .. } => Http2BuildError::InvalidRepresentation,
    }
}

fn validate_envelope(
    buffer: &[u8],
    payload_length: usize,
    maximum_payload: usize,
) -> Result<usize, Http2BuildError> {
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
    Ok(required)
}

fn length_octets(payload_length: usize) -> (u8, u8, u8) {
    (
        (payload_length >> 16) as u8,
        (payload_length >> 8) as u8,
        payload_length as u8,
    )
}

pub(super) fn write_frame_envelope<'a>(
    buffer: &'a mut [u8],
    payload_length: usize,
    frame_type: Http2FrameType,
    flags: u8,
    stream_id: Http2StreamId,
    maximum_payload: usize,
) -> Result<Http2FrameLayoutViewMut<'a>, Http2BuildError> {
    let required = validate_envelope(buffer, payload_length, maximum_payload)?;
    let (payload_length_high, payload_length_middle, payload_length_low) =
        length_octets(payload_length);
    let (layout, _) = Http2FrameLayoutBuilder::new()
        .payload_length_high(payload_length_high)
        .payload_length_middle(payload_length_middle)
        .payload_length_low(payload_length_low)
        .frame_type(frame_type)
        .flags(flags)
        .stream_id(stream_id)
        .payload_existing(payload_length)
        .build_into(&mut buffer[..required])
        .map_err(representation_error)?;
    Ok(layout)
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
        let required = validate_envelope(self.buffer, self.payload.len(), maximum_payload)?;
        let (payload_length_high, payload_length_middle, payload_length_low) =
            length_octets(self.payload.len());
        let (layout, _) = Http2FrameLayoutBuilder::new()
            .payload_length_high(payload_length_high)
            .payload_length_middle(payload_length_middle)
            .payload_length_low(payload_length_low)
            .frame_type(self.frame_type)
            .flags(self.flags)
            .stream_id(self.stream_id)
            .payload(self.payload)
            .build_into(&mut self.buffer[..required])
            .map_err(representation_error)?;
        Ok(Http2FrameMut::from_layout(layout))
    }
}
