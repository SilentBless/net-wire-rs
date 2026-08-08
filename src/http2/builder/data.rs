//! Atomic caller-buffer construction of standard HTTP/2 DATA, HEADERS, PUSH_PROMISE, and CONTINUATION frames.

use super::super::data::Http2Data;
use super::super::error::Http2BuildError;
use super::super::frame::Http2Frame;
use super::super::headers::{Http2Continuation, Http2Headers, Http2PushPromise};
use super::super::priority::Http2Priority;
use super::super::types::{Http2FrameType, Http2StreamId};
use super::raw::{FRAME_HEADER_LENGTH, MAXIMUM_PAYLOAD, write_frame_envelope};

const DATA_PADDED: u8 = 0x08;
const HEADERS_PRIORITY: u8 = 0x20;
const PUSH_PROMISE_PADDED: u8 = 0x08;

/// Builds a typed HTTP/2 DATA frame in caller-owned storage.
pub struct Http2DataBuilder<'a, 'b> {
    buffer: &'a mut [u8],
    stream_id: Http2StreamId,
    flags: u8,
    data: &'b [u8],
    padding_length: Option<u8>,
}

impl<'a, 'b> Http2DataBuilder<'a, 'b> {
    /// Creates a builder that copies DATA and emits zero-valued padding when requested.
    pub fn new(
        buffer: &'a mut [u8],
        stream_id: Http2StreamId,
        flags: u8,
        data: &'b [u8],
        padding_length: Option<u8>,
    ) -> Self {
        Self {
            buffer,
            stream_id,
            flags,
            data,
            padding_length,
        }
    }

    /// Validates HTTP/2's representable payload length and capacity before writing the frame.
    pub fn build(self) -> Result<Http2Data<'a>, Http2BuildError> {
        self.build_with_maximum(MAXIMUM_PAYLOAD)
    }

    /// Validates the caller-provided payload maximum and capacity before writing the frame.
    pub fn build_with_maximum(
        self,
        maximum_payload: usize,
    ) -> Result<Http2Data<'a>, Http2BuildError> {
        if self.flags & DATA_PADDED != 0 {
            return Err(Http2BuildError::DataPaddedFlagSet);
        }
        validate_stream_id(self.stream_id)?;
        let padding_length = self.padding_length;
        let flags = self.flags
            | if padding_length.is_some() {
                DATA_PADDED
            } else {
                0
            };
        let payload_length = self
            .data
            .len()
            .checked_add(usize::from(padding_length.is_some()))
            .and_then(|length| length.checked_add(usize::from(padding_length.unwrap_or(0))))
            .ok_or(Http2BuildError::PayloadTooLarge {
                maximum: maximum_payload.min(MAXIMUM_PAYLOAD),
                actual: self.data.len(),
            })?;
        let bytes = write_frame_envelope(
            self.buffer,
            payload_length,
            Http2FrameType::DATA,
            flags,
            self.stream_id,
            maximum_payload,
        )?;
        let mut offset = FRAME_HEADER_LENGTH;
        if let Some(padding_length) = padding_length {
            bytes[offset] = padding_length;
            offset += 1;
        }
        let data_end = offset + self.data.len();
        bytes[offset..data_end].copy_from_slice(self.data);
        bytes[data_end..].fill(0);
        Ok(Http2Data::from_validated(
            Http2Frame::from_validated(bytes),
            padding_length,
        ))
    }
}

/// Builds a typed HTTP/2 HEADERS frame in caller-owned storage.
pub struct Http2HeadersBuilder<'a, 'b> {
    buffer: &'a mut [u8],
    stream_id: Http2StreamId,
    flags: u8,
    field_block_fragment: &'b [u8],
    priority: Option<Http2Priority>,
    padding_length: Option<u8>,
}

impl<'a, 'b> Http2HeadersBuilder<'a, 'b> {
    /// Creates a builder that copies the field block fragment and optional layout sections.
    pub fn new(
        buffer: &'a mut [u8],
        stream_id: Http2StreamId,
        flags: u8,
        field_block_fragment: &'b [u8],
        priority: Option<Http2Priority>,
        padding_length: Option<u8>,
    ) -> Self {
        Self {
            buffer,
            stream_id,
            flags,
            field_block_fragment,
            priority,
            padding_length,
        }
    }

    /// Validates HTTP/2's representable payload length and capacity before writing the frame.
    pub fn build(self) -> Result<Http2Headers<'a>, Http2BuildError> {
        self.build_with_maximum(MAXIMUM_PAYLOAD)
    }

    /// Validates the caller-provided payload maximum and capacity before writing the frame.
    pub fn build_with_maximum(
        self,
        maximum_payload: usize,
    ) -> Result<Http2Headers<'a>, Http2BuildError> {
        if self.flags & DATA_PADDED != 0 {
            return Err(Http2BuildError::HeadersPaddedFlagSet);
        }
        if self.flags & HEADERS_PRIORITY != 0 {
            return Err(Http2BuildError::HeadersPriorityFlagSet);
        }
        validate_stream_id(self.stream_id)?;
        let flags = self.flags
            | if self.padding_length.is_some() {
                DATA_PADDED
            } else {
                0
            }
            | if self.priority.is_some() {
                HEADERS_PRIORITY
            } else {
                0
            };
        let payload_length = self
            .field_block_fragment
            .len()
            .checked_add(5 * usize::from(self.priority.is_some()))
            .and_then(|length| length.checked_add(usize::from(self.padding_length.is_some())))
            .and_then(|length| length.checked_add(usize::from(self.padding_length.unwrap_or(0))))
            .ok_or(Http2BuildError::PayloadTooLarge {
                maximum: maximum_payload.min(MAXIMUM_PAYLOAD),
                actual: self.field_block_fragment.len(),
            })?;
        let bytes = write_frame_envelope(
            self.buffer,
            payload_length,
            Http2FrameType::HEADERS,
            flags,
            self.stream_id,
            maximum_payload,
        )?;
        let mut offset = FRAME_HEADER_LENGTH;
        if let Some(padding_length) = self.padding_length {
            bytes[offset] = padding_length;
            offset += 1;
        }
        if let Some(priority) = self.priority {
            bytes[offset..offset + 4].copy_from_slice(&priority.raw_dependency().to_be_bytes());
            bytes[offset + 4] = priority.weight();
            offset += 5;
        }
        let fragment_end = offset + self.field_block_fragment.len();
        bytes[offset..fragment_end].copy_from_slice(self.field_block_fragment);
        bytes[fragment_end..].fill(0);
        Ok(Http2Headers::from_validated(
            Http2Frame::from_validated(bytes),
            self.padding_length,
            self.priority,
        ))
    }
}

/// Builds a typed HTTP/2 PUSH_PROMISE frame in caller-owned storage.
pub struct Http2PushPromiseBuilder<'a, 'b> {
    buffer: &'a mut [u8],
    stream_id: Http2StreamId,
    flags: u8,
    promised_stream_id: Http2StreamId,
    field_block_fragment: &'b [u8],
    padding_length: Option<u8>,
}

impl<'a, 'b> Http2PushPromiseBuilder<'a, 'b> {
    /// Creates a builder that copies the promised stream ID, field block fragment, and padding.
    pub fn new(
        buffer: &'a mut [u8],
        stream_id: Http2StreamId,
        flags: u8,
        promised_stream_id: Http2StreamId,
        field_block_fragment: &'b [u8],
        padding_length: Option<u8>,
    ) -> Self {
        Self {
            buffer,
            stream_id,
            flags,
            promised_stream_id,
            field_block_fragment,
            padding_length,
        }
    }

    /// Validates HTTP/2's representable payload length and capacity before writing the frame.
    pub fn build(self) -> Result<Http2PushPromise<'a>, Http2BuildError> {
        self.build_with_maximum(MAXIMUM_PAYLOAD)
    }

    /// Validates the caller-provided payload maximum and capacity before writing the frame.
    pub fn build_with_maximum(
        self,
        maximum_payload: usize,
    ) -> Result<Http2PushPromise<'a>, Http2BuildError> {
        if self.flags & PUSH_PROMISE_PADDED != 0 {
            return Err(Http2BuildError::PushPromisePaddedFlagSet);
        }
        if self.promised_stream_id.value() == 0 {
            return Err(Http2BuildError::ZeroPromisedStreamId);
        }
        if self.promised_stream_id.has_reserved_bit() {
            return Err(Http2BuildError::ReservedPromisedStreamId);
        }
        validate_stream_id(self.stream_id)?;
        let flags = self.flags
            | if self.padding_length.is_some() {
                PUSH_PROMISE_PADDED
            } else {
                0
            };
        let payload_length = self
            .field_block_fragment
            .len()
            .checked_add(4)
            .and_then(|length| length.checked_add(usize::from(self.padding_length.is_some())))
            .and_then(|length| length.checked_add(usize::from(self.padding_length.unwrap_or(0))))
            .ok_or(Http2BuildError::PayloadTooLarge {
                maximum: maximum_payload.min(MAXIMUM_PAYLOAD),
                actual: self.field_block_fragment.len(),
            })?;
        let bytes = write_frame_envelope(
            self.buffer,
            payload_length,
            Http2FrameType::PUSH_PROMISE,
            flags,
            self.stream_id,
            maximum_payload,
        )?;
        let mut offset = FRAME_HEADER_LENGTH;
        if let Some(padding_length) = self.padding_length {
            bytes[offset] = padding_length;
            offset += 1;
        }
        bytes[offset..offset + 4].copy_from_slice(&self.promised_stream_id.raw().to_be_bytes());
        offset += 4;
        let fragment_end = offset + self.field_block_fragment.len();
        bytes[offset..fragment_end].copy_from_slice(self.field_block_fragment);
        bytes[fragment_end..].fill(0);
        Ok(Http2PushPromise::from_validated(
            Http2Frame::from_validated(bytes),
            self.padding_length,
            self.promised_stream_id,
        ))
    }
}

/// Builds a typed HTTP/2 CONTINUATION frame in caller-owned storage.
pub struct Http2ContinuationBuilder<'a, 'b> {
    buffer: &'a mut [u8],
    stream_id: Http2StreamId,
    flags: u8,
    field_block_fragment: &'b [u8],
}

impl<'a, 'b> Http2ContinuationBuilder<'a, 'b> {
    /// Creates a builder that copies the complete field block fragment.
    pub fn new(
        buffer: &'a mut [u8],
        stream_id: Http2StreamId,
        flags: u8,
        field_block_fragment: &'b [u8],
    ) -> Self {
        Self {
            buffer,
            stream_id,
            flags,
            field_block_fragment,
        }
    }

    /// Validates HTTP/2's representable payload length and capacity before writing the frame.
    pub fn build(self) -> Result<Http2Continuation<'a>, Http2BuildError> {
        self.build_with_maximum(MAXIMUM_PAYLOAD)
    }

    /// Validates the caller-provided payload maximum and capacity before writing the frame.
    pub fn build_with_maximum(
        self,
        maximum_payload: usize,
    ) -> Result<Http2Continuation<'a>, Http2BuildError> {
        validate_stream_id(self.stream_id)?;
        let bytes = write_frame_envelope(
            self.buffer,
            self.field_block_fragment.len(),
            Http2FrameType::CONTINUATION,
            self.flags,
            self.stream_id,
            maximum_payload,
        )?;
        bytes[FRAME_HEADER_LENGTH..].copy_from_slice(self.field_block_fragment);
        Ok(Http2Continuation::from_validated(
            Http2Frame::from_validated(bytes),
        ))
    }
}

fn validate_stream_id(stream_id: Http2StreamId) -> Result<(), Http2BuildError> {
    if stream_id.value() == 0 {
        return Err(Http2BuildError::ZeroStreamId);
    }
    if stream_id.has_reserved_bit() {
        return Err(Http2BuildError::ReservedStreamId);
    }
    Ok(())
}
