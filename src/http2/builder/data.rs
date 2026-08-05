//! Atomic caller-buffer construction of standard HTTP/2 DATA, HEADERS, PUSH_PROMISE, and CONTINUATION frames.

use super::super::{
    Http2BuildError, Http2Continuation, Http2Data, Http2Frame, Http2FrameType, Http2Headers,
    Http2Priority, Http2PushPromise, Http2StreamId,
};

const HEADER_LENGTH: usize = 9;
const MAXIMUM_PAYLOAD: usize = 0x00ff_ffff;
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
        let padding_length = self.padding_length;
        let flags = self.flags
            | if padding_length.is_some() {
                DATA_PADDED
            } else {
                0
            };
        let bytes = write_frame(
            self.buffer,
            self.stream_id,
            Http2FrameType::DATA,
            flags,
            self.data,
            padding_length,
            maximum_payload,
        )?;
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
        let bytes = write_headers(
            self.buffer,
            self.stream_id,
            flags,
            self.field_block_fragment,
            self.priority,
            self.padding_length,
            maximum_payload,
        )?;
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
        let flags = self.flags
            | if self.padding_length.is_some() {
                PUSH_PROMISE_PADDED
            } else {
                0
            };
        let bytes = write_push_promise(
            self.buffer,
            self.stream_id,
            flags,
            self.promised_stream_id,
            self.field_block_fragment,
            self.padding_length,
            maximum_payload,
        )?;
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
        let bytes = write_frame(
            self.buffer,
            self.stream_id,
            Http2FrameType::CONTINUATION,
            self.flags,
            self.field_block_fragment,
            None,
            maximum_payload,
        )?;
        Ok(Http2Continuation::from_validated(
            Http2Frame::from_validated(bytes),
        ))
    }
}

fn write_headers<'a>(
    buffer: &'a mut [u8],
    stream_id: Http2StreamId,
    flags: u8,
    field_block_fragment: &[u8],
    priority: Option<Http2Priority>,
    padding_length: Option<u8>,
    maximum_payload: usize,
) -> Result<&'a [u8], Http2BuildError> {
    validate_stream_id(stream_id)?;
    let maximum_payload = maximum_payload.min(MAXIMUM_PAYLOAD);
    let payload_length = field_block_fragment
        .len()
        .checked_add(5 * usize::from(priority.is_some()))
        .and_then(|length| length.checked_add(usize::from(padding_length.is_some())))
        .and_then(|length| length.checked_add(usize::from(padding_length.unwrap_or(0))))
        .ok_or(Http2BuildError::PayloadTooLarge {
            maximum: maximum_payload,
            actual: field_block_fragment.len(),
        })?;
    let required = validate_payload_length(buffer, payload_length, maximum_payload)?;

    let bytes = &mut buffer[..required];
    write_frame_header(
        bytes,
        payload_length,
        Http2FrameType::HEADERS,
        flags,
        stream_id,
    );
    let mut offset = HEADER_LENGTH;
    if let Some(padding_length) = padding_length {
        bytes[offset] = padding_length;
        offset += 1;
    }
    if let Some(priority) = priority {
        bytes[offset..offset + 4].copy_from_slice(&priority.raw_dependency().to_be_bytes());
        bytes[offset + 4] = priority.weight();
        offset += 5;
    }
    let fragment_end = offset + field_block_fragment.len();
    bytes[offset..fragment_end].copy_from_slice(field_block_fragment);
    bytes[fragment_end..].fill(0);
    Ok(bytes)
}

fn write_push_promise<'a>(
    buffer: &'a mut [u8],
    stream_id: Http2StreamId,
    flags: u8,
    promised_stream_id: Http2StreamId,
    field_block_fragment: &[u8],
    padding_length: Option<u8>,
    maximum_payload: usize,
) -> Result<&'a [u8], Http2BuildError> {
    validate_stream_id(stream_id)?;
    let maximum_payload = maximum_payload.min(MAXIMUM_PAYLOAD);
    let payload_length = field_block_fragment
        .len()
        .checked_add(4)
        .and_then(|length| length.checked_add(usize::from(padding_length.is_some())))
        .and_then(|length| length.checked_add(usize::from(padding_length.unwrap_or(0))))
        .ok_or(Http2BuildError::PayloadTooLarge {
            maximum: maximum_payload,
            actual: field_block_fragment.len(),
        })?;
    let required = validate_payload_length(buffer, payload_length, maximum_payload)?;

    let bytes = &mut buffer[..required];
    write_frame_header(
        bytes,
        payload_length,
        Http2FrameType::PUSH_PROMISE,
        flags,
        stream_id,
    );
    let mut offset = HEADER_LENGTH;
    if let Some(padding_length) = padding_length {
        bytes[offset] = padding_length;
        offset += 1;
    }
    bytes[offset..offset + 4].copy_from_slice(&promised_stream_id.raw().to_be_bytes());
    offset += 4;
    let fragment_end = offset + field_block_fragment.len();
    bytes[offset..fragment_end].copy_from_slice(field_block_fragment);
    bytes[fragment_end..].fill(0);
    Ok(bytes)
}

fn write_frame<'a>(
    buffer: &'a mut [u8],
    stream_id: Http2StreamId,
    frame_type: Http2FrameType,
    flags: u8,
    payload: &[u8],
    padding_length: Option<u8>,
    maximum_payload: usize,
) -> Result<&'a [u8], Http2BuildError> {
    if stream_id.value() == 0 {
        return Err(Http2BuildError::ZeroStreamId);
    }
    if stream_id.has_reserved_bit() {
        return Err(Http2BuildError::ReservedStreamId);
    }
    let maximum_payload = maximum_payload.min(MAXIMUM_PAYLOAD);
    let payload_length = payload
        .len()
        .checked_add(usize::from(padding_length.is_some()))
        .and_then(|length| length.checked_add(usize::from(padding_length.unwrap_or(0))))
        .ok_or(Http2BuildError::PayloadTooLarge {
            maximum: maximum_payload,
            actual: payload.len(),
        })?;
    if payload_length > maximum_payload {
        return Err(Http2BuildError::PayloadTooLarge {
            maximum: maximum_payload,
            actual: payload_length,
        });
    }
    let required =
        HEADER_LENGTH
            .checked_add(payload_length)
            .ok_or(Http2BuildError::PayloadTooLarge {
                maximum: maximum_payload,
                actual: payload_length,
            })?;
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
    bytes[5..HEADER_LENGTH].copy_from_slice(&stream_id.raw().to_be_bytes());

    let mut offset = HEADER_LENGTH;
    if let Some(padding_length) = padding_length {
        bytes[offset] = padding_length;
        offset += 1;
    }
    let payload_end = offset + payload.len();
    bytes[offset..payload_end].copy_from_slice(payload);
    bytes[payload_end..].fill(0);
    Ok(bytes)
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

fn validate_payload_length(
    buffer: &[u8],
    payload_length: usize,
    maximum_payload: usize,
) -> Result<usize, Http2BuildError> {
    if payload_length > maximum_payload {
        return Err(Http2BuildError::PayloadTooLarge {
            maximum: maximum_payload,
            actual: payload_length,
        });
    }
    let required =
        HEADER_LENGTH
            .checked_add(payload_length)
            .ok_or(Http2BuildError::PayloadTooLarge {
                maximum: maximum_payload,
                actual: payload_length,
            })?;
    if buffer.len() < required {
        return Err(Http2BuildError::BufferTooShort {
            required,
            available: buffer.len(),
        });
    }
    Ok(required)
}

fn write_frame_header(
    bytes: &mut [u8],
    payload_length: usize,
    frame_type: Http2FrameType,
    flags: u8,
    stream_id: Http2StreamId,
) {
    let payload_length = payload_length as u32;
    bytes[0] = (payload_length >> 16) as u8;
    bytes[1] = (payload_length >> 8) as u8;
    bytes[2] = payload_length as u8;
    bytes[3] = frame_type.raw();
    bytes[4] = flags;
    bytes[5..HEADER_LENGTH].copy_from_slice(&stream_id.raw().to_be_bytes());
}
