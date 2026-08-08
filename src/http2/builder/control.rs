//! Atomic caller-buffer construction of HTTP/2 control frames.

use super::super::control::{
    Http2Goaway, Http2Ping, Http2PriorityFrame, Http2RstStream, Http2WindowIncrement,
    Http2WindowUpdate,
};
use super::super::error::Http2BuildError;
use super::super::frame::Http2Frame;
use super::super::priority::Http2Priority;
use super::super::settings::{Http2Setting, Http2Settings};
use super::super::types::{Http2ErrorCode, Http2FrameType, Http2StreamId};

const HEADER_LENGTH: usize = 9;
const MAXIMUM_PAYLOAD: usize = 0x00ff_ffff;

/// Builds a typed HTTP/2 SETTINGS frame in caller-owned storage.
pub struct Http2SettingsBuilder<'a, 'b> {
    buffer: &'a mut [u8],
    flags: u8,
    settings: &'b [Http2Setting],
}

impl<'a, 'b> Http2SettingsBuilder<'a, 'b> {
    /// Creates a builder that copies settings in the supplied order.
    pub fn new(buffer: &'a mut [u8], flags: u8, settings: &'b [Http2Setting]) -> Self {
        Self {
            buffer,
            flags,
            settings,
        }
    }

    /// Builds the frame after validating its payload and caller buffer.
    pub fn build(self) -> Result<Http2Settings<'a>, Http2BuildError> {
        self.build_with_maximum(MAXIMUM_PAYLOAD)
    }

    /// Builds the frame after validating the caller-provided payload maximum and capacity.
    pub fn build_with_maximum(
        self,
        maximum_payload: usize,
    ) -> Result<Http2Settings<'a>, Http2BuildError> {
        for setting in self.settings.iter().copied() {
            if !setting.has_valid_intrinsic_value() {
                return Err(Http2BuildError::InvalidSettingValue {
                    id: setting.id(),
                    value: setting.value(),
                });
            }
        }
        let payload_length =
            self.settings
                .len()
                .checked_mul(6)
                .ok_or(Http2BuildError::PayloadTooLarge {
                    maximum: maximum_payload.min(MAXIMUM_PAYLOAD),
                    actual: self.settings.len(),
                })?;
        if self.flags & 0x1 != 0 && payload_length != 0 {
            return Err(Http2BuildError::SettingsAckPayload {
                actual: payload_length,
            });
        }
        let bytes = write_settings(
            self.buffer,
            self.flags,
            self.settings,
            payload_length,
            maximum_payload,
        )?;
        Ok(Http2Settings::from_validated(Http2Frame::from_validated(
            bytes,
        )))
    }
}

/// Builds a typed HTTP/2 GOAWAY frame in caller-owned storage.
pub struct Http2GoawayBuilder<'a, 'b> {
    buffer: &'a mut [u8],
    flags: u8,
    last_stream_id: Http2StreamId,
    error_code: Http2ErrorCode,
    additional_debug_data: &'b [u8],
}

impl<'a, 'b> Http2GoawayBuilder<'a, 'b> {
    /// Creates a builder that copies the fixed prefix and opaque debug data.
    pub fn new(
        buffer: &'a mut [u8],
        flags: u8,
        last_stream_id: Http2StreamId,
        error_code: Http2ErrorCode,
        additional_debug_data: &'b [u8],
    ) -> Self {
        Self {
            buffer,
            flags,
            last_stream_id,
            error_code,
            additional_debug_data,
        }
    }

    /// Builds the frame after validating its payload and caller buffer.
    pub fn build(self) -> Result<Http2Goaway<'a>, Http2BuildError> {
        self.build_with_maximum(MAXIMUM_PAYLOAD)
    }

    /// Builds the frame after validating the caller-provided payload maximum and capacity.
    pub fn build_with_maximum(
        self,
        maximum_payload: usize,
    ) -> Result<Http2Goaway<'a>, Http2BuildError> {
        if self.last_stream_id.has_reserved_bit() {
            return Err(Http2BuildError::ReservedLastStreamId);
        }
        let payload_length = self.additional_debug_data.len().checked_add(8).ok_or(
            Http2BuildError::PayloadTooLarge {
                maximum: maximum_payload.min(MAXIMUM_PAYLOAD),
                actual: self.additional_debug_data.len(),
            },
        )?;
        let bytes = write_goaway(
            self.buffer,
            self.flags,
            self.last_stream_id,
            self.error_code,
            self.additional_debug_data,
            payload_length,
            maximum_payload,
        )?;
        Ok(Http2Goaway::from_validated(
            Http2Frame::from_validated(bytes),
            self.last_stream_id,
            self.error_code,
        ))
    }
}

/// Builds a typed HTTP/2 PRIORITY frame in caller-owned storage.
pub struct Http2PriorityFrameBuilder<'a> {
    buffer: &'a mut [u8],
    stream_id: Http2StreamId,
    flags: u8,
    priority: Http2Priority,
}

impl<'a> Http2PriorityFrameBuilder<'a> {
    /// Creates a builder for an exact five-byte priority section.
    pub fn new(
        buffer: &'a mut [u8],
        stream_id: Http2StreamId,
        flags: u8,
        priority: Http2Priority,
    ) -> Self {
        Self {
            buffer,
            stream_id,
            flags,
            priority,
        }
    }

    /// Builds the frame after validating its fixed payload and caller buffer.
    pub fn build(self) -> Result<Http2PriorityFrame<'a>, Http2BuildError> {
        self.build_with_maximum(MAXIMUM_PAYLOAD)
    }

    /// Builds the frame after validating the caller-provided payload maximum and capacity.
    pub fn build_with_maximum(
        self,
        maximum_payload: usize,
    ) -> Result<Http2PriorityFrame<'a>, Http2BuildError> {
        validate_required_stream_id(self.stream_id)?;
        let dependency = self.priority.raw_dependency();
        let payload = [
            dependency.to_be_bytes()[0],
            dependency.to_be_bytes()[1],
            dependency.to_be_bytes()[2],
            dependency.to_be_bytes()[3],
            self.priority.weight(),
        ];
        let bytes = write_fixed_frame(
            self.buffer,
            self.stream_id,
            Http2FrameType::PRIORITY,
            self.flags,
            &payload,
            maximum_payload,
        )?;
        Ok(Http2PriorityFrame::from_validated(
            Http2Frame::from_validated(bytes),
            self.priority,
        ))
    }
}

/// Builds a typed HTTP/2 RST_STREAM frame in caller-owned storage.
pub struct Http2RstStreamBuilder<'a> {
    buffer: &'a mut [u8],
    stream_id: Http2StreamId,
    flags: u8,
    error_code: Http2ErrorCode,
}

impl<'a> Http2RstStreamBuilder<'a> {
    /// Creates a builder for an exact four-byte error code.
    pub fn new(
        buffer: &'a mut [u8],
        stream_id: Http2StreamId,
        flags: u8,
        error_code: Http2ErrorCode,
    ) -> Self {
        Self {
            buffer,
            stream_id,
            flags,
            error_code,
        }
    }

    /// Builds the frame after validating its fixed payload and caller buffer.
    pub fn build(self) -> Result<Http2RstStream<'a>, Http2BuildError> {
        self.build_with_maximum(MAXIMUM_PAYLOAD)
    }

    /// Builds the frame after validating the caller-provided payload maximum and capacity.
    pub fn build_with_maximum(
        self,
        maximum_payload: usize,
    ) -> Result<Http2RstStream<'a>, Http2BuildError> {
        validate_required_stream_id(self.stream_id)?;
        let payload = self.error_code.raw().to_be_bytes();
        let bytes = write_fixed_frame(
            self.buffer,
            self.stream_id,
            Http2FrameType::RST_STREAM,
            self.flags,
            &payload,
            maximum_payload,
        )?;
        Ok(Http2RstStream::from_validated(
            Http2Frame::from_validated(bytes),
            self.error_code,
        ))
    }
}

/// Builds a typed HTTP/2 PING frame in caller-owned storage.
pub struct Http2PingBuilder<'a, 'b> {
    buffer: &'a mut [u8],
    flags: u8,
    opaque_data: &'b [u8; 8],
}

impl<'a, 'b> Http2PingBuilder<'a, 'b> {
    /// Creates a builder for eight opaque payload bytes on the connection stream.
    pub fn new(buffer: &'a mut [u8], flags: u8, opaque_data: &'b [u8; 8]) -> Self {
        Self {
            buffer,
            flags,
            opaque_data,
        }
    }

    /// Builds the frame after validating its fixed payload and caller buffer.
    pub fn build(self) -> Result<Http2Ping<'a>, Http2BuildError> {
        self.build_with_maximum(MAXIMUM_PAYLOAD)
    }

    /// Builds the frame after validating the caller-provided payload maximum and capacity.
    pub fn build_with_maximum(
        self,
        maximum_payload: usize,
    ) -> Result<Http2Ping<'a>, Http2BuildError> {
        let bytes = write_fixed_frame(
            self.buffer,
            Http2StreamId::new(0),
            Http2FrameType::PING,
            self.flags,
            self.opaque_data,
            maximum_payload,
        )?;
        let opaque_data =
            bytes[HEADER_LENGTH..]
                .try_into()
                .map_err(|_| Http2BuildError::BufferTooShort {
                    required: HEADER_LENGTH + 8,
                    available: bytes.len(),
                })?;
        Ok(Http2Ping::from_validated(
            Http2Frame::from_validated(bytes),
            opaque_data,
        ))
    }
}

/// Builds a typed HTTP/2 WINDOW_UPDATE frame in caller-owned storage.
pub struct Http2WindowUpdateBuilder<'a> {
    buffer: &'a mut [u8],
    stream_id: Http2StreamId,
    flags: u8,
    increment: Http2WindowIncrement,
}

impl<'a> Http2WindowUpdateBuilder<'a> {
    /// Creates a builder for an exact four-byte window increment.
    pub fn new(
        buffer: &'a mut [u8],
        stream_id: Http2StreamId,
        flags: u8,
        increment: Http2WindowIncrement,
    ) -> Self {
        Self {
            buffer,
            stream_id,
            flags,
            increment,
        }
    }

    /// Builds the frame after validating its fixed payload and caller buffer.
    pub fn build(self) -> Result<Http2WindowUpdate<'a>, Http2BuildError> {
        self.build_with_maximum(MAXIMUM_PAYLOAD)
    }

    /// Builds the frame after validating the caller-provided payload maximum and capacity.
    pub fn build_with_maximum(
        self,
        maximum_payload: usize,
    ) -> Result<Http2WindowUpdate<'a>, Http2BuildError> {
        if self.stream_id.has_reserved_bit() {
            return Err(Http2BuildError::ReservedStreamId);
        }
        if self.increment.has_reserved_bit() {
            return Err(Http2BuildError::ReservedWindowIncrement);
        }
        if self.increment.value() == 0 {
            return Err(Http2BuildError::ZeroWindowIncrement);
        }
        let payload = self.increment.raw().to_be_bytes();
        let bytes = write_fixed_frame(
            self.buffer,
            self.stream_id,
            Http2FrameType::WINDOW_UPDATE,
            self.flags,
            &payload,
            maximum_payload,
        )?;
        Ok(Http2WindowUpdate::from_validated(
            Http2Frame::from_validated(bytes),
            self.increment,
        ))
    }
}

fn validate_required_stream_id(stream_id: Http2StreamId) -> Result<(), Http2BuildError> {
    if stream_id.value() == 0 {
        return Err(Http2BuildError::ZeroStreamId);
    }
    if stream_id.has_reserved_bit() {
        return Err(Http2BuildError::ReservedStreamId);
    }
    Ok(())
}

fn write_settings<'a>(
    buffer: &'a mut [u8],
    flags: u8,
    settings: &[Http2Setting],
    payload_length: usize,
    maximum_payload: usize,
) -> Result<&'a [u8], Http2BuildError> {
    let required = validate_connection_payload(buffer, payload_length, maximum_payload)?;
    let bytes = &mut buffer[..required];
    write_connection_header(bytes, payload_length, Http2FrameType::SETTINGS, flags);
    for (index, setting) in settings.iter().copied().enumerate() {
        let offset = HEADER_LENGTH + index * 6;
        bytes[offset..offset + 2].copy_from_slice(&setting.id().raw().to_be_bytes());
        bytes[offset + 2..offset + 6].copy_from_slice(&setting.value().to_be_bytes());
    }
    Ok(bytes)
}

fn write_goaway<'a>(
    buffer: &'a mut [u8],
    flags: u8,
    last_stream_id: Http2StreamId,
    error_code: Http2ErrorCode,
    additional_debug_data: &[u8],
    payload_length: usize,
    maximum_payload: usize,
) -> Result<&'a [u8], Http2BuildError> {
    let required = validate_connection_payload(buffer, payload_length, maximum_payload)?;
    let bytes = &mut buffer[..required];
    write_connection_header(bytes, payload_length, Http2FrameType::GOAWAY, flags);
    bytes[HEADER_LENGTH..HEADER_LENGTH + 4].copy_from_slice(&last_stream_id.raw().to_be_bytes());
    bytes[HEADER_LENGTH + 4..HEADER_LENGTH + 8].copy_from_slice(&error_code.raw().to_be_bytes());
    bytes[HEADER_LENGTH + 8..].copy_from_slice(additional_debug_data);
    Ok(bytes)
}

fn validate_connection_payload(
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

fn write_connection_header(
    bytes: &mut [u8],
    payload_length: usize,
    frame_type: Http2FrameType,
    flags: u8,
) {
    let payload_length = payload_length as u32;
    bytes[0] = (payload_length >> 16) as u8;
    bytes[1] = (payload_length >> 8) as u8;
    bytes[2] = payload_length as u8;
    bytes[3] = frame_type.raw();
    bytes[4] = flags;
    bytes[5..HEADER_LENGTH].fill(0);
}

fn write_fixed_frame<'a>(
    buffer: &'a mut [u8],
    stream_id: Http2StreamId,
    frame_type: Http2FrameType,
    flags: u8,
    payload: &[u8],
    maximum_payload: usize,
) -> Result<&'a [u8], Http2BuildError> {
    let maximum_payload = maximum_payload.min(MAXIMUM_PAYLOAD);
    if payload.len() > maximum_payload {
        return Err(Http2BuildError::PayloadTooLarge {
            maximum: maximum_payload,
            actual: payload.len(),
        });
    }
    let required = HEADER_LENGTH + payload.len();
    if buffer.len() < required {
        return Err(Http2BuildError::BufferTooShort {
            required,
            available: buffer.len(),
        });
    }

    let bytes = &mut buffer[..required];
    let payload_length = payload.len() as u32;
    bytes[0] = (payload_length >> 16) as u8;
    bytes[1] = (payload_length >> 8) as u8;
    bytes[2] = payload_length as u8;
    bytes[3] = frame_type.raw();
    bytes[4] = flags;
    bytes[5..HEADER_LENGTH].copy_from_slice(&stream_id.raw().to_be_bytes());
    bytes[HEADER_LENGTH..].copy_from_slice(payload);
    Ok(bytes)
}
