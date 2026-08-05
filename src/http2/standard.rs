//! Typed borrowed views of standard HTTP/2 frame layouts.

use super::{Http2Frame, Http2FrameType, Http2ParseError, Http2StreamId};
use core::iter::FusedIterator;

const PADDED: u8 = 0x8;
const PRIORITY: u8 = 0x20;

/// A raw-preserving HTTP/2 SETTINGS parameter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http2Setting {
    id: super::Http2SettingId,
    value: u32,
}

impl Http2Setting {
    /// Creates a setting from a raw-preserving identifier and encoded value.
    pub const fn new(id: super::Http2SettingId, value: u32) -> Self {
        Self { id, value }
    }

    fn parse(bytes: &[u8]) -> Self {
        Self {
            id: super::Http2SettingId::new(u16::from_be_bytes([bytes[0], bytes[1]])),
            value: u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
        }
    }

    pub(super) const fn has_valid_intrinsic_value(self) -> bool {
        match self.id {
            super::Http2SettingId::ENABLE_PUSH | super::Http2SettingId::ENABLE_CONNECT_PROTOCOL => {
                self.value <= 1
            }
            super::Http2SettingId::INITIAL_WINDOW_SIZE => self.value <= 0x7fff_ffff,
            super::Http2SettingId::MAX_FRAME_SIZE => {
                self.value >= 0x4000 && self.value <= 0x00ff_ffff
            }
            _ => true,
        }
    }

    /// Returns the raw-preserving setting identifier.
    pub const fn id(self) -> super::Http2SettingId {
        self.id
    }

    /// Returns the raw encoded setting value.
    pub const fn value(self) -> u32 {
        self.value
    }
}

/// A validated borrowed HTTP/2 SETTINGS frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http2Settings<'a> {
    frame: Http2Frame<'a>,
}

impl<'a> Http2Settings<'a> {
    pub(super) fn from_validated(frame: Http2Frame<'a>) -> Self {
        Self { frame }
    }

    /// Parses the first complete SETTINGS frame, enforcing the caller-provided payload maximum.
    pub fn parse(bytes: &'a [u8], maximum_payload: usize) -> Result<Self, Http2ParseError> {
        Self::from_frame(Http2Frame::parse(bytes, maximum_payload)?)
    }

    /// Validates a raw SETTINGS frame's intrinsic layout.
    pub fn from_frame(frame: Http2Frame<'a>) -> Result<Self, Http2ParseError> {
        validate_type(frame, Http2FrameType::SETTINGS)?;
        validate_zero_stream(frame)?;
        let actual = frame.payload().len();
        if frame.flags() & 0x1 != 0 && actual != 0 {
            return Err(Http2ParseError::SettingsAckPayload { actual });
        }
        if !actual.is_multiple_of(6) {
            return Err(Http2ParseError::SettingsPayloadLength { actual });
        }
        for bytes in frame.payload().chunks_exact(6) {
            let setting = Http2Setting::parse(bytes);
            if !setting.has_valid_intrinsic_value() {
                return Err(Http2ParseError::InvalidSettingValue {
                    id: setting.id(),
                    value: setting.value(),
                });
            }
        }
        Ok(Self { frame })
    }

    /// Returns the validated raw frame.
    pub const fn frame(&self) -> Http2Frame<'a> {
        self.frame
    }

    /// Returns the exact represented frame bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.frame.as_bytes()
    }

    /// Returns whether the ACK flag is set.
    pub fn is_ack(&self) -> bool {
        self.frame.flags() & 0x1 != 0
    }

    /// Iterates SETTINGS parameters in wire order without combining duplicates.
    pub fn settings(&self) -> Http2SettingsIter<'a> {
        Http2SettingsIter {
            bytes: self.frame.payload(),
        }
    }
}

/// Iterator over validated HTTP/2 SETTINGS parameters.
#[derive(Clone, Debug)]
pub struct Http2SettingsIter<'a> {
    bytes: &'a [u8],
}

impl<'a> Iterator for Http2SettingsIter<'a> {
    type Item = Http2Setting;

    fn next(&mut self) -> Option<Self::Item> {
        let (setting, remaining) = self.bytes.split_first_chunk::<6>()?;
        self.bytes = remaining;
        Some(Http2Setting::parse(setting))
    }
}

impl FusedIterator for Http2SettingsIter<'_> {}

/// A validated borrowed HTTP/2 GOAWAY frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http2Goaway<'a> {
    frame: Http2Frame<'a>,
    last_stream_id: Http2StreamId,
    error_code: super::Http2ErrorCode,
}

impl<'a> Http2Goaway<'a> {
    pub(super) fn from_validated(
        frame: Http2Frame<'a>,
        last_stream_id: Http2StreamId,
        error_code: super::Http2ErrorCode,
    ) -> Self {
        Self {
            frame,
            last_stream_id,
            error_code,
        }
    }

    /// Parses the first complete GOAWAY frame, enforcing the caller-provided payload maximum.
    pub fn parse(bytes: &'a [u8], maximum_payload: usize) -> Result<Self, Http2ParseError> {
        Self::from_frame(Http2Frame::parse(bytes, maximum_payload)?)
    }

    /// Validates a raw GOAWAY frame's intrinsic layout.
    pub fn from_frame(frame: Http2Frame<'a>) -> Result<Self, Http2ParseError> {
        validate_type(frame, Http2FrameType::GOAWAY)?;
        validate_zero_stream(frame)?;
        let payload = frame.payload();
        if payload.len() < 8 {
            return Err(Http2ParseError::MalformedPayload {
                required: 8,
                available: payload.len(),
            });
        }
        Ok(Self {
            last_stream_id: Http2StreamId::new(u32::from_be_bytes([
                payload[0], payload[1], payload[2], payload[3],
            ])),
            error_code: super::Http2ErrorCode::new(u32::from_be_bytes([
                payload[4], payload[5], payload[6], payload[7],
            ])),
            frame,
        })
    }

    /// Returns the validated raw frame.
    pub const fn frame(&self) -> Http2Frame<'a> {
        self.frame
    }

    /// Returns the exact represented frame bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.frame.as_bytes()
    }

    /// Returns the raw last-stream identifier, including its reserved bit.
    pub const fn last_stream_id(&self) -> Http2StreamId {
        self.last_stream_id
    }

    /// Returns the raw-preserving connection error code.
    pub const fn error_code(&self) -> super::Http2ErrorCode {
        self.error_code
    }

    /// Returns the arbitrary trailing debug data.
    pub fn additional_debug_data(&self) -> &'a [u8] {
        &self.frame.payload()[8..]
    }
}

/// The priority section carried by a HEADERS frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http2Priority {
    raw_dependency: u32,
    weight: u8,
}

impl Http2Priority {
    /// Creates a priority section from its raw dependency field and encoded weight.
    pub const fn new(raw_dependency: u32, weight: u8) -> Self {
        Self {
            raw_dependency,
            weight,
        }
    }

    fn parse(bytes: &[u8]) -> Self {
        Self {
            raw_dependency: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            weight: bytes[4],
        }
    }

    /// Returns whether the exclusive dependency bit is set.
    pub const fn is_exclusive(self) -> bool {
        self.raw_dependency & 0x8000_0000 != 0
    }

    /// Returns the raw dependency field, including the exclusive bit.
    pub const fn raw_dependency(self) -> u32 {
        self.raw_dependency
    }

    /// Returns the 31-bit stream dependency value.
    pub const fn dependency(self) -> u32 {
        self.raw_dependency & 0x7fff_ffff
    }

    /// Returns the raw encoded weight.
    pub const fn weight(self) -> u8 {
        self.weight
    }
}

/// A WINDOW_UPDATE increment preserving its reserved high bit.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Http2WindowIncrement(u32);

impl Http2WindowIncrement {
    /// Creates an increment from its raw encoded field, including the reserved bit.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    fn parse(bytes: &[u8]) -> Self {
        Self(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Returns the raw encoded increment, including its reserved bit.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Returns the 31-bit window increment value.
    pub const fn value(self) -> u32 {
        self.0 & 0x7fff_ffff
    }

    /// Returns whether the raw encoded increment has its reserved bit set.
    pub const fn has_reserved_bit(self) -> bool {
        self.0 & 0x8000_0000 != 0
    }
}

/// A validated borrowed HTTP/2 DATA frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http2Data<'a> {
    frame: Http2Frame<'a>,
    data_start: usize,
    data_end: usize,
}

impl<'a> Http2Data<'a> {
    pub(super) fn from_validated(frame: Http2Frame<'a>, padding_length: Option<u8>) -> Self {
        let data_start = usize::from(padding_length.is_some());
        let data_end = frame.payload().len() - usize::from(padding_length.unwrap_or(0));
        Self {
            frame,
            data_start,
            data_end,
        }
    }

    /// Parses the first complete DATA frame, enforcing the caller-provided payload maximum.
    pub fn parse(bytes: &'a [u8], maximum_payload: usize) -> Result<Self, Http2ParseError> {
        Self::from_frame(Http2Frame::parse(bytes, maximum_payload)?)
    }

    /// Validates a raw DATA frame's intrinsic layout.
    pub fn from_frame(frame: Http2Frame<'a>) -> Result<Self, Http2ParseError> {
        validate_frame(frame, Http2FrameType::DATA)?;
        let payload = frame.payload();
        let data_start = if frame.flags() & PADDED != 0 {
            validate_padding(payload)?;
            1
        } else {
            0
        };
        let data_end = payload.len() - padding_length(frame);
        Ok(Self {
            frame,
            data_start,
            data_end,
        })
    }

    /// Returns the validated raw frame.
    pub const fn frame(&self) -> Http2Frame<'a> {
        self.frame
    }

    /// Returns the exact represented frame bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.frame.as_bytes()
    }

    /// Returns the DATA payload excluding pad metadata and trailing padding.
    pub fn data(&self) -> &'a [u8] {
        &self.frame.payload()[self.data_start..self.data_end]
    }

    /// Returns the trailing padding bytes.
    pub fn padding(&self) -> &'a [u8] {
        &self.frame.payload()[self.data_end..]
    }

    /// Returns the encoded padding length when PADDED is set.
    pub fn pad_length(&self) -> Option<u8> {
        (self.frame.flags() & PADDED != 0).then(|| self.frame.payload()[0])
    }
}

/// A validated borrowed HTTP/2 HEADERS frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http2Headers<'a> {
    frame: Http2Frame<'a>,
    field_block_start: usize,
    field_block_end: usize,
    priority: Option<Http2Priority>,
}

impl<'a> Http2Headers<'a> {
    pub(super) fn from_validated(
        frame: Http2Frame<'a>,
        padding_length: Option<u8>,
        priority: Option<Http2Priority>,
    ) -> Self {
        let field_block_start =
            usize::from(padding_length.is_some()) + 5 * usize::from(priority.is_some());
        let field_block_end = frame.payload().len() - usize::from(padding_length.unwrap_or(0));
        Self {
            frame,
            field_block_start,
            field_block_end,
            priority,
        }
    }

    /// Parses the first complete HEADERS frame, enforcing the caller-provided payload maximum.
    pub fn parse(bytes: &'a [u8], maximum_payload: usize) -> Result<Self, Http2ParseError> {
        Self::from_frame(Http2Frame::parse(bytes, maximum_payload)?)
    }

    /// Validates a raw HEADERS frame's intrinsic layout.
    pub fn from_frame(frame: Http2Frame<'a>) -> Result<Self, Http2ParseError> {
        validate_frame(frame, Http2FrameType::HEADERS)?;
        let payload = frame.payload();
        let padded = frame.flags() & PADDED != 0;
        if padded {
            validate_padding(payload)?;
        }
        let padding_length = padding_length(frame);
        let mut field_block_start = usize::from(padded);
        let field_block_end = payload.len() - padding_length;
        let priority = if frame.flags() & PRIORITY != 0 {
            let available = field_block_end - field_block_start;
            if available < 5 {
                return Err(Http2ParseError::MalformedPayload {
                    required: 5,
                    available,
                });
            }
            let priority = Http2Priority::parse(&payload[field_block_start..field_block_start + 5]);
            field_block_start += 5;
            Some(priority)
        } else {
            None
        };
        Ok(Self {
            frame,
            field_block_start,
            field_block_end,
            priority,
        })
    }

    /// Returns the validated raw frame.
    pub const fn frame(&self) -> Http2Frame<'a> {
        self.frame
    }

    /// Returns the exact represented frame bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.frame.as_bytes()
    }

    /// Returns the field block fragment excluding pad metadata, priority, and padding.
    pub fn field_block_fragment(&self) -> &'a [u8] {
        &self.frame.payload()[self.field_block_start..self.field_block_end]
    }

    /// Returns the trailing padding bytes.
    pub fn padding(&self) -> &'a [u8] {
        &self.frame.payload()[self.field_block_end..]
    }

    /// Returns the encoded padding length when PADDED is set.
    pub fn pad_length(&self) -> Option<u8> {
        (self.frame.flags() & PADDED != 0).then(|| self.frame.payload()[0])
    }

    /// Returns the optional priority section.
    pub const fn priority(&self) -> Option<Http2Priority> {
        self.priority
    }
}

/// A validated borrowed HTTP/2 PUSH_PROMISE frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http2PushPromise<'a> {
    frame: Http2Frame<'a>,
    field_block_start: usize,
    field_block_end: usize,
    promised_stream_id: Http2StreamId,
}

impl<'a> Http2PushPromise<'a> {
    pub(super) fn from_validated(
        frame: Http2Frame<'a>,
        padding_length: Option<u8>,
        promised_stream_id: Http2StreamId,
    ) -> Self {
        let field_block_start = usize::from(padding_length.is_some()) + 4;
        let field_block_end = frame.payload().len() - usize::from(padding_length.unwrap_or(0));
        Self {
            frame,
            field_block_start,
            field_block_end,
            promised_stream_id,
        }
    }

    /// Parses the first complete PUSH_PROMISE frame, enforcing the caller-provided payload maximum.
    pub fn parse(bytes: &'a [u8], maximum_payload: usize) -> Result<Self, Http2ParseError> {
        Self::from_frame(Http2Frame::parse(bytes, maximum_payload)?)
    }

    /// Validates a raw PUSH_PROMISE frame's intrinsic layout.
    pub fn from_frame(frame: Http2Frame<'a>) -> Result<Self, Http2ParseError> {
        validate_frame(frame, Http2FrameType::PUSH_PROMISE)?;
        let payload = frame.payload();
        let padded = frame.flags() & PADDED != 0;
        if padded {
            validate_padding(payload)?;
        }
        let field_block_start = usize::from(padded);
        let field_block_end = payload.len() - padding_length(frame);
        let available = field_block_end - field_block_start;
        if available < 4 {
            return Err(Http2ParseError::MalformedPayload {
                required: 4,
                available,
            });
        }
        let promised_stream_id = Http2StreamId::new(u32::from_be_bytes([
            payload[field_block_start],
            payload[field_block_start + 1],
            payload[field_block_start + 2],
            payload[field_block_start + 3],
        ]));
        if promised_stream_id.value() == 0 {
            return Err(Http2ParseError::ZeroPromisedStreamId);
        }
        Ok(Self {
            frame,
            field_block_start: field_block_start + 4,
            field_block_end,
            promised_stream_id,
        })
    }

    /// Returns the validated raw frame.
    pub const fn frame(&self) -> Http2Frame<'a> {
        self.frame
    }

    /// Returns the exact represented frame bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.frame.as_bytes()
    }

    /// Returns the raw promised stream identifier, including its reserved bit.
    pub const fn promised_stream_id(&self) -> Http2StreamId {
        self.promised_stream_id
    }

    /// Returns the field block fragment excluding pad metadata, promised stream ID, and padding.
    pub fn field_block_fragment(&self) -> &'a [u8] {
        &self.frame.payload()[self.field_block_start..self.field_block_end]
    }

    /// Returns the trailing padding bytes.
    pub fn padding(&self) -> &'a [u8] {
        &self.frame.payload()[self.field_block_end..]
    }

    /// Returns the encoded padding length when PADDED is set.
    pub fn pad_length(&self) -> Option<u8> {
        (self.frame.flags() & PADDED != 0).then(|| self.frame.payload()[0])
    }
}

/// A validated borrowed HTTP/2 CONTINUATION frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http2Continuation<'a> {
    frame: Http2Frame<'a>,
}

impl<'a> Http2Continuation<'a> {
    pub(super) fn from_validated(frame: Http2Frame<'a>) -> Self {
        Self { frame }
    }

    /// Parses the first complete CONTINUATION frame, enforcing the caller-provided payload maximum.
    pub fn parse(bytes: &'a [u8], maximum_payload: usize) -> Result<Self, Http2ParseError> {
        Self::from_frame(Http2Frame::parse(bytes, maximum_payload)?)
    }

    /// Validates a raw CONTINUATION frame's intrinsic layout.
    pub fn from_frame(frame: Http2Frame<'a>) -> Result<Self, Http2ParseError> {
        validate_frame(frame, Http2FrameType::CONTINUATION)?;
        Ok(Self { frame })
    }

    /// Returns the validated raw frame.
    pub const fn frame(&self) -> Http2Frame<'a> {
        self.frame
    }

    /// Returns the exact represented frame bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.frame.as_bytes()
    }

    /// Returns the complete CONTINUATION payload as a field block fragment.
    pub fn field_block_fragment(&self) -> &'a [u8] {
        self.frame.payload()
    }
}

/// A validated borrowed HTTP/2 PRIORITY frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http2PriorityFrame<'a> {
    frame: Http2Frame<'a>,
    priority: Http2Priority,
}

impl<'a> Http2PriorityFrame<'a> {
    pub(super) fn from_validated(frame: Http2Frame<'a>, priority: Http2Priority) -> Self {
        Self { frame, priority }
    }

    /// Parses the first complete PRIORITY frame, enforcing the caller-provided payload maximum.
    pub fn parse(bytes: &'a [u8], maximum_payload: usize) -> Result<Self, Http2ParseError> {
        Self::from_frame(Http2Frame::parse(bytes, maximum_payload)?)
    }

    /// Validates a raw PRIORITY frame's intrinsic layout.
    pub fn from_frame(frame: Http2Frame<'a>) -> Result<Self, Http2ParseError> {
        validate_frame(frame, Http2FrameType::PRIORITY)?;
        validate_exact_payload(frame, 5)?;
        Ok(Self {
            priority: Http2Priority::parse(frame.payload()),
            frame,
        })
    }

    /// Returns the validated raw frame.
    pub const fn frame(&self) -> Http2Frame<'a> {
        self.frame
    }
    /// Returns the exact represented frame bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.frame.as_bytes()
    }
    /// Returns the frame priority section.
    pub const fn priority(&self) -> Http2Priority {
        self.priority
    }
}

/// A validated borrowed HTTP/2 RST_STREAM frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http2RstStream<'a> {
    frame: Http2Frame<'a>,
    error_code: super::Http2ErrorCode,
}

impl<'a> Http2RstStream<'a> {
    pub(super) fn from_validated(frame: Http2Frame<'a>, error_code: super::Http2ErrorCode) -> Self {
        Self { frame, error_code }
    }

    /// Parses the first complete RST_STREAM frame, enforcing the caller-provided payload maximum.
    pub fn parse(bytes: &'a [u8], maximum_payload: usize) -> Result<Self, Http2ParseError> {
        Self::from_frame(Http2Frame::parse(bytes, maximum_payload)?)
    }

    /// Validates a raw RST_STREAM frame's intrinsic layout.
    pub fn from_frame(frame: Http2Frame<'a>) -> Result<Self, Http2ParseError> {
        validate_frame(frame, Http2FrameType::RST_STREAM)?;
        validate_exact_payload(frame, 4)?;
        let payload = frame.payload();
        Ok(Self {
            error_code: super::Http2ErrorCode::new(u32::from_be_bytes([
                payload[0], payload[1], payload[2], payload[3],
            ])),
            frame,
        })
    }

    /// Returns the validated raw frame.
    pub const fn frame(&self) -> Http2Frame<'a> {
        self.frame
    }
    /// Returns the exact represented frame bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.frame.as_bytes()
    }
    /// Returns the raw-preserving stream error code.
    pub const fn error_code(&self) -> super::Http2ErrorCode {
        self.error_code
    }
}

/// A validated borrowed HTTP/2 PING frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http2Ping<'a> {
    frame: Http2Frame<'a>,
    opaque_data: &'a [u8; 8],
}

impl<'a> Http2Ping<'a> {
    pub(super) fn from_validated(frame: Http2Frame<'a>, opaque_data: &'a [u8; 8]) -> Self {
        Self { frame, opaque_data }
    }

    /// Parses the first complete PING frame, enforcing the caller-provided payload maximum.
    pub fn parse(bytes: &'a [u8], maximum_payload: usize) -> Result<Self, Http2ParseError> {
        Self::from_frame(Http2Frame::parse(bytes, maximum_payload)?)
    }

    /// Validates a raw PING frame's intrinsic layout.
    pub fn from_frame(frame: Http2Frame<'a>) -> Result<Self, Http2ParseError> {
        validate_type(frame, Http2FrameType::PING)?;
        validate_zero_stream(frame)?;
        validate_exact_payload(frame, 8)?;
        let payload = frame.payload();
        let opaque_data = payload
            .try_into()
            .map_err(|_| Http2ParseError::FrameSizeMismatch {
                expected: 8,
                actual: payload.len(),
            })?;
        Ok(Self { frame, opaque_data })
    }

    /// Returns the validated raw frame.
    pub const fn frame(&self) -> Http2Frame<'a> {
        self.frame
    }
    /// Returns the exact represented frame bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.frame.as_bytes()
    }
    /// Returns the eight opaque payload bytes.
    pub const fn opaque_data(&self) -> &'a [u8; 8] {
        self.opaque_data
    }
    /// Returns whether the ACK flag is set.
    pub fn is_ack(&self) -> bool {
        self.frame.flags() & 0x1 != 0
    }
}

/// A validated borrowed HTTP/2 WINDOW_UPDATE frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http2WindowUpdate<'a> {
    frame: Http2Frame<'a>,
    increment: Http2WindowIncrement,
}

impl<'a> Http2WindowUpdate<'a> {
    pub(super) fn from_validated(frame: Http2Frame<'a>, increment: Http2WindowIncrement) -> Self {
        Self { frame, increment }
    }

    /// Parses the first complete WINDOW_UPDATE frame, enforcing the caller-provided payload maximum.
    pub fn parse(bytes: &'a [u8], maximum_payload: usize) -> Result<Self, Http2ParseError> {
        Self::from_frame(Http2Frame::parse(bytes, maximum_payload)?)
    }

    /// Validates a raw WINDOW_UPDATE frame's intrinsic layout.
    pub fn from_frame(frame: Http2Frame<'a>) -> Result<Self, Http2ParseError> {
        validate_type(frame, Http2FrameType::WINDOW_UPDATE)?;
        validate_exact_payload(frame, 4)?;
        let increment = Http2WindowIncrement::parse(frame.payload());
        if increment.value() == 0 {
            return Err(Http2ParseError::ZeroWindowIncrement);
        }
        Ok(Self { frame, increment })
    }

    /// Returns the validated raw frame.
    pub const fn frame(&self) -> Http2Frame<'a> {
        self.frame
    }
    /// Returns the exact represented frame bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.frame.as_bytes()
    }
    /// Returns the raw-preserving window increment.
    pub const fn increment(&self) -> Http2WindowIncrement {
        self.increment
    }
}

fn validate_frame(frame: Http2Frame<'_>, expected: Http2FrameType) -> Result<(), Http2ParseError> {
    validate_type(frame, expected)?;
    if frame.stream_id().value() == 0 {
        return Err(Http2ParseError::ZeroStreamId);
    }
    Ok(())
}

fn validate_type(frame: Http2Frame<'_>, expected: Http2FrameType) -> Result<(), Http2ParseError> {
    if frame.frame_type() != expected {
        return Err(Http2ParseError::WrongFrameType {
            expected,
            actual: frame.frame_type(),
        });
    }
    Ok(())
}

fn validate_zero_stream(frame: Http2Frame<'_>) -> Result<(), Http2ParseError> {
    if frame.stream_id().value() != 0 {
        return Err(Http2ParseError::ExpectedZeroStreamId);
    }
    Ok(())
}

fn validate_exact_payload(frame: Http2Frame<'_>, expected: usize) -> Result<(), Http2ParseError> {
    let actual = frame.payload().len();
    if actual != expected {
        return Err(Http2ParseError::FrameSizeMismatch { expected, actual });
    }
    Ok(())
}

fn validate_padding(payload: &[u8]) -> Result<(), Http2ParseError> {
    let Some(&padding_length) = payload.first() else {
        return Err(Http2ParseError::InvalidPadding {
            padding_length: 0,
            payload_length: 0,
        });
    };
    if usize::from(padding_length) >= payload.len() {
        return Err(Http2ParseError::InvalidPadding {
            padding_length,
            payload_length: payload.len(),
        });
    }
    Ok(())
}

fn padding_length(frame: Http2Frame<'_>) -> usize {
    if frame.flags() & PADDED != 0 {
        usize::from(frame.payload()[0])
    } else {
        0
    }
}
