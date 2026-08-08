use super::error::Http2ParseError;
use super::frame::Http2Frame;
use super::layout::{validate_exact_payload, validate_frame, validate_type, validate_zero_stream};
use super::priority::Http2Priority;
use super::types::{Http2ErrorCode, Http2FrameType, Http2StreamId};

/// A validated borrowed HTTP/2 GOAWAY frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http2Goaway<'a> {
    frame: Http2Frame<'a>,
    last_stream_id: Http2StreamId,
    error_code: Http2ErrorCode,
}

impl<'a> Http2Goaway<'a> {
    pub(super) fn from_validated(
        frame: Http2Frame<'a>,
        last_stream_id: Http2StreamId,
        error_code: Http2ErrorCode,
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
            error_code: Http2ErrorCode::new(u32::from_be_bytes([
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
    pub const fn error_code(&self) -> Http2ErrorCode {
        self.error_code
    }

    /// Returns the arbitrary trailing debug data.
    pub fn additional_debug_data(&self) -> &'a [u8] {
        &self.frame.payload()[8..]
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
    error_code: Http2ErrorCode,
}

impl<'a> Http2RstStream<'a> {
    pub(super) fn from_validated(frame: Http2Frame<'a>, error_code: Http2ErrorCode) -> Self {
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
            error_code: Http2ErrorCode::new(u32::from_be_bytes([
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
    pub const fn error_code(&self) -> Http2ErrorCode {
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
