use super::error::Http2ParseError;
use super::frame::Http2Frame;
use super::layout::{PADDED, padding_length, validate_frame, validate_padding};
use super::priority::Http2Priority;
use super::types::{Http2FrameType, Http2StreamId};

const PRIORITY: u8 = 0x20;

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
