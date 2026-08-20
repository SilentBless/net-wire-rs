//! Exact HTTP/2 client-preface and frame views.

use super::error::Http2ParseError;
pub(super) mod layout;

use self::layout::{
    FRAME_HEADER_LENGTH, Http2FrameLayout, Http2FrameLayoutError, Http2FrameLayoutViewMut,
};
use super::types::{Http2FrameType, Http2StreamId};
use core::fmt;

/// The exact HTTP/2 client connection preface.
pub const HTTP2_CLIENT_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// A validated borrowed HTTP/2 client connection preface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http2ClientPreface<'a> {
    bytes: &'a [u8],
}

impl<'a> Http2ClientPreface<'a> {
    /// Parses the exact client preface at the start of `bytes` and excludes any suffix.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Http2ParseError> {
        if bytes.len() < HTTP2_CLIENT_PREFACE.len() {
            return Err(Http2ParseError::Incomplete {
                required: HTTP2_CLIENT_PREFACE.len(),
                available: bytes.len(),
            });
        }
        for (offset, (&actual, &expected)) in
            bytes.iter().zip(HTTP2_CLIENT_PREFACE.iter()).enumerate()
        {
            if actual != expected {
                return Err(Http2ParseError::ClientPrefaceMismatch {
                    offset,
                    expected,
                    actual,
                });
            }
        }
        Ok(Self {
            bytes: &bytes[..HTTP2_CLIENT_PREFACE.len()],
        })
    }

    /// Returns the exact represented preface bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

fn layout_error(error: Http2FrameLayoutError, available: usize) -> Http2ParseError {
    match error {
        Http2FrameLayoutError::InputTooShort { expected, .. } => Http2ParseError::Incomplete {
            required: expected,
            available,
        },
        Http2FrameLayoutError::TrailingBytes { .. }
        | Http2FrameLayoutError::InvalidCodecWidth { .. }
        | Http2FrameLayoutError::InvalidRangeSource { .. }
        | Http2FrameLayoutError::RangeEndBeforeStart { .. }
        | Http2FrameLayoutError::InvalidPrefixExtent { .. } => {
            Http2ParseError::InvalidRepresentation
        }
    }
}

/// A structurally bounded raw HTTP/2 frame preserving all header fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http2Frame<'a> {
    layout: Http2FrameLayout<'a>,
}

impl<'a> Http2Frame<'a> {
    pub(super) const fn from_layout(layout: Http2FrameLayout<'a>) -> Self {
        Self { layout }
    }

    /// Parses the first complete frame, enforcing the caller-provided payload maximum.
    pub fn parse(bytes: &'a [u8], maximum_payload: usize) -> Result<Self, Http2ParseError> {
        if bytes.len() < FRAME_HEADER_LENGTH {
            return Err(Http2ParseError::Incomplete {
                required: FRAME_HEADER_LENGTH,
                available: bytes.len(),
            });
        }
        let header = Http2FrameLayout::view(bytes)
            .without_trailing()
            .map_err(|error| layout_error(error, bytes.len()))?;
        let payload_length = payload_length(&header);
        if payload_length > maximum_payload {
            return Err(Http2ParseError::PayloadTooLarge {
                maximum: maximum_payload,
                actual: payload_length,
            });
        }
        let required = FRAME_HEADER_LENGTH.checked_add(payload_length).ok_or(
            Http2ParseError::PayloadTooLarge {
                maximum: maximum_payload,
                actual: payload_length,
            },
        )?;
        if bytes.len() < required {
            return Err(Http2ParseError::Incomplete {
                required,
                available: bytes.len(),
            });
        }
        let layout = Http2FrameLayout::view(&bytes[..required])
            .without_trailing()
            .map_err(|error| layout_error(error, required))?;
        Ok(Self { layout })
    }

    /// Returns the declared payload length.
    pub fn payload_length(&self) -> usize {
        payload_length(&self.layout)
    }
    /// Returns the raw frame type.
    pub fn frame_type(&self) -> Http2FrameType {
        self.layout.frame_type()
    }
    /// Returns the unmodified flags byte.
    pub fn flags(&self) -> u8 {
        self.layout.flags()
    }
    /// Returns the raw stream identifier, including its reserved bit.
    pub fn stream_id(&self) -> Http2StreamId {
        self.layout.stream_id()
    }
    /// Returns the exact payload bytes.
    pub fn payload(&self) -> &'a [u8] {
        self.layout.payload()
    }
    /// Returns the exact represented frame bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.layout.as_bytes()
    }
}

/// A mutable structurally bounded raw HTTP/2 frame preserving all header fields.
pub struct Http2FrameMut<'a> {
    layout: Http2FrameLayoutViewMut<'a>,
}

impl fmt::Debug for Http2FrameMut<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Http2FrameMut")
            .field("bytes", &self.as_bytes())
            .finish()
    }
}

impl PartialEq for Http2FrameMut<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Http2FrameMut<'_> {}

impl<'a> Http2FrameMut<'a> {
    /// Parses the first complete frame, enforcing the caller-provided payload maximum.
    pub fn parse(bytes: &'a mut [u8], maximum_payload: usize) -> Result<Self, Http2ParseError> {
        let available = bytes.len();
        if available < FRAME_HEADER_LENGTH {
            return Err(Http2ParseError::Incomplete {
                required: FRAME_HEADER_LENGTH,
                available,
            });
        }
        let header = Http2FrameLayout::view(bytes)
            .without_trailing()
            .map_err(|error| layout_error(error, available))?;
        let payload_length = payload_length(&header);
        if payload_length > maximum_payload {
            return Err(Http2ParseError::PayloadTooLarge {
                maximum: maximum_payload,
                actual: payload_length,
            });
        }
        let required = FRAME_HEADER_LENGTH.checked_add(payload_length).ok_or(
            Http2ParseError::PayloadTooLarge {
                maximum: maximum_payload,
                actual: payload_length,
            },
        )?;
        if available < required {
            return Err(Http2ParseError::Incomplete {
                required,
                available,
            });
        }
        let layout = Http2FrameLayoutViewMut::parse_exact_mut(&mut bytes[..required])
            .map_err(|error| layout_error(error, required))?;
        Ok(Self { layout })
    }

    pub(super) const fn from_layout(layout: Http2FrameLayoutViewMut<'a>) -> Self {
        Self { layout }
    }

    /// Returns the declared payload length.
    pub fn payload_length(&self) -> usize {
        usize::from(self.layout.payload_length_high()) << 16
            | usize::from(self.layout.payload_length_middle()) << 8
            | usize::from(self.layout.payload_length_low())
    }
    /// Returns the raw frame type.
    pub fn frame_type(&self) -> Http2FrameType {
        self.layout.frame_type()
    }
    /// Returns the unmodified flags byte.
    pub fn flags(&self) -> u8 {
        self.layout.flags()
    }
    /// Returns the raw stream identifier, including its reserved bit.
    pub fn stream_id(&self) -> Http2StreamId {
        self.layout.stream_id()
    }
    /// Returns the exact payload bytes.
    pub fn payload(&self) -> &[u8] {
        self.layout.payload()
    }
    /// Returns the exact payload bytes mutably without changing their encoded length.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        self.layout.payload_mut()
    }
    /// Returns the exact represented frame bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.layout.as_bytes()
    }
}

fn payload_length(layout: &Http2FrameLayout<'_>) -> usize {
    usize::from(layout.payload_length_high()) << 16
        | usize::from(layout.payload_length_middle()) << 8
        | usize::from(layout.payload_length_low())
}
