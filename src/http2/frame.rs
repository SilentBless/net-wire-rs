//! Exact HTTP/2 client-preface and frame views.

use super::error::Http2ParseError;
use super::types::{Http2FrameType, Http2StreamId};

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

/// A structurally bounded raw HTTP/2 frame preserving all header fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http2Frame<'a> {
    bytes: &'a [u8],
}

impl<'a> Http2Frame<'a> {
    pub(super) fn from_validated(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Parses the first complete frame, enforcing the caller-provided payload maximum.
    pub fn parse(bytes: &'a [u8], maximum_payload: usize) -> Result<Self, Http2ParseError> {
        let length = frame_length(bytes, maximum_payload)?;
        Ok(Self {
            bytes: &bytes[..length],
        })
    }

    /// Returns the declared payload length.
    pub fn payload_length(&self) -> usize {
        usize::from(self.bytes[0]) << 16
            | usize::from(self.bytes[1]) << 8
            | usize::from(self.bytes[2])
    }

    /// Returns the raw frame type.
    pub fn frame_type(&self) -> Http2FrameType {
        Http2FrameType::new(self.bytes[3])
    }

    /// Returns the unmodified flags byte.
    pub fn flags(&self) -> u8 {
        self.bytes[4]
    }

    /// Returns the raw stream identifier, including its reserved bit.
    pub fn stream_id(&self) -> Http2StreamId {
        Http2StreamId::new(u32::from_be_bytes([
            self.bytes[5],
            self.bytes[6],
            self.bytes[7],
            self.bytes[8],
        ]))
    }

    /// Returns the exact payload bytes.
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[9..]
    }

    /// Returns the exact represented frame bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

/// A mutable structurally bounded raw HTTP/2 frame preserving all header fields.
#[derive(Debug, Eq, PartialEq)]
pub struct Http2FrameMut<'a> {
    bytes: &'a mut [u8],
}

impl<'a> Http2FrameMut<'a> {
    /// Parses the first complete frame, enforcing the caller-provided payload maximum.
    pub fn parse(bytes: &'a mut [u8], maximum_payload: usize) -> Result<Self, Http2ParseError> {
        let length = frame_length(bytes, maximum_payload)?;
        Ok(Self {
            bytes: &mut bytes[..length],
        })
    }

    pub(crate) fn from_validated(bytes: &'a mut [u8]) -> Self {
        Self { bytes }
    }

    /// Returns the declared payload length.
    pub fn payload_length(&self) -> usize {
        usize::from(self.bytes[0]) << 16
            | usize::from(self.bytes[1]) << 8
            | usize::from(self.bytes[2])
    }

    /// Returns the raw frame type.
    pub fn frame_type(&self) -> Http2FrameType {
        Http2FrameType::new(self.bytes[3])
    }

    /// Returns the unmodified flags byte.
    pub fn flags(&self) -> u8 {
        self.bytes[4]
    }

    /// Returns the raw stream identifier, including its reserved bit.
    pub fn stream_id(&self) -> Http2StreamId {
        Http2StreamId::new(u32::from_be_bytes([
            self.bytes[5],
            self.bytes[6],
            self.bytes[7],
            self.bytes[8],
        ]))
    }

    /// Returns the exact payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.bytes[9..]
    }

    /// Returns the exact payload bytes mutably without changing their encoded length.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[9..]
    }

    /// Returns the exact represented frame bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }
}

fn frame_length(bytes: &[u8], maximum_payload: usize) -> Result<usize, Http2ParseError> {
    const HEADER_LENGTH: usize = 9;

    if bytes.len() < HEADER_LENGTH {
        return Err(Http2ParseError::Incomplete {
            required: HEADER_LENGTH,
            available: bytes.len(),
        });
    }
    let payload_length =
        usize::from(bytes[0]) << 16 | usize::from(bytes[1]) << 8 | usize::from(bytes[2]);
    if payload_length > maximum_payload {
        return Err(Http2ParseError::PayloadTooLarge {
            maximum: maximum_payload,
            actual: payload_length,
        });
    }
    let required =
        HEADER_LENGTH
            .checked_add(payload_length)
            .ok_or(Http2ParseError::PayloadTooLarge {
                maximum: maximum_payload,
                actual: payload_length,
            })?;
    if bytes.len() < required {
        return Err(Http2ParseError::Incomplete {
            required,
            available: bytes.len(),
        });
    }
    Ok(required)
}
