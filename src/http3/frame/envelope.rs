//! Exact HTTP/3 frame envelope views.
//!
//! Atomic caller-buffer construction of raw HTTP/3 frames.

use core::fmt;

use crate::quic::varint::{
    QuicVarInt, QuicVarIntBuildError, QuicVarIntBuilder, QuicVarIntLen, QuicVarIntParseError,
};

use super::super::codepoints::Http3FrameType;

/// Failure to parse a structurally bounded HTTP/3 frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3FrameParseError {
    /// The frame type variable-length integer is incomplete.
    TypeVarInt(QuicVarIntParseError),
    /// The payload length variable-length integer is incomplete.
    LengthVarInt(QuicVarIntParseError),
    /// The encoded payload length cannot be represented as `usize`.
    PayloadLengthNotRepresentable {
        /// Encoded payload length.
        value: u64,
    },
    /// Adding the encoded header and payload lengths overflows `usize`.
    FrameLengthOverflow {
        /// Encoded type length in bytes.
        type_length: usize,
        /// Encoded payload-length length in bytes.
        length_length: usize,
        /// Decoded payload length in bytes.
        payload_length: usize,
    },
    /// The declared payload exceeds the caller-provided maximum.
    PayloadTooLarge {
        /// Caller-provided maximum payload length.
        maximum: usize,
        /// Declared payload length.
        actual: usize,
    },
    /// The complete frame is not available.
    IncompletePayload {
        /// Bytes required for the complete frame.
        required: usize,
        /// Bytes available in the input.
        available: usize,
    },
}

impl fmt::Display for Http3FrameParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypeVarInt(error) => {
                write!(f, "HTTP/3 frame type variable-length integer: {error}")
            }
            Self::LengthVarInt(error) => {
                write!(
                    f,
                    "HTTP/3 frame payload length variable-length integer: {error}"
                )
            }
            Self::PayloadLengthNotRepresentable { value } => write!(
                f,
                "HTTP/3 frame payload length {value} cannot be represented as usize"
            ),
            Self::FrameLengthOverflow {
                type_length,
                length_length,
                payload_length,
            } => write!(
                f,
                "HTTP/3 frame length overflows: type {type_length} bytes, length {length_length} bytes, payload {payload_length} bytes"
            ),
            Self::PayloadTooLarge { maximum, actual } => write!(
                f,
                "HTTP/3 frame payload is too large: maximum {maximum}, got {actual}"
            ),
            Self::IncompletePayload {
                required,
                available,
            } => write!(
                f,
                "HTTP/3 frame payload is incomplete: need {required} bytes, have {available}"
            ),
        }
    }
}

impl core::error::Error for Http3FrameParseError {}

/// A structurally bounded HTTP/3 frame preserving exact variable-integer encodings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3Frame<'a> {
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    payload_length: QuicVarInt<'a>,
}

impl<'a> Http3Frame<'a> {
    pub(super) fn from_validated(
        bytes: &'a [u8],
        frame_type_value: u64,
        frame_type_length: QuicVarIntLen,
        payload_length_value: u64,
        payload_length_length: QuicVarIntLen,
    ) -> Self {
        let type_end = frame_type_length.byte_len();
        let length_end = type_end + payload_length_length.byte_len();
        Self {
            bytes,
            frame_type: QuicVarInt::from_validated(
                &bytes[..type_end],
                frame_type_value,
                frame_type_length,
            ),
            payload_length: QuicVarInt::from_validated(
                &bytes[type_end..length_end],
                payload_length_value,
                payload_length_length,
            ),
        }
    }

    /// Parses the first complete frame, enforcing the caller-provided payload maximum.
    pub fn parse(bytes: &'a [u8], maximum_payload: usize) -> Result<Self, Http3FrameParseError> {
        let frame_type = QuicVarInt::parse(bytes).map_err(Http3FrameParseError::TypeVarInt)?;
        let type_length = frame_type.byte_len();
        let payload_length =
            QuicVarInt::parse(&bytes[type_length..]).map_err(Http3FrameParseError::LengthVarInt)?;
        let total_length = frame_length(
            type_length,
            payload_length.byte_len(),
            payload_length.value(),
            maximum_payload,
            bytes.len(),
        )?;
        Ok(Self {
            bytes: &bytes[..total_length],
            frame_type,
            payload_length,
        })
    }

    /// Returns the raw frame type.
    pub const fn frame_type(&self) -> Http3FrameType {
        Http3FrameType::new(self.frame_type.value())
    }

    /// Returns the exact frame type variable-length integer.
    pub const fn frame_type_varint(&self) -> QuicVarInt<'a> {
        self.frame_type
    }

    /// Returns the exact payload length variable-length integer.
    pub const fn payload_length_varint(&self) -> QuicVarInt<'a> {
        self.payload_length
    }

    /// Returns the declared payload length.
    pub fn payload_length(&self) -> usize {
        self.payload().len()
    }

    /// Returns the exact payload bytes.
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[self.frame_type.byte_len() + self.payload_length.byte_len()..]
    }

    /// Returns the exact represented frame bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

/// A mutable structurally bounded HTTP/3 frame.
#[derive(Debug, Eq, PartialEq)]
pub struct Http3FrameMut<'a> {
    bytes: &'a mut [u8],
    frame_type: Http3FrameType,
    payload_offset: usize,
}

impl<'a> Http3FrameMut<'a> {
    /// Parses the first complete frame, enforcing the caller-provided payload maximum.
    pub fn parse(
        bytes: &'a mut [u8],
        maximum_payload: usize,
    ) -> Result<Self, Http3FrameParseError> {
        let (frame_type, payload_offset, total_length) = frame_layout(bytes, maximum_payload)?;
        Ok(Self {
            bytes: &mut bytes[..total_length],
            frame_type,
            payload_offset,
        })
    }

    /// Returns the raw frame type.
    pub const fn frame_type(&self) -> Http3FrameType {
        self.frame_type
    }

    /// Returns the declared payload length.
    pub fn payload_length(&self) -> usize {
        self.bytes.len() - self.payload_offset
    }

    /// Returns the exact payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.bytes[self.payload_offset..]
    }

    /// Returns the exact payload bytes mutably without changing their encoded length.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[self.payload_offset..]
    }

    /// Returns the exact represented frame bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }
}

fn frame_layout(
    bytes: &[u8],
    maximum_payload: usize,
) -> Result<(Http3FrameType, usize, usize), Http3FrameParseError> {
    let frame_type = QuicVarInt::parse(bytes).map_err(Http3FrameParseError::TypeVarInt)?;
    let type_length = frame_type.byte_len();
    let payload_length =
        QuicVarInt::parse(&bytes[type_length..]).map_err(Http3FrameParseError::LengthVarInt)?;
    let payload_offset = type_length + payload_length.byte_len();
    let total_length = frame_length(
        type_length,
        payload_length.byte_len(),
        payload_length.value(),
        maximum_payload,
        bytes.len(),
    )?;
    Ok((
        Http3FrameType::new(frame_type.value()),
        payload_offset,
        total_length,
    ))
}

fn frame_length(
    type_length: usize,
    length_length: usize,
    payload_length_value: u64,
    maximum_payload: usize,
    available: usize,
) -> Result<usize, Http3FrameParseError> {
    let payload_length = usize::try_from(payload_length_value).map_err(|_| {
        Http3FrameParseError::PayloadLengthNotRepresentable {
            value: payload_length_value,
        }
    })?;
    if payload_length > maximum_payload {
        return Err(Http3FrameParseError::PayloadTooLarge {
            maximum: maximum_payload,
            actual: payload_length,
        });
    }
    let header_length = type_length.checked_add(length_length).ok_or(
        Http3FrameParseError::FrameLengthOverflow {
            type_length,
            length_length,
            payload_length,
        },
    )?;
    let required = header_length.checked_add(payload_length).ok_or(
        Http3FrameParseError::FrameLengthOverflow {
            type_length,
            length_length,
            payload_length,
        },
    )?;
    if available < required {
        return Err(Http3FrameParseError::IncompletePayload {
            required,
            available,
        });
    }
    Ok(required)
}

/// Failure to build an HTTP/3 frame in caller-provided storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3FrameBuildError {
    /// The frame type cannot be encoded as a QUIC variable-length integer.
    TypeVarInt(QuicVarIntBuildError),
    /// The payload length cannot be encoded as a QUIC variable-length integer.
    LengthVarInt(QuicVarIntBuildError),
    /// The payload length cannot be represented as `u64`.
    PayloadLengthNotRepresentable {
        /// Supplied payload length.
        length: usize,
    },
    /// Adding the encoded header and payload lengths overflows `usize`.
    FrameLengthOverflow {
        /// Encoded type length in bytes.
        type_length: usize,
        /// Encoded payload-length length in bytes.
        length_length: usize,
        /// Supplied payload length in bytes.
        payload_length: usize,
    },
    /// The caller buffer cannot contain the complete frame.
    BufferTooShort {
        /// Bytes required for the complete frame.
        required: usize,
        /// Bytes available in the destination.
        available: usize,
    },
}

impl fmt::Display for Http3FrameBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypeVarInt(error) => {
                write!(f, "HTTP/3 frame type variable-length integer: {error}")
            }
            Self::LengthVarInt(error) => {
                write!(
                    f,
                    "HTTP/3 frame payload length variable-length integer: {error}"
                )
            }
            Self::PayloadLengthNotRepresentable { length } => write!(
                f,
                "HTTP/3 frame payload length {length} cannot be represented as u64"
            ),
            Self::FrameLengthOverflow {
                type_length,
                length_length,
                payload_length,
            } => write!(
                f,
                "HTTP/3 frame length overflows: type {type_length} bytes, length {length_length} bytes, payload {payload_length} bytes"
            ),
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                f,
                "HTTP/3 frame destination is too short: need {required} bytes, have {available}"
            ),
        }
    }
}

impl core::error::Error for Http3FrameBuildError {}

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
