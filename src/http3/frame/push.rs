//! Typed HTTP/3 push frame payload views and builders.

use crate::http3::codepoints::Http3FrameType;
use crate::http3::ids::Http3PushId;
use crate::quic::varint::{QuicVarInt, QuicVarIntLen};

use super::envelope::Http3Frame;
use super::payload::{
    Http3FramePayloadBuildError, Http3FramePayloadField, Http3FramePayloadParseError, add_payload,
    encode_varint, envelope, parse_exact_varint, parse_payload_varint, validate_type,
};

/// A validated borrowed HTTP/3 CANCEL_PUSH frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3CancelPush<'a> {
    frame: Http3Frame<'a>,
    push_id: QuicVarInt<'a>,
}

impl<'a> Http3CancelPush<'a> {
    /// Assembles a CANCEL_PUSH view from builder-validated components.
    pub(in crate::http3) fn from_validated(
        frame: Http3Frame<'a>,
        push_id: Http3PushId,
        push_id_length: QuicVarIntLen,
    ) -> Self {
        let push_id = QuicVarInt::from_validated(
            &frame.payload()[..push_id_length.byte_len()],
            push_id.value(),
            push_id_length,
        );
        Self { frame, push_id }
    }

    /// Parses the first complete CANCEL_PUSH frame, enforcing the caller-provided payload maximum.
    pub fn parse(
        bytes: &'a [u8],
        maximum_payload: usize,
    ) -> Result<Self, Http3FramePayloadParseError> {
        Self::from_frame(
            Http3Frame::parse(bytes, maximum_payload)
                .map_err(Http3FramePayloadParseError::Frame)?,
        )
    }

    /// Validates a raw CANCEL_PUSH frame's intrinsic layout.
    pub fn from_frame(frame: Http3Frame<'a>) -> Result<Self, Http3FramePayloadParseError> {
        validate_type(frame, Http3FrameType::CANCEL_PUSH)?;
        let push_id = parse_exact_varint(frame.payload(), Http3FramePayloadField::PushId)?;
        Ok(Self { frame, push_id })
    }

    /// Returns the validated raw frame.
    pub const fn frame(&self) -> Http3Frame<'a> {
        self.frame
    }

    /// Returns the exact represented frame bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.frame.as_bytes()
    }

    /// Returns the raw-preserving Push ID.
    pub const fn push_id(&self) -> Http3PushId {
        Http3PushId::new(self.push_id.value())
    }

    /// Returns the exact Push ID variable-length integer.
    pub const fn push_id_varint(&self) -> QuicVarInt<'a> {
        self.push_id
    }
}

/// A validated borrowed HTTP/3 PUSH_PROMISE frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3PushPromise<'a> {
    frame: Http3Frame<'a>,
    push_id: QuicVarInt<'a>,
}

impl<'a> Http3PushPromise<'a> {
    /// Assembles a PUSH_PROMISE view from builder-validated components.
    pub(in crate::http3) fn from_validated(
        frame: Http3Frame<'a>,
        push_id: Http3PushId,
        push_id_length: QuicVarIntLen,
    ) -> Self {
        let push_id = QuicVarInt::from_validated(
            &frame.payload()[..push_id_length.byte_len()],
            push_id.value(),
            push_id_length,
        );
        Self { frame, push_id }
    }

    /// Parses the first complete PUSH_PROMISE frame, enforcing the caller-provided payload maximum.
    pub fn parse(
        bytes: &'a [u8],
        maximum_payload: usize,
    ) -> Result<Self, Http3FramePayloadParseError> {
        Self::from_frame(
            Http3Frame::parse(bytes, maximum_payload)
                .map_err(Http3FramePayloadParseError::Frame)?,
        )
    }

    /// Validates a raw PUSH_PROMISE frame's initial Push ID without decoding QPACK.
    pub fn from_frame(frame: Http3Frame<'a>) -> Result<Self, Http3FramePayloadParseError> {
        validate_type(frame, Http3FrameType::PUSH_PROMISE)?;
        let push_id = parse_payload_varint(frame.payload(), Http3FramePayloadField::PushId, 0)?;
        Ok(Self { frame, push_id })
    }

    /// Returns the validated raw frame.
    pub const fn frame(&self) -> Http3Frame<'a> {
        self.frame
    }

    /// Returns the exact represented frame bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.frame.as_bytes()
    }

    /// Returns the raw-preserving Push ID.
    pub const fn push_id(&self) -> Http3PushId {
        Http3PushId::new(self.push_id.value())
    }

    /// Returns the exact Push ID variable-length integer.
    pub const fn push_id_varint(&self) -> QuicVarInt<'a> {
        self.push_id
    }

    /// Returns the remaining opaque QPACK-encoded field section.
    pub fn encoded_field_section(&self) -> &'a [u8] {
        &self.frame.payload()[self.push_id.byte_len()..]
    }
}

/// A validated borrowed HTTP/3 MAX_PUSH_ID frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3MaxPushId<'a> {
    frame: Http3Frame<'a>,
    push_id: QuicVarInt<'a>,
}

impl<'a> Http3MaxPushId<'a> {
    /// Assembles a MAX_PUSH_ID view from builder-validated components.
    pub(in crate::http3) fn from_validated(
        frame: Http3Frame<'a>,
        push_id: Http3PushId,
        push_id_length: QuicVarIntLen,
    ) -> Self {
        let push_id = QuicVarInt::from_validated(
            &frame.payload()[..push_id_length.byte_len()],
            push_id.value(),
            push_id_length,
        );
        Self { frame, push_id }
    }

    /// Parses the first complete MAX_PUSH_ID frame, enforcing the caller-provided payload maximum.
    pub fn parse(
        bytes: &'a [u8],
        maximum_payload: usize,
    ) -> Result<Self, Http3FramePayloadParseError> {
        Self::from_frame(
            Http3Frame::parse(bytes, maximum_payload)
                .map_err(Http3FramePayloadParseError::Frame)?,
        )
    }

    /// Validates a raw MAX_PUSH_ID frame's intrinsic layout.
    pub fn from_frame(frame: Http3Frame<'a>) -> Result<Self, Http3FramePayloadParseError> {
        validate_type(frame, Http3FrameType::MAX_PUSH_ID)?;
        let push_id = parse_exact_varint(frame.payload(), Http3FramePayloadField::PushId)?;
        Ok(Self { frame, push_id })
    }

    /// Returns the validated raw frame.
    pub const fn frame(&self) -> Http3Frame<'a> {
        self.frame
    }

    /// Returns the exact represented frame bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.frame.as_bytes()
    }

    /// Returns the raw-preserving Push ID.
    pub const fn push_id(&self) -> Http3PushId {
        Http3PushId::new(self.push_id.value())
    }

    /// Returns the exact Push ID variable-length integer.
    pub const fn push_id_varint(&self) -> QuicVarInt<'a> {
        self.push_id
    }
}

/// Builds a typed HTTP/3 CANCEL_PUSH frame in caller-owned storage.
pub struct Http3CancelPushBuilder<'output> {
    destination: &'output mut [u8],
    push_id: Http3PushId,
}

impl<'output> Http3CancelPushBuilder<'output> {
    /// Creates a CANCEL_PUSH builder for a raw Push ID.
    pub fn new(destination: &'output mut [u8], push_id: Http3PushId) -> Self {
        Self {
            destination,
            push_id,
        }
    }

    /// Canonically encodes and atomically writes the CANCEL_PUSH frame.
    pub fn build(self) -> Result<Http3CancelPush<'output>, Http3FramePayloadBuildError> {
        let push_id = encode_varint(self.push_id.value()).map_err(|error| {
            Http3FramePayloadBuildError::PayloadVarInt {
                field: Http3FramePayloadField::PushId,
                error,
            }
        })?;
        let plan = envelope(
            Http3FrameType::CANCEL_PUSH,
            push_id.byte_len(),
            self.destination,
        )?;
        let header_length = plan.header_length();
        let required = plan.required();
        let bytes = &mut self.destination[..required];
        plan.write_header(bytes);
        bytes[header_length..].copy_from_slice(push_id.bytes());
        let frame = plan.finish(bytes);
        Ok(Http3CancelPush::from_validated(
            frame,
            self.push_id,
            push_id.len,
        ))
    }
}

/// Builds a typed HTTP/3 PUSH_PROMISE frame in caller-owned storage.
pub struct Http3PushPromiseBuilder<'output, 'section> {
    destination: &'output mut [u8],
    push_id: Http3PushId,
    encoded_field_section: &'section [u8],
}

impl<'output, 'section> Http3PushPromiseBuilder<'output, 'section> {
    /// Creates a PUSH_PROMISE builder for a raw Push ID and opaque QPACK field section.
    pub fn new(
        destination: &'output mut [u8],
        push_id: Http3PushId,
        encoded_field_section: &'section [u8],
    ) -> Self {
        Self {
            destination,
            push_id,
            encoded_field_section,
        }
    }

    /// Canonically encodes and atomically writes the PUSH_PROMISE frame.
    pub fn build(self) -> Result<Http3PushPromise<'output>, Http3FramePayloadBuildError> {
        let push_id = encode_varint(self.push_id.value()).map_err(|error| {
            Http3FramePayloadBuildError::PayloadVarInt {
                field: Http3FramePayloadField::PushId,
                error,
            }
        })?;
        let payload_length = add_payload(push_id.byte_len(), self.encoded_field_section.len())
            .ok_or(Http3FramePayloadBuildError::PayloadLengthOverflow {
                current: push_id.byte_len(),
                addition: self.encoded_field_section.len(),
            })?;
        let plan = envelope(
            Http3FrameType::PUSH_PROMISE,
            payload_length,
            self.destination,
        )?;
        let header_length = plan.header_length();
        let required = plan.required();
        let bytes = &mut self.destination[..required];
        plan.write_header(bytes);
        let payload = &mut bytes[header_length..];
        let push_id_length = push_id.byte_len();
        payload[..push_id_length].copy_from_slice(push_id.bytes());
        payload[push_id_length..].copy_from_slice(self.encoded_field_section);
        let frame = plan.finish(bytes);
        Ok(Http3PushPromise::from_validated(
            frame,
            self.push_id,
            push_id.len,
        ))
    }
}

/// Builds a typed HTTP/3 MAX_PUSH_ID frame in caller-owned storage.
pub struct Http3MaxPushIdBuilder<'output> {
    destination: &'output mut [u8],
    push_id: Http3PushId,
}

impl<'output> Http3MaxPushIdBuilder<'output> {
    /// Creates a MAX_PUSH_ID builder for a raw Push ID.
    pub fn new(destination: &'output mut [u8], push_id: Http3PushId) -> Self {
        Self {
            destination,
            push_id,
        }
    }

    /// Canonically encodes and atomically writes the MAX_PUSH_ID frame.
    pub fn build(self) -> Result<Http3MaxPushId<'output>, Http3FramePayloadBuildError> {
        let push_id = encode_varint(self.push_id.value()).map_err(|error| {
            Http3FramePayloadBuildError::PayloadVarInt {
                field: Http3FramePayloadField::PushId,
                error,
            }
        })?;
        let plan = envelope(
            Http3FrameType::MAX_PUSH_ID,
            push_id.byte_len(),
            self.destination,
        )?;
        let header_length = plan.header_length();
        let required = plan.required();
        let bytes = &mut self.destination[..required];
        plan.write_header(bytes);
        bytes[header_length..].copy_from_slice(push_id.bytes());
        let frame = plan.finish(bytes);
        Ok(Http3MaxPushId::from_validated(
            frame,
            self.push_id,
            push_id.len,
        ))
    }
}
