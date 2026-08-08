//! Typed HTTP/3 GOAWAY frame payload view and builder.

use crate::http3::codepoints::Http3FrameType;
use crate::quic::varint::{QuicVarInt, QuicVarIntLen};

use super::envelope::Http3Frame;
use super::payload::{
    Http3FramePayloadBuildError, Http3FramePayloadField, Http3FramePayloadParseError,
    encode_varint, envelope, parse_exact_varint, validate_type,
};

/// A validated borrowed HTTP/3 GOAWAY frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3Goaway<'a> {
    frame: Http3Frame<'a>,
    identifier: QuicVarInt<'a>,
}

impl<'a> Http3Goaway<'a> {
    /// Assembles a GOAWAY view from builder-validated components.
    pub(in crate::http3) fn from_validated(
        frame: Http3Frame<'a>,
        identifier: u64,
        identifier_length: QuicVarIntLen,
    ) -> Self {
        let identifier = QuicVarInt::from_validated(
            &frame.payload()[..identifier_length.byte_len()],
            identifier,
            identifier_length,
        );
        Self { frame, identifier }
    }

    /// Parses the first complete GOAWAY frame, enforcing the caller-provided payload maximum.
    pub fn parse(
        bytes: &'a [u8],
        maximum_payload: usize,
    ) -> Result<Self, Http3FramePayloadParseError> {
        Self::from_frame(
            Http3Frame::parse(bytes, maximum_payload)
                .map_err(Http3FramePayloadParseError::Frame)?,
        )
    }

    /// Validates a raw GOAWAY frame's intrinsic layout without assigning identifier role.
    pub fn from_frame(frame: Http3Frame<'a>) -> Result<Self, Http3FramePayloadParseError> {
        validate_type(frame, Http3FrameType::GOAWAY)?;
        let identifier =
            parse_exact_varint(frame.payload(), Http3FramePayloadField::GoawayIdentifier)?;
        Ok(Self { frame, identifier })
    }

    /// Returns the validated raw frame.
    pub const fn frame(&self) -> Http3Frame<'a> {
        self.frame
    }

    /// Returns the exact represented frame bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.frame.as_bytes()
    }

    /// Returns the role-neutral GOAWAY identifier value.
    pub const fn identifier(&self) -> u64 {
        self.identifier.value()
    }

    /// Returns the exact role-neutral GOAWAY identifier variable-length integer.
    pub const fn identifier_varint(&self) -> QuicVarInt<'a> {
        self.identifier
    }
}

/// Builds a typed HTTP/3 GOAWAY frame in caller-owned storage.
pub struct Http3GoawayBuilder<'output> {
    destination: &'output mut [u8],
    identifier: u64,
}

impl<'output> Http3GoawayBuilder<'output> {
    /// Creates a role-neutral GOAWAY builder.
    pub fn new(destination: &'output mut [u8], identifier: u64) -> Self {
        Self {
            destination,
            identifier,
        }
    }

    /// Canonically encodes and atomically writes the GOAWAY frame.
    pub fn build(self) -> Result<Http3Goaway<'output>, Http3FramePayloadBuildError> {
        let identifier = encode_varint(self.identifier).map_err(|error| {
            Http3FramePayloadBuildError::PayloadVarInt {
                field: Http3FramePayloadField::GoawayIdentifier,
                error,
            }
        })?;
        let plan = envelope(
            Http3FrameType::GOAWAY,
            identifier.byte_len(),
            self.destination,
        )?;
        let header_length = plan.header_length();
        let required = plan.required();
        let bytes = &mut self.destination[..required];
        plan.write_header(bytes);
        bytes[header_length..].copy_from_slice(identifier.bytes());
        let frame = plan.finish(bytes);
        Ok(Http3Goaway::from_validated(
            frame,
            self.identifier,
            identifier.len,
        ))
    }
}
