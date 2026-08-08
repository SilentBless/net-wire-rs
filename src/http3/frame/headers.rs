//! Typed HTTP/3 HEADERS frame payload view and builder.

use super::envelope::{Http3Frame, Http3FrameBuildError, Http3FrameBuilder};
use super::payload::{Http3FramePayloadParseError, validate_type};
use crate::http3::codepoints::Http3FrameType;

/// A validated borrowed HTTP/3 HEADERS frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3Headers<'a> {
    frame: Http3Frame<'a>,
}

impl<'a> Http3Headers<'a> {
    /// Assembles a HEADERS view from a builder-validated frame.
    pub(in crate::http3) const fn from_validated(frame: Http3Frame<'a>) -> Self {
        Self { frame }
    }

    /// Parses the first complete HEADERS frame, enforcing the caller-provided payload maximum.
    pub fn parse(
        bytes: &'a [u8],
        maximum_payload: usize,
    ) -> Result<Self, Http3FramePayloadParseError> {
        Self::from_frame(
            Http3Frame::parse(bytes, maximum_payload)
                .map_err(Http3FramePayloadParseError::Frame)?,
        )
    }

    /// Validates a raw HEADERS frame's intrinsic layout without decoding QPACK.
    pub fn from_frame(frame: Http3Frame<'a>) -> Result<Self, Http3FramePayloadParseError> {
        validate_type(frame, Http3FrameType::HEADERS)?;
        Ok(Self { frame })
    }

    /// Returns the validated raw frame.
    pub const fn frame(&self) -> Http3Frame<'a> {
        self.frame
    }

    /// Returns the exact represented frame bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.frame.as_bytes()
    }

    /// Returns the complete opaque QPACK-encoded field section.
    pub fn encoded_field_section(&self) -> &'a [u8] {
        self.frame.payload()
    }
}

/// Builds a typed HTTP/3 HEADERS frame in caller-owned storage.
pub struct Http3HeadersBuilder<'output, 'section> {
    destination: &'output mut [u8],
    encoded_field_section: &'section [u8],
}

impl<'output, 'section> Http3HeadersBuilder<'output, 'section> {
    /// Creates a HEADERS builder for an opaque QPACK-encoded field section.
    pub fn new(destination: &'output mut [u8], encoded_field_section: &'section [u8]) -> Self {
        Self {
            destination,
            encoded_field_section,
        }
    }

    /// Canonically encodes and atomically writes the HEADERS frame.
    pub fn build(self) -> Result<Http3Headers<'output>, Http3FrameBuildError> {
        let frame = Http3FrameBuilder::new(
            self.destination,
            Http3FrameType::HEADERS,
            self.encoded_field_section,
        )
        .build()?;
        Ok(Http3Headers::from_validated(frame))
    }
}
