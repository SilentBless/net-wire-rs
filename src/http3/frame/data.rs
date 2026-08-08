//! Typed HTTP/3 DATA frame payload view and builder.

use super::envelope::{Http3Frame, Http3FrameBuildError, Http3FrameBuilder};
use super::payload::{Http3FramePayloadParseError, validate_type};
use crate::http3::codepoints::Http3FrameType;

/// A validated borrowed HTTP/3 DATA frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3Data<'a> {
    frame: Http3Frame<'a>,
}

impl<'a> Http3Data<'a> {
    /// Assembles a DATA view from a builder-validated frame.
    pub(in crate::http3) const fn from_validated(frame: Http3Frame<'a>) -> Self {
        Self { frame }
    }

    /// Parses the first complete DATA frame, enforcing the caller-provided payload maximum.
    pub fn parse(
        bytes: &'a [u8],
        maximum_payload: usize,
    ) -> Result<Self, Http3FramePayloadParseError> {
        Self::from_frame(
            Http3Frame::parse(bytes, maximum_payload)
                .map_err(Http3FramePayloadParseError::Frame)?,
        )
    }

    /// Validates a raw DATA frame's intrinsic layout.
    pub fn from_frame(frame: Http3Frame<'a>) -> Result<Self, Http3FramePayloadParseError> {
        validate_type(frame, Http3FrameType::DATA)?;
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

    /// Returns the complete opaque DATA payload.
    pub fn data(&self) -> &'a [u8] {
        self.frame.payload()
    }
}

/// Builds a typed HTTP/3 DATA frame in caller-owned storage.
pub struct Http3DataBuilder<'output, 'payload> {
    destination: &'output mut [u8],
    data: &'payload [u8],
}

impl<'output, 'payload> Http3DataBuilder<'output, 'payload> {
    /// Creates a DATA builder for opaque payload bytes.
    pub fn new(destination: &'output mut [u8], data: &'payload [u8]) -> Self {
        Self { destination, data }
    }

    /// Canonically encodes and atomically writes the DATA frame.
    pub fn build(self) -> Result<Http3Data<'output>, Http3FrameBuildError> {
        let frame =
            Http3FrameBuilder::new(self.destination, Http3FrameType::DATA, self.data).build()?;
        Ok(Http3Data::from_validated(frame))
    }
}
