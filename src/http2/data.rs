use super::error::Http2ParseError;
use super::frame::Http2Frame;
use super::layout::{PADDED, padding_length, validate_frame, validate_padding};
use super::types::Http2FrameType;

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
