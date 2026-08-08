//! HTTP/1 message head views.

use super::error::Http1ParseError;
use super::fields::{Http1Fields, LineEndError, find_line_end, is_token};
use super::framing::Http1BodyFraming;
use super::framing::framing;

/// A supported HTTP/1 protocol version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http1Version {
    /// HTTP/1.0.
    Http10,
    /// HTTP/1.1.
    Http11,
}

impl Http1Version {
    pub(crate) fn parse(value: &[u8]) -> Option<Self> {
        match value {
            b"HTTP/1.0" => Some(Self::Http10),
            b"HTTP/1.1" => Some(Self::Http11),
            _ => None,
        }
    }

    /// Returns the exact wire spelling.
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Http10 => b"HTTP/1.0",
            Self::Http11 => b"HTTP/1.1",
        }
    }
}

/// A parsed HTTP/1 request head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http1RequestHead<'a> {
    bytes: &'a [u8],
    method: &'a [u8],
    target: &'a [u8],
    version: Http1Version,
    fields: Http1Fields<'a>,
}

impl<'a> Http1RequestHead<'a> {
    /// Parses exactly one complete request head.
    pub fn parse(input: &'a [u8]) -> Result<Self, Http1ParseError> {
        let split = split_head(input)?;
        let first_space = split
            .start_line
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or(Http1ParseError::InvalidStartLine)?;
        let second_space = split.start_line[first_space + 1..]
            .iter()
            .position(|byte| *byte == b' ')
            .map(|offset| first_space + 1 + offset)
            .ok_or(Http1ParseError::InvalidStartLine)?;
        let method = &split.start_line[..first_space];
        let target = &split.start_line[first_space + 1..second_space];
        let version = &split.start_line[second_space + 1..];
        if method.is_empty()
            || !method.iter().copied().all(is_token)
            || !valid_request_target(target)
        {
            return Err(Http1ParseError::InvalidStartLine);
        }
        let version = Http1Version::parse(version).ok_or(Http1ParseError::InvalidStartLine)?;
        let fields = Http1Fields::parse(split.fields, false)?;
        Ok(Self {
            bytes: split.bytes,
            method,
            target,
            version,
            fields,
        })
    }

    pub(crate) fn from_validated(
        bytes: &'a [u8],
        method_end: usize,
        target_end: usize,
        fields_start: usize,
        version: Http1Version,
    ) -> Self {
        Self {
            bytes,
            method: &bytes[..method_end],
            target: &bytes[method_end + 1..target_end],
            version,
            fields: Http1Fields::from_validated(&bytes[fields_start..bytes.len() - 2]),
        }
    }

    /// Returns the complete encoded head, including the terminating blank line.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the encoded head length.
    pub const fn head_len(self) -> usize {
        self.bytes.len()
    }

    /// Returns the raw method.
    pub const fn method(self) -> &'a [u8] {
        self.method
    }

    /// Returns the raw request target.
    pub const fn target(self) -> &'a [u8] {
        self.target
    }

    /// Returns the protocol version.
    pub const fn version(self) -> Http1Version {
        self.version
    }

    /// Returns ordered fields without combining duplicates.
    pub const fn fields(self) -> Http1Fields<'a> {
        self.fields
    }

    /// Determines request-body framing according to RFC 9112.
    pub fn body_framing(self) -> Result<Http1BodyFraming, Http1ParseError> {
        framing(self.fields, true, None, None)
    }
}

/// A parsed HTTP/1 response head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http1ResponseHead<'a> {
    bytes: &'a [u8],
    status: u16,
    reason: &'a [u8],
    version: Http1Version,
    fields: Http1Fields<'a>,
}

impl<'a> Http1ResponseHead<'a> {
    /// Parses exactly one complete response head.
    pub fn parse(input: &'a [u8]) -> Result<Self, Http1ParseError> {
        let split = split_head(input)?;
        let line = split.start_line;
        if line.len() < 13 || line.get(8) != Some(&b' ') || line.get(12) != Some(&b' ') {
            return Err(Http1ParseError::InvalidStartLine);
        }
        let version = Http1Version::parse(&line[..8]).ok_or(Http1ParseError::InvalidStartLine)?;
        let status_bytes = &line[9..12];
        if !status_bytes.iter().all(u8::is_ascii_digit) || !valid_reason(&line[13..]) {
            return Err(Http1ParseError::InvalidStartLine);
        }
        let status = u16::from(status_bytes[0] - b'0') * 100
            + u16::from(status_bytes[1] - b'0') * 10
            + u16::from(status_bytes[2] - b'0');
        let fields = Http1Fields::parse(split.fields, false)?;
        Ok(Self {
            bytes: split.bytes,
            status,
            reason: &line[13..],
            version,
            fields,
        })
    }

    pub(crate) fn from_validated(
        bytes: &'a [u8],
        status: u16,
        reason_start: usize,
        fields_start: usize,
        version: Http1Version,
    ) -> Self {
        Self {
            bytes,
            status,
            reason: &bytes[reason_start..fields_start - 2],
            version,
            fields: Http1Fields::from_validated(&bytes[fields_start..bytes.len() - 2]),
        }
    }

    /// Returns the complete encoded head, including the terminating blank line.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the encoded head length.
    pub const fn head_len(self) -> usize {
        self.bytes.len()
    }

    /// Returns the numeric status code.
    pub const fn status(self) -> u16 {
        self.status
    }

    /// Returns the raw reason phrase.
    pub const fn reason(self) -> &'a [u8] {
        self.reason
    }

    /// Returns the protocol version.
    pub const fn version(self) -> Http1Version {
        self.version
    }

    /// Returns ordered fields without combining duplicates.
    pub const fn fields(self) -> Http1Fields<'a> {
        self.fields
    }

    /// Determines response-body framing using the associated request method when known.
    pub fn body_framing(
        self,
        request_method: Option<&[u8]>,
    ) -> Result<Http1BodyFraming, Http1ParseError> {
        framing(self.fields, false, Some(self.status), request_method)
    }
}

struct SplitHead<'a> {
    bytes: &'a [u8],
    start_line: &'a [u8],
    fields: &'a [u8],
}

fn split_head(input: &[u8]) -> Result<SplitHead<'_>, Http1ParseError> {
    let first_end = map_line_end(input, 0, Http1ParseError::InvalidStartLine)?;
    let fields_start = first_end + 2;
    let mut offset = fields_start;
    loop {
        let end = map_line_end(input, offset, Http1ParseError::InvalidField)?;
        if end == offset {
            return Ok(SplitHead {
                bytes: &input[..end + 2],
                start_line: &input[..first_end],
                fields: &input[fields_start..offset],
            });
        }
        offset = end + 2;
    }
}

fn map_line_end(
    input: &[u8],
    start: usize,
    malformed: Http1ParseError,
) -> Result<usize, Http1ParseError> {
    match find_line_end(input, start) {
        Ok(end) => Ok(end),
        Err(LineEndError::Malformed) => Err(malformed),
        Err(LineEndError::Incomplete) => Err(Http1ParseError::Incomplete {
            required: input.len().saturating_add(1),
            available: input.len(),
        }),
    }
}

pub(crate) fn valid_request_target(target: &[u8]) -> bool {
    !target.is_empty() && !target.iter().any(|byte| *byte <= 0x20 || *byte == 0x7f)
}

pub(crate) fn valid_reason(reason: &[u8]) -> bool {
    !reason
        .iter()
        .any(|byte| matches!(*byte, 0..=8 | 10..=31 | 127))
}
