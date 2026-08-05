//! RFC 9000 PATH_CHALLENGE and PATH_RESPONSE frame parsing.

use super::super::{QuicFrameField, QuicFrameParseError, QuicVarInt};

/// A checked borrowed RFC 9000 PATH_CHALLENGE frame view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicPathChallengeFrame<'a> {
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    data: &'a [u8; 8],
}

impl<'a> QuicPathChallengeFrame<'a> {
    /// Returns the exact encoded frame bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact encoded frame-type variable integer.
    pub const fn frame_type(self) -> QuicVarInt<'a> {
        self.frame_type
    }

    /// Returns the opaque path-validation data.
    pub const fn data(self) -> &'a [u8; 8] {
        self.data
    }
}

/// A checked borrowed RFC 9000 PATH_RESPONSE frame view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicPathResponseFrame<'a> {
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    data: &'a [u8; 8],
}

impl<'a> QuicPathResponseFrame<'a> {
    /// Returns the exact encoded frame bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact encoded frame-type variable integer.
    pub const fn frame_type(self) -> QuicVarInt<'a> {
        self.frame_type
    }

    /// Returns the opaque path-validation data.
    pub const fn data(self) -> &'a [u8; 8] {
        self.data
    }
}

pub(super) fn parse_path_challenge<'a>(
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    offset: usize,
) -> Result<(QuicPathChallengeFrame<'a>, &'a [u8]), QuicFrameParseError> {
    let parsed = parse_path_data(bytes, frame_type, offset)?;
    Ok((
        QuicPathChallengeFrame {
            bytes: parsed.bytes,
            frame_type,
            data: parsed.data,
        },
        parsed.suffix,
    ))
}

pub(super) fn parse_path_response<'a>(
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    offset: usize,
) -> Result<(QuicPathResponseFrame<'a>, &'a [u8]), QuicFrameParseError> {
    let parsed = parse_path_data(bytes, frame_type, offset)?;
    Ok((
        QuicPathResponseFrame {
            bytes: parsed.bytes,
            frame_type,
            data: parsed.data,
        },
        parsed.suffix,
    ))
}

struct ParsedPathData<'a> {
    bytes: &'a [u8],
    data: &'a [u8; 8],
    suffix: &'a [u8],
}

fn parse_path_data<'a>(
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    offset: usize,
) -> Result<ParsedPathData<'a>, QuicFrameParseError> {
    let data_start = frame_type.byte_len();
    let input = &bytes[data_start..];
    let Some((data, suffix)) = input.split_first_chunk::<8>() else {
        return Err(QuicFrameParseError::IncompleteBytes {
            field: QuicFrameField::PathData,
            offset: offset + data_start,
            required: 8,
            available: input.len(),
        });
    };
    let frame_len = bytes.len() - suffix.len();
    Ok(ParsedPathData {
        bytes: &bytes[..frame_len],
        data,
        suffix,
    })
}
