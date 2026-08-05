//! RFC 9000 CONNECTION_CLOSE frame parsing.

use super::super::{QuicFrameField, QuicFrameParseError, QuicVarInt};

/// A checked borrowed RFC 9000 CONNECTION_CLOSE frame view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicConnectionCloseFrame<'a> {
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    error_code: QuicVarInt<'a>,
    triggering_frame_type: Option<QuicVarInt<'a>>,
    reason_phrase_length: QuicVarInt<'a>,
    reason_phrase: &'a [u8],
}

impl<'a> QuicConnectionCloseFrame<'a> {
    /// Returns the exact encoded frame bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact encoded frame-type variable integer.
    pub const fn frame_type(self) -> QuicVarInt<'a> {
        self.frame_type
    }

    /// Returns the exact encoded error-code variable integer.
    pub const fn error_code(self) -> QuicVarInt<'a> {
        self.error_code
    }

    /// Returns the triggering frame type for a transport close, if present.
    pub const fn triggering_frame_type(self) -> Option<QuicVarInt<'a>> {
        self.triggering_frame_type
    }

    /// Returns the exact encoded reason-phrase-length variable integer.
    pub const fn reason_phrase_length(self) -> QuicVarInt<'a> {
        self.reason_phrase_length
    }

    /// Returns the exact opaque reason-phrase bytes, which may be empty.
    pub const fn reason_phrase(self) -> &'a [u8] {
        self.reason_phrase
    }
}

pub(super) fn parse_connection_close<'a>(
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    offset: usize,
) -> Result<(QuicConnectionCloseFrame<'a>, &'a [u8]), QuicFrameParseError> {
    let mut start = frame_type.byte_len();
    let error_code = parse_field(
        bytes,
        start,
        offset,
        QuicFrameField::ConnectionCloseErrorCode,
    )?;
    start += error_code.byte_len();

    let triggering_frame_type = if frame_type.value() == 0x1c {
        let triggering_frame_type =
            parse_field(bytes, start, offset, QuicFrameField::TriggeringFrameType)?;
        start += triggering_frame_type.byte_len();
        Some(triggering_frame_type)
    } else {
        None
    };

    let reason_phrase_length =
        parse_field(bytes, start, offset, QuicFrameField::ReasonPhraseLength)?;
    start += reason_phrase_length.byte_len();
    let reason_length_value = reason_phrase_length.value();
    let reason_length = usize::try_from(reason_length_value).map_err(|_| {
        QuicFrameParseError::LengthNotRepresentable {
            field: QuicFrameField::ReasonPhraseLength,
            offset: offset + start - reason_phrase_length.byte_len(),
            value: reason_length_value,
        }
    })?;
    let reason_offset = offset + start;
    let end = start
        .checked_add(reason_length)
        .ok_or(QuicFrameParseError::LengthOverflow {
            field: QuicFrameField::ReasonPhrase,
            offset: reason_offset,
            length: reason_length,
        })?;
    let available = bytes.len() - start;
    if available < reason_length {
        return Err(QuicFrameParseError::IncompleteBytes {
            field: QuicFrameField::ReasonPhrase,
            offset: reason_offset,
            required: reason_length,
            available,
        });
    }

    Ok((
        QuicConnectionCloseFrame {
            bytes: &bytes[..end],
            frame_type,
            error_code,
            triggering_frame_type,
            reason_phrase_length,
            reason_phrase: &bytes[start..end],
        },
        &bytes[end..],
    ))
}

fn parse_field<'a>(
    bytes: &'a [u8],
    start: usize,
    offset: usize,
    field: QuicFrameField,
) -> Result<QuicVarInt<'a>, QuicFrameParseError> {
    QuicVarInt::parse(&bytes[start..]).map_err(|error| QuicFrameParseError::Field {
        field,
        offset: offset + start,
        error,
    })
}
