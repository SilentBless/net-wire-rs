//! RFC 9000 NEW_TOKEN frame parsing.

use super::super::{QuicFrameField, QuicFrameParseError, QuicVarInt};

/// A checked borrowed RFC 9000 NEW_TOKEN frame view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicNewTokenFrame<'a> {
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    token_length: QuicVarInt<'a>,
    token: &'a [u8],
}

impl<'a> QuicNewTokenFrame<'a> {
    /// Returns the exact encoded frame bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact encoded frame-type variable integer.
    pub const fn frame_type(self) -> QuicVarInt<'a> {
        self.frame_type
    }

    /// Returns the exact encoded token-length variable integer.
    pub const fn token_length(self) -> QuicVarInt<'a> {
        self.token_length
    }

    /// Returns the nonempty opaque token bytes.
    pub const fn token(self) -> &'a [u8] {
        self.token
    }
}

pub(super) fn parse_new_token<'a>(
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    offset: usize,
) -> Result<(QuicNewTokenFrame<'a>, &'a [u8]), QuicFrameParseError> {
    let frame_type_len = frame_type.byte_len();
    let token_length_offset = offset + frame_type_len;
    let token_length = QuicVarInt::parse(&bytes[frame_type_len..]).map_err(|error| {
        QuicFrameParseError::Field {
            field: QuicFrameField::TokenLength,
            offset: token_length_offset,
            error,
        }
    })?;
    let token_length_value = token_length.value();
    let token_length_usize = usize::try_from(token_length_value).map_err(|_| {
        QuicFrameParseError::LengthNotRepresentable {
            field: QuicFrameField::TokenLength,
            offset: token_length_offset,
            value: token_length_value,
        }
    })?;
    let token_start = frame_type_len + token_length.byte_len();
    let token_offset = token_length_offset + token_length.byte_len();

    if token_length_usize == 0 {
        return Err(QuicFrameParseError::EmptyField {
            field: QuicFrameField::Token,
            offset: token_offset,
        });
    }

    let token_end =
        token_start
            .checked_add(token_length_usize)
            .ok_or(QuicFrameParseError::LengthOverflow {
                field: QuicFrameField::Token,
                offset: token_offset,
                length: token_length_usize,
            })?;
    let available = bytes.len() - token_start;
    if available < token_length_usize {
        return Err(QuicFrameParseError::IncompleteBytes {
            field: QuicFrameField::Token,
            offset: token_offset,
            required: token_length_usize,
            available,
        });
    }

    Ok((
        QuicNewTokenFrame {
            bytes: &bytes[..token_end],
            frame_type,
            token_length,
            token: &bytes[token_start..token_end],
        },
        &bytes[token_end..],
    ))
}
