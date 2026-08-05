//! RFC 9000 NEW_CONNECTION_ID and RETIRE_CONNECTION_ID frame parsing.

use super::super::{QuicConnectionId, QuicFrameField, QuicFrameParseError, QuicVarInt};

const STATELESS_RESET_TOKEN_LEN: usize = 16;
const MAX_CONNECTION_ID_LEN: u8 = 20;

/// A checked borrowed RFC 9000 NEW_CONNECTION_ID frame view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicNewConnectionIdFrame<'a> {
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    sequence_number: QuicVarInt<'a>,
    retire_prior_to: QuicVarInt<'a>,
    connection_id_length: u8,
    connection_id: QuicConnectionId<'a>,
    stateless_reset_token: &'a [u8; STATELESS_RESET_TOKEN_LEN],
}

impl<'a> QuicNewConnectionIdFrame<'a> {
    /// Returns the exact encoded frame bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact encoded frame-type variable integer.
    pub const fn frame_type(self) -> QuicVarInt<'a> {
        self.frame_type
    }

    /// Returns the exact encoded sequence-number variable integer.
    pub const fn sequence_number(self) -> QuicVarInt<'a> {
        self.sequence_number
    }

    /// Returns the exact encoded retire-prior-to variable integer.
    pub const fn retire_prior_to(self) -> QuicVarInt<'a> {
        self.retire_prior_to
    }

    /// Returns the decoded connection-ID length byte.
    pub const fn connection_id_length(self) -> u8 {
        self.connection_id_length
    }

    /// Returns the nonempty opaque connection ID.
    pub const fn connection_id(self) -> QuicConnectionId<'a> {
        self.connection_id
    }

    /// Returns the stateless reset token.
    pub const fn stateless_reset_token(self) -> &'a [u8; STATELESS_RESET_TOKEN_LEN] {
        self.stateless_reset_token
    }
}

/// A checked borrowed RFC 9000 RETIRE_CONNECTION_ID frame view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicRetireConnectionIdFrame<'a> {
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    sequence_number: QuicVarInt<'a>,
}

impl<'a> QuicRetireConnectionIdFrame<'a> {
    /// Returns the exact encoded frame bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact encoded frame-type variable integer.
    pub const fn frame_type(self) -> QuicVarInt<'a> {
        self.frame_type
    }

    /// Returns the exact encoded sequence-number variable integer.
    pub const fn sequence_number(self) -> QuicVarInt<'a> {
        self.sequence_number
    }
}

pub(super) fn parse_new_connection_id<'a>(
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    offset: usize,
) -> Result<(QuicNewConnectionIdFrame<'a>, &'a [u8]), QuicFrameParseError> {
    let sequence_start = frame_type.byte_len();
    let sequence_offset = offset + sequence_start;
    let sequence_number = QuicVarInt::parse(&bytes[sequence_start..]).map_err(|error| {
        QuicFrameParseError::Field {
            field: QuicFrameField::SequenceNumber,
            offset: sequence_offset,
            error,
        }
    })?;

    let retire_start = sequence_start + sequence_number.byte_len();
    let retire_offset = offset + retire_start;
    let retire_prior_to =
        QuicVarInt::parse(&bytes[retire_start..]).map_err(|error| QuicFrameParseError::Field {
            field: QuicFrameField::RetirePriorTo,
            offset: retire_offset,
            error,
        })?;

    if retire_prior_to.value() > sequence_number.value() {
        return Err(QuicFrameParseError::FieldValueExceedsField {
            field: QuicFrameField::RetirePriorTo,
            offset: retire_offset,
            value: retire_prior_to.value(),
            maximum_field: QuicFrameField::SequenceNumber,
            maximum: sequence_number.value(),
        });
    }

    let connection_id_length_start = retire_start + retire_prior_to.byte_len();
    let connection_id_length_offset = offset + connection_id_length_start;
    let Some(&connection_id_length) = bytes.get(connection_id_length_start) else {
        return Err(QuicFrameParseError::IncompleteBytes {
            field: QuicFrameField::ConnectionIdLength,
            offset: connection_id_length_offset,
            required: 1,
            available: 0,
        });
    };
    if connection_id_length > MAX_CONNECTION_ID_LEN {
        return Err(QuicFrameParseError::FieldValueOutOfRange {
            field: QuicFrameField::ConnectionIdLength,
            offset: connection_id_length_offset,
            value: u64::from(connection_id_length),
            maximum: u64::from(MAX_CONNECTION_ID_LEN),
        });
    }

    let connection_id_start = connection_id_length_start + 1;
    let connection_id_offset = offset + connection_id_start;
    let connection_id_len = usize::from(connection_id_length);
    if connection_id_len == 0 {
        return Err(QuicFrameParseError::EmptyField {
            field: QuicFrameField::ConnectionId,
            offset: connection_id_offset,
        });
    }
    let connection_id_end = connection_id_start.checked_add(connection_id_len).ok_or(
        QuicFrameParseError::LengthOverflow {
            field: QuicFrameField::ConnectionId,
            offset: connection_id_offset,
            length: connection_id_len,
        },
    )?;
    let connection_id_input = &bytes[connection_id_start..];
    if connection_id_input.len() < connection_id_len {
        return Err(QuicFrameParseError::IncompleteBytes {
            field: QuicFrameField::ConnectionId,
            offset: connection_id_offset,
            required: connection_id_len,
            available: connection_id_input.len(),
        });
    }

    let stateless_reset_token_offset = offset + connection_id_end;
    let token_input = &bytes[connection_id_end..];
    let Some((stateless_reset_token, suffix)) =
        token_input.split_first_chunk::<STATELESS_RESET_TOKEN_LEN>()
    else {
        return Err(QuicFrameParseError::IncompleteBytes {
            field: QuicFrameField::StatelessResetToken,
            offset: stateless_reset_token_offset,
            required: STATELESS_RESET_TOKEN_LEN,
            available: token_input.len(),
        });
    };
    let frame_len = bytes.len() - suffix.len();

    Ok((
        QuicNewConnectionIdFrame {
            bytes: &bytes[..frame_len],
            frame_type,
            sequence_number,
            retire_prior_to,
            connection_id_length,
            connection_id: QuicConnectionId::new(&bytes[connection_id_start..connection_id_end]),
            stateless_reset_token,
        },
        suffix,
    ))
}

pub(super) fn parse_retire_connection_id<'a>(
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    offset: usize,
) -> Result<(QuicRetireConnectionIdFrame<'a>, &'a [u8]), QuicFrameParseError> {
    let sequence_start = frame_type.byte_len();
    let sequence_number = QuicVarInt::parse(&bytes[sequence_start..]).map_err(|error| {
        QuicFrameParseError::Field {
            field: QuicFrameField::SequenceNumber,
            offset: offset + sequence_start,
            error,
        }
    })?;
    let frame_len = sequence_start + sequence_number.byte_len();

    Ok((
        QuicRetireConnectionIdFrame {
            bytes: &bytes[..frame_len],
            frame_type,
            sequence_number,
        },
        &bytes[frame_len..],
    ))
}
