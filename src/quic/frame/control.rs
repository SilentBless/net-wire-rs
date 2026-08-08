//! RFC 9000 scalar control frame views.

use super::super::varint::QuicVarInt;
use super::parse::{QuicFrameField, QuicFrameParseError};

const MAXIMUM_STREAMS_LIMIT: u64 = 1 << 60;

/// Identifies whether a QUIC stream is bidirectional or unidirectional.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum QuicStreamDirection {
    /// A stream carrying data in both directions.
    Bidirectional,
    /// A stream carrying data in one direction.
    Unidirectional,
}

/// A checked borrowed RFC 9000 MAX_STREAMS frame view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicMaxStreamsFrame<'a> {
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    direction: QuicStreamDirection,
    maximum_streams: QuicVarInt<'a>,
}

impl<'a> QuicMaxStreamsFrame<'a> {
    /// Returns the exact encoded frame bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact encoded frame-type variable integer.
    pub const fn frame_type(self) -> QuicVarInt<'a> {
        self.frame_type
    }

    /// Returns the stream direction selected by the frame type.
    pub const fn direction(self) -> QuicStreamDirection {
        self.direction
    }

    /// Returns the exact encoded maximum-streams variable integer.
    pub const fn maximum_streams(self) -> QuicVarInt<'a> {
        self.maximum_streams
    }
}

/// A checked borrowed RFC 9000 STREAMS_BLOCKED frame view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicStreamsBlockedFrame<'a> {
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    direction: QuicStreamDirection,
    maximum_streams: QuicVarInt<'a>,
}

impl<'a> QuicStreamsBlockedFrame<'a> {
    /// Returns the exact encoded frame bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact encoded frame-type variable integer.
    pub const fn frame_type(self) -> QuicVarInt<'a> {
        self.frame_type
    }

    /// Returns the stream direction selected by the frame type.
    pub const fn direction(self) -> QuicStreamDirection {
        self.direction
    }

    /// Returns the exact encoded maximum-streams variable integer.
    pub const fn maximum_streams(self) -> QuicVarInt<'a> {
        self.maximum_streams
    }
}

/// A checked borrowed RFC 9000 MAX_DATA frame view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicMaxDataFrame<'a> {
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    maximum_data: QuicVarInt<'a>,
}

impl<'a> QuicMaxDataFrame<'a> {
    /// Returns the exact encoded frame bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Returns the exact encoded frame-type variable integer.
    pub const fn frame_type(self) -> QuicVarInt<'a> {
        self.frame_type
    }
    /// Returns the exact encoded maximum-data variable integer.
    pub const fn maximum_data(self) -> QuicVarInt<'a> {
        self.maximum_data
    }
}

/// A checked borrowed RFC 9000 MAX_STREAM_DATA frame view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicMaxStreamDataFrame<'a> {
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    stream_id: QuicVarInt<'a>,
    maximum_stream_data: QuicVarInt<'a>,
}

impl<'a> QuicMaxStreamDataFrame<'a> {
    /// Returns the exact encoded frame bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Returns the exact encoded frame-type variable integer.
    pub const fn frame_type(self) -> QuicVarInt<'a> {
        self.frame_type
    }
    /// Returns the exact encoded stream-ID variable integer.
    pub const fn stream_id(self) -> QuicVarInt<'a> {
        self.stream_id
    }
    /// Returns the exact encoded maximum-stream-data variable integer.
    pub const fn maximum_stream_data(self) -> QuicVarInt<'a> {
        self.maximum_stream_data
    }
}

/// A checked borrowed RFC 9000 DATA_BLOCKED frame view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicDataBlockedFrame<'a> {
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    maximum_data: QuicVarInt<'a>,
}

impl<'a> QuicDataBlockedFrame<'a> {
    /// Returns the exact encoded frame bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Returns the exact encoded frame-type variable integer.
    pub const fn frame_type(self) -> QuicVarInt<'a> {
        self.frame_type
    }
    /// Returns the exact encoded maximum-data variable integer.
    pub const fn maximum_data(self) -> QuicVarInt<'a> {
        self.maximum_data
    }
}

/// A checked borrowed RFC 9000 STREAM_DATA_BLOCKED frame view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicStreamDataBlockedFrame<'a> {
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    stream_id: QuicVarInt<'a>,
    maximum_stream_data: QuicVarInt<'a>,
}

impl<'a> QuicStreamDataBlockedFrame<'a> {
    /// Returns the exact encoded frame bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Returns the exact encoded frame-type variable integer.
    pub const fn frame_type(self) -> QuicVarInt<'a> {
        self.frame_type
    }
    /// Returns the exact encoded stream-ID variable integer.
    pub const fn stream_id(self) -> QuicVarInt<'a> {
        self.stream_id
    }
    /// Returns the exact encoded maximum-stream-data variable integer.
    pub const fn maximum_stream_data(self) -> QuicVarInt<'a> {
        self.maximum_stream_data
    }
}

pub(super) fn parse_max_data<'a>(
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    offset: usize,
) -> Result<(QuicMaxDataFrame<'a>, &'a [u8]), QuicFrameParseError> {
    let input = &bytes[frame_type.byte_len()..];
    let (maximum_data, suffix) = parse_field(
        input,
        offset + frame_type.byte_len(),
        QuicFrameField::MaximumData,
    )?;
    let frame_len = bytes.len() - suffix.len();
    Ok((
        QuicMaxDataFrame {
            bytes: &bytes[..frame_len],
            frame_type,
            maximum_data,
        },
        suffix,
    ))
}

pub(super) fn parse_max_stream_data<'a>(
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    offset: usize,
) -> Result<(QuicMaxStreamDataFrame<'a>, &'a [u8]), QuicFrameParseError> {
    let input = &bytes[frame_type.byte_len()..];
    let (stream_id, input) = parse_field(
        input,
        offset + frame_type.byte_len(),
        QuicFrameField::StreamId,
    )?;
    let (maximum_stream_data, suffix) = parse_field(
        input,
        offset + bytes.len() - input.len(),
        QuicFrameField::MaximumStreamData,
    )?;
    let frame_len = bytes.len() - suffix.len();
    Ok((
        QuicMaxStreamDataFrame {
            bytes: &bytes[..frame_len],
            frame_type,
            stream_id,
            maximum_stream_data,
        },
        suffix,
    ))
}

pub(super) fn parse_data_blocked<'a>(
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    offset: usize,
) -> Result<(QuicDataBlockedFrame<'a>, &'a [u8]), QuicFrameParseError> {
    let input = &bytes[frame_type.byte_len()..];
    let (maximum_data, suffix) = parse_field(
        input,
        offset + frame_type.byte_len(),
        QuicFrameField::MaximumData,
    )?;
    let frame_len = bytes.len() - suffix.len();
    Ok((
        QuicDataBlockedFrame {
            bytes: &bytes[..frame_len],
            frame_type,
            maximum_data,
        },
        suffix,
    ))
}

pub(super) fn parse_max_streams<'a>(
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    offset: usize,
    direction: QuicStreamDirection,
) -> Result<(QuicMaxStreamsFrame<'a>, &'a [u8]), QuicFrameParseError> {
    let (maximum_streams, suffix) = parse_maximum_streams(bytes, frame_type, offset)?;
    let frame_len = bytes.len() - suffix.len();
    Ok((
        QuicMaxStreamsFrame {
            bytes: &bytes[..frame_len],
            frame_type,
            direction,
            maximum_streams,
        },
        suffix,
    ))
}

pub(super) fn parse_streams_blocked<'a>(
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    offset: usize,
    direction: QuicStreamDirection,
) -> Result<(QuicStreamsBlockedFrame<'a>, &'a [u8]), QuicFrameParseError> {
    let (maximum_streams, suffix) = parse_maximum_streams(bytes, frame_type, offset)?;
    let frame_len = bytes.len() - suffix.len();
    Ok((
        QuicStreamsBlockedFrame {
            bytes: &bytes[..frame_len],
            frame_type,
            direction,
            maximum_streams,
        },
        suffix,
    ))
}

pub(super) fn parse_stream_data_blocked<'a>(
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    offset: usize,
) -> Result<(QuicStreamDataBlockedFrame<'a>, &'a [u8]), QuicFrameParseError> {
    let input = &bytes[frame_type.byte_len()..];
    let (stream_id, input) = parse_field(
        input,
        offset + frame_type.byte_len(),
        QuicFrameField::StreamId,
    )?;
    let (maximum_stream_data, suffix) = parse_field(
        input,
        offset + bytes.len() - input.len(),
        QuicFrameField::MaximumStreamData,
    )?;
    let frame_len = bytes.len() - suffix.len();
    Ok((
        QuicStreamDataBlockedFrame {
            bytes: &bytes[..frame_len],
            frame_type,
            stream_id,
            maximum_stream_data,
        },
        suffix,
    ))
}

/// A checked borrowed RFC 9000 RESET_STREAM frame view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicResetStreamFrame<'a> {
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    stream_id: QuicVarInt<'a>,
    application_error_code: QuicVarInt<'a>,
    final_size: QuicVarInt<'a>,
}

impl<'a> QuicResetStreamFrame<'a> {
    /// Returns the exact encoded frame bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact encoded frame-type variable integer.
    pub const fn frame_type(self) -> QuicVarInt<'a> {
        self.frame_type
    }

    /// Returns the exact encoded stream-ID variable integer.
    pub const fn stream_id(self) -> QuicVarInt<'a> {
        self.stream_id
    }

    /// Returns the exact encoded application-error-code variable integer.
    pub const fn application_error_code(self) -> QuicVarInt<'a> {
        self.application_error_code
    }

    /// Returns the exact encoded final-size variable integer.
    pub const fn final_size(self) -> QuicVarInt<'a> {
        self.final_size
    }
}

/// A checked borrowed RFC 9000 STOP_SENDING frame view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicStopSendingFrame<'a> {
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    stream_id: QuicVarInt<'a>,
    application_error_code: QuicVarInt<'a>,
}

impl<'a> QuicStopSendingFrame<'a> {
    /// Returns the exact encoded frame bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact encoded frame-type variable integer.
    pub const fn frame_type(self) -> QuicVarInt<'a> {
        self.frame_type
    }

    /// Returns the exact encoded stream-ID variable integer.
    pub const fn stream_id(self) -> QuicVarInt<'a> {
        self.stream_id
    }

    /// Returns the exact encoded application-error-code variable integer.
    pub const fn application_error_code(self) -> QuicVarInt<'a> {
        self.application_error_code
    }
}

pub(super) fn parse_reset_stream<'a>(
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    offset: usize,
) -> Result<(QuicResetStreamFrame<'a>, &'a [u8]), QuicFrameParseError> {
    let input = &bytes[frame_type.byte_len()..];
    let (stream_id, input) = parse_field(
        input,
        offset + frame_type.byte_len(),
        QuicFrameField::StreamId,
    )?;
    let (application_error_code, input) = parse_field(
        input,
        offset + bytes.len() - input.len(),
        QuicFrameField::ApplicationErrorCode,
    )?;
    let (final_size, suffix) = parse_field(
        input,
        offset + bytes.len() - input.len(),
        QuicFrameField::FinalSize,
    )?;
    let frame_len = bytes.len() - suffix.len();
    Ok((
        QuicResetStreamFrame {
            bytes: &bytes[..frame_len],
            frame_type,
            stream_id,
            application_error_code,
            final_size,
        },
        suffix,
    ))
}

pub(super) fn parse_stop_sending<'a>(
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    offset: usize,
) -> Result<(QuicStopSendingFrame<'a>, &'a [u8]), QuicFrameParseError> {
    let input = &bytes[frame_type.byte_len()..];
    let (stream_id, input) = parse_field(
        input,
        offset + frame_type.byte_len(),
        QuicFrameField::StreamId,
    )?;
    let (application_error_code, suffix) = parse_field(
        input,
        offset + bytes.len() - input.len(),
        QuicFrameField::ApplicationErrorCode,
    )?;
    let frame_len = bytes.len() - suffix.len();
    Ok((
        QuicStopSendingFrame {
            bytes: &bytes[..frame_len],
            frame_type,
            stream_id,
            application_error_code,
        },
        suffix,
    ))
}

fn parse_field<'a>(
    input: &'a [u8],
    offset: usize,
    field: QuicFrameField,
) -> Result<(QuicVarInt<'a>, &'a [u8]), QuicFrameParseError> {
    let value = QuicVarInt::parse(input).map_err(|error| QuicFrameParseError::Field {
        field,
        offset,
        error,
    })?;
    Ok((value, &input[value.byte_len()..]))
}

fn parse_maximum_streams<'a>(
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    offset: usize,
) -> Result<(QuicVarInt<'a>, &'a [u8]), QuicFrameParseError> {
    let field_offset = offset + frame_type.byte_len();
    let (maximum_streams, suffix) = parse_field(
        &bytes[frame_type.byte_len()..],
        field_offset,
        QuicFrameField::MaximumStreams,
    )?;
    if maximum_streams.value() > MAXIMUM_STREAMS_LIMIT {
        return Err(QuicFrameParseError::FieldValueOutOfRange {
            field: QuicFrameField::MaximumStreams,
            offset: field_offset,
            value: maximum_streams.value(),
            maximum: MAXIMUM_STREAMS_LIMIT,
        });
    }
    Ok((maximum_streams, suffix))
}
