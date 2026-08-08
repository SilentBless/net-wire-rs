//! RFC 9000 STREAM frame parsing.

use super::super::varint::QuicVarInt;
use super::parse::{QuicFrameField, QuicFrameParseError};

const MAX_STREAM_RANGE_END: u64 = (1 << 62) - 1;

/// A checked borrowed RFC 9000 STREAM frame view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicStreamFrame<'a> {
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    stream_id: QuicVarInt<'a>,
    offset: Option<QuicVarInt<'a>>,
    length: Option<QuicVarInt<'a>>,
    stream_data: &'a [u8],
}

impl<'a> QuicStreamFrame<'a> {
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

    /// Returns the exact encoded offset when the OFF bit is present.
    ///
    /// `None` means the effective stream offset is zero.
    pub const fn offset(self) -> Option<QuicVarInt<'a>> {
        self.offset
    }

    /// Returns the exact encoded data length when the LEN bit is present.
    ///
    /// `None` means stream data consumes the remaining supplied frame-sequence bytes.
    pub const fn length(self) -> Option<QuicVarInt<'a>> {
        self.length
    }

    /// Returns the exact borrowed STREAM data bytes, which may be empty.
    pub const fn stream_data(self) -> &'a [u8] {
        self.stream_data
    }

    /// Returns whether the FIN bit is set in the frame type.
    pub const fn fin(self) -> bool {
        self.frame_type.value() & 0x01 != 0
    }
}

pub(super) fn parse_stream<'a>(
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    offset: usize,
) -> Result<(QuicStreamFrame<'a>, &'a [u8]), QuicFrameParseError> {
    let flags = frame_type.value();
    let has_offset = flags & 0x04 != 0;
    let has_length = flags & 0x02 != 0;

    let stream_id_start = frame_type.byte_len();
    let stream_id_offset = offset + stream_id_start;
    let stream_id = QuicVarInt::parse(&bytes[stream_id_start..]).map_err(|error| {
        QuicFrameParseError::Field {
            field: QuicFrameField::StreamId,
            offset: stream_id_offset,
            error,
        }
    })?;

    let mut data_start = stream_id_start + stream_id.byte_len();
    // For an implicit offset, this is the first byte after Stream ID, where zero applies.
    let range_offset = offset + data_start;
    let stream_offset = if has_offset {
        let field_offset = offset + data_start;
        let value = QuicVarInt::parse(&bytes[data_start..]).map_err(|error| {
            QuicFrameParseError::Field {
                field: QuicFrameField::StreamOffset,
                offset: field_offset,
                error,
            }
        })?;
        data_start += value.byte_len();
        Some(value)
    } else {
        None
    };

    let length = if has_length {
        let field_offset = offset + data_start;
        let value = QuicVarInt::parse(&bytes[data_start..]).map_err(|error| {
            QuicFrameParseError::Field {
                field: QuicFrameField::StreamLength,
                offset: field_offset,
                error,
            }
        })?;
        data_start += value.byte_len();
        Some((value, field_offset))
    } else {
        None
    };

    let start = stream_offset.map_or(0, QuicVarInt::value);
    let data_offset = offset + data_start;
    let (length_varint, data_end) = match length {
        Some((length, length_offset)) => {
            let data_length = length.value();
            validate_range(start, data_length, range_offset)?;
            let length_usize = usize::try_from(data_length).map_err(|_| {
                QuicFrameParseError::LengthNotRepresentable {
                    field: QuicFrameField::StreamLength,
                    offset: length_offset,
                    value: data_length,
                }
            })?;
            let data_end = data_start.checked_add(length_usize).ok_or(
                QuicFrameParseError::LengthOverflow {
                    field: QuicFrameField::StreamData,
                    offset: data_offset,
                    length: length_usize,
                },
            )?;
            let available = bytes.len() - data_start;
            if available < length_usize {
                return Err(QuicFrameParseError::IncompleteBytes {
                    field: QuicFrameField::StreamData,
                    offset: data_offset,
                    required: length_usize,
                    available,
                });
            }
            (Some(length), data_end)
        }
        None => {
            let data_end = bytes.len();
            // Rust supports no target where usize is wider than u64; preserve the
            // conversion site so that this cannot silently become truncating there.
            let data_length = match u64::try_from(data_end - data_start) {
                Ok(value) => value,
                Err(_) => {
                    return Err(QuicFrameParseError::ImplicitLengthNotRepresentable {
                        field: QuicFrameField::StreamData,
                        offset: data_offset,
                        length: data_end - data_start,
                    });
                }
            };
            validate_range(start, data_length, range_offset)?;
            (None, data_end)
        }
    };

    Ok((
        QuicStreamFrame {
            bytes: &bytes[..data_end],
            frame_type,
            stream_id,
            offset: stream_offset,
            length: length_varint,
            stream_data: &bytes[data_start..data_end],
        },
        &bytes[data_end..],
    ))
}

fn validate_range(start: u64, length: u64, offset: usize) -> Result<(), QuicFrameParseError> {
    if start
        .checked_add(length)
        .is_none_or(|end| end > MAX_STREAM_RANGE_END)
    {
        return Err(QuicFrameParseError::FieldRangeOutOfRange {
            field: QuicFrameField::StreamOffset,
            offset,
            start,
            length,
            maximum: MAX_STREAM_RANGE_END,
        });
    }
    Ok(())
}
