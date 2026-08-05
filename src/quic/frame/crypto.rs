//! RFC 9000 CRYPTO frame parsing.

use super::super::{QuicFrameField, QuicFrameParseError, QuicVarInt};

const MAX_CRYPTO_RANGE_END: u64 = (1 << 62) - 1;

/// A checked borrowed RFC 9000 CRYPTO frame view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicCryptoFrame<'a> {
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    offset: QuicVarInt<'a>,
    length: QuicVarInt<'a>,
    crypto_data: &'a [u8],
}

impl<'a> QuicCryptoFrame<'a> {
    /// Returns the exact encoded frame bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact encoded frame-type variable integer.
    pub const fn frame_type(self) -> QuicVarInt<'a> {
        self.frame_type
    }

    /// Returns the exact encoded CRYPTO offset variable integer.
    pub const fn offset(self) -> QuicVarInt<'a> {
        self.offset
    }

    /// Returns the exact encoded CRYPTO data-length variable integer.
    pub const fn length(self) -> QuicVarInt<'a> {
        self.length
    }

    /// Returns the exact borrowed CRYPTO data bytes, which may be empty.
    pub const fn crypto_data(self) -> &'a [u8] {
        self.crypto_data
    }
}

pub(super) fn parse_crypto<'a>(
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    offset: usize,
) -> Result<(QuicCryptoFrame<'a>, &'a [u8]), QuicFrameParseError> {
    let offset_start = frame_type.byte_len();
    let offset_offset = offset + offset_start;
    let crypto_offset =
        QuicVarInt::parse(&bytes[offset_start..]).map_err(|error| QuicFrameParseError::Field {
            field: QuicFrameField::CryptoOffset,
            offset: offset_offset,
            error,
        })?;

    let length_start = offset_start + crypto_offset.byte_len();
    let length_offset = offset + length_start;
    let length =
        QuicVarInt::parse(&bytes[length_start..]).map_err(|error| QuicFrameParseError::Field {
            field: QuicFrameField::CryptoLength,
            offset: length_offset,
            error,
        })?;

    let range_end = crypto_offset.value().checked_add(length.value());
    if range_end.is_none_or(|end| end > MAX_CRYPTO_RANGE_END) {
        return Err(QuicFrameParseError::FieldRangeOutOfRange {
            field: QuicFrameField::CryptoOffset,
            offset: offset_offset,
            start: crypto_offset.value(),
            length: length.value(),
            maximum: MAX_CRYPTO_RANGE_END,
        });
    }

    let length_value = length.value();
    let length_usize =
        usize::try_from(length_value).map_err(|_| QuicFrameParseError::LengthNotRepresentable {
            field: QuicFrameField::CryptoLength,
            offset: length_offset,
            value: length_value,
        })?;
    // Each parsed variable integer is at most eight bytes wide.
    let data_start = length_start + length.byte_len();
    let data_offset = offset + data_start;
    let data_end =
        data_start
            .checked_add(length_usize)
            .ok_or(QuicFrameParseError::LengthOverflow {
                field: QuicFrameField::CryptoData,
                offset: data_offset,
                length: length_usize,
            })?;
    let available = bytes.len() - data_start;
    if available < length_usize {
        return Err(QuicFrameParseError::IncompleteBytes {
            field: QuicFrameField::CryptoData,
            offset: data_offset,
            required: length_usize,
            available,
        });
    }

    Ok((
        QuicCryptoFrame {
            bytes: &bytes[..data_end],
            frame_type,
            offset: crypto_offset,
            length,
            crypto_data: &bytes[data_start..data_end],
        },
        &bytes[data_end..],
    ))
}
