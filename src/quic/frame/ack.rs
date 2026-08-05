//! RFC 9000 ACK and ACK_ECN frame parsing.

use core::iter::FusedIterator;

use super::super::{QuicFrameField, QuicFrameParseError, QuicVarInt};

/// A checked borrowed RFC 9000 ACK or ACK_ECN frame view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicAckFrame<'a> {
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    largest_acknowledged: QuicVarInt<'a>,
    ack_delay: QuicVarInt<'a>,
    ack_range_count: QuicVarInt<'a>,
    first_ack_range: QuicVarInt<'a>,
    first_smallest_acknowledged: u64,
    ranges: &'a [u8],
    ranges_offset: usize,
    ecn_counts: Option<QuicEcnCounts<'a>>,
}

impl<'a> QuicAckFrame<'a> {
    /// Returns the exact encoded frame bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact encoded frame-type variable integer.
    pub const fn frame_type(self) -> QuicVarInt<'a> {
        self.frame_type
    }

    /// Returns the exact encoded largest-acknowledged variable integer.
    pub const fn largest_acknowledged(self) -> QuicVarInt<'a> {
        self.largest_acknowledged
    }

    /// Returns the exact encoded ACK-delay variable integer.
    pub const fn ack_delay(self) -> QuicVarInt<'a> {
        self.ack_delay
    }

    /// Returns the exact encoded additional ACK-range count variable integer.
    pub const fn ack_range_count(self) -> QuicVarInt<'a> {
        self.ack_range_count
    }

    /// Returns the exact encoded first ACK-range variable integer.
    pub const fn first_ack_range(self) -> QuicVarInt<'a> {
        self.first_ack_range
    }

    /// Returns the decoded smallest packet number in the first ACK range.
    pub const fn first_smallest_acknowledged(self) -> u64 {
        self.first_smallest_acknowledged
    }

    /// Returns a fresh iterator over additional ACK ranges in wire order.
    pub const fn ranges(self) -> QuicAckRanges<'a> {
        QuicAckRanges {
            remaining: self.ranges,
            remaining_count: self.ack_range_count.value(),
            previous_smallest: self.first_smallest_acknowledged,
            offset: self.ranges_offset,
            failed: false,
        }
    }

    /// Returns exact ECN count fields for an ACK_ECN frame.
    pub const fn ecn_counts(self) -> Option<QuicEcnCounts<'a>> {
        self.ecn_counts
    }
}

/// One checked additional ACK range in an ACK or ACK_ECN frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicAckRange<'a> {
    bytes: &'a [u8],
    gap: QuicVarInt<'a>,
    ack_range_length: QuicVarInt<'a>,
    largest_acknowledged: u64,
    smallest_acknowledged: u64,
}

impl<'a> QuicAckRange<'a> {
    /// Returns the exact encoded Gap and ACK Range Length bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact encoded Gap variable integer.
    pub const fn gap(self) -> QuicVarInt<'a> {
        self.gap
    }

    /// Returns the exact encoded ACK Range Length variable integer.
    pub const fn ack_range_length(self) -> QuicVarInt<'a> {
        self.ack_range_length
    }

    /// Returns the decoded largest packet number in this ACK range.
    pub const fn largest_acknowledged(self) -> u64 {
        self.largest_acknowledged
    }

    /// Returns the decoded smallest packet number in this ACK range.
    pub const fn smallest_acknowledged(self) -> u64 {
        self.smallest_acknowledged
    }
}

/// A fused iterator over checked additional ACK ranges.
#[derive(Clone, Debug)]
pub struct QuicAckRanges<'a> {
    remaining: &'a [u8],
    remaining_count: u64,
    previous_smallest: u64,
    offset: usize,
    failed: bool,
}

impl<'a> Iterator for QuicAckRanges<'a> {
    type Item = QuicAckRange<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.remaining_count == 0 {
            return None;
        }
        let parsed = match parse_range(self.remaining, self.previous_smallest, self.offset) {
            Ok(range) => range,
            Err(_) => {
                self.failed = true;
                self.remaining_count = 0;
                return None;
            }
        };
        self.remaining = &self.remaining[parsed.bytes.len()..];
        self.remaining_count -= 1;
        self.previous_smallest = parsed.smallest_acknowledged;
        self.offset += parsed.bytes.len();
        Some(parsed)
    }
}

impl FusedIterator for QuicAckRanges<'_> {}

/// Exact ECN count fields carried by an RFC 9000 ACK_ECN frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicEcnCounts<'a> {
    bytes: &'a [u8],
    ect0_count: QuicVarInt<'a>,
    ect1_count: QuicVarInt<'a>,
    ecn_ce_count: QuicVarInt<'a>,
}

impl<'a> QuicEcnCounts<'a> {
    /// Returns the exact encoded ECN count bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact encoded ECT(0) count variable integer.
    pub const fn ect0_count(self) -> QuicVarInt<'a> {
        self.ect0_count
    }

    /// Returns the exact encoded ECT(1) count variable integer.
    pub const fn ect1_count(self) -> QuicVarInt<'a> {
        self.ect1_count
    }

    /// Returns the exact encoded ECN-CE count variable integer.
    pub const fn ecn_ce_count(self) -> QuicVarInt<'a> {
        self.ecn_ce_count
    }
}

pub(super) fn parse_ack<'a>(
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
    offset: usize,
) -> Result<(QuicAckFrame<'a>, &'a [u8]), QuicFrameParseError> {
    let mut cursor = frame_type.byte_len();
    let largest_acknowledged =
        parse_field(bytes, cursor, offset, QuicFrameField::LargestAcknowledged)?;
    cursor += largest_acknowledged.byte_len();
    let ack_delay = parse_field(bytes, cursor, offset, QuicFrameField::AckDelay)?;
    cursor += ack_delay.byte_len();
    let ack_range_count = parse_field(bytes, cursor, offset, QuicFrameField::AckRangeCount)?;
    cursor += ack_range_count.byte_len();
    let first_ack_range = parse_field(bytes, cursor, offset, QuicFrameField::FirstAckRange)?;
    let first_offset = offset + cursor;
    cursor += first_ack_range.byte_len();

    let first_smallest_acknowledged = subtract(
        largest_acknowledged.value(),
        first_ack_range.value(),
        0,
        QuicFrameField::FirstAckRange,
        first_offset,
    )?;
    let ranges_start = cursor;
    let ranges_offset = offset + ranges_start;
    let mut previous_smallest = first_smallest_acknowledged;
    let mut remaining_count = ack_range_count.value();
    while remaining_count != 0 {
        let range = parse_range(&bytes[cursor..], previous_smallest, offset + cursor)?;
        cursor += range.bytes.len();
        previous_smallest = range.smallest_acknowledged;
        remaining_count -= 1;
    }
    let ranges = &bytes[ranges_start..cursor];

    let ecn_counts = if frame_type.value() == 3 {
        let counts_start = cursor;
        let ect0_count = parse_field(bytes, cursor, offset, QuicFrameField::Ect0Count)?;
        cursor += ect0_count.byte_len();
        let ect1_count = parse_field(bytes, cursor, offset, QuicFrameField::Ect1Count)?;
        cursor += ect1_count.byte_len();
        let ecn_ce_count = parse_field(bytes, cursor, offset, QuicFrameField::EcnCeCount)?;
        cursor += ecn_ce_count.byte_len();
        Some(QuicEcnCounts {
            bytes: &bytes[counts_start..cursor],
            ect0_count,
            ect1_count,
            ecn_ce_count,
        })
    } else {
        None
    };

    Ok((
        QuicAckFrame {
            bytes: &bytes[..cursor],
            frame_type,
            largest_acknowledged,
            ack_delay,
            ack_range_count,
            first_ack_range,
            first_smallest_acknowledged,
            ranges,
            ranges_offset,
            ecn_counts,
        },
        &bytes[cursor..],
    ))
}

fn parse_range<'a>(
    bytes: &'a [u8],
    previous_smallest: u64,
    offset: usize,
) -> Result<QuicAckRange<'a>, QuicFrameParseError> {
    let gap = parse_field(bytes, 0, offset, QuicFrameField::AckGap)?;
    let length_start = gap.byte_len();
    let ack_range_length =
        parse_field(bytes, length_start, offset, QuicFrameField::AckRangeLength)?;
    let largest_acknowledged = subtract(
        previous_smallest,
        gap.value(),
        2,
        QuicFrameField::AckGap,
        offset,
    )?;
    let smallest_acknowledged = subtract(
        largest_acknowledged,
        ack_range_length.value(),
        0,
        QuicFrameField::AckRangeLength,
        offset + length_start,
    )?;
    let end = length_start + ack_range_length.byte_len();
    Ok(QuicAckRange {
        bytes: &bytes[..end],
        gap,
        ack_range_length,
        largest_acknowledged,
        smallest_acknowledged,
    })
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

fn subtract(
    base: u64,
    value: u64,
    adjustment: u64,
    field: QuicFrameField,
    offset: usize,
) -> Result<u64, QuicFrameParseError> {
    base.checked_sub(value)
        .and_then(|value| value.checked_sub(adjustment))
        .ok_or(QuicFrameParseError::AckRangeUnderflow {
            field,
            offset,
            base,
            value,
            adjustment,
        })
}
