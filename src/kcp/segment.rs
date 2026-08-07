//! Exact immutable KCP segment views.

use super::{
    KcpCommand, KcpConversationId, KcpFragment, KcpSegmentParseError, KcpSequenceNumber,
    KcpTimestamp, KcpUnacknowledged,
};

/// The fixed KCP segment header length in bytes.
pub const KCP_SEGMENT_HEADER_LEN: usize = 24;

/// An exact borrowed KCP segment with a structurally complete declared payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KcpSegment<'a> {
    bytes: &'a [u8],
}

impl<'a> KcpSegment<'a> {
    /// Parses exactly one KCP segment and returns the unconsumed input suffix.
    ///
    /// This validates only structural boundaries. Raw command bytes and all field values are
    /// preserved without runtime KCP semantic validation.
    pub fn parse(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), KcpSegmentParseError> {
        if bytes.len() < KCP_SEGMENT_HEADER_LEN {
            return Err(KcpSegmentParseError::HeaderTruncated {
                required: KCP_SEGMENT_HEADER_LEN,
                available: bytes.len(),
            });
        }

        let payload_length = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
        let payload_length = usize::try_from(payload_length).map_err(|_| {
            KcpSegmentParseError::PayloadLengthNotRepresentable {
                value: payload_length,
            }
        })?;
        let length = KCP_SEGMENT_HEADER_LEN.checked_add(payload_length).ok_or(
            KcpSegmentParseError::LengthOverflow {
                header_length: KCP_SEGMENT_HEADER_LEN,
                payload_length,
            },
        )?;
        if bytes.len() < length {
            return Err(KcpSegmentParseError::PayloadTruncated {
                required: length,
                available: bytes.len(),
            });
        }

        Ok((
            Self {
                bytes: &bytes[..length],
            },
            &bytes[length..],
        ))
    }

    /// Returns the conversation identifier.
    pub const fn conversation_id(self) -> KcpConversationId {
        KcpConversationId::new(u32::from_le_bytes([
            self.bytes[0],
            self.bytes[1],
            self.bytes[2],
            self.bytes[3],
        ]))
    }

    /// Returns the raw command byte.
    pub const fn command(self) -> KcpCommand {
        KcpCommand::new(self.bytes[4])
    }

    /// Returns the fragment number.
    pub const fn fragment(self) -> KcpFragment {
        KcpFragment::new(self.bytes[5])
    }

    /// Returns the advertised receive window.
    pub const fn window_size(self) -> u16 {
        u16::from_le_bytes([self.bytes[6], self.bytes[7]])
    }

    /// Returns the timestamp.
    pub const fn timestamp(self) -> KcpTimestamp {
        KcpTimestamp::new(u32::from_le_bytes([
            self.bytes[8],
            self.bytes[9],
            self.bytes[10],
            self.bytes[11],
        ]))
    }

    /// Returns the sequence number.
    pub const fn sequence_number(self) -> KcpSequenceNumber {
        KcpSequenceNumber::new(u32::from_le_bytes([
            self.bytes[12],
            self.bytes[13],
            self.bytes[14],
            self.bytes[15],
        ]))
    }

    /// Returns the unacknowledged sequence-number marker.
    pub const fn unacknowledged(self) -> KcpUnacknowledged {
        KcpUnacknowledged::new(u32::from_le_bytes([
            self.bytes[16],
            self.bytes[17],
            self.bytes[18],
            self.bytes[19],
        ]))
    }

    /// Returns the encoded payload length.
    pub const fn payload_length(self) -> u32 {
        u32::from_le_bytes([
            self.bytes[20],
            self.bytes[21],
            self.bytes[22],
            self.bytes[23],
        ])
    }

    /// Returns the exact payload bytes.
    pub fn payload(self) -> &'a [u8] {
        &self.bytes[KCP_SEGMENT_HEADER_LEN..]
    }

    /// Returns the exact complete segment bytes, excluding any input suffix.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
}
