//! Exact immutable and mutable KCP segment views.

use super::error::KcpSegmentParseError;
use super::types::{
    KcpCommand, KcpConversationId, KcpFragment, KcpSequenceNumber, KcpTimestamp, KcpUnacknowledged,
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

/// An exact mutable KCP segment with a structurally complete declared payload.
#[derive(Debug, Eq, PartialEq)]
pub struct KcpSegmentMut<'a> {
    bytes: &'a mut [u8],
}

impl<'a> KcpSegmentMut<'a> {
    /// Parses exactly one KCP segment and returns the unconsumed mutable input suffix.
    ///
    /// This validates only structural boundaries. Raw command bytes and all field values are
    /// preserved without runtime KCP semantic validation.
    pub fn parse(bytes: &'a mut [u8]) -> Result<(Self, &'a mut [u8]), KcpSegmentParseError> {
        let (segment, _) = KcpSegment::parse(bytes)?;
        let (segment_bytes, suffix) = bytes.split_at_mut(segment.as_bytes().len());
        Ok((Self::from_validated(segment_bytes), suffix))
    }

    pub(crate) fn from_validated(bytes: &'a mut [u8]) -> Self {
        Self { bytes }
    }

    /// Returns the conversation identifier.
    pub fn conversation_id(&self) -> KcpConversationId {
        KcpConversationId::new(u32::from_le_bytes([
            self.bytes[0],
            self.bytes[1],
            self.bytes[2],
            self.bytes[3],
        ]))
    }

    /// Returns the raw command byte.
    pub fn command(&self) -> KcpCommand {
        KcpCommand::new(self.bytes[4])
    }

    /// Returns the fragment number.
    pub fn fragment(&self) -> KcpFragment {
        KcpFragment::new(self.bytes[5])
    }

    /// Returns the advertised receive window.
    pub fn window_size(&self) -> u16 {
        u16::from_le_bytes([self.bytes[6], self.bytes[7]])
    }

    /// Returns the timestamp.
    pub fn timestamp(&self) -> KcpTimestamp {
        KcpTimestamp::new(u32::from_le_bytes([
            self.bytes[8],
            self.bytes[9],
            self.bytes[10],
            self.bytes[11],
        ]))
    }

    /// Returns the sequence number.
    pub fn sequence_number(&self) -> KcpSequenceNumber {
        KcpSequenceNumber::new(u32::from_le_bytes([
            self.bytes[12],
            self.bytes[13],
            self.bytes[14],
            self.bytes[15],
        ]))
    }

    /// Returns the unacknowledged sequence-number marker.
    pub fn unacknowledged(&self) -> KcpUnacknowledged {
        KcpUnacknowledged::new(u32::from_le_bytes([
            self.bytes[16],
            self.bytes[17],
            self.bytes[18],
            self.bytes[19],
        ]))
    }

    /// Returns the encoded payload length.
    pub fn payload_length(&self) -> u32 {
        u32::from_le_bytes([
            self.bytes[20],
            self.bytes[21],
            self.bytes[22],
            self.bytes[23],
        ])
    }

    /// Returns the exact payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.bytes[KCP_SEGMENT_HEADER_LEN..]
    }

    /// Returns the exact payload bytes mutably without changing its encoded length.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[KCP_SEGMENT_HEADER_LEN..]
    }

    /// Returns the exact complete segment bytes, excluding any input suffix.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }

    /// Replaces the conversation identifier.
    pub fn set_conversation_id(&mut self, value: KcpConversationId) {
        self.bytes[0..4].copy_from_slice(&value.raw().to_le_bytes());
    }

    /// Replaces the raw command byte.
    pub fn set_command(&mut self, value: KcpCommand) {
        self.bytes[4] = value.raw();
    }

    /// Replaces the fragment number.
    pub fn set_fragment(&mut self, value: KcpFragment) {
        self.bytes[5] = value.raw();
    }

    /// Replaces the advertised receive window.
    pub fn set_window_size(&mut self, value: u16) {
        self.bytes[6..8].copy_from_slice(&value.to_le_bytes());
    }

    /// Replaces the timestamp.
    pub fn set_timestamp(&mut self, value: KcpTimestamp) {
        self.bytes[8..12].copy_from_slice(&value.raw().to_le_bytes());
    }

    /// Replaces the sequence number.
    pub fn set_sequence_number(&mut self, value: KcpSequenceNumber) {
        self.bytes[12..16].copy_from_slice(&value.raw().to_le_bytes());
    }

    /// Replaces the unacknowledged sequence-number marker.
    pub fn set_unacknowledged(&mut self, value: KcpUnacknowledged) {
        self.bytes[16..20].copy_from_slice(&value.raw().to_le_bytes());
    }
}
