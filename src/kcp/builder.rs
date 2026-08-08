//! KCP caller-buffer segment construction.

use super::error::KcpSegmentBuildError;
use super::segment::{KCP_SEGMENT_HEADER_LEN, KcpSegmentMut};
use super::types::{
    KcpCommand, KcpConversationId, KcpFragment, KcpSequenceNumber, KcpTimestamp, KcpUnacknowledged,
};

/// Builds one complete KCP segment in caller-owned storage.
pub struct KcpSegmentBuilder<'a, 'b> {
    destination: &'a mut [u8],
    conversation_id: KcpConversationId,
    command: KcpCommand,
    payload: &'b [u8],
    fragment: KcpFragment,
    window_size: u16,
    timestamp: KcpTimestamp,
    sequence_number: KcpSequenceNumber,
    unacknowledged: KcpUnacknowledged,
}

impl<'a, 'b> KcpSegmentBuilder<'a, 'b> {
    /// Starts a builder with the required fields and a copied payload.
    pub fn new(
        destination: &'a mut [u8],
        conversation_id: KcpConversationId,
        command: KcpCommand,
        payload: &'b [u8],
    ) -> Self {
        Self {
            destination,
            conversation_id,
            command,
            payload,
            fragment: KcpFragment::new(0),
            window_size: 0,
            timestamp: KcpTimestamp::new(0),
            sequence_number: KcpSequenceNumber::new(0),
            unacknowledged: KcpUnacknowledged::new(0),
        }
    }

    /// Supplies the fragment number; it defaults to zero.
    pub fn fragment(mut self, value: KcpFragment) -> Self {
        self.fragment = value;
        self
    }

    /// Supplies the advertised receive window; it defaults to zero.
    pub fn window_size(mut self, value: u16) -> Self {
        self.window_size = value;
        self
    }

    /// Supplies the timestamp; it defaults to zero.
    pub fn timestamp(mut self, value: KcpTimestamp) -> Self {
        self.timestamp = value;
        self
    }

    /// Supplies the sequence number; it defaults to zero.
    pub fn sequence_number(mut self, value: KcpSequenceNumber) -> Self {
        self.sequence_number = value;
        self
    }

    /// Supplies the unacknowledged marker; it defaults to zero.
    pub fn unacknowledged(mut self, value: KcpUnacknowledged) -> Self {
        self.unacknowledged = value;
        self
    }

    /// Validates all boundaries, then writes one complete KCP segment.
    pub fn build(self) -> Result<KcpSegmentMut<'a>, KcpSegmentBuildError> {
        let payload_length = self.payload.len();
        let encoded_payload_length = u32::try_from(payload_length).map_err(|_| {
            KcpSegmentBuildError::PayloadLengthTooLarge {
                length: payload_length,
            }
        })?;
        let segment_length = KCP_SEGMENT_HEADER_LEN.checked_add(payload_length).ok_or(
            KcpSegmentBuildError::LengthOverflow {
                header_length: KCP_SEGMENT_HEADER_LEN,
                payload_length,
            },
        )?;
        if self.destination.len() < segment_length {
            return Err(KcpSegmentBuildError::BufferTooShort {
                required: segment_length,
                available: self.destination.len(),
            });
        }

        let bytes = &mut self.destination[..segment_length];
        bytes[0..4].copy_from_slice(&self.conversation_id.raw().to_le_bytes());
        bytes[4] = self.command.raw();
        bytes[5] = self.fragment.raw();
        bytes[6..8].copy_from_slice(&self.window_size.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.timestamp.raw().to_le_bytes());
        bytes[12..16].copy_from_slice(&self.sequence_number.raw().to_le_bytes());
        bytes[16..20].copy_from_slice(&self.unacknowledged.raw().to_le_bytes());
        bytes[20..24].copy_from_slice(&encoded_payload_length.to_le_bytes());
        bytes[KCP_SEGMENT_HEADER_LEN..].copy_from_slice(self.payload);
        Ok(KcpSegmentMut::from_validated(bytes))
    }
}
