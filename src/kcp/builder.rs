//! KCP caller-buffer segment construction.

use super::error::KcpSegmentBuildError;
use super::layout::{KCP_SEGMENT_HEADER_LEN, KcpSegmentLayoutBuilder, KcpSegmentLayoutWriteError};
use super::segment::KcpSegmentMut;
use super::types::{
    KcpCommand, KcpConversationId, KcpFragment, KcpSequenceNumber, KcpTimestamp, KcpUnacknowledged,
};

fn representation_error(error: KcpSegmentLayoutWriteError) -> KcpSegmentBuildError {
    match error {
        KcpSegmentLayoutWriteError::FieldConversationId(error)
        | KcpSegmentLayoutWriteError::FieldCommand(error)
        | KcpSegmentLayoutWriteError::FieldFragment(error)
        | KcpSegmentLayoutWriteError::FieldWindowSize(error)
        | KcpSegmentLayoutWriteError::FieldTimestamp(error)
        | KcpSegmentLayoutWriteError::FieldSequenceNumber(error)
        | KcpSegmentLayoutWriteError::FieldUnacknowledged(error)
        | KcpSegmentLayoutWriteError::FieldPayloadLength(error) => match error {},
        KcpSegmentLayoutWriteError::InvalidPlanLength {
            field,
            expected,
            actual,
        } => KcpSegmentBuildError::InvalidFieldEncoding {
            field,
            expected,
            actual,
        },
        KcpSegmentLayoutWriteError::MissingContext { .. }
        | KcpSegmentLayoutWriteError::InvalidCodecWidth { .. }
        | KcpSegmentLayoutWriteError::InvalidRangeSource { .. }
        | KcpSegmentLayoutWriteError::ConflictingRangeSources { .. }
        | KcpSegmentLayoutWriteError::InvalidPrefixPlanLength { .. }
        | KcpSegmentLayoutWriteError::InvalidLayoutExtent { .. }
        | KcpSegmentLayoutWriteError::OutputTooShort { .. }
        | KcpSegmentLayoutWriteError::MissingField { .. } => {
            KcpSegmentBuildError::InvalidRepresentation
        }
    }
}

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
        let (layout, _) = KcpSegmentLayoutBuilder::new()
            .conversation_id(self.conversation_id)
            .command(self.command)
            .fragment(self.fragment)
            .window_size(self.window_size)
            .timestamp(self.timestamp)
            .sequence_number(self.sequence_number)
            .unacknowledged(self.unacknowledged)
            .payload_length(encoded_payload_length)
            .payload(self.payload)
            .build_into(&mut self.destination[..segment_length])
            .map_err(representation_error)?;
        Ok(KcpSegmentMut::from_layout(layout))
    }
}
