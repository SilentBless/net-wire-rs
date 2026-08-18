//! Exact immutable and mutable KCP segment views.

use core::fmt;

use super::error::{KcpSegmentMutationError, KcpSegmentParseError};
use super::layout::{
    KCP_SEGMENT_HEADER_LEN, KcpSegmentLayoutError, KcpSegmentLayoutMutationError,
    KcpSegmentLayoutView, KcpSegmentLayoutViewMut,
};
use super::types::{
    KcpCommand, KcpConversationId, KcpFragment, KcpSequenceNumber, KcpTimestamp, KcpUnacknowledged,
};

fn layout_error(error: KcpSegmentLayoutError, available: usize) -> KcpSegmentParseError {
    match error {
        KcpSegmentLayoutError::InputTooShort { .. }
        | KcpSegmentLayoutError::TrailingBytes { .. }
        | KcpSegmentLayoutError::InvalidCodecWidth { .. }
        | KcpSegmentLayoutError::InvalidRangeSource { .. }
        | KcpSegmentLayoutError::RangeEndBeforeStart { .. }
        | KcpSegmentLayoutError::InvalidPrefixExtent { .. } => {
            KcpSegmentParseError::HeaderTruncated {
                required: KCP_SEGMENT_HEADER_LEN,
                available,
            }
        }
    }
}

fn segment_length(bytes: &[u8]) -> Result<usize, KcpSegmentParseError> {
    if bytes.len() < KCP_SEGMENT_HEADER_LEN {
        return Err(KcpSegmentParseError::HeaderTruncated {
            required: KCP_SEGMENT_HEADER_LEN,
            available: bytes.len(),
        });
    }

    let (preliminary, _) = KcpSegmentLayoutView::parse_prefix(bytes)
        .map_err(|error| layout_error(error, bytes.len()))?;
    let payload_length = usize::try_from(preliminary.payload_length()).map_err(|_| {
        KcpSegmentParseError::PayloadLengthNotRepresentable {
            value: preliminary.payload_length(),
        }
    })?;
    let segment_length = KCP_SEGMENT_HEADER_LEN.checked_add(payload_length).ok_or(
        KcpSegmentParseError::LengthOverflow {
            header_length: KCP_SEGMENT_HEADER_LEN,
            payload_length,
        },
    )?;
    if bytes.len() < segment_length {
        return Err(KcpSegmentParseError::PayloadTruncated {
            required: segment_length,
            available: bytes.len(),
        });
    }
    Ok(segment_length)
}

fn mutation_error(error: KcpSegmentLayoutMutationError) -> KcpSegmentMutationError {
    match error {
        KcpSegmentLayoutMutationError::FieldConversationId(error)
        | KcpSegmentLayoutMutationError::FieldCommand(error)
        | KcpSegmentLayoutMutationError::FieldFragment(error)
        | KcpSegmentLayoutMutationError::FieldWindowSize(error)
        | KcpSegmentLayoutMutationError::FieldTimestamp(error)
        | KcpSegmentLayoutMutationError::FieldSequenceNumber(error)
        | KcpSegmentLayoutMutationError::FieldUnacknowledged(error)
        | KcpSegmentLayoutMutationError::FieldPayloadLength(error) => match error {},
        KcpSegmentLayoutMutationError::InvalidPlanLength {
            field,
            expected,
            actual,
        } => KcpSegmentMutationError::InvalidFieldEncoding {
            field,
            expected,
            actual,
        },
    }
}

/// An exact borrowed KCP segment with a structurally complete declared payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KcpSegment<'a> {
    layout: KcpSegmentLayoutView<'a>,
}

impl<'a> KcpSegment<'a> {
    /// Parses exactly one KCP segment and returns the unconsumed input suffix.
    pub fn parse(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), KcpSegmentParseError> {
        let segment_length = segment_length(bytes)?;
        let (segment, suffix) = bytes.split_at(segment_length);
        let layout = KcpSegmentLayoutView::parse_exact(segment)
            .map_err(|error| layout_error(error, segment.len()))?;
        Ok((Self { layout }, suffix))
    }
    /// Returns the conversation identifier.
    pub fn conversation_id(self) -> KcpConversationId {
        self.layout.conversation_id()
    }
    /// Returns the raw command byte.
    pub fn command(self) -> KcpCommand {
        self.layout.command()
    }
    /// Returns the fragment number.
    pub fn fragment(self) -> KcpFragment {
        self.layout.fragment()
    }
    /// Returns the advertised receive window.
    pub fn window_size(self) -> u16 {
        self.layout.window_size()
    }
    /// Returns the timestamp.
    pub fn timestamp(self) -> KcpTimestamp {
        self.layout.timestamp()
    }
    /// Returns the sequence number.
    pub fn sequence_number(self) -> KcpSequenceNumber {
        self.layout.sequence_number()
    }
    /// Returns the unacknowledged sequence-number marker.
    pub fn unacknowledged(self) -> KcpUnacknowledged {
        self.layout.unacknowledged()
    }
    /// Returns the encoded payload length.
    pub fn payload_length(self) -> u32 {
        self.layout.payload_length()
    }
    /// Returns the exact payload bytes.
    pub fn payload(self) -> &'a [u8] {
        self.layout.payload()
    }
    /// Returns the exact complete segment bytes, excluding any input suffix.
    pub fn as_bytes(self) -> &'a [u8] {
        self.layout.as_bytes()
    }
}

/// An exact mutable KCP segment with a structurally complete declared payload.
pub struct KcpSegmentMut<'a> {
    layout: KcpSegmentLayoutViewMut<'a>,
}

impl fmt::Debug for KcpSegmentMut<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KcpSegmentMut")
            .field("bytes", &self.as_bytes())
            .finish()
    }
}
impl PartialEq for KcpSegmentMut<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}
impl Eq for KcpSegmentMut<'_> {}

impl<'a> KcpSegmentMut<'a> {
    /// Parses exactly one KCP segment and returns the unconsumed mutable input suffix.
    pub fn parse(bytes: &'a mut [u8]) -> Result<(Self, &'a mut [u8]), KcpSegmentParseError> {
        let segment_length = segment_length(bytes)?;
        let (segment, suffix) = bytes.split_at_mut(segment_length);
        let available = segment.len();
        let layout = KcpSegmentLayoutViewMut::parse_exact_mut(segment)
            .map_err(|error| layout_error(error, available))?;
        Ok((Self { layout }, suffix))
    }
    pub(super) const fn from_layout(layout: KcpSegmentLayoutViewMut<'a>) -> Self {
        Self { layout }
    }
    /// Returns the conversation identifier.
    pub fn conversation_id(&self) -> KcpConversationId {
        self.layout.conversation_id()
    }
    /// Returns the raw command byte.
    pub fn command(&self) -> KcpCommand {
        self.layout.command()
    }
    /// Returns the fragment number.
    pub fn fragment(&self) -> KcpFragment {
        self.layout.fragment()
    }
    /// Returns the advertised receive window.
    pub fn window_size(&self) -> u16 {
        self.layout.window_size()
    }
    /// Returns the timestamp.
    pub fn timestamp(&self) -> KcpTimestamp {
        self.layout.timestamp()
    }
    /// Returns the sequence number.
    pub fn sequence_number(&self) -> KcpSequenceNumber {
        self.layout.sequence_number()
    }
    /// Returns the unacknowledged sequence-number marker.
    pub fn unacknowledged(&self) -> KcpUnacknowledged {
        self.layout.unacknowledged()
    }
    /// Returns the encoded payload length.
    pub fn payload_length(&self) -> u32 {
        self.layout.payload_length()
    }
    /// Returns the exact payload bytes.
    pub fn payload(&self) -> &[u8] {
        self.layout.payload()
    }
    /// Returns the exact payload bytes mutably without changing its encoded length.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        self.layout.payload_mut()
    }
    /// Returns the exact complete segment bytes, excluding any input suffix.
    pub fn as_bytes(&self) -> &[u8] {
        self.layout.as_bytes()
    }
    /// Replaces the conversation identifier.
    pub fn set_conversation_id(
        &mut self,
        value: KcpConversationId,
    ) -> Result<(), KcpSegmentMutationError> {
        self.layout
            .set_conversation_id(value)
            .map_err(mutation_error)
    }
    /// Replaces the raw command byte.
    pub fn set_command(&mut self, value: KcpCommand) -> Result<(), KcpSegmentMutationError> {
        self.layout.set_command(value).map_err(mutation_error)
    }
    /// Replaces the fragment number.
    pub fn set_fragment(&mut self, value: KcpFragment) -> Result<(), KcpSegmentMutationError> {
        self.layout.set_fragment(value).map_err(mutation_error)
    }
    /// Replaces the advertised receive window.
    pub fn set_window_size(&mut self, value: u16) -> Result<(), KcpSegmentMutationError> {
        self.layout.set_window_size(value).map_err(mutation_error)
    }
    /// Replaces the timestamp.
    pub fn set_timestamp(&mut self, value: KcpTimestamp) -> Result<(), KcpSegmentMutationError> {
        self.layout.set_timestamp(value).map_err(mutation_error)
    }
    /// Replaces the sequence number.
    pub fn set_sequence_number(
        &mut self,
        value: KcpSequenceNumber,
    ) -> Result<(), KcpSegmentMutationError> {
        self.layout
            .set_sequence_number(value)
            .map_err(mutation_error)
    }
    /// Replaces the unacknowledged marker.
    pub fn set_unacknowledged(
        &mut self,
        value: KcpUnacknowledged,
    ) -> Result<(), KcpSegmentMutationError> {
        self.layout
            .set_unacknowledged(value)
            .map_err(mutation_error)
    }
}
