//! Private KCP segment physical representation.

/// The fixed KCP segment header length in bytes.
pub const KCP_SEGMENT_HEADER_LEN: usize = 24;

wire_repr::wire_repr! {
    /// One KCP segment with its payload extending to the supplied buffer end.
    ///
    /// KCP's encoded payload length is semantic framing owned by the public view,
    /// not a second physical layout schema.
    pub(super) layout KcpSegmentLayout {
        /// The conversation identifier.
        conversation_id: LeU32 as super::types::KcpConversationId;
        /// The raw command.
        command: U8 as super::types::KcpCommand;
        /// The fragment number.
        fragment: U8 as super::types::KcpFragment;
        /// The advertised receive window.
        window_size: LeU16;
        /// The timestamp.
        timestamp: LeU32 as super::types::KcpTimestamp;
        /// The sequence number.
        sequence_number: LeU32 as super::types::KcpSequenceNumber;
        /// The unacknowledged marker.
        unacknowledged: LeU32 as super::types::KcpUnacknowledged;
        /// The encoded payload length, derived from `payload` during construction.
        payload_length: LeU32;
        /// The opaque terminal payload.
        payload: remaining_bytes;
    }
}
