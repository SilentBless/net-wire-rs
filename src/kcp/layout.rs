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
        field conversation_id: LeU32 as super::types::KcpConversationId;
        /// The raw command.
        field command: U8 as super::types::KcpCommand;
        /// The fragment number.
        field fragment: U8 as super::types::KcpFragment;
        /// The advertised receive window.
        field window_size: LeU16;
        /// The timestamp.
        field timestamp: LeU32 as super::types::KcpTimestamp;
        /// The sequence number.
        field sequence_number: LeU32 as super::types::KcpSequenceNumber;
        /// The unacknowledged marker.
        field unacknowledged: LeU32 as super::types::KcpUnacknowledged;
        /// The encoded payload length, derived from `payload` during construction.
        field payload_length: LeU32;
        /// The opaque terminal payload.
        field payload: bytes(current_pos..buf_end);
    }
}
