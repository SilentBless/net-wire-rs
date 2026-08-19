//! Private RFC 9113 common frame-envelope physical representation.

pub(in crate::http2) const FRAME_HEADER_LENGTH: usize = 9;
pub(in crate::http2) const MAXIMUM_PAYLOAD: usize = 0x00ff_ffff;

wire_repr::wire_repr! {
    /// An HTTP/2 frame envelope with a caller-bounded terminal payload.
    pub(in crate::http2) layout Http2FrameLayout {
        /// High payload-length octet.
        field payload_length_high: U8;
        /// Middle payload-length octet.
        field payload_length_middle: U8;
        /// Low payload-length octet.
        field payload_length_low: U8;
        /// Raw frame type.
        field frame_type: U8 as super::super::types::Http2FrameType;
        /// Raw frame flags.
        field flags: U8;
        /// Raw stream identifier, including its reserved bit.
        field stream_id: BeU32 as super::super::types::Http2StreamId;
        /// Every byte in the structurally bounded payload.
        field payload: bytes(current_pos..buf_end);
    }
}
