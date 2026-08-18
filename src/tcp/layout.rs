//! Private RFC 9293 fixed-header physical representation.

pub(super) const HEADER_LENGTH: usize = 20;

wire_repr::wire_repr! {
    /// A TCP segment with a caller-bounded terminal body.
    pub(super) layout TcpSegmentLayout {
        /// The source port.
        field source_port: BeU16;
        /// The destination port.
        field destination_port: BeU16;
        /// The sequence number.
        field sequence_number: BeU32;
        /// The acknowledgment number.
        field acknowledgment_number: BeU32;
        /// The combined data-offset and reserved-bits octet.
        field data_offset_reserved: U8 {
            projections {
                bits data_offset: 4..=7;
                bits reserved: 0..=3;
            }
        }
        /// The control flags.
        field flags: U8 as super::flags::TcpFlags;
        /// The window size.
        field window_size: BeU16;
        /// The encoded checksum.
        field checksum: BeU16;
        /// The urgent pointer.
        field urgent_pointer: BeU16;
        /// Every caller-supplied byte after the fixed TCP header.
        field body: bytes(current_pos..buf_end);
    }
}
