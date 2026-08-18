//! Private RFC 768 physical representation.

pub(super) const HEADER_LENGTH: usize = 8;

wire_repr::wire_repr! {
    /// A UDP datagram with a caller-bounded terminal payload.
    pub(super) layout UdpDatagramLayout {
        /// The source port.
        field source_port: BeU16;
        /// The destination port.
        field destination_port: BeU16;
        /// The complete UDP datagram length.
        field length: BeU16;
        /// The UDP checksum.
        field checksum: BeU16;
        /// Every caller-supplied byte after the UDP header.
        field payload: bytes(current_pos..buf_end);
    }
}
