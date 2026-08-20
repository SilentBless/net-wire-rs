//! Private RFC 768 physical representation.

pub(super) const HEADER_LENGTH: usize = 8;

wire_repr::wire_repr! {
    /// A UDP datagram with a caller-bounded terminal payload.
    pub(super) layout UdpDatagramLayout {
        /// The source port.
        source_port: BeU16;
        /// The destination port.
        destination_port: BeU16;
        /// The complete UDP datagram length.
        length: BeU16;
        /// The UDP checksum.
        checksum: BeU16;
        /// Every caller-supplied byte after the UDP header.
        payload: remaining_bytes;
    }
}
