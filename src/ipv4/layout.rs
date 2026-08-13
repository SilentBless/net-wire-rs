//! Private fixed RFC 791 header representation.

wire_repr::wire_repr! {
    /// The fixed twenty-octet portion of an IPv4 header.
    pub(super) layout Ipv4FixedHeader {
        /// The combined version and Internet Header Length octet.
        field version_ihl: U8;
        /// The combined differentiated-services and ECN octet.
        field dscp_ecn: U8;
        /// The complete IPv4 packet length.
        field total_length: BeU16;
        /// The datagram identification.
        field identification: BeU16;
        /// The flags and fragment offset.
        field flags_fragment_offset: BeU16;
        /// The time to live.
        field ttl: U8;
        /// The next-header protocol number.
        field protocol: U8;
        /// The fixed-header checksum.
        field header_checksum: BeU16;
        /// The source IPv4 address.
        field source: bytes(4);
        /// The destination IPv4 address.
        field destination: bytes(4);
    }
}
