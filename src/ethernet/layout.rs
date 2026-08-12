//! RFC 894 Ethernet II frame layout.

wire_repr::wire_repr! {
    /// An Ethernet II frame whose payload is bounded entirely by the caller's input.
    pub layout EthernetFrame {
        /// The destination Ethernet hardware address.
        field destination: bytes(6) as super::types::MacAddress;
        /// The source Ethernet hardware address.
        field source: bytes(6) as super::types::MacAddress;
        /// The Ethernet protocol type.
        field ether_type: BeU16 as super::types::EtherType;
        /// Every caller-supplied byte after the Ethernet header.
        field payload: remainder;
    }
}
