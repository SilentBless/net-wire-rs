//! RFC 826 packet layout.

wire_repr::wire_repr! {
    /// An RFC 826 ARP packet with caller-defined hardware and protocol address widths.
    pub layout ArpPacket {
        /// The hardware address space.
        field hardware_type: BeU16 as super::types::ArpHardwareType;
        /// The protocol address space.
        field protocol_type: BeU16 as super::types::ArpProtocolType;
        /// The encoded width of each hardware address.
        field hardware_address_length: U8;
        /// The encoded width of each protocol address.
        field protocol_address_length: U8;
        /// The requested or performed operation.
        field operation: BeU16 as super::types::ArpOperation;
        /// The sender hardware address bytes.
        field sender_hardware_address: bytes(current_pos..current_pos + hardware_address_length);
        /// The sender protocol address bytes.
        field sender_protocol_address: bytes(current_pos..current_pos + protocol_address_length);
        /// The target hardware address bytes.
        field target_hardware_address: bytes(current_pos..current_pos + hardware_address_length);
        /// The target protocol address bytes.
        field target_protocol_address: bytes(current_pos..current_pos + protocol_address_length);
    }
}
