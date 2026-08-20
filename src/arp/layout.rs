//! RFC 826 packet layout.

wire_repr::wire_repr! {
    /// An RFC 826 ARP packet with caller-defined hardware and protocol address widths.
    pub layout ArpPacket {
        /// The hardware address space.
        hardware_type: BeU16 as super::types::ArpHardwareType;
        /// The protocol address space.
        protocol_type: BeU16 as super::types::ArpProtocolType;
        /// The encoded width of each hardware address.
        hardware_address_length: U8;
        /// The encoded width of each protocol address.
        protocol_address_length: U8;
        /// The requested or performed operation.
        operation: BeU16 as super::types::ArpOperation;
        /// The sender hardware address bytes.
        sender_hardware_address: bytes(hardware_address_length);
        /// The sender protocol address bytes.
        sender_protocol_address: bytes(protocol_address_length);
        /// The target hardware address bytes.
        target_hardware_address: bytes(hardware_address_length);
        /// The target protocol address bytes.
        target_protocol_address: bytes(protocol_address_length);
    }
}
