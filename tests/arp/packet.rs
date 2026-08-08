use net_wire::ParseError;
use net_wire::arp::{ArpHardwareType, ArpOperation, ArpPacket, ArpPacketMut, ArpProtocolType};

use super::fixtures::GENERIC;

#[test]
fn generic_rfc826_layout_preserves_unknowns_and_bounds() {
    let packet = ArpPacket::parse(&GENERIC).unwrap();
    assert_eq!(packet.hardware_type().raw(), 0x1234);
    assert_eq!(packet.protocol_type().raw(), 0xbeef);
    assert_eq!(packet.operation().raw(), 0xcafe);
    assert_eq!(
        (
            packet.hardware_address_length(),
            packet.protocol_address_length(),
            packet.hlen(),
            packet.plen()
        ),
        (3, 2, 3, 2)
    );
    assert_eq!(packet.sender_hardware_address(), &[1, 2, 3]);
    assert_eq!(packet.sender_protocol_address(), &[4, 5]);
    assert_eq!(packet.target_hardware_address(), &[6, 7, 8]);
    assert_eq!(packet.target_protocol_address(), &[9, 10]);
    assert_eq!(packet.as_bytes(), &GENERIC[..18]);
}

#[test]
fn parsing_accepts_zero_addresses_and_rejects_short_layouts() {
    assert_eq!(
        ArpPacket::parse(&GENERIC[..7]),
        Err(ParseError::Truncated {
            minimum: 8,
            available: 7
        })
    );
    assert_eq!(
        ArpPacket::parse(&GENERIC[..17]),
        Err(ParseError::Truncated {
            minimum: 18,
            available: 17
        })
    );
    let zero = ArpPacket::parse(&[0, 1, 8, 0, 0, 0, 0, 1, 0xaa]).unwrap();
    assert_eq!(zero.as_bytes(), &[0, 1, 8, 0, 0, 0, 0, 1]);
    assert_eq!(zero.sender_hardware_address(), &[]);
    assert_eq!(zero.target_protocol_address(), &[]);
}

#[test]
fn mutable_view_changes_fields_and_not_lengths() {
    let mut bytes = GENERIC;
    let mut packet = ArpPacketMut::parse(&mut bytes).unwrap();
    assert_eq!(
        (
            packet.hardware_type().raw(),
            packet.protocol_type().raw(),
            packet.operation().raw()
        ),
        (0x1234, 0xbeef, 0xcafe)
    );
    packet.set_hardware_type(ArpHardwareType::ETHERNET);
    packet.set_protocol_type(ArpProtocolType::IPV4);
    packet.set_operation(ArpOperation::REPLY);
    packet
        .sender_hardware_address_mut()
        .copy_from_slice(&[13, 14, 15]);
    packet
        .sender_protocol_address_mut()
        .copy_from_slice(&[16, 17]);
    packet
        .target_hardware_address_mut()
        .copy_from_slice(&[18, 19, 20]);
    packet
        .target_protocol_address_mut()
        .copy_from_slice(&[21, 22]);
    packet.as_bytes_mut()[7] = 1;
    assert_eq!(
        (
            packet.hardware_address_length(),
            packet.protocol_address_length(),
            packet.hlen(),
            packet.plen()
        ),
        (3, 2, 3, 2)
    );
    assert_eq!(packet.sender_hardware_address(), &[13, 14, 15]);
    assert_eq!(packet.sender_protocol_address(), &[16, 17]);
    assert_eq!(packet.target_hardware_address(), &[18, 19, 20]);
    assert_eq!(packet.target_protocol_address(), &[21, 22]);
    assert_eq!(packet.as_bytes().len(), 18);
}
