use net_wire::arp::{
    ArpHardwareType, ArpOperation, ArpPacketView, ArpPacketViewMut, ArpProtocolType,
};

use super::fixtures::GENERIC;

#[test]
fn prefix_and_exact_parsing_bound_the_rfc826_layout() {
    let (packet, suffix) = ArpPacketView::parse_prefix(&GENERIC).unwrap();
    assert_eq!(packet.hardware_type(), ArpHardwareType::new(0x1234));
    assert_eq!(packet.hardware_type_raw(), 0x1234);
    assert_eq!(packet.protocol_type(), ArpProtocolType::new(0xbeef));
    assert_eq!(packet.protocol_type_raw(), 0xbeef);
    assert_eq!(packet.operation(), ArpOperation::new(0xcafe));
    assert_eq!(packet.operation_raw(), 0xcafe);
    assert_eq!(packet.hardware_address_length(), 3);
    assert_eq!(packet.protocol_address_length(), 2);
    assert_eq!(packet.sender_hardware_address(), &[1, 2, 3]);
    assert_eq!(packet.sender_protocol_address(), &[4, 5]);
    assert_eq!(packet.target_hardware_address(), &[6, 7, 8]);
    assert_eq!(packet.target_protocol_address(), &[9, 10]);
    assert_eq!(packet.as_bytes(), &GENERIC[..18]);
    assert_eq!(suffix, &[11, 12, 0xee]);
    assert!(ArpPacketView::parse_exact(&GENERIC).is_err());
    assert!(ArpPacketView::parse_prefix(&GENERIC[..7]).is_err());
    assert!(ArpPacketView::parse_prefix(&GENERIC[..17]).is_err());
}

#[test]
fn zero_lengths_and_unknown_wrappers_are_valid() {
    let bytes = [0x12, 0x34, 0xbe, 0xef, 0, 0, 0xca, 0xfe, 0xaa];
    let (packet, suffix) = ArpPacketView::parse_prefix(&bytes).unwrap();
    assert_eq!(packet.hardware_type(), ArpHardwareType::new(0x1234));
    assert_eq!(packet.hardware_type_raw(), 0x1234);
    assert_eq!(packet.protocol_type(), ArpProtocolType::new(0xbeef));
    assert_eq!(packet.protocol_type_raw(), 0xbeef);
    assert_eq!(packet.operation(), ArpOperation::new(0xcafe));
    assert_eq!(packet.operation_raw(), 0xcafe);
    assert_eq!(packet.sender_hardware_address(), &[]);
    assert_eq!(packet.sender_protocol_address(), &[]);
    assert_eq!(packet.target_hardware_address(), &[]);
    assert_eq!(packet.target_protocol_address(), &[]);
    assert_eq!(suffix, &[0xaa]);
}

#[test]
fn mutable_view_updates_scalars_and_regions_without_touching_suffix() {
    let mut bytes = GENERIC;
    let (mut packet, suffix) = ArpPacketViewMut::parse_prefix_mut(&mut bytes).unwrap();
    packet.set_hardware_type(ArpHardwareType::ETHERNET).unwrap();
    packet.set_hardware_type_raw(0x1234).unwrap();
    packet.set_protocol_type(ArpProtocolType::IPV4).unwrap();
    packet.set_protocol_type_raw(0xbeef).unwrap();
    packet.set_operation(ArpOperation::REPLY).unwrap();
    packet.set_operation_raw(0xcafe).unwrap();
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
    assert_eq!(packet.hardware_type(), ArpHardwareType::new(0x1234));
    assert_eq!(packet.hardware_type_raw(), 0x1234);
    assert_eq!(packet.protocol_type(), ArpProtocolType::new(0xbeef));
    assert_eq!(packet.protocol_type_raw(), 0xbeef);
    assert_eq!(packet.operation(), ArpOperation::new(0xcafe));
    assert_eq!(packet.operation_raw(), 0xcafe);
    assert_eq!(packet.hardware_address_length(), 3);
    assert_eq!(packet.protocol_address_length(), 2);
    assert_eq!(packet.sender_hardware_address(), &[13, 14, 15]);
    assert_eq!(packet.sender_protocol_address(), &[16, 17]);
    assert_eq!(packet.target_hardware_address(), &[18, 19, 20]);
    assert_eq!(packet.target_protocol_address(), &[21, 22]);
    assert_eq!(suffix, &[11, 12, 0xee]);
}
