#![cfg(all(feature = "arp", feature = "ipv4"))]

use net_wire::{ArpPacket, Ipv4Address};

#[test]
fn ipv4_helpers_require_ipv4_type_and_four_octets() {
    let wrong_type = [
        0, 1, 0x12, 0x34, 1, 4, 0, 1, 9, 192, 0, 2, 1, 8, 192, 0, 2, 2,
    ];
    let wrong_length = [0, 1, 8, 0, 1, 3, 0, 1, 9, 192, 0, 2, 8, 192, 0, 3];
    assert_eq!(
        ArpPacket::parse(&wrong_type).unwrap().sender_ipv4_address(),
        None
    );
    assert_eq!(
        ArpPacket::parse(&wrong_length)
            .unwrap()
            .target_ipv4_address(),
        None
    );

    let valid = [0, 1, 8, 0, 1, 4, 0, 1, 9, 192, 0, 2, 1, 8, 192, 0, 2, 2];
    let packet = ArpPacket::parse(&valid).unwrap();
    assert_eq!(
        packet.sender_ipv4_address(),
        Some(Ipv4Address::new([192, 0, 2, 1]))
    );
    assert_eq!(
        packet.target_ipv4_address(),
        Some(Ipv4Address::new([192, 0, 2, 2]))
    );
}
