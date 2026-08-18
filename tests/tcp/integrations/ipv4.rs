use crate::fixtures::checksum;
use net_wire::ipv4::Ipv4Address;
use net_wire::tcp::{TcpChecksumError, TcpSegmentMut};

fn pseudo(s: Ipv4Address, d: Ipv4Address, segment: &[u8]) -> u16 {
    let mut bytes = [0u8; 37];
    bytes[..4].copy_from_slice(&s.octets());
    bytes[4..8].copy_from_slice(&d.octets());
    bytes[9] = 6;
    bytes[10..12].copy_from_slice(&(segment.len() as u16).to_be_bytes());
    bytes[12..12 + segment.len()].copy_from_slice(segment);
    checksum(&bytes[..12 + segment.len()])
}

#[test]
fn known_wrong_stale_and_updated() {
    let s = Ipv4Address::new([192, 0, 2, 1]);
    let d = Ipv4Address::new([198, 51, 100, 2]);
    let wrong = Ipv4Address::new([198, 51, 100, 3]);
    let mut b = [
        0x12, 0x34, 0xab, 0xcd, 0, 0, 0, 3, 0, 0, 0, 4, 0x50, 0x12, 0x20, 0, 0, 0, 0, 7, 8,
    ];
    assert_eq!(pseudo(s, d, &b), 0xdd8a);
    let mut p = TcpSegmentMut::parse(&mut b).unwrap();
    let result: Result<(), TcpChecksumError> = p.update_checksum_ipv4(s, d);
    result.unwrap();
    assert_eq!(p.checksum(), 0xdd8a);
    assert!(p.checksum_is_valid_ipv4(s, d).unwrap());
    assert!(!p.checksum_is_valid_ipv4(s, wrong).unwrap());
    p.set_source_port(3).unwrap();
    assert!(!p.checksum_is_valid_ipv4(s, d).unwrap());
    p.update_checksum_ipv4(s, d).unwrap();
    assert!(p.checksum_is_valid_ipv4(s, d).unwrap());
}
#[test]
fn options_reserved_bits_and_odd_payload_are_covered_in_wire_order() {
    let source = Ipv4Address::new([192, 0, 2, 1]);
    let destination = Ipv4Address::new([198, 51, 100, 2]);
    let mut bytes = [
        0x12, 0x34, 0xab, 0xcd, 0, 0, 0, 3, 0, 0, 0, 4, 0x65, 0xa5, 0x20, 0, 0, 0, 0, 7, 1, 2, 3,
        4, 9,
    ];
    let expected = pseudo(source, destination, &bytes);

    let mut segment = TcpSegmentMut::parse(&mut bytes).unwrap();
    segment.update_checksum_ipv4(source, destination).unwrap();

    assert_eq!(segment.checksum(), expected);
    assert!(segment.checksum_is_valid_ipv4(source, destination).unwrap());
}
