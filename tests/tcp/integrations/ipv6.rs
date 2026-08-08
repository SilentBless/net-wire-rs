use crate::fixtures::checksum;
use net_wire::ipv6::Ipv6Address;
use net_wire::tcp::TcpSegmentMut;

fn pseudo(s: Ipv6Address, d: Ipv6Address, segment: &[u8]) -> u16 {
    let mut bytes = [0u8; 61];
    bytes[..16].copy_from_slice(&s.octets());
    bytes[16..32].copy_from_slice(&d.octets());
    bytes[32..36].copy_from_slice(&(segment.len() as u32).to_be_bytes());
    bytes[39] = 6;
    bytes[40..].copy_from_slice(segment);
    checksum(&bytes)
}

#[test]
fn known_wrong_stale_and_updated() {
    let s = Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let d = Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let wrong = Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
    let mut b = [
        0x12, 0x34, 0xab, 0xcd, 0, 0, 0, 3, 0, 0, 0, 4, 0x50, 0x12, 0x20, 0, 0, 0, 0, 7, 8,
    ];
    assert_eq!(pseudo(s, d, &b), 0x6e4d);
    let mut p = TcpSegmentMut::parse(&mut b).unwrap();
    p.update_checksum_ipv6(s, d).unwrap();
    assert_eq!(p.checksum(), 0x6e4d);
    assert!(p.checksum_is_valid_ipv6(s, d).unwrap());
    assert!(!p.checksum_is_valid_ipv6(s, wrong).unwrap());
    p.set_source_port(3);
    assert!(!p.checksum_is_valid_ipv6(s, d).unwrap());
    p.update_checksum_ipv6(s, d).unwrap();
    assert!(p.checksum_is_valid_ipv6(s, d).unwrap());
}
