use crate::fixtures::checksum;
use net_wire::ipv6::Ipv6Address;
use net_wire::udp::UdpDatagramMut;

fn pseudo(source: Ipv6Address, destination: Ipv6Address, datagram: &[u8]) -> u16 {
    let mut bytes = [0u8; 50];
    bytes[..16].copy_from_slice(&source.octets());
    bytes[16..32].copy_from_slice(&destination.octets());
    bytes[32..36].copy_from_slice(&(datagram.len() as u32).to_be_bytes());
    bytes[39] = 17;
    bytes[40..].copy_from_slice(datagram);
    checksum(&bytes)
}

#[test]
fn ipv6_zero_is_invalid_and_update_uses_pseudoheader() {
    let source = Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let destination = Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let mut bytes = [0x12, 0x34, 0xab, 0xcd, 0, 10, 0, 0, 0xde, 0xad];
    assert_eq!(pseudo(source, destination, &bytes), 0x07b6);
    let mut d = UdpDatagramMut::parse(&mut bytes).unwrap();
    assert!(!d.checksum_is_valid_ipv6(source, destination));
    d.update_checksum_ipv6(source, destination);
    assert_eq!(d.checksum(), 0x07b6);
    assert!(d.checksum_is_valid_ipv6(source, destination));
    d.set_checksum(1);
    assert!(!d.checksum_is_valid_ipv6(source, destination));
}
