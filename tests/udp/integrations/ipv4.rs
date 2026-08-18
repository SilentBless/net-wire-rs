use crate::fixtures::checksum;
use net_wire::ipv4::Ipv4Address;
use net_wire::udp::{UdpChecksumStatus, UdpDatagramMut};

fn pseudo(source: Ipv4Address, destination: Ipv4Address, datagram: &[u8]) -> u16 {
    let mut bytes = [0u8; 22];
    bytes[..4].copy_from_slice(&source.octets());
    bytes[4..8].copy_from_slice(&destination.octets());
    bytes[9] = 17;
    bytes[10..12].copy_from_slice(&(datagram.len() as u16).to_be_bytes());
    bytes[12..].copy_from_slice(datagram);
    checksum(&bytes)
}

#[test]
fn ipv4_statuses_known_checksum_and_zero_encoding() {
    let source = Ipv4Address::new([192, 0, 2, 1]);
    let destination = Ipv4Address::new([198, 51, 100, 2]);
    let mut bytes = [0x12, 0x34, 0xab, 0xcd, 0, 10, 0, 0, 0xde, 0xad];
    assert_eq!(pseudo(source, destination, &bytes), 0x76f3);
    let mut d = UdpDatagramMut::parse(&mut bytes).unwrap();
    assert_eq!(
        d.checksum_status_ipv4(source, destination),
        UdpChecksumStatus::NotPresent
    );
    d.update_checksum_ipv4(source, destination).unwrap();
    assert_eq!(d.checksum(), 0x76f3);
    assert_eq!(
        d.checksum_status_ipv4(source, destination),
        UdpChecksumStatus::Valid
    );
    d.set_source_port(3).unwrap();
    assert_eq!(
        d.checksum_status_ipv4(source, destination),
        UdpChecksumStatus::Invalid
    );
    let mut zero = [0x12, 0x34, 0xab, 0xcd, 0, 10, 0, 0, 0x55, 0xa1];
    assert_eq!(pseudo(source, destination, &zero), 0);
    let mut zero = UdpDatagramMut::parse(&mut zero).unwrap();
    zero.update_checksum_ipv4(source, destination).unwrap();
    assert_eq!(zero.checksum(), 0xffff);
}
