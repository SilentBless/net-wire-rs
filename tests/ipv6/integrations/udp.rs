use crate::fixtures::packet;
use net_wire::ParseError;
use net_wire::ipv6::{Ipv6DispatchError, Ipv6NextHeader, Ipv6Packet, Ipv6PacketMut};

#[test]
fn direct_udp_dispatch_valid_mismatch_malformed_and_mutable() {
    let udp = packet(Ipv6NextHeader::UDP, &[0, 1, 0, 2, 0, 8, 0, 0]);
    let ipv6 = Ipv6Packet::parse(&udp).unwrap();
    assert_eq!(ipv6.udp().unwrap().unwrap().source_port(), 1);
    #[cfg(feature = "tcp")]
    assert_eq!(ipv6.tcp(), Ok(None));

    let bytes = packet(
        Ipv6NextHeader::TCP,
        &[
            0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0, 0, 0, 0, 0, 0, 0,
        ],
    );
    let ipv6 = Ipv6Packet::parse(&bytes).unwrap();
    assert_eq!(ipv6.udp(), Ok(None));

    let bytes = packet(Ipv6NextHeader::UDP, &[0; 7]);
    let ipv6 = Ipv6Packet::parse(&bytes).unwrap();
    assert_eq!(
        ipv6.udp(),
        Err(Ipv6DispatchError::UpperLayer(ParseError::Truncated {
            minimum: 8,
            available: 7,
        }))
    );

    let mut bytes = packet(Ipv6NextHeader::UDP, &[0, 1, 0, 2, 0, 8, 0, 0]);
    let mut ipv6 = Ipv6PacketMut::parse(&mut bytes).unwrap();
    ipv6.udp_mut().unwrap().unwrap().set_source_port(9);
    assert_eq!(&ipv6.payload()[..2], &[0, 9]);
}
