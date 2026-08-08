use crate::fixtures::packet;
use net_wire::ParseError;
use net_wire::ipv6::{Ipv6DispatchError, Ipv6NextHeader, Ipv6Packet, Ipv6PacketMut};

#[test]
fn direct_tcp_dispatch_valid_mismatch_malformed_and_mutable() {
    let tcp = packet(
        Ipv6NextHeader::TCP,
        &[
            0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0, 0, 0, 0, 0, 0, 0,
        ],
    );
    let ipv6 = Ipv6Packet::parse(&tcp).unwrap();
    #[cfg(feature = "icmpv6")]
    assert_eq!(ipv6.icmpv6(), Ok(None));
    assert_eq!(ipv6.tcp().unwrap().unwrap().destination_port(), 2);

    let bytes = packet(Ipv6NextHeader::ICMPV6, &[128, 0, 0, 0]);
    let ipv6 = Ipv6Packet::parse(&bytes).unwrap();
    assert_eq!(ipv6.tcp(), Ok(None));

    let bytes = packet(Ipv6NextHeader::TCP, &[0; 19]);
    let ipv6 = Ipv6Packet::parse(&bytes).unwrap();
    assert_eq!(
        ipv6.tcp(),
        Err(Ipv6DispatchError::UpperLayer(ParseError::Truncated {
            minimum: 20,
            available: 19,
        }))
    );

    let mut bytes = packet(
        Ipv6NextHeader::TCP,
        &[
            0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0, 0, 0, 0, 0, 0, 0,
        ],
    );
    let mut ipv6 = Ipv6PacketMut::parse(&mut bytes).unwrap();
    ipv6.tcp_mut().unwrap().unwrap().set_source_port(9);
    assert_eq!(&ipv6.payload()[..2], &[0, 9]);
}
