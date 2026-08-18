use crate::fixtures::packet;
use net_wire::ParseError;
use net_wire::ipv6::{Ipv6DispatchError, Ipv6NextHeader, Ipv6Packet, Ipv6PacketMut};

#[test]
fn direct_icmpv6_dispatch_valid_mismatch_malformed_and_mutable() {
    let icmp = packet(Ipv6NextHeader::ICMPV6, &[128, 0, 0, 0]);
    let ipv6 = Ipv6Packet::parse(&icmp).unwrap();
    assert_eq!(ipv6.icmpv6().unwrap().unwrap().message_type().raw(), 128);
    #[cfg(feature = "udp")]
    assert_eq!(ipv6.udp(), Ok(None));
    #[cfg(feature = "tcp")]
    assert_eq!(ipv6.tcp(), Ok(None));

    let bytes = packet(Ipv6NextHeader::UDP, &[0, 1, 0, 2, 0, 8, 0, 0]);
    let ipv6 = Ipv6Packet::parse(&bytes).unwrap();
    assert_eq!(ipv6.icmpv6(), Ok(None));

    let bytes = packet(Ipv6NextHeader::ICMPV6, &[0, 0, 0]);
    let ipv6 = Ipv6Packet::parse(&bytes).unwrap();
    assert_eq!(
        ipv6.icmpv6(),
        Err(Ipv6DispatchError::UpperLayer(ParseError::Truncated {
            minimum: 4,
            available: 3,
        }))
    );

    let mut bytes = packet(Ipv6NextHeader::ICMPV6, &[128, 0, 0, 0]);
    let mut ipv6 = Ipv6PacketMut::parse(&mut bytes).unwrap();
    {
        let mut icmpv6 = ipv6.icmpv6_mut().unwrap().unwrap();
        assert_eq!(icmpv6.message_type().raw(), 128);
        icmpv6.set_code(7).unwrap();
    }
    assert_eq!(ipv6.payload()[1], 7);
}
