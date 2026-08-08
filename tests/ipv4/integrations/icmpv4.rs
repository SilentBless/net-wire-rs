use crate::fixtures::packet;
use net_wire::ParseError;
use net_wire::ipv4::{Ipv4Packet, Ipv4PacketMut};

#[test]
fn dispatches_icmpv4_only_when_complete_and_atomic() {
    assert!(
        Ipv4Packet::parse(&packet(1, 0, &[8, 0, 0, 0]))
            .unwrap()
            .icmpv4()
            .unwrap()
            .is_some()
    );
    assert_eq!(
        Ipv4Packet::parse(&packet(17, 0, &[8, 0, 0, 0]))
            .unwrap()
            .icmpv4(),
        Ok(None)
    );
    assert_eq!(
        Ipv4Packet::parse(&packet(1, 0, &[8, 0, 0]))
            .unwrap()
            .icmpv4(),
        Err(ParseError::Truncated {
            minimum: 4,
            available: 3
        })
    );
    for fragment in [0x2000, 1] {
        assert_eq!(
            Ipv4Packet::parse(&packet(1, fragment, &[8, 0, 0, 0]))
                .unwrap()
                .icmpv4(),
            Ok(None)
        );
    }
    for fragment in [0x4000, 0x8000] {
        assert!(
            Ipv4Packet::parse(&packet(1, fragment, &[8, 0, 0, 0]))
                .unwrap()
                .icmpv4()
                .unwrap()
                .is_some()
        );
    }
}

#[test]
fn mutable_icmpv4_dispatch_writes_through() {
    let mut bytes = packet(1, 0, &[8, 0, 0, 0]);
    let mut ipv4 = Ipv4PacketMut::parse(&mut bytes).unwrap();
    ipv4.icmpv4_mut().unwrap().unwrap().set_code(7);
    assert_eq!(ipv4.payload()[1], 7);
}
