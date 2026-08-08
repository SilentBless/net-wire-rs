use crate::fixtures::packet;
use net_wire::ParseError;
use net_wire::ipv4::{Ipv4Packet, Ipv4PacketMut};

#[test]
fn dispatches_udp_only_when_complete_and_atomic() {
    let valid = [0, 1, 0, 2, 0, 8, 0, 0];
    assert!(
        Ipv4Packet::parse(&packet(17, 0, &valid))
            .unwrap()
            .udp()
            .unwrap()
            .is_some()
    );
    assert_eq!(
        Ipv4Packet::parse(&packet(1, 0, &valid)).unwrap().udp(),
        Ok(None)
    );
    assert_eq!(
        Ipv4Packet::parse(&packet(17, 0, &valid[..7]))
            .unwrap()
            .udp(),
        Err(ParseError::Truncated {
            minimum: 8,
            available: 7
        })
    );
    for fragment in [0x2000, 1] {
        assert_eq!(
            Ipv4Packet::parse(&packet(17, fragment, &valid))
                .unwrap()
                .udp(),
            Ok(None)
        );
    }
    for fragment in [0x4000, 0x8000] {
        assert!(
            Ipv4Packet::parse(&packet(17, fragment, &valid))
                .unwrap()
                .udp()
                .unwrap()
                .is_some()
        );
    }
}

#[test]
fn mutable_udp_dispatch_writes_through() {
    let mut bytes = packet(17, 0, &[0, 1, 0, 2, 0, 8, 0, 0]);
    let mut ipv4 = Ipv4PacketMut::parse(&mut bytes).unwrap();
    ipv4.udp_mut().unwrap().unwrap().set_source_port(9);
    assert_eq!(&ipv4.payload()[..2], &[0, 9]);
}
