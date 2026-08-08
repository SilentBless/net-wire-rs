use crate::fixtures::packet;
use net_wire::ParseError;
use net_wire::ipv4::{Ipv4Packet, Ipv4PacketMut};

#[test]
fn dispatches_tcp_only_when_complete_and_atomic() {
    let valid = [
        0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert!(
        Ipv4Packet::parse(&packet(6, 0, &valid))
            .unwrap()
            .tcp()
            .unwrap()
            .is_some()
    );
    assert_eq!(
        Ipv4Packet::parse(&packet(17, 0, &valid)).unwrap().tcp(),
        Ok(None)
    );
    assert_eq!(
        Ipv4Packet::parse(&packet(6, 0, &valid[..19]))
            .unwrap()
            .tcp(),
        Err(ParseError::Truncated {
            minimum: 20,
            available: 19
        })
    );
    for fragment in [0x2000, 1] {
        assert_eq!(
            Ipv4Packet::parse(&packet(6, fragment, &valid))
                .unwrap()
                .tcp(),
            Ok(None)
        );
    }
    for fragment in [0x4000, 0x8000] {
        assert!(
            Ipv4Packet::parse(&packet(6, fragment, &valid))
                .unwrap()
                .tcp()
                .unwrap()
                .is_some()
        );
    }
}

#[test]
fn mutable_tcp_dispatch_writes_through() {
    let payload = [
        0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0, 0, 0, 0, 0, 0, 0,
    ];
    let mut bytes = packet(6, 0, &payload);
    let mut ipv4 = Ipv4PacketMut::parse(&mut bytes).unwrap();
    ipv4.tcp_mut().unwrap().unwrap().set_source_port(9);
    assert_eq!(&ipv4.payload()[..2], &[0, 9]);
}
