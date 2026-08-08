use crate::fixtures::WIRE;
use net_wire::ParseError;
use net_wire::ipv6::{
    Ipv6Address, Ipv6NextHeader, Ipv6Packet, Ipv6PacketBuildError, Ipv6PacketMut, Ipv6PayloadLength,
};

#[test]
fn base_header_bounds_and_zero_ambiguity() {
    let p = Ipv6Packet::parse(&WIRE).unwrap();
    assert_eq!(
        (
            p.traffic_class(),
            p.flow_label(),
            p.payload_length(),
            p.raw_payload_length(),
            p.next_header().raw(),
            p.hop_limit(),
            p.payload(),
            p.as_bytes().len()
        ),
        (
            0xab,
            0xcdeef,
            Ipv6PayloadLength::Declared(3),
            3,
            0xfd,
            64,
            &[1, 2, 3][..],
            43
        )
    );
    assert_eq!(
        p.source().octets(),
        [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    );
    assert_eq!(p.destination().to_string(), "2001:db8::2");
    let mut z = [0; 40];
    z[0] = 0x60;
    assert_eq!(
        Ipv6Packet::parse(&z).unwrap().payload_length(),
        Ipv6PayloadLength::Unspecified
    );
    let tail = z;
    let mut v = tail.to_vec();
    v.extend_from_slice(&[1, 2]);
    let q = Ipv6Packet::parse(&v).unwrap();
    assert_eq!(
        (q.payload_length(), q.payload(), q.as_bytes()),
        (Ipv6PayloadLength::Unspecified, &[1, 2][..], v.as_slice())
    );
}

#[test]
fn errors_and_mutation() {
    assert_eq!(
        Ipv6Packet::parse(&WIRE[..39]),
        Err(ParseError::Truncated {
            minimum: 40,
            available: 39
        })
    );
    let mut b = WIRE;
    b[0] = 0x50;
    assert_eq!(
        Ipv6Packet::parse(&b),
        Err(ParseError::InvalidVersion {
            expected: 6,
            actual: 5
        })
    );
    b = WIRE;
    b[4] = 0;
    b[5] = 5;
    assert_eq!(
        Ipv6Packet::parse(&b),
        Err(ParseError::Truncated {
            minimum: 45,
            available: 44
        })
    );
    let mut b = WIRE;
    let mut p = Ipv6PacketMut::parse(&mut b).unwrap();
    p.set_traffic_class(1);
    p.set_flow_label(2).unwrap();
    p.set_next_header(Ipv6NextHeader::new(3));
    p.set_hop_limit(4);
    p.set_source(Ipv6Address::new([5; 16]));
    p.set_destination(Ipv6Address::new([6; 16]));
    p.payload_mut()[0] = 7;
    p.as_bytes_mut()[3] = 2;
    let old = p.as_bytes().to_vec();
    assert_eq!(
        p.set_flow_label(0x10_0000),
        Err(Ipv6PacketBuildError::FlowLabelTooLarge)
    );
    assert_eq!(p.as_bytes(), old);
    assert_eq!(
        (
            p.traffic_class(),
            p.flow_label(),
            p.next_header().raw(),
            p.hop_limit(),
            p.source().octets(),
            p.destination().octets(),
            p.payload()
        ),
        (1, 2, 3, 4, [5; 16], [6; 16], &[7, 2, 3][..])
    );
}
