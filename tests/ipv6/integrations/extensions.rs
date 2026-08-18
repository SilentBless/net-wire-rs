use crate::fixtures::packet;
use net_wire::ParseError;
use net_wire::ipv6::{
    Ipv6DispatchError, Ipv6ExtensionTraversalError, Ipv6NextHeader, Ipv6Packet, Ipv6PacketMut,
};

fn assert_terminal_none(next_header: Ipv6NextHeader, payload: &[u8]) {
    let bytes = packet(next_header, payload);
    let ipv6 = Ipv6Packet::parse(&bytes).unwrap();
    assert_eq!(ipv6.icmpv6(), Ok(None));
    assert_eq!(ipv6.udp(), Ok(None));
    assert_eq!(ipv6.tcp(), Ok(None));
}

#[test]
fn extensions_reach_transport_at_the_correct_offset() {
    let udp = [0, 1, 0, 2, 0, 8, 0, 0];
    let payload = [
        43, 0, 0, 0, 0, 0, 0, 0, // Hop-by-Hop, 8 bytes
        60, 0, 0, 0, 0, 0, 0, 0, // Routing, 8 bytes
        17, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // DestOpts, 16 bytes
        udp[0], udp[1], udp[2], udp[3], udp[4], udp[5], udp[6], udp[7],
    ];
    let bytes = packet(Ipv6NextHeader::HOPOPT, &payload);
    let ipv6 = Ipv6Packet::parse(&bytes).unwrap();
    assert_eq!(ipv6.udp().unwrap().unwrap().destination_port(), 2);

    let mut bytes = bytes;
    let mut ipv6 = Ipv6PacketMut::parse(&mut bytes).unwrap();
    ipv6.udp_mut().unwrap().unwrap().set_source_port(9).unwrap();
    assert_eq!(&bytes[72..74], &[0, 9]);
}

#[test]
fn authentication_and_fragment_traversal_are_bounded() {
    let udp = [0, 1, 0, 2, 0, 8, 0, 0];
    let ah = [17, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut payload = ah.to_vec();
    payload.extend_from_slice(&udp);
    let bytes = packet(Ipv6NextHeader::AUTHENTICATION, &payload);
    assert_eq!(
        Ipv6Packet::parse(&bytes)
            .unwrap()
            .udp()
            .unwrap()
            .unwrap()
            .source_port(),
        1
    );

    let mut atomic = vec![0, 0, 0, 0, 0, 0, 0, 0];
    atomic[0] = 17;
    atomic.extend_from_slice(&udp);
    let bytes = packet(Ipv6NextHeader::FRAGMENT, &atomic);
    assert_eq!(
        Ipv6Packet::parse(&bytes)
            .unwrap()
            .udp()
            .unwrap()
            .unwrap()
            .destination_port(),
        2
    );

    for fragment in [[0, 8], [0, 1]] {
        let bytes = packet(
            Ipv6NextHeader::FRAGMENT,
            &[0, 0, fragment[0], fragment[1], 0, 0, 0, 0, 0, 1],
        );
        let ipv6 = Ipv6Packet::parse(&bytes).unwrap();
        assert_eq!(ipv6.udp(), Ok(None));
    }
}

#[test]
fn extension_errors_and_terminal_headers_are_explicit() {
    let bytes = packet(Ipv6NextHeader::HOPOPT, &[17]);
    assert_eq!(
        Ipv6Packet::parse(&bytes).unwrap().udp(),
        Err(Ipv6DispatchError::Traversal(
            Ipv6ExtensionTraversalError::Parse(ParseError::Truncated {
                minimum: 2,
                available: 1
            })
        ))
    );
    let bytes = packet(Ipv6NextHeader::HOPOPT, &[17, 1, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        Ipv6Packet::parse(&bytes).unwrap().udp(),
        Err(Ipv6DispatchError::Traversal(
            Ipv6ExtensionTraversalError::Parse(ParseError::Truncated {
                minimum: 16,
                available: 8
            })
        ))
    );
    let bytes = packet(Ipv6NextHeader::AUTHENTICATION, &[17, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        Ipv6Packet::parse(&bytes).unwrap().udp(),
        Err(Ipv6DispatchError::Traversal(
            Ipv6ExtensionTraversalError::InvalidExtensionHeaderLength {
                next_header: 51,
                minimum: 12,
                actual: 8
            }
        ))
    );

    assert_terminal_none(Ipv6NextHeader::ESP, &[1, 2]);
    assert_terminal_none(Ipv6NextHeader::new(253), &[1, 2]);
    assert_terminal_none(Ipv6NextHeader::NO_NEXT_HEADER, &[1, 2]);
    assert_terminal_none(Ipv6NextHeader::NO_NEXT_HEADER, &[]);
    assert_terminal_none(Ipv6NextHeader::new(253), &[]);

    let mut unresolved = packet(Ipv6NextHeader::UDP, &[]);
    unresolved[4..6].fill(0);
    unresolved.extend_from_slice(&[0; 8]);
    let ipv6 = Ipv6Packet::parse(&unresolved).unwrap();
    assert_eq!(
        ipv6.icmpv6(),
        Err(Ipv6DispatchError::Traversal(
            Ipv6ExtensionTraversalError::UnresolvedPayloadLength
        ))
    );
    assert_eq!(
        ipv6.udp(),
        Err(Ipv6DispatchError::Traversal(
            Ipv6ExtensionTraversalError::UnresolvedPayloadLength
        ))
    );
    assert_eq!(
        ipv6.tcp(),
        Err(Ipv6DispatchError::Traversal(
            Ipv6ExtensionTraversalError::UnresolvedPayloadLength
        ))
    );
}
