use net_wire::ParseError;
use net_wire::ipv6::{
    Ipv6DispatchError, Ipv6ExtensionTraversalError, Ipv6NextHeader, Ipv6Packet, Ipv6PacketMut,
};

fn packet(next_header: Ipv6NextHeader, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 40 + payload.len()];
    bytes[0] = 0x60;
    bytes[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes[6] = next_header.raw();
    bytes[7] = 64;
    bytes[8..24].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    bytes[24..40].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    bytes[40..].copy_from_slice(payload);
    bytes
}

fn assert_terminal_none(next_header: Ipv6NextHeader, payload: &[u8]) {
    let bytes = packet(next_header, payload);
    let ipv6 = Ipv6Packet::parse(&bytes).unwrap();
    assert_eq!(ipv6.icmpv6(), Ok(None));
    assert_eq!(ipv6.udp(), Ok(None));
    assert_eq!(ipv6.tcp(), Ok(None));
}

#[test]
fn direct_dispatch_valid_mismatch_and_malformed() {
    let icmp = packet(Ipv6NextHeader::ICMPV6, &[128, 0, 0, 0]);
    let ipv6 = Ipv6Packet::parse(&icmp).unwrap();
    assert_eq!(ipv6.icmpv6().unwrap().unwrap().message_type().raw(), 128);
    assert_eq!(ipv6.udp(), Ok(None));
    assert_eq!(ipv6.tcp(), Ok(None));

    let udp = packet(Ipv6NextHeader::UDP, &[0, 1, 0, 2, 0, 8, 0, 0]);
    let ipv6 = Ipv6Packet::parse(&udp).unwrap();
    assert_eq!(ipv6.icmpv6(), Ok(None));
    assert_eq!(ipv6.udp().unwrap().unwrap().source_port(), 1);
    assert_eq!(ipv6.tcp(), Ok(None));

    let tcp = packet(
        Ipv6NextHeader::TCP,
        &[
            0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0, 0, 0, 0, 0, 0, 0,
        ],
    );
    let ipv6 = Ipv6Packet::parse(&tcp).unwrap();
    assert_eq!(ipv6.icmpv6(), Ok(None));
    assert_eq!(ipv6.udp(), Ok(None));
    assert_eq!(ipv6.tcp().unwrap().unwrap().destination_port(), 2);

    for (next, payload, error) in [
        (
            Ipv6NextHeader::ICMPV6,
            &[0, 0, 0][..],
            Ipv6DispatchError::UpperLayer(ParseError::Truncated {
                minimum: 4,
                available: 3,
            }),
        ),
        (
            Ipv6NextHeader::UDP,
            &[0; 7][..],
            Ipv6DispatchError::UpperLayer(ParseError::Truncated {
                minimum: 8,
                available: 7,
            }),
        ),
        (
            Ipv6NextHeader::TCP,
            &[0; 19][..],
            Ipv6DispatchError::UpperLayer(ParseError::Truncated {
                minimum: 20,
                available: 19,
            }),
        ),
    ] {
        let bytes = packet(next, payload);
        let ipv6 = Ipv6Packet::parse(&bytes).unwrap();
        match next.raw() {
            58 => assert_eq!(ipv6.icmpv6(), Err(error)),
            17 => assert_eq!(ipv6.udp(), Err(error)),
            6 => assert_eq!(ipv6.tcp(), Err(error)),
            _ => unreachable!(),
        }
    }
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
    ipv6.udp_mut().unwrap().unwrap().set_source_port(9);
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
