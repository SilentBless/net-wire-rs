use net_wire::*;
const WIRE: [u8; 44] = [
    0x6a, 0xbc, 0xde, 0xef, 0, 3, 0xfd, 64, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 2, 3, 0xee,
];
const ZERO_WIRE: [u8; 40] = [
    0x6a, 0xbc, 0xde, 0xef, 0, 0, 0xfd, 64, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
];
fn complete<'a>(b: &'a mut [u8], n: usize) -> Result<Ipv6PacketMut<'a>, Ipv6PacketBuildError> {
    Ipv6PacketBuilder::new(b, n)
        .next_header(Ipv6NextHeader::new(0xfd))
        .hop_limit(64)
        .source(Ipv6Address::new([
            0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]))
        .destination(Ipv6Address::new([
            0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ]))
        .traffic_class(0xab)
        .flow_label(0xcdeef)
        .build()
}
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
#[test]
fn builder_is_exact_and_atomic() {
    let mut zero = [0xa5; 40];
    let p = complete(&mut zero, 0).unwrap();
    assert_eq!(p.as_bytes(), &ZERO_WIRE);
    let mut b = [0xa5; 46];
    let p = complete(&mut b, 3).unwrap();
    assert_eq!(&p.as_bytes()[..40], &WIRE[..40]);
    assert_eq!(p.payload(), &[0xa5; 3]);
    assert_eq!(&b[40..], &[0xa5; 6]);
    macro_rules! e {
        ($x:expr,$w:expr) => {{
            let mut b = [0xa5; 50];
            let o = b;
            assert_eq!($x(&mut b), Err($w));
            assert_eq!(b, o)
        }};
    }
    fn a(b: &mut [u8]) -> Result<Ipv6PacketMut<'_>, Ipv6PacketBuildError> {
        Ipv6PacketBuilder::new(b, 0).build()
    }
    fn c(b: &mut [u8]) -> Result<Ipv6PacketMut<'_>, Ipv6PacketBuildError> {
        Ipv6PacketBuilder::new(b, 0)
            .next_header(Ipv6NextHeader::new(1))
            .build()
    }
    fn d(b: &mut [u8]) -> Result<Ipv6PacketMut<'_>, Ipv6PacketBuildError> {
        Ipv6PacketBuilder::new(b, 0)
            .next_header(Ipv6NextHeader::new(1))
            .hop_limit(1)
            .build()
    }
    fn e2(b: &mut [u8]) -> Result<Ipv6PacketMut<'_>, Ipv6PacketBuildError> {
        Ipv6PacketBuilder::new(b, 0)
            .next_header(Ipv6NextHeader::new(1))
            .hop_limit(1)
            .source(Ipv6Address::new([1; 16]))
            .build()
    }
    e!(a, Ipv6PacketBuildError::MissingNextHeader);
    e!(c, Ipv6PacketBuildError::MissingHopLimit);
    e!(d, Ipv6PacketBuildError::MissingSource);
    e!(e2, Ipv6PacketBuildError::MissingDestination);
    let mut b = [0xa5; 50];
    let o = b;
    assert_eq!(
        Ipv6PacketBuilder::new(&mut b, 0)
            .next_header(Ipv6NextHeader::new(1))
            .hop_limit(1)
            .source(Ipv6Address::new([1; 16]))
            .destination(Ipv6Address::new([2; 16]))
            .flow_label(0x10_0000)
            .build(),
        Err(Ipv6PacketBuildError::FlowLabelTooLarge)
    );
    assert_eq!(b, o);
    let mut b = [0xa5; 50];
    let o = b;
    assert_eq!(
        Ipv6PacketBuilder::new(&mut b, 65536)
            .next_header(Ipv6NextHeader::new(1))
            .hop_limit(1)
            .source(Ipv6Address::new([1; 16]))
            .destination(Ipv6Address::new([2; 16]))
            .build(),
        Err(Ipv6PacketBuildError::PayloadLengthTooLarge)
    );
    assert_eq!(b, o);
    let mut b = [0xa5; 42];
    let o = b;
    assert_eq!(
        complete(&mut b, 3).map(|_| ()),
        Err(Ipv6PacketBuildError::BufferTooShort {
            required: 43,
            available: 42
        })
    );
    assert_eq!(b, o);
}

#[cfg(feature = "ethernet")]
mod ethernet {
    use super::*;

    fn frame(ether_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 14];
        bytes[12..14].copy_from_slice(&ether_type.to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn ipv6_dispatch_contract() {
        let ip = &WIRE[..43];
        assert_eq!(
            EthernetFrame::parse(&frame(0x0800, ip))
                .unwrap()
                .ipv6()
                .unwrap(),
            None
        );

        let bytes = frame(0x86dd, ip);
        let packet = EthernetFrame::parse(&bytes)
            .unwrap()
            .ipv6()
            .unwrap()
            .unwrap();
        assert_eq!((packet.as_bytes(), packet.next_header().raw()), (ip, 0xfd));

        assert_eq!(
            EthernetFrame::parse(&frame(0x86dd, &ip[..40]))
                .unwrap()
                .ipv6(),
            Err(ParseError::Truncated {
                minimum: 43,
                available: 40
            })
        );
    }

    #[test]
    fn mutable_ipv6_dispatch_writes_frame_payload() {
        let mut bytes = frame(0x86dd, &WIRE[..43]);
        let mut frame = EthernetFrameMut::parse(&mut bytes).unwrap();
        frame.ipv6_mut().unwrap().unwrap().payload_mut()[1] = 9;
        assert_eq!(bytes[14 + 41], 9);
    }
}

#[test]
fn next_header_constants_are_public_protocol_numbers() {
    assert_eq!(
        [
            Ipv6NextHeader::HOPOPT.raw(),
            Ipv6NextHeader::ROUTING.raw(),
            Ipv6NextHeader::FRAGMENT.raw(),
            Ipv6NextHeader::ESP.raw(),
            Ipv6NextHeader::AUTHENTICATION.raw(),
            Ipv6NextHeader::DESTINATION_OPTIONS.raw(),
            Ipv6NextHeader::TCP.raw(),
            Ipv6NextHeader::UDP.raw(),
            Ipv6NextHeader::ICMPV6.raw(),
            Ipv6NextHeader::NO_NEXT_HEADER.raw(),
        ],
        [0, 43, 44, 50, 51, 60, 6, 17, 58, 59]
    );
}

#[cfg(all(feature = "icmpv6", feature = "udp", feature = "tcp"))]
mod dispatch {
    use super::*;

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
                ParseError::Truncated {
                    minimum: 4,
                    available: 3,
                },
            ),
            (
                Ipv6NextHeader::UDP,
                &[0; 7][..],
                ParseError::Truncated {
                    minimum: 8,
                    available: 7,
                },
            ),
            (
                Ipv6NextHeader::TCP,
                &[0; 19][..],
                ParseError::Truncated {
                    minimum: 20,
                    available: 19,
                },
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
            Err(ParseError::Truncated {
                minimum: 2,
                available: 1
            })
        );
        let bytes = packet(Ipv6NextHeader::HOPOPT, &[17, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            Ipv6Packet::parse(&bytes).unwrap().udp(),
            Err(ParseError::Truncated {
                minimum: 16,
                available: 8
            })
        );
        let bytes = packet(Ipv6NextHeader::AUTHENTICATION, &[17, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            Ipv6Packet::parse(&bytes).unwrap().udp(),
            Err(ParseError::InvalidExtensionHeaderLength {
                next_header: 51,
                minimum: 12,
                actual: 8
            })
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
        assert_eq!(ipv6.icmpv6(), Err(ParseError::UnresolvedPayloadLength));
        assert_eq!(ipv6.udp(), Err(ParseError::UnresolvedPayloadLength));
        assert_eq!(ipv6.tcp(), Err(ParseError::UnresolvedPayloadLength));
    }
}
