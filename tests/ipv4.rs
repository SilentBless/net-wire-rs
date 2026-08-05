use net_wire::*;
const BASIC: [u8; 21] = [
    0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0xf6, 0xe0, 192, 0, 2, 1, 192, 0, 2, 2, 0xee,
];
const OPTIONS: [u8; 29] = [
    0x46, 0xab, 0, 28, 0x12, 0x34, 0x20, 5, 60, 0xfd, 0x59, 0xc4, 192, 0, 2, 1, 198, 51, 100, 2, 1,
    2, 3, 4, 9, 8, 7, 6, 0xee,
];
fn complete<'a>(
    b: &'a mut [u8],
    options: &[u8],
) -> Result<Ipv4PacketMut<'a>, Ipv4PacketBuildError> {
    Ipv4PacketBuilder::new(b, 4)
        .source(Ipv4Address::new([192, 0, 2, 1]))
        .destination(Ipv4Address::new([198, 51, 100, 2]))
        .protocol(Ipv4Protocol::new(0xfd))
        .ttl(60)
        .identification(0x1234)
        .flags_fragment_offset(0x2005)
        .dscp_ecn(0xab)
        .options(options)
        .build()
}
fn built_from_local(buffer: &mut [u8]) -> Ipv4PacketMut<'_> {
    let options = [1, 2, 3, 4];
    complete(buffer, &options).unwrap()
}
#[test]
fn fixed_and_option_layouts_are_bounded_and_valid() {
    let p = Ipv4Packet::parse(&BASIC).unwrap();
    assert_eq!(
        (
            p.dscp_ecn(),
            p.total_length(),
            p.identification(),
            p.flags_fragment_offset(),
            p.ttl(),
            p.protocol().raw(),
            p.header_checksum(),
            p.source(),
            p.destination()
        ),
        (
            0,
            20,
            0,
            0,
            64,
            6,
            0xf6e0,
            Ipv4Address::new([192, 0, 2, 1]),
            Ipv4Address::new([192, 0, 2, 2])
        )
    );
    assert_eq!(
        (
            p.options(),
            p.payload(),
            p.as_bytes(),
            p.checksum_is_valid()
        ),
        (&[][..], &[][..], &BASIC[..20], true)
    );
    let q = Ipv4Packet::parse(&OPTIONS).unwrap();
    assert_eq!(
        (
            q.options(),
            q.payload(),
            q.as_bytes().len(),
            q.protocol().raw(),
            q.checksum_is_valid()
        ),
        (&[1, 2, 3, 4][..], &[9, 8, 7, 6][..], 28, 0xfd, true)
    );
}
#[test]
fn parse_errors_and_permissive_capture_fields() {
    assert_eq!(
        Ipv4Packet::parse(&BASIC[..19]),
        Err(ParseError::Truncated {
            minimum: 20,
            available: 19
        })
    );
    let mut b = BASIC;
    b[0] = 0x55;
    assert_eq!(
        Ipv4Packet::parse(&b),
        Err(ParseError::InvalidVersion {
            expected: 4,
            actual: 5
        })
    );
    b = BASIC;
    b[0] = 0x44;
    assert_eq!(
        Ipv4Packet::parse(&b),
        Err(ParseError::InvalidHeaderLength {
            minimum: 20,
            actual: 16
        })
    );
    let mut option_header = OPTIONS;
    option_header[0] = 0x47;
    assert_eq!(
        Ipv4Packet::parse(&option_header[..24]),
        Err(ParseError::Truncated {
            minimum: 28,
            available: 24
        })
    );
    b = BASIC;
    b[2] = 0;
    b[3] = 19;
    assert_eq!(
        Ipv4Packet::parse(&b),
        Err(ParseError::InvalidTotalLength {
            header_length: 20,
            total_length: 19
        })
    );
    b = BASIC;
    b[2] = 0;
    b[3] = 22;
    assert_eq!(
        Ipv4Packet::parse(&b),
        Err(ParseError::Truncated {
            minimum: 22,
            available: 21
        })
    );
    b = BASIC;
    b[10] ^= 1;
    assert!(!Ipv4Packet::parse(&b).unwrap().checksum_is_valid());
    b = BASIC;
    b[6] = 0x80;
    assert_eq!(
        Ipv4Packet::parse(&b).unwrap().flags_fragment_offset(),
        0x8000
    );
}
#[test]
fn mutable_fields_and_checksum_boundary() {
    let mut b = OPTIONS;
    let mut p = Ipv4PacketMut::parse(&mut b).unwrap();
    assert_eq!(
        (
            p.dscp_ecn(),
            p.total_length(),
            p.identification(),
            p.flags_fragment_offset(),
            p.ttl(),
            p.protocol().raw(),
            p.header_checksum(),
            p.source(),
            p.destination()
        ),
        (
            0xab,
            28,
            0x1234,
            0x2005,
            60,
            0xfd,
            0x59c4,
            Ipv4Address::new([192, 0, 2, 1]),
            Ipv4Address::new([198, 51, 100, 2])
        )
    );
    p.set_dscp_ecn(1);
    p.set_identification(2);
    p.set_flags_fragment_offset(3);
    p.set_ttl(4);
    p.set_protocol(Ipv4Protocol::new(5));
    p.set_source(Ipv4Address::new([1, 1, 1, 1]));
    p.set_destination(Ipv4Address::new([2, 2, 2, 2]));
    p.options_mut()[0] = 9;
    assert!(!p.checksum_is_valid());
    p.update_header_checksum();
    assert!(p.checksum_is_valid());
    let c = p.header_checksum();
    p.payload_mut()[0] = 0;
    assert!(p.checksum_is_valid());
    p.set_header_checksum(c);
    p.as_bytes_mut()[1] = 1;
    assert_eq!(p.options(), &[9, 2, 3, 4]);
}
#[test]
fn builder_is_exact_and_errors_atomic() {
    let mut b = [0xa5; 31];
    let p = built_from_local(&mut b);
    assert_eq!(
        p.as_bytes(),
        &[
            0x46, 0xab, 0, 28, 0x12, 0x34, 0x20, 5, 60, 0xfd, 0x59, 0xc4, 192, 0, 2, 1, 198, 51,
            100, 2, 1, 2, 3, 4, 0xa5, 0xa5, 0xa5, 0xa5,
        ]
    );
    assert_eq!(&b[24..], &[0xa5; 7]);
    macro_rules! e {
        ($x:expr,$want:expr) => {{
            let mut b = [0xa5; 64];
            let old = b;
            assert_eq!($x(&mut b), Err($want));
            assert_eq!(b, old)
        }};
    }
    fn m1(b: &mut [u8]) -> Result<Ipv4PacketMut<'_>, Ipv4PacketBuildError> {
        Ipv4PacketBuilder::new(b, 0).build()
    }
    fn m2(b: &mut [u8]) -> Result<Ipv4PacketMut<'_>, Ipv4PacketBuildError> {
        Ipv4PacketBuilder::new(b, 0)
            .source(Ipv4Address::new([1; 4]))
            .build()
    }
    fn m3(b: &mut [u8]) -> Result<Ipv4PacketMut<'_>, Ipv4PacketBuildError> {
        Ipv4PacketBuilder::new(b, 0)
            .source(Ipv4Address::new([1; 4]))
            .destination(Ipv4Address::new([2; 4]))
            .build()
    }
    fn m4(b: &mut [u8]) -> Result<Ipv4PacketMut<'_>, Ipv4PacketBuildError> {
        Ipv4PacketBuilder::new(b, 0)
            .source(Ipv4Address::new([1; 4]))
            .destination(Ipv4Address::new([2; 4]))
            .protocol(Ipv4Protocol::new(1))
            .build()
    }
    e!(m1, Ipv4PacketBuildError::MissingSource);
    e!(m2, Ipv4PacketBuildError::MissingDestination);
    e!(m3, Ipv4PacketBuildError::MissingProtocol);
    e!(m4, Ipv4PacketBuildError::MissingTtl);
    let mut b = [0xa5; 64];
    let old = b;
    assert_eq!(
        complete(&mut b, &[1, 2, 3]).map(|_| ()),
        Err(Ipv4PacketBuildError::InvalidOptionsLength)
    );
    assert_eq!(b, old);
    let mut b = [0xa5; 64];
    let old = b;
    assert_eq!(
        complete(&mut b, &[0; 44]).map(|_| ()),
        Err(Ipv4PacketBuildError::InvalidOptionsLength)
    );
    assert_eq!(b, old);
    let mut b = [0xa5; 64];
    let old = b;
    assert_eq!(
        Ipv4PacketBuilder::new(&mut b, 0)
            .source(Ipv4Address::new([1; 4]))
            .destination(Ipv4Address::new([2; 4]))
            .protocol(Ipv4Protocol::new(1))
            .ttl(1)
            .flags_fragment_offset(0x8000)
            .build(),
        Err(Ipv4PacketBuildError::ReservedFlagSet)
    );
    assert_eq!(b, old);
    let mut b = [0xa5; 64];
    let old = b;
    assert_eq!(
        Ipv4PacketBuilder::new(&mut b, usize::MAX)
            .source(Ipv4Address::new([1; 4]))
            .destination(Ipv4Address::new([2; 4]))
            .protocol(Ipv4Protocol::new(1))
            .ttl(1)
            .build(),
        Err(Ipv4PacketBuildError::TotalLengthTooLarge)
    );
    assert_eq!(b, old);
    let mut b = [0xa5; 64];
    let old = b;
    assert_eq!(
        Ipv4PacketBuilder::new(&mut b, 65_516)
            .source(Ipv4Address::new([1; 4]))
            .destination(Ipv4Address::new([2; 4]))
            .protocol(Ipv4Protocol::new(1))
            .ttl(1)
            .build(),
        Err(Ipv4PacketBuildError::TotalLengthTooLarge)
    );
    assert_eq!(b, old);
    let mut b = [0xa5; 23];
    let old = b;
    assert_eq!(
        complete(&mut b, &[]).map(|_| ()),
        Err(Ipv4PacketBuildError::BufferTooShort {
            required: 24,
            available: 23
        })
    );
    assert_eq!(b, old);
}

#[cfg(feature = "ethernet")]
mod ethernet_dispatch {
    use super::*;

    fn frame(ether_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![
            0,
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            (ether_type >> 8) as u8,
            ether_type as u8,
        ];
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn ipv4_dispatch_matches_ether_type_and_writes_through() {
        assert!(
            EthernetFrame::parse(&frame(0x0800, &BASIC[..20]))
                .unwrap()
                .ipv4()
                .unwrap()
                .is_some()
        );
        assert_eq!(
            EthernetFrame::parse(&frame(0x86dd, &BASIC[..20]))
                .unwrap()
                .ipv4(),
            Ok(None)
        );
        assert_eq!(
            EthernetFrame::parse(&frame(0x0800, &BASIC[..19]))
                .unwrap()
                .ipv4(),
            Err(ParseError::Truncated {
                minimum: 20,
                available: 19,
            })
        );

        let mut bytes = frame(0x0800, &BASIC[..20]);
        let mut ethernet = EthernetFrameMut::parse(&mut bytes).unwrap();
        ethernet.ipv4_mut().unwrap().unwrap().set_ttl(1);
        assert_eq!(ethernet.payload()[8], 1);
    }
}

#[cfg(feature = "icmpv4")]
mod icmpv4_dispatch {
    use super::*;

    fn packet(protocol: u8, fragment: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![
            0x45,
            0,
            0,
            (20 + payload.len()) as u8,
            0,
            0,
            (fragment >> 8) as u8,
            fragment as u8,
            64,
            protocol,
            0,
            0,
            192,
            0,
            2,
            1,
            192,
            0,
            2,
            2,
        ];
        bytes.extend_from_slice(payload);
        bytes
    }

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
}

#[cfg(feature = "udp")]
mod udp_dispatch {
    use super::*;

    fn packet(protocol: u8, fragment: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![
            0x45,
            0,
            0,
            (20 + payload.len()) as u8,
            0,
            0,
            (fragment >> 8) as u8,
            fragment as u8,
            64,
            protocol,
            0,
            0,
            192,
            0,
            2,
            1,
            192,
            0,
            2,
            2,
        ];
        bytes.extend_from_slice(payload);
        bytes
    }

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
}

#[cfg(feature = "tcp")]
mod tcp_dispatch {
    use super::*;

    fn packet(protocol: u8, fragment: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![
            0x45,
            0,
            0,
            (20 + payload.len()) as u8,
            0,
            0,
            (fragment >> 8) as u8,
            fragment as u8,
            64,
            protocol,
            0,
            0,
            192,
            0,
            2,
            1,
            192,
            0,
            2,
            2,
        ];
        bytes.extend_from_slice(payload);
        bytes
    }

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
}
