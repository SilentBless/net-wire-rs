use net_wire::quic::*;

#[test]
fn datagram_partitions_coalesced_protected_packets_and_terminal_short() {
    let bytes = [
        0xc0, 0, 0, 0, 1, 0, 0, 0, 2, 0xa1, 0xa2, // Initial
        0xd0, 0, 0, 0, 1, 0, 0, 2, 0xb2, 0xb3, // 0-RTT
        0xe0, 0, 0, 0, 1, 0, 0, 2, 0xc3, 0xc4, // Handshake
        0x40, 0xd4, 0xe5, // terminal short, one-byte DCID
    ];
    let datagram = QuicDatagram::parse(&bytes, Some(QuicShortHeaderContext::new(1))).unwrap();
    assert_eq!(datagram.as_bytes(), &bytes);

    let mut packets = datagram.packets();
    let initial = packets.next().unwrap().unwrap();
    let zero_rtt = packets.next().unwrap().unwrap();
    let handshake = packets.next().unwrap().unwrap();
    let short = packets.next().unwrap().unwrap();
    assert_eq!(initial.as_bytes(), &bytes[..11]);
    assert_eq!(zero_rtt.as_bytes(), &bytes[11..21]);
    assert_eq!(handshake.as_bytes(), &bytes[21..31]);
    assert_eq!(short.as_bytes(), &bytes[31..]);
    assert!(matches!(initial, QuicPacket::ProtectedLong(_)));
    assert!(matches!(short, QuicPacket::Short(_)));
    assert!(initial.is_long_header());
    assert!(!short.is_long_header());
    assert_eq!(packets.next(), None);
}

#[test]
fn datagram_long_only_needs_no_short_context() {
    let bytes = [0xd0, 0, 0, 0, 1, 0, 0, 2, 0xaa, 0xbb];
    let datagram = QuicDatagram::parse(&bytes, None).unwrap();
    let packet = datagram.packets().next().unwrap().unwrap();
    assert_eq!(packet.as_bytes(), &bytes);
    assert!(matches!(packet, QuicPacket::ProtectedLong(_)));
}

#[test]
fn datagram_short_without_context_is_rejected_and_iterator_fails_closed() {
    let bytes = [0x40, 0xaa];
    assert_eq!(
        QuicDatagram::parse(&bytes, None),
        Err(QuicPacketParseError::ShortHeaderContextRequired)
    );
    let mut packets = QuicPackets::new(&bytes, None);
    assert_eq!(
        packets.next(),
        Some(Err(QuicPacketParseError::ShortHeaderContextRequired))
    );
    assert_eq!(packets.next(), None);
    assert_eq!(packets.next(), None);
}

#[test]
fn datagram_middle_error_fails_closed_and_validation_rejects_it() {
    let bytes = [
        0xd0, 0, 0, 0, 1, 0, 0, 2, 0xaa, 0xbb, // valid 0-RTT
        0xd0, 0, 0, 0, 1, 0, 0, 3, 0xbb, // truncated 0-RTT
    ];
    let expected = QuicPacketParseError::Incomplete {
        required: 11,
        available: 9,
    };
    assert_eq!(QuicDatagram::parse(&bytes, None), Err(expected));
    let mut packets = QuicPackets::new(&bytes, None);
    assert!(packets.next().unwrap().is_ok());
    assert_eq!(packets.next(), Some(Err(expected)));
    assert_eq!(packets.next(), None);
}

#[test]
fn datagram_terminal_and_unknown_long_dispatches_preserve_complete_remainder() {
    let vn = [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let retry = [
        0xf0, 0, 0, 0, 1, 0, 0, 0xaa, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    ];
    let unknown = [0xf0, 0x0a, 0x0a, 0x0a, 0x0a, 1, 0x11, 1, 0x22, 0xde, 0xad];
    for (bytes, matcher) in [(&vn[..], 0), (&retry[..], 1), (&unknown[..], 2)] {
        let datagram = QuicDatagram::parse(bytes, None).unwrap();
        let mut packets = datagram.packets();
        let packet = packets.next().unwrap().unwrap();
        assert_eq!(packet.as_bytes(), bytes);
        match matcher {
            0 => assert!(matches!(packet, QuicPacket::VersionNegotiation(_))),
            1 => assert!(matches!(packet, QuicPacket::Retry(_))),
            _ => match packet {
                QuicPacket::UnknownLong(packet) => {
                    assert_eq!(packet.header().as_bytes(), &bytes[..9]);
                    assert_eq!(packet.header().version(), QuicVersion::new(0x0a0a_0a0a));
                    assert_eq!(packet.as_bytes(), bytes);
                }
                _ => panic!("expected opaque unknown-version long packet"),
            },
        }
        assert_eq!(packets.next(), None);
    }
    assert_eq!(
        QuicDatagram::parse(&[], None),
        Err(QuicPacketParseError::EmptyDatagram)
    );
}
