use net_wire::quic::*;

#[test]
fn protected_long_packets_map_v1_v2_and_bound_the_suffix() {
    let cases = [
        (
            &[0xc0, 0, 0, 0, 1, 0, 0, 0, 2, 0xaa, 0xbb, 0xfe][..],
            QuicLongPacketType::Initial,
            9,
        ),
        (
            &[0xd0, 0, 0, 0, 1, 0, 0, 2, 0xaa, 0xbb, 0xfe][..],
            QuicLongPacketType::ZeroRtt,
            8,
        ),
        (
            &[0xe0, 0, 0, 0, 1, 0, 0, 2, 0xaa, 0xbb, 0xfe][..],
            QuicLongPacketType::Handshake,
            8,
        ),
        (
            &[0xd0, 0x6b, 0x33, 0x43, 0xcf, 0, 0, 0, 2, 0xaa, 0xbb, 0xfe][..],
            QuicLongPacketType::Initial,
            9,
        ),
        (
            &[0xe0, 0x6b, 0x33, 0x43, 0xcf, 0, 0, 2, 0xaa, 0xbb, 0xfe][..],
            QuicLongPacketType::ZeroRtt,
            8,
        ),
        (
            &[0xf0, 0x6b, 0x33, 0x43, 0xcf, 0, 0, 2, 0xaa, 0xbb, 0xfe][..],
            QuicLongPacketType::Handshake,
            8,
        ),
    ];
    for (bytes, packet_type, packet_number_offset) in cases {
        let (packet, suffix) = QuicProtectedLongPacket::parse(bytes).unwrap();
        assert_eq!(packet.packet_type(), packet_type);
        assert_eq!(packet.as_bytes(), &bytes[..bytes.len() - 1]);
        assert_eq!(suffix, &[0xfe]);
        assert_eq!(packet.packet_number_offset(), packet_number_offset);
        assert_eq!(packet.protected_remainder(), &[0xaa, 0xbb]);
    }
}

#[test]
fn protected_initial_preserves_token_representations_and_empty_token_layout() {
    let empty = [0xc3, 0, 0, 0, 1, 0, 0, 0, 2, 0xaa, 0xbb];
    let (packet, suffix) = QuicProtectedLongPacket::parse(&empty).unwrap();
    assert_eq!(packet.token_length().unwrap().as_bytes(), &[0]);
    assert_eq!(packet.token(), Some(&[][..]));
    assert_eq!(packet.length().as_bytes(), &[2]);
    assert_eq!(packet.packet_number_offset(), 9);
    assert_eq!(packet.protected_remainder(), &[0xaa, 0xbb]);
    assert!(suffix.is_empty());

    let nonminimal = [
        0xc0, 0, 0, 0, 1, 0, 0, 0x40, 0x02, 0x10, 0x11, 0x40, 0x02, 0xaa, 0xbb,
    ];
    let (packet, suffix) = QuicProtectedLongPacket::parse(&nonminimal).unwrap();
    assert_eq!(packet.token_length().unwrap().as_bytes(), &[0x40, 0x02]);
    assert_eq!(packet.token(), Some(&[0x10, 0x11][..]));
    assert_eq!(packet.length().as_bytes(), &[0x40, 0x02]);
    assert!(!packet.token_length().unwrap().is_canonical());
    assert!(!packet.length().is_canonical());
    assert_eq!(packet.packet_number_offset(), 13);
    assert_eq!(packet.protected_remainder(), &[0xaa, 0xbb]);
    assert_eq!(packet.as_bytes(), &nonminimal);
    assert!(suffix.is_empty());
}

#[test]
fn protected_zero_rtt_and_handshake_have_no_token_and_ignore_low_bits() {
    for bytes in [
        &[0xdf, 0, 0, 0, 1, 0, 0, 2, 0xaa, 0xbb][..],
        &[0xef, 0, 0, 0, 1, 0, 0, 2, 0xaa, 0xbb][..],
    ] {
        let (packet, suffix) = QuicProtectedLongPacket::parse(bytes).unwrap();
        assert_eq!(packet.token_length(), None);
        assert_eq!(packet.token(), None);
        assert_eq!(packet.length().value(), 2);
        assert_eq!(packet.packet_number_offset(), 8);
        assert_eq!(packet.protected_remainder(), &[0xaa, 0xbb]);
        assert_eq!(packet.as_bytes(), bytes);
        assert!(suffix.is_empty());
    }
}

#[test]
fn protected_long_packet_semantic_errors_preserve_invariant_header_permissiveness() {
    let fixed_clear = [0x80, 0, 0, 0, 1, 0, 0, 0, 1, 0xaa];
    assert_eq!(
        QuicProtectedLongPacket::parse(&fixed_clear),
        Err(QuicPacketParseError::FixedBitNotSet { first_byte: 0x80 })
    );
    assert!(QuicLongHeader::parse(&fixed_clear).is_ok());

    let mut destination_21 = [0u8; 50];
    destination_21[..6].copy_from_slice(&[0xc0, 0, 0, 0, 1, 21]);
    destination_21[6..27].fill(1);
    destination_21[27] = 0;
    assert_eq!(
        QuicProtectedLongPacket::parse(&destination_21),
        Err(QuicPacketParseError::ConnectionIdTooLong {
            field: QuicConnectionIdField::Destination,
            length: 21,
        })
    );
    assert!(QuicLongHeader::parse(&destination_21).is_ok());

    let mut source_21 = [0u8; 50];
    source_21[..7].copy_from_slice(&[0xc0, 0, 0, 0, 1, 0, 21]);
    source_21[7..28].fill(2);
    assert_eq!(
        QuicProtectedLongPacket::parse(&source_21),
        Err(QuicPacketParseError::ConnectionIdTooLong {
            field: QuicConnectionIdField::Source,
            length: 21,
        })
    );

    let retry = [0xf0, 0, 0, 0, 1, 0, 0];
    assert_eq!(
        QuicProtectedLongPacket::parse(&retry),
        Err(QuicPacketParseError::NotLengthDelimited {
            packet_type: QuicLongPacketType::Retry,
        })
    );
    let negotiation = [0xc0, 0, 0, 0, 0, 0, 0];
    assert_eq!(
        QuicProtectedLongPacket::parse(&negotiation),
        Err(QuicPacketParseError::UnsupportedVersion {
            version: QuicVersion::NEGOTIATION,
        })
    );
    let unknown = [0xc0, 0xde, 0xad, 0xbe, 0xef, 0, 0];
    assert_eq!(
        QuicProtectedLongPacket::parse(&unknown),
        Err(QuicPacketParseError::UnsupportedVersion {
            version: QuicVersion::new(0xdead_beef),
        })
    );
    assert!(QuicLongHeader::parse(&unknown).is_ok());
}

#[test]
fn protected_long_packet_truncations_and_minimum_lengths_report_exact_bounds() {
    for (bytes, required) in [
        (&[0xc0, 0, 0, 0, 1, 0, 0, 0x40][..], 9),
        (&[0xc0, 0, 0, 0, 1, 0, 0, 2, 0xaa][..], 10),
        (&[0xc0, 0, 0, 0, 1, 0, 0, 0, 0x40][..], 10),
        (&[0xc0, 0, 0, 0, 1, 0, 0, 0, 3, 0xaa][..], 12),
    ] {
        assert_eq!(
            QuicProtectedLongPacket::parse(bytes),
            Err(QuicPacketParseError::Incomplete {
                required,
                available: bytes.len(),
            })
        );
    }
    for (bytes, actual) in [
        (&[0xc0, 0, 0, 0, 1, 0, 0, 0, 0][..], 0),
        (&[0xc0, 0, 0, 0, 1, 0, 0, 0, 1][..], 1),
        (&[0xd0, 0, 0, 0, 1, 0, 0, 0][..], 0),
        (&[0xd0, 0, 0, 0, 1, 0, 0, 1][..], 1),
    ] {
        assert_eq!(
            QuicProtectedLongPacket::parse(bytes),
            Err(QuicPacketParseError::ProtectedRemainderTooShort { minimum: 2, actual })
        );
    }
}

#[cfg(target_pointer_width = "32")]
#[test]
fn protected_long_packet_rejects_unrepresentable_lengths() {
    let bytes = [
        0xd0, 0, 0, 0, 1, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];
    assert_eq!(
        QuicProtectedLongPacket::parse(&bytes),
        Err(QuicPacketParseError::LengthNotRepresentable {
            value: (1u64 << 62) - 1,
        })
    );
}

#[test]
fn protected_long_packet_parses_exactly() {
    let bytes = [0xd0, 0, 0, 0, 1, 0, 0, 2, 0xaa, 0xbb];
    let (packet, _) = QuicProtectedLongPacket::parse(&bytes).unwrap();
    assert_eq!(packet.version(), QuicVersion::V1);
}
