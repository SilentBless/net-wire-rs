use net_wire::quic::*;

#[test]
fn unprotected_long_headers_preserve_v1_v2_types_and_exact_packet_numbers() {
    let cases = [
        (
            &[0xd3, 0, 0, 0, 1, 0, 0, 4, 0xaa, 0xbb, 0xcc, 0xdd][..],
            0xd0,
            &[0x12][..],
            QuicPacketNumberLen::One,
            0x12,
            0,
            QuicLongPacketType::ZeroRtt,
            QuicVersion::V1,
        ),
        (
            &[0xd0, 0, 0, 0, 1, 0, 0, 4, 0xaa, 0xbb, 0xcc, 0xdd][..],
            0xd5,
            &[0x12, 0x34][..],
            QuicPacketNumberLen::Two,
            0x1234,
            1,
            QuicLongPacketType::ZeroRtt,
            QuicVersion::V1,
        ),
        (
            &[0xd1, 0, 0, 0, 1, 0, 0, 4, 0xaa, 0xbb, 0xcc, 0xdd][..],
            0xda,
            &[0x12, 0x34, 0x56][..],
            QuicPacketNumberLen::Three,
            0x123456,
            2,
            QuicLongPacketType::ZeroRtt,
            QuicVersion::V1,
        ),
        (
            &[
                0xe2, 0x6b, 0x33, 0x43, 0xcf, 0, 0, 4, 0xaa, 0xbb, 0xcc, 0xdd,
            ][..],
            0xef,
            &[0x12, 0x34, 0x56, 0x78][..],
            QuicPacketNumberLen::Four,
            0x12345678,
            3,
            QuicLongPacketType::ZeroRtt,
            QuicVersion::V2,
        ),
    ];
    for (bytes, first_byte, packet_number_bytes, length, value, reserved, packet_type, version) in
        cases
    {
        let (protected, _) = QuicProtectedLongPacket::parse(bytes).unwrap();
        let overlay =
            QuicUnprotectedLongHeader::new(protected, first_byte, packet_number_bytes).unwrap();
        assert_eq!(overlay.protected_packet(), protected);
        assert_eq!(overlay.unprotected_first_byte(), first_byte);
        assert_eq!(overlay.packet_number().as_bytes(), packet_number_bytes);
        assert_eq!(overlay.packet_number().encoded_len(), length);
        assert_eq!(overlay.packet_number().value(), value);
        assert_eq!(overlay.raw_reserved_bits(), reserved);
        assert_eq!(overlay.protected_packet().packet_type(), packet_type);
        assert_eq!(overlay.protected_packet().version(), version);
    }
}

#[test]
fn unprotected_short_headers_use_separate_packet_number_storage() {
    let bytes = [0x63, 0x44, 0xaa, 0xbb, 0xcc, 0xdd];
    let protected = QuicShortHeader::parse(&bytes, QuicShortHeaderContext::new(1)).unwrap();
    let cases = [
        (0x60, &[0x12][..], QuicPacketNumberLen::One, 0x12, 0),
        (0x6d, &[0x12, 0x34][..], QuicPacketNumberLen::Two, 0x1234, 1),
        (
            0x72,
            &[0x12, 0x34, 0x56][..],
            QuicPacketNumberLen::Three,
            0x123456,
            2,
        ),
        (
            0x7f,
            &[0x12, 0x34, 0x56, 0x78][..],
            QuicPacketNumberLen::Four,
            0x12345678,
            3,
        ),
    ];
    for (first_byte, packet_number_bytes, length, value, reserved) in cases {
        let overlay =
            QuicUnprotectedShortHeader::new(protected, first_byte, packet_number_bytes).unwrap();
        assert_eq!(overlay.protected_packet(), protected);
        assert_eq!(overlay.unprotected_first_byte(), first_byte);
        assert_eq!(overlay.packet_number().as_bytes(), packet_number_bytes);
        assert_eq!(overlay.packet_number().encoded_len(), length);
        assert_eq!(overlay.packet_number().value(), value);
        assert_eq!(overlay.raw_reserved_bits(), reserved);
        assert!(overlay.spin_bit());
        assert_eq!(overlay.key_phase(), first_byte & 0x04 != 0);
    }
}

#[test]
fn unprotected_overlays_reject_preserved_bits_before_other_inputs() {
    let long_bytes = [0xd3, 0, 0, 0, 1, 0, 0, 2, 0xaa, 0xbb];
    let long_before = long_bytes;
    let (long, _) = QuicProtectedLongPacket::parse(&long_bytes).unwrap();
    assert_eq!(
        QuicUnprotectedLongHeader::new(long, 0x53, &[]),
        Err(QuicUnprotectedHeaderError::PreservedBitsMismatch {
            protected_first_byte: 0xd3,
            unprotected_first_byte: 0x53,
            preserved_mask: 0xf0,
        })
    );
    assert_eq!(long_bytes, long_before);

    let short_bytes = [0x63, 0x44, 0xaa];
    let short_before = short_bytes;
    let short = QuicShortHeader::parse(&short_bytes, QuicShortHeaderContext::new(1)).unwrap();
    assert_eq!(
        QuicUnprotectedShortHeader::new(short, 0x43, &[]),
        Err(QuicUnprotectedHeaderError::PreservedBitsMismatch {
            protected_first_byte: 0x63,
            unprotected_first_byte: 0x43,
            preserved_mask: 0xe0,
        })
    );
    assert_eq!(short_bytes, short_before);
}

#[test]
fn unprotected_overlays_report_packet_number_width_and_physical_bounds() {
    let long_bytes = [0xd0, 0, 0, 0, 1, 0, 0, 2, 0xaa, 0xbb];
    let (long, _) = QuicProtectedLongPacket::parse(&long_bytes).unwrap();
    assert_eq!(
        QuicUnprotectedLongHeader::new(long, 0xd1, &[0x12]),
        Err(QuicUnprotectedHeaderError::PacketNumberLengthMismatch {
            expected: 2,
            supplied: 1,
        })
    );
    assert_eq!(
        QuicUnprotectedLongHeader::new(long, 0xd3, &[0x12, 0x34, 0x56, 0x78]),
        Err(QuicUnprotectedHeaderError::ProtectedRemainderTooShort {
            required: 4,
            available: 2,
        })
    );

    let short_bytes = [0x60, 0x44, 0xaa, 0xbb];
    let short = QuicShortHeader::parse(&short_bytes, QuicShortHeaderContext::new(1)).unwrap();
    assert_eq!(
        QuicUnprotectedShortHeader::new(short, 0x61, &[0x12]),
        Err(QuicUnprotectedHeaderError::PacketNumberLengthMismatch {
            expected: 2,
            supplied: 1,
        })
    );
    assert_eq!(
        QuicUnprotectedShortHeader::new(short, 0x63, &[0x12, 0x34, 0x56, 0x78]),
        Err(QuicUnprotectedHeaderError::ProtectedRemainderTooShort {
            required: 4,
            available: 2,
        })
    );
}

#[test]
fn unprotected_overlay_types_expose_packet_number_widths_and_errors() {
    assert_eq!(QuicPacketNumberLen::Four.byte_len(), 4);
    let error = QuicUnprotectedHeaderError::PacketNumberLengthMismatch {
        expected: 1,
        supplied: 2,
    };
    assert_eq!(error, error);
    assert_eq!(
        error.to_string(),
        "QUIC unprotected packet-number width mismatch: need 1 bytes, have 2"
    );
}
