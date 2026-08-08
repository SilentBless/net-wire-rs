use net_wire::quic::*;

#[test]
fn exposes_width_limits_versions_and_packet_type_mappings() {
    assert_eq!(QuicVarIntLen::One.byte_len(), 1);
    assert_eq!(QuicVarIntLen::Two.max_value(), 16_383);
    assert_eq!(QuicVarIntLen::Four.max_value(), 1_073_741_823);
    assert_eq!(QuicVarIntLen::Eight.max_value(), (1u64 << 62) - 1);

    assert_eq!(QuicVersion::NEGOTIATION.raw(), 0);
    assert_eq!(QuicVersion::V1.raw(), 1);
    assert_eq!(QuicVersion::V2.raw(), 0x6b33_43cf);
    assert!(QuicVersion::new(0x0a0a_0a0a).is_reserved());
    assert!(QuicVersion::new(0xfafa_fafa).is_reserved());
    assert!(!QuicVersion::V1.is_reserved());
    assert!(!QuicVersion::new(0x0a0a_0a0b).is_reserved());

    let v1 = [
        (0, QuicLongPacketType::Initial),
        (1, QuicLongPacketType::ZeroRtt),
        (2, QuicLongPacketType::Handshake),
        (3, QuicLongPacketType::Retry),
    ];
    let v2 = [
        (0, QuicLongPacketType::Retry),
        (1, QuicLongPacketType::Initial),
        (2, QuicLongPacketType::ZeroRtt),
        (3, QuicLongPacketType::Handshake),
    ];
    for (version, mappings) in [(QuicVersion::V1, v1), (QuicVersion::V2, v2)] {
        for (raw, packet_type) in mappings {
            assert_eq!(
                QuicLongPacketType::from_raw(version, raw),
                Some(packet_type)
            );
            assert_eq!(packet_type.raw_type(version), Some(raw));
        }
    }
    assert_eq!(QuicLongPacketType::from_raw(QuicVersion::V1, 4), None);
    assert_eq!(QuicLongPacketType::from_raw(QuicVersion::new(7), 0), None);
    assert_eq!(
        QuicLongPacketType::Initial.raw_type(QuicVersion::new(7)),
        None
    );
}

#[test]
fn long_headers_preserve_invariant_boundaries_and_arbitrary_cid_lengths() {
    let zero = [0x80, 0, 0, 0, 1, 0, 0, 0xaa];
    let parsed = QuicLongHeader::parse(&zero).unwrap();
    assert_eq!(parsed.first_byte(), 0x80);
    assert!(!parsed.has_fixed_bit());
    assert_eq!(parsed.version(), QuicVersion::V1);
    assert!(parsed.destination_connection_id().is_empty());
    assert!(parsed.source_connection_id().is_empty());
    assert_eq!(parsed.as_bytes(), &zero[..7]);
    assert_eq!(parsed.version_specific(), &[0xaa]);

    let normal = [0xd3, 0, 0, 0, 1, 2, 0x10, 0x11, 3, 0x20, 0x21, 0x22, 0xfe];
    let parsed = QuicLongHeader::parse(&normal).unwrap();
    assert!(parsed.has_fixed_bit());
    assert_eq!(parsed.raw_type_bits(), 1);
    assert_eq!(parsed.destination_connection_id().as_bytes(), &[0x10, 0x11]);
    assert_eq!(
        parsed.source_connection_id().as_bytes(),
        &[0x20, 0x21, 0x22]
    );
    assert_eq!(parsed.as_bytes(), &normal[..12]);
    assert_eq!(parsed.version_specific(), &[0xfe]);

    let mut twenty = [0u8; 47];
    twenty[..6].copy_from_slice(&[0xc0, 0, 0, 0, 1, 20]);
    twenty[6..26].fill(0x11);
    twenty[26] = 20;
    twenty[27..47].fill(0x22);
    let parsed = QuicLongHeader::parse(&twenty).unwrap();
    assert_eq!(parsed.destination_connection_id().len(), 20);
    assert_eq!(parsed.source_connection_id().len(), 20);
    assert_eq!(parsed.as_bytes(), &twenty);

    let mut oversized = [0u8; 517];
    oversized[..6].copy_from_slice(&[0xc0, 0x0a, 0x0a, 0x0a, 0x0a, 255]);
    oversized[6..261].fill(0x33);
    oversized[261] = 255;
    oversized[262..517].fill(0x44);
    let parsed = QuicLongHeader::parse(&oversized).unwrap();
    assert_eq!(parsed.version(), QuicVersion::new(0x0a0a_0a0a));
    assert_eq!(parsed.destination_connection_id().len(), 255);
    assert_eq!(parsed.source_connection_id().len(), 255);
    assert_eq!(parsed.as_bytes(), &oversized);
    assert!(parsed.version_specific().is_empty());
}

#[test]
fn long_headers_keep_raw_type_bits_but_only_classify_known_versions() {
    for (version, expected) in [
        (
            QuicVersion::V1,
            [
                QuicLongPacketType::Initial,
                QuicLongPacketType::ZeroRtt,
                QuicLongPacketType::Handshake,
                QuicLongPacketType::Retry,
            ],
        ),
        (
            QuicVersion::V2,
            [
                QuicLongPacketType::Retry,
                QuicLongPacketType::Initial,
                QuicLongPacketType::ZeroRtt,
                QuicLongPacketType::Handshake,
            ],
        ),
    ] {
        for (raw_type, packet_type) in expected.into_iter().enumerate() {
            let mut bytes = [0u8; 7];
            bytes[0] = 0xc0 | ((raw_type as u8) << 4);
            bytes[1..5].copy_from_slice(&version.raw().to_be_bytes());
            let parsed = QuicLongHeader::parse(&bytes).unwrap();
            assert_eq!(parsed.raw_type_bits(), raw_type as u8);
            assert_eq!(parsed.long_packet_type(), Some(packet_type));
        }
    }

    let unknown = [0xf0, 0xde, 0xad, 0xbe, 0xef, 0, 0, 1, 2];
    let parsed = QuicLongHeader::parse(&unknown).unwrap();
    assert_eq!(parsed.raw_type_bits(), 3);
    assert_eq!(parsed.version().raw(), 0xdead_beef);
    assert_eq!(parsed.long_packet_type(), None);
    assert_eq!(parsed.as_bytes(), &unknown[..7]);
    assert_eq!(parsed.version_specific(), &[1, 2]);
}

#[test]
fn long_header_forms_and_truncations_report_exact_bounds() {
    assert_eq!(
        QuicLongHeader::parse(&[0x40]),
        Err(QuicPacketParseError::WrongHeaderForm {
            expected_long: true,
            first_byte: 0x40,
        })
    );
    for (input, required) in [
        (&[0x80][..], 5),
        (&[0x80, 0, 0, 0, 1][..], 6),
        (&[0x80, 0, 0, 0, 1, 2, 1][..], 8),
        (&[0x80, 0, 0, 0, 1, 0][..], 7),
        (&[0x80, 0, 0, 0, 1, 0, 2, 1][..], 9),
    ] {
        assert_eq!(
            QuicLongHeader::parse(input),
            Err(QuicPacketParseError::Incomplete {
                required,
                available: input.len(),
            })
        );
    }

    let mut cid_21 = [0u8; 49];
    cid_21[..6].copy_from_slice(&[0xc0, 0, 0, 0, 1, 21]);
    cid_21[6..27].fill(1);
    cid_21[27] = 21;
    cid_21[28..49].fill(2);
    assert!(QuicLongHeader::parse(&cid_21).is_ok());
}

#[test]
fn short_headers_use_only_caller_context_and_preserve_protected_remainder() {
    let zero = [0x03, 0xaa, 0xbb];
    let parsed = QuicShortHeader::parse(&zero, QuicShortHeaderContext::new(0)).unwrap();
    assert_eq!(parsed.first_byte(), 0x03);
    assert!(!parsed.has_fixed_bit());
    assert!(parsed.destination_connection_id().is_empty());
    assert_eq!(parsed.protected_remainder(), &[0xaa, 0xbb]);
    assert_eq!(parsed.as_bytes(), &zero);

    let normal = [0x7f, 0x10, 0x11, 0x12, 0xfe, 0xed];
    let context = QuicShortHeaderContext::new(3);
    assert_eq!(context.destination_connection_id_len(), 3);
    let parsed = QuicShortHeader::parse(&normal, context).unwrap();
    assert!(parsed.has_fixed_bit());
    assert_eq!(
        parsed.destination_connection_id().as_bytes(),
        &[0x10, 0x11, 0x12]
    );
    assert_eq!(parsed.protected_remainder(), &[0xfe, 0xed]);
    assert_eq!(parsed.as_bytes(), &normal);

    let mut twenty = [0u8; 23];
    twenty[0] = 0x40;
    twenty[1..21].fill(0x55);
    twenty[21..].copy_from_slice(&[0x99, 0x88]);
    let parsed = QuicShortHeader::parse(&twenty, QuicShortHeaderContext::new(20)).unwrap();
    assert_eq!(parsed.destination_connection_id().len(), 20);
    assert_eq!(parsed.protected_remainder(), &[0x99, 0x88]);
}

#[test]
fn short_header_forms_and_bounds_are_explicit() {
    assert_eq!(
        QuicShortHeader::parse(&[0xc0], QuicShortHeaderContext::new(0)),
        Err(QuicPacketParseError::WrongHeaderForm {
            expected_long: false,
            first_byte: 0xc0,
        })
    );
    assert_eq!(
        QuicShortHeader::parse(&[], QuicShortHeaderContext::new(0)),
        Err(QuicPacketParseError::Incomplete {
            required: 1,
            available: 0,
        })
    );
    assert_eq!(
        QuicShortHeader::parse(&[0x40, 1], QuicShortHeaderContext::new(2)),
        Err(QuicPacketParseError::Incomplete {
            required: 3,
            available: 2,
        })
    );
    assert_eq!(
        QuicShortHeader::parse(&[0x40], QuicShortHeaderContext::new(usize::MAX)),
        Err(QuicPacketParseError::LengthOverflow {
            offset: 1,
            length: usize::MAX,
        })
    );
}
