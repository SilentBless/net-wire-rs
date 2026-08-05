use net_wire::*;

#[test]
fn parses_rfc_9000_appendix_a_1_values_and_exact_views() {
    let fixtures = [
        (37, &[0x25][..], QuicVarIntLen::One),
        (15_293, &[0x7b, 0xbd][..], QuicVarIntLen::Two),
        (
            494_878_333,
            &[0x9d, 0x7f, 0x3e, 0x7d][..],
            QuicVarIntLen::Four,
        ),
        (
            151_288_809_941_952_652,
            &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c][..],
            QuicVarIntLen::Eight,
        ),
    ];

    for (value, bytes, length) in fixtures {
        let mut input = [0xee; 9];
        input[..bytes.len()].copy_from_slice(bytes);
        let parsed = QuicVarInt::parse(&input).unwrap();
        assert_eq!(parsed.value(), value);
        assert_eq!(parsed.as_bytes(), bytes);
        assert_eq!(parsed.encoded_len(), length);
        assert_eq!(parsed.byte_len(), bytes.len());
        assert!(parsed.is_canonical());
    }
}

#[test]
fn parses_boundaries_noncanonical_values_and_all_truncations() {
    let boundaries = [
        (63, &[0x3f][..], QuicVarIntLen::One),
        (64, &[0x40, 0x40][..], QuicVarIntLen::Two),
        (16_383, &[0x7f, 0xff][..], QuicVarIntLen::Two),
        (16_384, &[0x80, 0x00, 0x40, 0x00][..], QuicVarIntLen::Four),
        (
            1_073_741_823,
            &[0xbf, 0xff, 0xff, 0xff][..],
            QuicVarIntLen::Four,
        ),
        (
            1_073_741_824,
            &[0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00][..],
            QuicVarIntLen::Eight,
        ),
        (
            (1u64 << 62) - 1,
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..],
            QuicVarIntLen::Eight,
        ),
    ];
    for (value, bytes, length) in boundaries {
        let parsed = QuicVarInt::parse(bytes).unwrap();
        assert_eq!((parsed.value(), parsed.encoded_len()), (value, length));
        assert!(parsed.is_canonical());
    }

    let noncanonical = QuicVarInt::parse(&[0x40, 0x25]).unwrap();
    assert_eq!(noncanonical.value(), 37);
    assert_eq!(noncanonical.encoded_len(), QuicVarIntLen::Two);
    assert!(!noncanonical.is_canonical());

    assert_eq!(
        QuicVarInt::parse(&[]),
        Err(QuicVarIntParseError::Incomplete {
            required: 1,
            available: 0
        })
    );
    for (input, required) in [
        (&[0x40][..], 2),
        (&[0x80, 0][..], 4),
        (&[0xc0, 0, 0][..], 8),
    ] {
        assert_eq!(
            QuicVarInt::parse(input),
            Err(QuicVarIntParseError::Incomplete {
                required,
                available: input.len()
            })
        );
    }
}

#[test]
fn builds_canonical_and_explicit_widths_atomically() {
    let fixtures = [
        (37, &[0x25][..]),
        (15_293, &[0x7b, 0xbd][..]),
        (494_878_333, &[0x9d, 0x7f, 0x3e, 0x7d][..]),
        (
            151_288_809_941_952_652,
            &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c][..],
        ),
    ];
    for (value, expected) in fixtures {
        let mut destination = [0xa5; 9];
        let built = QuicVarIntBuilder::new(&mut destination, value)
            .build()
            .unwrap();
        assert_eq!(built.as_bytes(), expected);
        assert_eq!(destination[expected.len()], 0xa5);
    }

    let mut destination = [0xa5; 3];
    let built = QuicVarIntBuilder::new(&mut destination, 37)
        .with_len(QuicVarIntLen::Two)
        .build()
        .unwrap();
    assert_eq!(built.as_bytes(), &[0x40, 0x25]);
    assert_eq!(destination[2], 0xa5);

    let mut failures = [0xa5; 8];
    let before = failures;
    assert_eq!(
        QuicVarIntBuilder::new(&mut failures, 1u64 << 62).build(),
        Err(QuicVarIntBuildError::ValueTooLarge { value: 1u64 << 62 })
    );
    assert_eq!(failures, before);
    assert_eq!(
        QuicVarIntBuilder::new(&mut failures, 64)
            .with_len(QuicVarIntLen::One)
            .build(),
        Err(QuicVarIntBuildError::WidthTooSmall {
            length: QuicVarIntLen::One,
            value: 64
        })
    );
    assert_eq!(failures, before);
    assert_eq!(
        QuicVarIntBuilder::new(&mut failures[..1], 64).build(),
        Err(QuicVarIntBuildError::BufferTooShort {
            required: 2,
            available: 1
        })
    );
    assert_eq!(failures, before);
}

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
fn protected_long_packet_is_reexported_from_the_crate_root() {
    let bytes = [0xd0, 0, 0, 0, 1, 0, 0, 2, 0xaa, 0xbb];
    let (packet, _) = QuicProtectedLongPacket::parse(&bytes).unwrap();
    assert_eq!(packet.version(), QuicVersion::V1);
}

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
fn unprotected_overlay_types_are_reexported_from_the_crate_root() {
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

#[test]
fn version_negotiation_owns_complete_datagram_and_exact_versions() {
    let bytes = [
        0x83, 0, 0, 0, 0, 0, 0, // invariant header
        0, 0, 0, 0, // raw zero
        0, 0, 0, 1, // v1
        0x6b, 0x33, 0x43, 0xcf, // v2
        0xde, 0xad, 0xbe, 0xef, // unknown
        0x0a, 0x0a, 0x0a, 0x0a, // reserved
    ];
    let packet = QuicVersionNegotiationPacket::parse(&bytes).unwrap();
    assert!(!packet.header().has_fixed_bit());
    assert_eq!(packet.header().first_byte(), 0x83);
    assert_eq!(packet.header().as_bytes(), &bytes[..7]);
    assert_eq!(packet.version_list_bytes(), &bytes[7..]);
    assert_eq!(packet.as_bytes(), &bytes);

    let mut versions = packet.versions();
    assert_eq!(versions.len(), 5);
    assert_eq!(versions.size_hint(), (5, Some(5)));
    assert_eq!(versions.next(), Some(QuicVersion::NEGOTIATION));
    assert_eq!(versions.next(), Some(QuicVersion::V1));
    assert_eq!(versions.next(), Some(QuicVersion::V2));
    assert_eq!(versions.next(), Some(QuicVersion::new(0xdead_beef)));
    assert_eq!(versions.next(), Some(QuicVersion::new(0x0a0a_0a0a)));
    assert_eq!(versions.len(), 0);
    assert_eq!(versions.next(), None);
    assert_eq!(versions.next(), None);

    let mut twenty = [0u8; 51];
    twenty[..6].copy_from_slice(&[0x80, 0, 0, 0, 0, 20]);
    twenty[6..26].fill(0x11);
    twenty[26] = 20;
    twenty[27..47].fill(0x22);
    twenty[47..].copy_from_slice(&[0, 0, 0, 1]);
    let packet = QuicVersionNegotiationPacket::parse(&twenty).unwrap();
    assert_eq!(packet.header().destination_connection_id().len(), 20);
    assert_eq!(packet.header().source_connection_id().len(), 20);
    assert_eq!(packet.version_list_bytes(), &[0, 0, 0, 1]);

    let mut oversized = [0u8; 521];
    oversized[..6].copy_from_slice(&[0x80, 0, 0, 0, 0, 255]);
    oversized[6..261].fill(0x33);
    oversized[261] = 255;
    oversized[262..517].fill(0x44);
    oversized[517..].copy_from_slice(&[0, 0, 0, 0]);
    let packet = QuicVersionNegotiationPacket::parse(&oversized).unwrap();
    assert_eq!(packet.header().destination_connection_id().len(), 255);
    assert_eq!(packet.header().source_connection_id().len(), 255);
    assert_eq!(packet.versions().next(), Some(QuicVersion::NEGOTIATION));
}

#[test]
fn version_negotiation_rejects_wrong_version_empty_and_misaligned_lists() {
    assert_eq!(
        QuicVersionNegotiationPacket::parse(&[0x80, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1]),
        Err(QuicPacketParseError::WrongVersion {
            version: QuicVersion::V1,
        })
    );
    assert_eq!(
        QuicVersionNegotiationPacket::parse(&[0x80, 0, 0, 0, 0, 0, 0]),
        Err(QuicPacketParseError::EmptyVersionList)
    );
    assert_eq!(
        QuicVersionNegotiationPacket::parse(&[0x80, 0, 0, 0, 0, 0, 0, 1, 2, 3]),
        Err(QuicPacketParseError::MisalignedVersionList { length: 3 })
    );
}

#[test]
fn retry_views_v1_v2_and_terminal_errors_are_exact() {
    let v1 = [
        0xf5, 0, 0, 0, 1, 0, 0, 0x91, 0x92, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    ];
    let packet = QuicRetryPacket::parse(&v1).unwrap();
    assert_eq!(packet.version(), QuicVersion::V1);
    assert_eq!(packet.packet_type(), QuicLongPacketType::Retry);
    assert_eq!(packet.header().first_byte(), 0xf5);
    assert_eq!(packet.token(), &[0x91, 0x92]);
    assert_eq!(packet.integrity_tag(), &v1[9..]);
    assert_eq!(packet.as_bytes(), &v1);

    let v2 = [
        0xcf, 0x6b, 0x33, 0x43, 0xcf, 0, 0, 0x99, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
        15,
    ];
    let packet = QuicRetryPacket::parse(&v2).unwrap();
    assert_eq!(packet.version(), QuicVersion::V2);
    assert_eq!(packet.token(), &[0x99]);
    assert_eq!(packet.integrity_tag(), &v2[8..]);

    assert_eq!(
        QuicRetryPacket::parse(&[0xb0, 0, 0, 0, 1, 0, 0]),
        Err(QuicPacketParseError::FixedBitNotSet { first_byte: 0xb0 })
    );
    assert_eq!(
        QuicRetryPacket::parse(&[0xc0, 0, 0, 0, 1, 0, 0]),
        Err(QuicPacketParseError::NotRetry {
            packet_type: QuicLongPacketType::Initial,
        })
    );
    assert_eq!(
        QuicRetryPacket::parse(&[0xc0, 0, 0, 0, 0, 0, 0]),
        Err(QuicPacketParseError::UnsupportedVersion {
            version: QuicVersion::NEGOTIATION,
        })
    );
    assert_eq!(
        QuicRetryPacket::parse(&[0xc0, 0xde, 0xad, 0xbe, 0xef, 0, 0]),
        Err(QuicPacketParseError::UnsupportedVersion {
            version: QuicVersion::new(0xdead_beef),
        })
    );

    let mut destination_21 = [0u8; 28];
    destination_21[..6].copy_from_slice(&[0xf0, 0, 0, 0, 1, 21]);
    destination_21[6..27].fill(1);
    destination_21[27] = 0;
    assert_eq!(
        QuicRetryPacket::parse(&destination_21),
        Err(QuicPacketParseError::ConnectionIdTooLong {
            field: QuicConnectionIdField::Destination,
            length: 21,
        })
    );
    let mut source_21 = [0u8; 28];
    source_21[..7].copy_from_slice(&[0xf0, 0, 0, 0, 1, 0, 21]);
    source_21[7..].fill(2);
    assert_eq!(
        QuicRetryPacket::parse(&source_21),
        Err(QuicPacketParseError::ConnectionIdTooLong {
            field: QuicConnectionIdField::Source,
            length: 21,
        })
    );
}

#[test]
fn retry_requires_nonempty_token_and_full_terminal_tag() {
    let mut short = [0u8; 22];
    short[..7].copy_from_slice(&[0xf0, 0, 0, 0, 1, 0, 0]);
    assert_eq!(
        QuicRetryPacket::parse(&short),
        Err(QuicPacketParseError::Incomplete {
            required: 23,
            available: 22,
        })
    );

    let empty_token = [
        0xf0, 0, 0, 0, 1, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    ];
    assert_eq!(
        QuicRetryPacket::parse(&empty_token),
        Err(QuicPacketParseError::EmptyRetryToken)
    );
    let one_token = [
        0xf0, 0, 0, 0, 1, 0, 0, 0xaa, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    ];
    let packet = QuicRetryPacket::parse(&one_token).unwrap();
    assert_eq!(packet.token(), &[0xaa]);
    assert_eq!(packet.integrity_tag(), &one_token[8..]);
}

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
fn datagram_long_only_needs_no_short_context_and_root_facade_is_exact() {
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

#[test]
fn builds_version_negotiation_packets_exactly_and_preserves_suffix() {
    let versions = [
        QuicVersion::V1,
        QuicVersion::NEGOTIATION,
        QuicVersion::new(0x0a0a_0a0a),
        QuicVersion::new(0xdead_beef),
        QuicVersion::V1,
    ];
    let mut destination = [0xa5; 64];
    let packet = QuicVersionNegotiationPacketBuilder::new(
        &mut destination,
        0x12,
        QuicConnectionId::new(&[0x10, 0x11]),
        QuicConnectionId::new(&[0x20]),
        &versions,
    )
    .build()
    .unwrap();
    assert_eq!(packet.as_bytes()[0], 0x92);
    assert_eq!(packet.header().version(), QuicVersion::NEGOTIATION);
    assert_eq!(
        packet.header().destination_connection_id().as_bytes(),
        &[0x10, 0x11]
    );
    assert_eq!(packet.header().source_connection_id().as_bytes(), &[0x20]);
    assert_eq!(packet.versions().collect::<std::vec::Vec<_>>(), versions);
    assert_eq!(packet.as_bytes().len(), 30);
    assert_eq!(destination[30], 0xa5);

    let mut empty_ids = [0; 11];
    let packet = QuicVersionNegotiationPacketBuilder::new(
        &mut empty_ids,
        0,
        QuicConnectionId::new(&[]),
        QuicConnectionId::new(&[]),
        &[QuicVersion::V2],
    )
    .build()
    .unwrap();
    assert_eq!(
        packet.as_bytes(),
        &[0x80, 0, 0, 0, 0, 0, 0, 0x6b, 0x33, 0x43, 0xcf]
    );
}

#[test]
fn builds_retry_v1_and_v2_exactly_and_preserves_suffix() {
    let tag = [0x55; 16];
    for (version, first_byte) in [(QuicVersion::V1, 0xf9), (QuicVersion::V2, 0xc9)] {
        let mut destination = [0xa5; 64];
        let packet = QuicRetryPacketBuilder::new(
            &mut destination,
            version,
            9,
            QuicConnectionId::new(&[1, 2]),
            QuicConnectionId::new(&[3]),
            &[4, 5, 6],
            &tag,
        )
        .build()
        .unwrap();
        assert_eq!(packet.as_bytes()[0], first_byte);
        assert_eq!(packet.version(), version);
        assert_eq!(packet.packet_type(), QuicLongPacketType::Retry);
        assert_eq!(packet.token(), &[4, 5, 6]);
        assert_eq!(packet.integrity_tag(), tag);
        assert_eq!(packet.as_bytes().len(), 29);
        assert_eq!(destination[29], 0xa5);
    }
}

#[test]
fn terminal_builder_failures_are_exact_and_atomic() {
    let tag = [0; 16];
    let mut buffer = [0xa5; 600];
    let before = buffer;
    assert_eq!(
        QuicVersionNegotiationPacketBuilder::new(
            &mut buffer,
            0x80,
            QuicConnectionId::new(&[]),
            QuicConnectionId::new(&[]),
            &[QuicVersion::V1],
        )
        .build(),
        Err(QuicPacketBuildError::UnusedBitsOutOfRange {
            maximum: 0x7f,
            actual: 0x80,
        })
    );
    assert_eq!(buffer, before);
    assert_eq!(
        QuicRetryPacketBuilder::new(
            &mut buffer,
            QuicVersion::new(7),
            0,
            QuicConnectionId::new(&[]),
            QuicConnectionId::new(&[]),
            &[1],
            &tag,
        )
        .build(),
        Err(QuicPacketBuildError::UnsupportedVersion {
            version: QuicVersion::new(7),
        })
    );
    assert_eq!(buffer, before);
    assert_eq!(
        QuicVersionNegotiationPacketBuilder::new(
            &mut buffer,
            0,
            QuicConnectionId::new(&[0; 256]),
            QuicConnectionId::new(&[]),
            &[QuicVersion::V1],
        )
        .build(),
        Err(QuicPacketBuildError::ConnectionIdTooLong {
            field: QuicConnectionIdField::Destination,
            maximum: 255,
            actual: 256,
        })
    );
    assert_eq!(buffer, before);
    assert_eq!(
        QuicRetryPacketBuilder::new(
            &mut buffer,
            QuicVersion::V1,
            0,
            QuicConnectionId::new(&[]),
            QuicConnectionId::new(&[0; 21]),
            &[1],
            &tag,
        )
        .build(),
        Err(QuicPacketBuildError::ConnectionIdTooLong {
            field: QuicConnectionIdField::Source,
            maximum: 20,
            actual: 21,
        })
    );
    assert_eq!(buffer, before);
    assert_eq!(
        QuicVersionNegotiationPacketBuilder::new(
            &mut buffer,
            0,
            QuicConnectionId::new(&[]),
            QuicConnectionId::new(&[]),
            &[],
        )
        .build(),
        Err(QuicPacketBuildError::EmptyVersionList)
    );
    assert_eq!(buffer, before);
    assert_eq!(
        QuicRetryPacketBuilder::new(
            &mut buffer,
            QuicVersion::V1,
            0,
            QuicConnectionId::new(&[]),
            QuicConnectionId::new(&[]),
            &[],
            &tag,
        )
        .build(),
        Err(QuicPacketBuildError::EmptyRetryToken)
    );
    assert_eq!(buffer, before);

    let mut short = [0xa5; 10];
    let before_short = short;
    assert_eq!(
        QuicVersionNegotiationPacketBuilder::new(
            &mut short,
            0,
            QuicConnectionId::new(&[]),
            QuicConnectionId::new(&[]),
            &[QuicVersion::V1],
        )
        .build(),
        Err(QuicPacketBuildError::BufferTooShort {
            required: 11,
            available: 10,
        })
    );
    assert_eq!(short, before_short);
}

#[test]
fn terminal_builders_roundtrip_after_dropping_views_and_copy_inputs() {
    let mut destination_connection_id = [0x10, 0x11];
    let mut source_connection_id = [0x20];
    let mut versions = [QuicVersion::V1, QuicVersion::new(0x0a0a_0a0a)];
    let mut destination = [0xa5; 24];
    let packet_len = {
        let packet = QuicVersionNegotiationPacketBuilder::new(
            &mut destination,
            0x12,
            QuicConnectionId::new(&destination_connection_id),
            QuicConnectionId::new(&source_connection_id),
            &versions,
        )
        .build()
        .unwrap();
        assert_eq!(packet.as_bytes().len(), 18);
        18
    };
    destination_connection_id.fill(0xee);
    source_connection_id.fill(0xee);
    versions.fill(QuicVersion::V2);
    assert_eq!(
        &destination[..packet_len],
        &[
            0x92, 0, 0, 0, 0, 2, 0x10, 0x11, 1, 0x20, 0, 0, 0, 1, 0x0a, 0x0a, 0x0a, 0x0a,
        ]
    );
    let packet = QuicVersionNegotiationPacket::parse(&destination[..packet_len]).unwrap();
    assert_eq!(
        packet.header().destination_connection_id().as_bytes(),
        &[0x10, 0x11]
    );
    assert_eq!(packet.header().source_connection_id().as_bytes(), &[0x20]);
    assert_eq!(
        packet.version_list_bytes(),
        &[0, 0, 0, 1, 0x0a, 0x0a, 0x0a, 0x0a]
    );

    let mut version = QuicVersion::V1;
    let mut destination_connection_id = [1, 2];
    let mut source_connection_id = [3];
    let mut token = [4, 5, 6];
    let mut tag = [0x55; 16];
    let mut destination = [0xa5; 32];
    let packet_len = {
        let packet = QuicRetryPacketBuilder::new(
            &mut destination,
            version,
            9,
            QuicConnectionId::new(&destination_connection_id),
            QuicConnectionId::new(&source_connection_id),
            &token,
            &tag,
        )
        .build()
        .unwrap();
        assert_eq!(packet.as_bytes().len(), 29);
        29
    };
    version = QuicVersion::V2;
    destination_connection_id.fill(0xee);
    source_connection_id.fill(0xee);
    token.fill(0xee);
    tag.fill(0xee);
    assert_eq!(version, QuicVersion::V2);
    assert_eq!(
        &destination[..13],
        &[0xf9, 0, 0, 0, 1, 2, 1, 2, 1, 3, 4, 5, 6]
    );
    assert_eq!(&destination[13..packet_len], &[0x55; 16]);
    let packet = QuicRetryPacket::parse(&destination[..packet_len]).unwrap();
    assert_eq!(packet.version(), QuicVersion::V1);
    assert_eq!(
        packet.header().destination_connection_id().as_bytes(),
        &[1, 2]
    );
    assert_eq!(packet.header().source_connection_id().as_bytes(), &[3]);
    assert_eq!(packet.token(), &[4, 5, 6]);
    assert_eq!(packet.integrity_tag(), &[0x55; 16]);
}

#[test]
fn terminal_builders_accept_exact_capacity_and_reject_one_byte_short_atomically() {
    let mut version_negotiation = [0xa5; 11];
    let packet = QuicVersionNegotiationPacketBuilder::new(
        &mut version_negotiation,
        0,
        QuicConnectionId::new(&[]),
        QuicConnectionId::new(&[]),
        &[QuicVersion::V1],
    )
    .build()
    .unwrap();
    assert_eq!(packet.as_bytes(), &[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    let mut retry = [0xa5; 24];
    let packet = QuicRetryPacketBuilder::new(
        &mut retry,
        QuicVersion::V1,
        0,
        QuicConnectionId::new(&[]),
        QuicConnectionId::new(&[]),
        &[0xaa],
        &[0x55; 16],
    )
    .build()
    .unwrap();
    assert_eq!(&packet.as_bytes()[..8], &[0xf0, 0, 0, 0, 1, 0, 0, 0xaa]);
    assert_eq!(&packet.as_bytes()[8..], &[0x55; 16]);

    let mut version_negotiation = [0xa5; 10];
    let before = version_negotiation;
    assert_eq!(
        QuicVersionNegotiationPacketBuilder::new(
            &mut version_negotiation,
            0,
            QuicConnectionId::new(&[]),
            QuicConnectionId::new(&[]),
            &[QuicVersion::V1],
        )
        .build(),
        Err(QuicPacketBuildError::BufferTooShort {
            required: 11,
            available: 10,
        })
    );
    assert_eq!(version_negotiation, before);

    let mut retry = [0xa5; 23];
    let before = retry;
    assert_eq!(
        QuicRetryPacketBuilder::new(
            &mut retry,
            QuicVersion::V1,
            0,
            QuicConnectionId::new(&[]),
            QuicConnectionId::new(&[]),
            &[0xaa],
            &[0x55; 16],
        )
        .build(),
        Err(QuicPacketBuildError::BufferTooShort {
            required: 24,
            available: 23,
        })
    );
    assert_eq!(retry, before);
}

#[test]
fn terminal_builder_connection_id_width_boundaries_are_exact() {
    let destination_connection_id = [0x11; 255];
    let source_connection_id = [0x22; 255];
    let mut destination = [0; 521];
    {
        let packet = QuicVersionNegotiationPacketBuilder::new(
            &mut destination,
            0,
            QuicConnectionId::new(&destination_connection_id),
            QuicConnectionId::new(&source_connection_id),
            &[QuicVersion::V1],
        )
        .build()
        .unwrap();
        assert_eq!(packet.header().destination_connection_id().len(), 255);
        assert_eq!(packet.header().source_connection_id().len(), 255);
    }

    let too_long = [0; 256];
    let before = destination;
    assert_eq!(
        QuicVersionNegotiationPacketBuilder::new(
            &mut destination,
            0,
            QuicConnectionId::new(&too_long),
            QuicConnectionId::new(&[]),
            &[QuicVersion::V1],
        )
        .build(),
        Err(QuicPacketBuildError::ConnectionIdTooLong {
            field: QuicConnectionIdField::Destination,
            maximum: 255,
            actual: 256,
        })
    );
    assert_eq!(destination, before);
    assert_eq!(
        QuicVersionNegotiationPacketBuilder::new(
            &mut destination,
            0,
            QuicConnectionId::new(&[]),
            QuicConnectionId::new(&too_long),
            &[QuicVersion::V1],
        )
        .build(),
        Err(QuicPacketBuildError::ConnectionIdTooLong {
            field: QuicConnectionIdField::Source,
            maximum: 255,
            actual: 256,
        })
    );
    assert_eq!(destination, before);

    let destination_connection_id = [0x11; 20];
    let source_connection_id = [0x22; 20];
    let too_long = [0; 21];
    for version in [QuicVersion::V1, QuicVersion::V2] {
        let mut destination = [0; 64];
        let packet = QuicRetryPacketBuilder::new(
            &mut destination,
            version,
            0,
            QuicConnectionId::new(&destination_connection_id),
            QuicConnectionId::new(&source_connection_id),
            &[0xaa],
            &[0x55; 16],
        )
        .build()
        .unwrap();
        assert_eq!(packet.header().destination_connection_id().len(), 20);
        assert_eq!(packet.header().source_connection_id().len(), 20);

        let before = destination;
        assert_eq!(
            QuicRetryPacketBuilder::new(
                &mut destination,
                version,
                0,
                QuicConnectionId::new(&too_long),
                QuicConnectionId::new(&[]),
                &[0xaa],
                &[0x55; 16],
            )
            .build(),
            Err(QuicPacketBuildError::ConnectionIdTooLong {
                field: QuicConnectionIdField::Destination,
                maximum: 20,
                actual: 21,
            })
        );
        assert_eq!(destination, before);
        assert_eq!(
            QuicRetryPacketBuilder::new(
                &mut destination,
                version,
                0,
                QuicConnectionId::new(&[]),
                QuicConnectionId::new(&too_long),
                &[0xaa],
                &[0x55; 16],
            )
            .build(),
            Err(QuicPacketBuildError::ConnectionIdTooLong {
                field: QuicConnectionIdField::Source,
                maximum: 20,
                actual: 21,
            })
        );
        assert_eq!(destination, before);
    }
}

#[test]
fn retry_unused_bits_error_is_exact_and_atomic() {
    let mut destination = [0xa5; 24];
    let before = destination;
    assert_eq!(
        QuicRetryPacketBuilder::new(
            &mut destination,
            QuicVersion::V1,
            0x10,
            QuicConnectionId::new(&[]),
            QuicConnectionId::new(&[]),
            &[0xaa],
            &[0x55; 16],
        )
        .build(),
        Err(QuicPacketBuildError::UnusedBitsOutOfRange {
            maximum: 0x0f,
            actual: 0x10,
        })
    );
    assert_eq!(destination, before);
}

#[test]
fn protected_long_builders_map_versions_low_bits_and_exact_fields() {
    use net_wire::{
        QuicHandshakePacketBuilder, QuicInitialPacketBuilder, QuicZeroRttPacketBuilder,
    };

    for version in [QuicVersion::V1, QuicVersion::V2] {
        for low_bits in [0, 0x0f] {
            let mut initial_bytes = [0xa5; 32];
            let initial = QuicInitialPacketBuilder::new(
                &mut initial_bytes,
                version,
                low_bits,
                QuicConnectionId::new(b"d"),
                QuicConnectionId::new(b"s"),
                &[0xaa, 0xbb],
                &[1, 2, 3],
            )
            .build()
            .unwrap();
            assert_eq!(
                initial.header().first_byte(),
                0xc0 | (QuicLongPacketType::Initial.raw_type(version).unwrap() << 4) | low_bits
            );
            assert_eq!(initial.token_length().unwrap().as_bytes(), &[2]);
            assert_eq!(initial.token(), Some(&[0xaa, 0xbb][..]));
            assert_eq!(initial.length().as_bytes(), &[3]);
            assert_eq!(initial.protected_remainder(), &[1, 2, 3]);
            assert_eq!(initial_bytes[initial.as_bytes().len()], 0xa5);

            let mut zero_bytes = [0; 24];
            let zero = QuicZeroRttPacketBuilder::new(
                &mut zero_bytes,
                version,
                low_bits,
                QuicConnectionId::new(&[]),
                QuicConnectionId::new(&[]),
                &[4, 5],
            )
            .build()
            .unwrap();
            assert_eq!(
                zero.header().first_byte(),
                0xc0 | (QuicLongPacketType::ZeroRtt.raw_type(version).unwrap() << 4) | low_bits
            );
            assert_eq!((zero.token_length(), zero.token()), (None, None));

            let mut handshake_bytes = [0; 24];
            let handshake = QuicHandshakePacketBuilder::new(
                &mut handshake_bytes,
                version,
                low_bits,
                QuicConnectionId::new(&[]),
                QuicConnectionId::new(&[]),
                &[5, 6],
            )
            .build()
            .unwrap();
            assert_eq!(
                handshake.header().first_byte(),
                0xc0 | (QuicLongPacketType::Handshake.raw_type(version).unwrap() << 4) | low_bits
            );
            assert_eq!((handshake.token_length(), handshake.token()), (None, None));
        }
    }
}

#[test]
fn protected_long_builders_preserve_widths_roundtrip_and_copy_inputs() {
    let mut destination = [0xa5; 32];
    let mut token = [0x11];
    let mut remainder = [0x22, 0x33];
    let packet = QuicInitialPacketBuilder::new(
        &mut destination,
        QuicVersion::V2,
        7,
        QuicConnectionId::new(b"d"),
        QuicConnectionId::new(b"s"),
        &token,
        &remainder,
    )
    .with_token_length_len(QuicVarIntLen::Two)
    .with_length_len(QuicVarIntLen::Four)
    .build()
    .unwrap();
    assert_eq!(packet.token_length().unwrap().as_bytes(), &[0x40, 1]);
    assert_eq!(packet.length().as_bytes(), &[0x80, 0, 0, 2]);
    let expected = [
        0xd7, 0x6b, 0x33, 0x43, 0xcf, 1, b'd', 1, b's', 0x40, 1, 0x11, 0x80, 0, 0, 2, 0x22, 0x33,
    ];
    assert_eq!(packet.as_bytes(), expected);
    token[0] = 0xff;
    remainder[0] = 0xff;
    assert_eq!(token, [0xff]);
    assert_eq!(remainder, [0xff, 0x33]);
    assert_eq!(packet.as_bytes(), expected);
    let (parsed, suffix) = QuicProtectedLongPacket::parse(packet.as_bytes()).unwrap();
    assert!(suffix.is_empty());
    assert_eq!(parsed.token(), Some(&[0x11][..]));
    assert_eq!(parsed.protected_remainder(), &[0x22, 0x33]);
    assert_eq!(destination[expected.len()], 0xa5);

    let token_boundary = [0; 64];
    let remainder_boundary = [0; 64];
    let mut canonical_destination = [0; 160];
    let canonical = QuicInitialPacketBuilder::new(
        &mut canonical_destination,
        QuicVersion::V1,
        0,
        QuicConnectionId::new(&[]),
        QuicConnectionId::new(&[]),
        &token_boundary,
        &remainder_boundary,
    )
    .build()
    .unwrap();
    assert_eq!(canonical.token_length().unwrap().as_bytes(), &[0x40, 64]);
    assert_eq!(canonical.length().as_bytes(), &[0x40, 64]);

    let mut empty_token_destination = [0; 16];
    let empty_token = QuicInitialPacketBuilder::new(
        &mut empty_token_destination,
        QuicVersion::V1,
        0,
        QuicConnectionId::new(&[]),
        QuicConnectionId::new(&[]),
        &[],
        &[1, 2],
    )
    .build()
    .unwrap();
    assert_eq!(
        empty_token.as_bytes(),
        &[0xc0, 0, 0, 0, 1, 0, 0, 0, 2, 1, 2]
    );
}

#[test]
fn protected_long_builder_failures_are_exact_and_atomic() {
    let oversized = [0; 21];
    let boundary = [0; 20];
    let mut destination = [0xa5; 32];
    let before = destination;
    assert_eq!(
        QuicZeroRttPacketBuilder::new(
            &mut destination,
            QuicVersion::new(7),
            0,
            QuicConnectionId::new(&[]),
            QuicConnectionId::new(&[]),
            &[1],
        )
        .build(),
        Err(QuicPacketBuildError::UnsupportedVersion {
            version: QuicVersion::new(7)
        })
    );
    assert_eq!(destination, before);
    assert_eq!(
        QuicZeroRttPacketBuilder::new(
            &mut destination,
            QuicVersion::V1,
            0x10,
            QuicConnectionId::new(&[]),
            QuicConnectionId::new(&[]),
            &[1],
        )
        .build(),
        Err(QuicPacketBuildError::ProtectedLowBitsOutOfRange {
            maximum: 0x0f,
            actual: 0x10
        })
    );
    assert_eq!(destination, before);
    for (field, destination_connection_id, source_connection_id) in [
        (
            QuicConnectionIdField::Destination,
            QuicConnectionId::new(&oversized),
            QuicConnectionId::new(&[]),
        ),
        (
            QuicConnectionIdField::Source,
            QuicConnectionId::new(&[]),
            QuicConnectionId::new(&oversized),
        ),
    ] {
        assert_eq!(
            QuicZeroRttPacketBuilder::new(
                &mut destination,
                QuicVersion::V1,
                0,
                destination_connection_id,
                source_connection_id,
                &[1],
            )
            .build(),
            Err(QuicPacketBuildError::ConnectionIdTooLong {
                field,
                maximum: 20,
                actual: 21
            })
        );
        assert_eq!(destination, before);
    }
    let mut boundary_destination = [0; 64];
    let boundary_built = QuicZeroRttPacketBuilder::new(
        &mut boundary_destination,
        QuicVersion::V1,
        0,
        QuicConnectionId::new(&boundary),
        QuicConnectionId::new(&boundary),
        &[1, 2],
    )
    .build();
    assert!(boundary_built.is_ok());
    destination.fill(0xa5);
    assert_eq!(
        QuicZeroRttPacketBuilder::new(
            &mut destination,
            QuicVersion::V1,
            0,
            QuicConnectionId::new(&[]),
            QuicConnectionId::new(&[]),
            &[],
        )
        .build(),
        Err(QuicPacketBuildError::ProtectedRemainderTooShort {
            minimum: 2,
            actual: 0,
        })
    );
    assert_eq!(destination, before);
    assert_eq!(
        QuicInitialPacketBuilder::new(
            &mut destination,
            QuicVersion::V1,
            0,
            QuicConnectionId::new(&[]),
            QuicConnectionId::new(&[]),
            &[0; 64],
            &[1, 2],
        )
        .with_token_length_len(QuicVarIntLen::One)
        .build(),
        Err(QuicPacketBuildError::VarInt {
            field: QuicPacketBuildField::TokenLength,
            error: QuicVarIntBuildError::WidthTooSmall {
                length: QuicVarIntLen::One,
                value: 64
            }
        })
    );
    assert_eq!(destination, before);
    assert_eq!(
        QuicZeroRttPacketBuilder::new(
            &mut destination[..7],
            QuicVersion::V1,
            0,
            QuicConnectionId::new(&[]),
            QuicConnectionId::new(&[]),
            &[0; 64],
        )
        .with_length_len(QuicVarIntLen::One)
        .build(),
        Err(QuicPacketBuildError::VarInt {
            field: QuicPacketBuildField::ProtectedLength,
            error: QuicVarIntBuildError::WidthTooSmall {
                length: QuicVarIntLen::One,
                value: 64
            }
        })
    );
    assert_eq!(destination, before);

    let mut exact = [0; 10];
    let exact_built = QuicZeroRttPacketBuilder::new(
        &mut exact,
        QuicVersion::V1,
        0,
        QuicConnectionId::new(&[]),
        QuicConnectionId::new(&[]),
        &[1, 2],
    )
    .build();
    assert!(exact_built.is_ok());
    let mut short = [0xa5; 9];
    let short_before = short;
    assert_eq!(
        QuicZeroRttPacketBuilder::new(
            &mut short,
            QuicVersion::V1,
            0,
            QuicConnectionId::new(&[]),
            QuicConnectionId::new(&[]),
            &[1, 2],
        )
        .build(),
        Err(QuicPacketBuildError::BufferTooShort {
            required: 10,
            available: 9
        })
    );
    assert_eq!(short, short_before);
}

#[test]
fn protected_long_builders_enforce_minimum_remainder_atomically() {
    for (remainder, actual) in [(&[][..], 0), (&[0xaa][..], 1)] {
        let expected = Err(QuicPacketBuildError::ProtectedRemainderTooShort { minimum: 2, actual });

        let mut initial = [0xa5; 11];
        let before = initial;
        assert_eq!(
            QuicInitialPacketBuilder::new(
                &mut initial,
                QuicVersion::V1,
                0,
                QuicConnectionId::new(&[]),
                QuicConnectionId::new(&[]),
                &[],
                remainder,
            )
            .build(),
            expected
        );
        assert_eq!(initial, before);

        let mut zero_rtt = [0xa5; 10];
        let before = zero_rtt;
        assert_eq!(
            QuicZeroRttPacketBuilder::new(
                &mut zero_rtt,
                QuicVersion::V1,
                0,
                QuicConnectionId::new(&[]),
                QuicConnectionId::new(&[]),
                remainder,
            )
            .build(),
            expected
        );
        assert_eq!(zero_rtt, before);

        let mut handshake = [0xa5; 10];
        let before = handshake;
        assert_eq!(
            QuicHandshakePacketBuilder::new(
                &mut handshake,
                QuicVersion::V1,
                0,
                QuicConnectionId::new(&[]),
                QuicConnectionId::new(&[]),
                remainder,
            )
            .build(),
            expected
        );
        assert_eq!(handshake, before);
    }

    let mut initial = [0; 11];
    assert_eq!(
        QuicInitialPacketBuilder::new(
            &mut initial,
            QuicVersion::V1,
            0,
            QuicConnectionId::new(&[]),
            QuicConnectionId::new(&[]),
            &[],
            &[0xaa, 0xbb],
        )
        .build()
        .unwrap()
        .as_bytes(),
        &[0xc0, 0, 0, 0, 1, 0, 0, 0, 2, 0xaa, 0xbb]
    );
    let mut zero_rtt = [0; 10];
    assert_eq!(
        QuicZeroRttPacketBuilder::new(
            &mut zero_rtt,
            QuicVersion::V1,
            0,
            QuicConnectionId::new(&[]),
            QuicConnectionId::new(&[]),
            &[0xaa, 0xbb],
        )
        .build()
        .unwrap()
        .as_bytes(),
        &[0xd0, 0, 0, 0, 1, 0, 0, 2, 0xaa, 0xbb]
    );
    let mut handshake = [0; 10];
    assert_eq!(
        QuicHandshakePacketBuilder::new(
            &mut handshake,
            QuicVersion::V1,
            0,
            QuicConnectionId::new(&[]),
            QuicConnectionId::new(&[]),
            &[0xaa, 0xbb],
        )
        .build()
        .unwrap()
        .as_bytes(),
        &[0xe0, 0, 0, 0, 1, 0, 0, 2, 0xaa, 0xbb]
    );
}

#[test]
fn short_packet_builder_synthesizes_exact_first_bytes() {
    for (spin, protected_low_bits, expected) in [
        (false, 0, 0x40),
        (false, 0x1f, 0x5f),
        (true, 0, 0x60),
        (true, 0x1f, 0x7f),
    ] {
        let mut destination = [0; 3];
        let packet = QuicShortPacketBuilder::new(
            &mut destination,
            spin,
            protected_low_bits,
            QuicConnectionId::new(&[]),
            &[0xaa, 0xbb],
        )
        .build()
        .unwrap();
        assert_eq!(packet.as_bytes(), &[expected, 0xaa, 0xbb]);
    }
}

#[test]
fn short_packet_builder_accepts_connection_id_boundaries_and_rejects_overflow_atomically() {
    let mut zero_destination = [0; 3];
    let zero = QuicShortPacketBuilder::new(
        &mut zero_destination,
        false,
        0,
        QuicConnectionId::new(&[]),
        &[0xaa, 0xbb],
    )
    .build()
    .unwrap();
    assert!(zero.destination_connection_id().is_empty());

    let connection_id = [0x11; 20];
    let mut twenty_destination = [0; 23];
    let twenty = QuicShortPacketBuilder::new(
        &mut twenty_destination,
        false,
        0,
        QuicConnectionId::new(&connection_id),
        &[0xaa, 0xbb],
    )
    .build()
    .unwrap();
    assert_eq!(
        twenty.destination_connection_id().as_bytes(),
        &connection_id
    );

    let oversized = [0; 21];
    let mut destination = [0xa5; 32];
    let before = destination;
    assert_eq!(
        QuicShortPacketBuilder::new(
            &mut destination,
            false,
            0,
            QuicConnectionId::new(&oversized),
            &[0xaa],
        )
        .build(),
        Err(QuicPacketBuildError::ConnectionIdTooLong {
            field: QuicConnectionIdField::Destination,
            maximum: 20,
            actual: 21,
        })
    );
    assert_eq!(destination, before);
}

#[test]
fn short_packet_builder_copies_complete_packet_and_roundtrips_with_context() {
    let mut destination = [0xa5; 8];
    let packet = QuicShortPacketBuilder::new(
        &mut destination,
        true,
        0x1f,
        QuicConnectionId::new(&[0x10, 0x11, 0x12]),
        &[0xaa, 0xbb, 0xcc],
    )
    .build()
    .unwrap();
    assert_eq!(
        packet.as_bytes(),
        &[0x7f, 0x10, 0x11, 0x12, 0xaa, 0xbb, 0xcc]
    );
    assert_eq!(
        packet.destination_connection_id().as_bytes(),
        &[0x10, 0x11, 0x12]
    );
    assert_eq!(packet.protected_remainder(), &[0xaa, 0xbb, 0xcc]);

    let packet_len = packet.as_bytes().len();
    let reparsed =
        QuicShortHeader::parse(packet.as_bytes(), QuicShortHeaderContext::new(3)).unwrap();
    assert_eq!(reparsed, packet);
    assert_eq!(destination[packet_len], 0xa5);
}

#[test]
fn short_packet_builder_output_lifetime_depends_only_on_destination() {
    let mut connection_id = [0x10, 0x11];
    let mut protected_remainder = [0xaa, 0xbb];
    let mut destination = [0; 5];
    let packet = QuicShortPacketBuilder::new(
        &mut destination,
        false,
        3,
        QuicConnectionId::new(&connection_id),
        &protected_remainder,
    )
    .build()
    .unwrap();
    connection_id.fill(0xee);
    protected_remainder.fill(0xee);
    assert_eq!(packet.destination_connection_id().as_bytes(), &[0x10, 0x11]);
    assert_eq!(packet.protected_remainder(), &[0xaa, 0xbb]);
}

#[test]
fn short_packet_builder_checks_exact_capacity_before_writing() {
    let connection_id = [0x10, 0x11];
    let protected_remainder = [0xaa, 0xbb, 0xcc];
    let mut exact = [0; 6];
    let packet = QuicShortPacketBuilder::new(
        &mut exact,
        false,
        0,
        QuicConnectionId::new(&connection_id),
        &protected_remainder,
    )
    .build()
    .unwrap();
    assert_eq!(packet.as_bytes(), &[0x40, 0x10, 0x11, 0xaa, 0xbb, 0xcc]);

    let mut short = [0xa5; 5];
    let before = short;
    assert_eq!(
        QuicShortPacketBuilder::new(
            &mut short,
            false,
            0,
            QuicConnectionId::new(&connection_id),
            &protected_remainder,
        )
        .build(),
        Err(QuicPacketBuildError::BufferTooShort {
            required: 6,
            available: 5,
        })
    );
    assert_eq!(short, before);
}

#[test]
fn short_packet_builder_rejects_protected_bits_and_short_remainders_atomically() {
    let mut destination = [0xa5; 4];
    let before = destination;
    assert_eq!(
        QuicShortPacketBuilder::new(
            &mut destination,
            false,
            0x20,
            QuicConnectionId::new(&[]),
            &[0xaa, 0xbb],
        )
        .build(),
        Err(QuicPacketBuildError::ProtectedLowBitsOutOfRange {
            maximum: 0x1f,
            actual: 0x20,
        })
    );
    assert_eq!(destination, before);
    for (remainder, actual) in [(&[][..], 0), (&[0xaa][..], 1)] {
        assert_eq!(
            QuicShortPacketBuilder::new(
                &mut destination,
                false,
                0,
                QuicConnectionId::new(&[]),
                remainder,
            )
            .build(),
            Err(QuicPacketBuildError::ProtectedRemainderTooShort { minimum: 2, actual })
        );
        assert_eq!(destination, before);
    }

    let mut exact = [0; 3];
    assert_eq!(
        QuicShortPacketBuilder::new(
            &mut exact,
            false,
            0,
            QuicConnectionId::new(&[]),
            &[0xaa, 0xbb],
        )
        .build()
        .unwrap()
        .as_bytes(),
        &[0x40, 0xaa, 0xbb]
    );
}

#[test]
fn short_packet_builder_is_reexported_from_the_crate_root() {
    let mut destination = [0; 3];
    let packet = QuicShortPacketBuilder::new(
        &mut destination,
        false,
        0,
        QuicConnectionId::new(&[]),
        &[0xaa, 0xbb],
    )
    .build()
    .unwrap();
    assert_eq!(packet.first_byte(), 0x40);
}

#[test]
fn quic_frames_preserve_exact_padding_and_ping_type_encodings() {
    for (bytes, expected_type) in [
        (&[0x00, 0xfe][..], QuicVarIntLen::One),
        (&[0x40, 0x00, 0xfe][..], QuicVarIntLen::Two),
        (&[0x01, 0xfe][..], QuicVarIntLen::One),
        (&[0x40, 0x01, 0xfe][..], QuicVarIntLen::Two),
    ] {
        let (frame, suffix) = QuicFrame::parse(bytes).unwrap();
        assert_eq!(frame.as_bytes(), &bytes[..expected_type.byte_len()]);
        assert_eq!(frame.frame_type().as_bytes(), frame.as_bytes());
        assert_eq!(frame.frame_type().encoded_len(), expected_type);
        assert_eq!(suffix, &bytes[expected_type.byte_len()..]);
    }
}

#[test]
fn quic_frames_keep_adjacent_padding_distinct_and_validate_sequences() {
    let bytes = [0, 0, 0x40, 1, 0];
    let frames = QuicFrames::parse(&bytes).unwrap();
    assert_eq!(frames.as_bytes(), &bytes);

    let mut iter = frames.iter();
    assert!(matches!(iter.next(), Some(Ok(QuicFrame::Padding(_)))));
    assert!(matches!(iter.next(), Some(Ok(QuicFrame::Padding(_)))));
    let ping = iter.next().unwrap().unwrap();
    assert!(matches!(ping, QuicFrame::Ping(_)));
    assert_eq!(ping.as_bytes(), &[0x40, 1]);
    assert!(matches!(iter.next(), Some(Ok(QuicFrame::Padding(_)))));
    assert_eq!(iter.next(), None);
}

#[test]
fn quic_frames_report_empty_and_truncated_frame_types() {
    assert_eq!(
        QuicFrames::parse(&[]),
        Err(QuicFrameParseError::EmptySequence)
    );

    for (input, required) in [
        (&[][..], 1),
        (&[0x40][..], 2),
        (&[0x80, 0, 0][..], 4),
        (&[0xc0, 0, 0, 0, 0, 0, 0][..], 8),
    ] {
        assert_eq!(
            QuicFrame::parse(input),
            Err(QuicFrameParseError::FrameType {
                offset: 0,
                error: QuicVarIntParseError::Incomplete {
                    required,
                    available: input.len(),
                },
            })
        );
    }
}

#[test]
fn quic_frames_fail_closed_with_exact_unknown_type_details() {
    for (input, value, length) in [
        (&[0x1f][..], 0x1f, QuicVarIntLen::One),
        (&[0x40, 0x1f][..], 0x1f, QuicVarIntLen::Two),
    ] {
        assert_eq!(
            QuicFrame::parse(input),
            Err(QuicFrameParseError::UnsupportedFrameType {
                value,
                length,
                offset: 0,
            })
        );
    }

    let bytes = [0, 1, 0x40, 0x1f];
    assert_eq!(
        QuicFrames::parse(&bytes),
        Err(QuicFrameParseError::UnsupportedFrameType {
            value: 0x1f,
            length: QuicVarIntLen::Two,
            offset: 2,
        })
    );
}

#[test]
fn raw_quic_frame_iterator_exposes_prefix_then_one_error_and_is_fused() {
    let mut unknown = QuicFrameIter::new(&[0, 0x40, 0x1f]);
    assert!(matches!(unknown.next(), Some(Ok(QuicFrame::Padding(_)))));
    assert_eq!(
        unknown.next(),
        Some(Err(QuicFrameParseError::UnsupportedFrameType {
            value: 0x1f,
            length: QuicVarIntLen::Two,
            offset: 1,
        }))
    );
    assert_eq!(unknown.next(), None);

    let truncated_bytes = [1, 0x80, 0];
    assert_eq!(
        QuicFrames::parse(&truncated_bytes),
        Err(QuicFrameParseError::FrameType {
            offset: 1,
            error: QuicVarIntParseError::Incomplete {
                required: 4,
                available: 2,
            },
        })
    );

    let mut truncated = QuicFrameIter::new(&truncated_bytes);
    assert!(matches!(truncated.next(), Some(Ok(QuicFrame::Ping(_)))));
    assert_eq!(
        truncated.next(),
        Some(Err(QuicFrameParseError::FrameType {
            offset: 1,
            error: QuicVarIntParseError::Incomplete {
                required: 4,
                available: 2,
            },
        }))
    );
    assert_eq!(truncated.next(), None);
}

#[test]
fn quic_frame_types_are_reexported_from_the_crate_root() {
    let (frame, _) = QuicFrame::parse(&[1]).unwrap();
    assert!(matches!(frame, QuicFrame::Ping(_)));
}

#[test]
fn reset_stream_and_stop_sending_parse_exact_layouts_and_suffixes() {
    let reset_bytes = [4, 9, 0x40, 0x2a, 63, 0xfe];
    let (frame, suffix) = QuicFrame::parse(&reset_bytes).unwrap();
    let QuicFrame::ResetStream(reset) = frame else {
        panic!("expected RESET_STREAM")
    };
    assert_eq!(reset.as_bytes(), &reset_bytes[..5]);
    assert_eq!(reset.frame_type().value(), 4);
    assert_eq!(reset.stream_id().value(), 9);
    assert_eq!(reset.application_error_code().value(), 42);
    assert_eq!(reset.final_size().value(), 63);
    assert_eq!(suffix, &[0xfe]);

    let stop_bytes = [5, 7, 0x40, 0x2a, 0xfe];
    let (frame, suffix) = QuicFrame::parse(&stop_bytes).unwrap();
    let QuicFrame::StopSending(stop) = frame else {
        panic!("expected STOP_SENDING")
    };
    assert_eq!(stop.as_bytes(), &stop_bytes[..4]);
    assert_eq!(stop.frame_type().value(), 5);
    assert_eq!(stop.stream_id().value(), 7);
    assert_eq!(stop.application_error_code().value(), 42);
    assert_eq!(suffix, &[0xfe]);
}

#[test]
fn control_frames_preserve_each_nested_noncanonical_width() {
    let reset_bytes = [4, 0x40, 1, 0x80, 0, 0, 2, 0xc0, 0, 0, 0, 0, 0, 0, 3];
    let (frame, suffix) = QuicFrame::parse(&reset_bytes).unwrap();
    let QuicFrame::ResetStream(reset) = frame else {
        panic!("expected RESET_STREAM")
    };
    assert!(suffix.is_empty());
    assert_eq!(reset.stream_id().as_bytes(), &[0x40, 1]);
    assert_eq!(reset.application_error_code().as_bytes(), &[0x80, 0, 0, 2]);
    assert_eq!(reset.final_size().as_bytes(), &[0xc0, 0, 0, 0, 0, 0, 0, 3]);
    assert!(!reset.stream_id().is_canonical());
    assert!(!reset.application_error_code().is_canonical());
    assert!(!reset.final_size().is_canonical());

    let stop_bytes = [5, 0x80, 0, 0, 1, 0xc0, 0, 0, 0, 0, 0, 0, 2];
    let (frame, suffix) = QuicFrame::parse(&stop_bytes).unwrap();
    let QuicFrame::StopSending(stop) = frame else {
        panic!("expected STOP_SENDING")
    };
    assert!(suffix.is_empty());
    assert_eq!(stop.stream_id().as_bytes(), &[0x80, 0, 0, 1]);
    assert_eq!(
        stop.application_error_code().as_bytes(),
        &[0xc0, 0, 0, 0, 0, 0, 0, 2]
    );
}

#[test]
fn control_frame_field_truncations_report_semantic_absolute_offsets() {
    for (frame_type, fields) in [(4u8, 3usize), (5u8, 2usize)] {
        for field_index in 0..fields {
            let field = match field_index {
                0 => QuicFrameField::StreamId,
                1 => QuicFrameField::ApplicationErrorCode,
                _ => QuicFrameField::FinalSize,
            };
            for (prefix, required) in [
                (&[][..], 1),
                (&[0x40][..], 2),
                (&[0x80, 0, 0][..], 4),
                (&[0xc0, 0, 0, 0, 0, 0, 0][..], 8),
            ] {
                let mut bytes = [0; 32];
                bytes[0] = frame_type;
                let field_offset = field_index + 1;
                bytes[1..field_offset].fill(0);
                bytes[field_offset..field_offset + prefix.len()].copy_from_slice(prefix);
                let input = &bytes[..field_offset + prefix.len()];
                assert_eq!(
                    QuicFrame::parse(input),
                    Err(QuicFrameParseError::Field {
                        field,
                        offset: field_offset,
                        error: QuicVarIntParseError::Incomplete {
                            required,
                            available: prefix.len(),
                        },
                    })
                );
            }
        }
    }
}

#[test]
fn control_frames_iterate_with_padding_and_ping_at_exact_boundaries() {
    let bytes = [0, 1, 4, 2, 3, 4, 5, 6, 7, 0];
    let frames = QuicFrames::parse(&bytes).unwrap();
    let mut iter = frames.iter();
    for expected in [1usize, 1, 4, 3, 1] {
        let frame = iter.next().unwrap().unwrap();
        assert_eq!(frame.as_bytes().len(), expected);
    }
    assert!(matches!(
        QuicFrame::parse(&bytes[2..]).unwrap().0,
        QuicFrame::ResetStream(_)
    ));
    assert!(matches!(
        QuicFrame::parse(&bytes[6..]).unwrap().0,
        QuicFrame::StopSending(_)
    ));
    assert_eq!(iter.next(), None);
}

#[test]
fn malformed_control_frame_has_absolute_offset_and_fused_raw_iterator() {
    let bytes = [1, 5, 9, 0x80, 0];
    let expected = QuicFrameParseError::Field {
        field: QuicFrameField::ApplicationErrorCode,
        offset: 3,
        error: QuicVarIntParseError::Incomplete {
            required: 4,
            available: 2,
        },
    };
    assert_eq!(QuicFrames::parse(&bytes), Err(expected));
    let mut iter = QuicFrameIter::new(&bytes);
    assert!(matches!(iter.next(), Some(Ok(QuicFrame::Ping(_)))));
    assert_eq!(iter.next(), Some(Err(expected)));
    assert_eq!(iter.next(), None);
    assert_eq!(iter.next(), None);
}

#[test]
fn control_frames_accept_raw_error_codes_and_maximum_varints() {
    let maximum = [0xff; 8];
    let mut reset_bytes = [0; 25];
    reset_bytes[0] = 4;
    reset_bytes[1..9].copy_from_slice(&maximum);
    reset_bytes[9..17].copy_from_slice(&maximum);
    reset_bytes[17..25].copy_from_slice(&maximum);
    let (frame, suffix) = QuicFrame::parse(&reset_bytes).unwrap();
    let QuicFrame::ResetStream(reset) = frame else {
        panic!("expected RESET_STREAM")
    };
    assert!(suffix.is_empty());
    assert_eq!(reset.stream_id().value(), (1u64 << 62) - 1);
    assert_eq!(reset.application_error_code().as_bytes(), &maximum);
    assert_eq!(reset.final_size().value(), (1u64 << 62) - 1);

    let stop_bytes = [5, 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let (frame, _) = QuicFrame::parse(&stop_bytes).unwrap();
    let QuicFrame::StopSending(stop) = frame else {
        panic!("expected STOP_SENDING")
    };
    assert_eq!(stop.application_error_code().value(), (1u64 << 62) - 1);
}

#[test]
fn control_frame_views_and_field_errors_are_reexported_from_the_crate_root() {
    let _reset: Option<QuicResetStreamFrame<'_>> = None;
    let _stop: Option<QuicStopSendingFrame<'_>> = None;
    assert_eq!(QuicFrameField::StreamId, QuicFrameField::StreamId);
}

#[test]
fn data_limit_frames_parse_exact_layouts_accessors_and_suffixes() {
    let max_data = [0x10, 0x2a, 0xfe];
    let (frame, suffix) = QuicFrame::parse(&max_data).unwrap();
    let QuicFrame::MaxData(frame) = frame else {
        panic!("expected MAX_DATA")
    };
    assert_eq!(frame.as_bytes(), &max_data[..2]);
    assert_eq!(frame.frame_type().as_bytes(), &[0x10]);
    assert_eq!(frame.maximum_data().value(), 42);
    assert_eq!(suffix, &[0xfe]);

    let max_stream_data = [0x11, 7, 0x40, 0x2a, 0xfe];
    let (frame, suffix) = QuicFrame::parse(&max_stream_data).unwrap();
    let QuicFrame::MaxStreamData(frame) = frame else {
        panic!("expected MAX_STREAM_DATA")
    };
    assert_eq!(frame.as_bytes(), &max_stream_data[..4]);
    assert_eq!(frame.stream_id().value(), 7);
    assert_eq!(frame.maximum_stream_data().value(), 42);
    assert_eq!(suffix, &[0xfe]);

    let data_blocked = [0x14, 0x2a, 0xfe];
    let (frame, suffix) = QuicFrame::parse(&data_blocked).unwrap();
    let QuicFrame::DataBlocked(frame) = frame else {
        panic!("expected DATA_BLOCKED")
    };
    assert_eq!(frame.as_bytes(), &data_blocked[..2]);
    assert_eq!(frame.maximum_data().value(), 42);
    assert_eq!(suffix, &[0xfe]);

    let stream_data_blocked = [0x15, 7, 0x40, 0x2a, 0xfe];
    let (frame, suffix) = QuicFrame::parse(&stream_data_blocked).unwrap();
    let QuicFrame::StreamDataBlocked(frame) = frame else {
        panic!("expected STREAM_DATA_BLOCKED")
    };
    assert_eq!(frame.as_bytes(), &stream_data_blocked[..4]);
    assert_eq!(frame.stream_id().value(), 7);
    assert_eq!(frame.maximum_stream_data().value(), 42);
    assert_eq!(suffix, &[0xfe]);
}

#[test]
fn data_limit_frames_preserve_noncanonical_types_and_each_field_width() {
    let max_data = [0x40, 0x10, 0x40, 1];
    let (QuicFrame::MaxData(frame), suffix) = QuicFrame::parse(&max_data).unwrap() else {
        panic!("expected MAX_DATA")
    };
    assert!(suffix.is_empty());
    assert_eq!(frame.frame_type().as_bytes(), &[0x40, 0x10]);
    assert_eq!(frame.maximum_data().as_bytes(), &[0x40, 1]);

    let max_stream_data = [0x40, 0x11, 0x80, 0, 0, 2, 0xc0, 0, 0, 0, 0, 0, 0, 3];
    let (QuicFrame::MaxStreamData(frame), suffix) = QuicFrame::parse(&max_stream_data).unwrap()
    else {
        panic!("expected MAX_STREAM_DATA")
    };
    assert!(suffix.is_empty());
    assert_eq!(frame.stream_id().as_bytes(), &[0x80, 0, 0, 2]);
    assert_eq!(
        frame.maximum_stream_data().as_bytes(),
        &[0xc0, 0, 0, 0, 0, 0, 0, 3]
    );

    let data_blocked = [0x40, 0x14, 0x80, 0, 0, 4];
    let (QuicFrame::DataBlocked(frame), _) = QuicFrame::parse(&data_blocked).unwrap() else {
        panic!("expected DATA_BLOCKED")
    };
    assert_eq!(frame.maximum_data().as_bytes(), &[0x80, 0, 0, 4]);

    let stream_data_blocked = [0x40, 0x15, 0xc0, 0, 0, 0, 0, 0, 0, 5, 0x40, 6];
    let (QuicFrame::StreamDataBlocked(frame), _) = QuicFrame::parse(&stream_data_blocked).unwrap()
    else {
        panic!("expected STREAM_DATA_BLOCKED")
    };
    assert_eq!(frame.stream_id().as_bytes(), &[0xc0, 0, 0, 0, 0, 0, 0, 5]);
    assert_eq!(frame.maximum_stream_data().as_bytes(), &[0x40, 6]);
}

#[test]
fn data_limit_frame_field_truncations_report_exact_absolute_offsets() {
    let cases = [
        (0x10, 0, QuicFrameField::MaximumData),
        (0x11, 0, QuicFrameField::StreamId),
        (0x11, 1, QuicFrameField::MaximumStreamData),
        (0x14, 0, QuicFrameField::MaximumData),
        (0x15, 0, QuicFrameField::StreamId),
        (0x15, 1, QuicFrameField::MaximumStreamData),
    ];
    for (frame_type, field_index, field) in cases {
        for (prefix, required) in [
            (&[][..], 1),
            (&[0x40][..], 2),
            (&[0x80, 0, 0][..], 4),
            (&[0xc0, 0, 0, 0, 0, 0, 0][..], 8),
        ] {
            let mut bytes = [0; 16];
            bytes[0] = frame_type;
            bytes[1..field_index + 1].fill(0);
            bytes[field_index + 1..field_index + 1 + prefix.len()].copy_from_slice(prefix);
            let input = &bytes[..field_index + 1 + prefix.len()];
            assert_eq!(
                QuicFrame::parse(input),
                Err(QuicFrameParseError::Field {
                    field,
                    offset: field_index + 1,
                    error: QuicVarIntParseError::Incomplete {
                        required,
                        available: prefix.len(),
                    },
                })
            );
        }
    }
}

#[test]
fn data_limit_frames_iterate_among_existing_frames_at_exact_boundaries() {
    let bytes = [0, 0x10, 1, 1, 0x11, 2, 3, 0x14, 5, 0x15, 6, 7, 0];
    let frames = QuicFrames::parse(&bytes).unwrap();
    let mut iter = frames.iter();
    for (length, variant) in [(1, 0), (2, 1), (1, 2), (3, 3), (2, 4), (3, 5), (1, 6)] {
        let frame = iter.next().unwrap().unwrap();
        assert_eq!(frame.as_bytes().len(), length);
        match variant {
            0 | 6 => assert!(matches!(frame, QuicFrame::Padding(_))),
            1 => assert!(matches!(frame, QuicFrame::MaxData(_))),
            2 => assert!(matches!(frame, QuicFrame::Ping(_))),
            3 => assert!(matches!(frame, QuicFrame::MaxStreamData(_))),
            4 => assert!(matches!(frame, QuicFrame::DataBlocked(_))),
            _ => assert!(matches!(frame, QuicFrame::StreamDataBlocked(_))),
        }
    }
    assert_eq!(iter.next(), None);
}

#[test]
fn malformed_later_data_limit_frame_fails_closed_at_absolute_offset() {
    let bytes = [1, 0x15, 9, 0x80, 0];
    let expected = QuicFrameParseError::Field {
        field: QuicFrameField::MaximumStreamData,
        offset: 3,
        error: QuicVarIntParseError::Incomplete {
            required: 4,
            available: 2,
        },
    };
    assert_eq!(QuicFrames::parse(&bytes), Err(expected));
    let mut iter = QuicFrameIter::new(&bytes);
    assert!(matches!(iter.next(), Some(Ok(QuicFrame::Ping(_)))));
    assert_eq!(iter.next(), Some(Err(expected)));
    assert_eq!(iter.next(), None);
    assert_eq!(iter.next(), None);
}

#[test]
fn data_limit_frames_accept_maximum_62_bit_values() {
    let maximum = [0xff; 8];
    let max_data = [0x10, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let (QuicFrame::MaxData(frame), _) = QuicFrame::parse(&max_data).unwrap() else {
        panic!("expected MAX_DATA")
    };
    assert_eq!(frame.maximum_data().as_bytes(), maximum);
    assert_eq!(frame.maximum_data().value(), (1u64 << 62) - 1);

    let max_stream_data = [
        0x11, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ];
    let (QuicFrame::MaxStreamData(frame), _) = QuicFrame::parse(&max_stream_data).unwrap() else {
        panic!("expected MAX_STREAM_DATA")
    };
    assert_eq!(frame.stream_id().value(), (1u64 << 62) - 1);
    assert_eq!(frame.maximum_stream_data().as_bytes(), maximum);

    let data_blocked = [0x14, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let (QuicFrame::DataBlocked(frame), _) = QuicFrame::parse(&data_blocked).unwrap() else {
        panic!("expected DATA_BLOCKED")
    };
    assert_eq!(frame.maximum_data().value(), (1u64 << 62) - 1);

    let stream_data_blocked = [
        0x15, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ];
    let (QuicFrame::StreamDataBlocked(frame), _) = QuicFrame::parse(&stream_data_blocked).unwrap()
    else {
        panic!("expected STREAM_DATA_BLOCKED")
    };
    assert_eq!(frame.stream_id().as_bytes(), maximum);
    assert_eq!(frame.maximum_stream_data().value(), (1u64 << 62) - 1);
}

#[test]
fn data_limit_frame_views_are_reexported_from_the_crate_root() {
    let _max_data: Option<QuicMaxDataFrame<'_>> = None;
    let _max_stream_data: Option<QuicMaxStreamDataFrame<'_>> = None;
    let _data_blocked: Option<QuicDataBlockedFrame<'_>> = None;
    let _stream_data_blocked: Option<QuicStreamDataBlockedFrame<'_>> = None;
    assert_eq!(QuicFrameField::MaximumData, QuicFrameField::MaximumData);
}

#[test]
fn stream_count_frames_parse_exact_layouts_directions_and_suffixes() {
    for (bytes, direction, blocked) in [
        (
            &[0x12, 3, 0xfe][..],
            QuicStreamDirection::Bidirectional,
            false,
        ),
        (
            &[0x13, 4, 0xfe][..],
            QuicStreamDirection::Unidirectional,
            false,
        ),
        (
            &[0x16, 5, 0xfe][..],
            QuicStreamDirection::Bidirectional,
            true,
        ),
        (
            &[0x17, 6, 0xfe][..],
            QuicStreamDirection::Unidirectional,
            true,
        ),
    ] {
        let (frame, suffix) = QuicFrame::parse(bytes).unwrap();
        assert_eq!(frame.as_bytes(), &bytes[..2]);
        assert_eq!(frame.frame_type().value(), bytes[0] as u64);
        assert_eq!(suffix, &[0xfe]);
        match (frame, blocked) {
            (QuicFrame::MaxStreams(frame), false) => {
                assert_eq!(frame.direction(), direction);
                assert_eq!(frame.maximum_streams().value(), bytes[1] as u64);
            }
            (QuicFrame::StreamsBlocked(frame), true) => {
                assert_eq!(frame.direction(), direction);
                assert_eq!(frame.maximum_streams().value(), bytes[1] as u64);
            }
            _ => panic!("unexpected stream-count frame variant"),
        }
    }
}

#[test]
fn stream_count_frames_preserve_noncanonical_type_and_field_widths() {
    for (bytes, blocked) in [
        (&[0x40, 0x12, 0x80, 0, 0, 1][..], false),
        (&[0x40, 0x13, 0x40, 2][..], false),
        (&[0x40, 0x16, 0x80, 0, 0, 3][..], true),
        (&[0x40, 0x17, 0xc0, 0, 0, 0, 0, 0, 0, 4][..], true),
    ] {
        let (frame, suffix) = QuicFrame::parse(bytes).unwrap();
        assert!(suffix.is_empty());
        assert_eq!(frame.frame_type().as_bytes(), &bytes[..2]);
        match (frame, blocked) {
            (QuicFrame::MaxStreams(frame), false) => {
                assert_eq!(frame.maximum_streams().as_bytes(), &bytes[2..]);
            }
            (QuicFrame::StreamsBlocked(frame), true) => {
                assert_eq!(frame.maximum_streams().as_bytes(), &bytes[2..]);
            }
            _ => panic!("unexpected stream-count frame variant"),
        }
    }
}

#[test]
fn stream_count_frame_field_truncations_report_exact_offsets() {
    for frame_type in [0x12u8, 0x13, 0x16, 0x17] {
        for (field, required) in [
            (&[][..], 1),
            (&[0x40][..], 2),
            (&[0x80, 0, 0][..], 4),
            (&[0xc0, 0, 0, 0, 0, 0, 0][..], 8),
        ] {
            let mut bytes = [0; 8];
            bytes[0] = frame_type;
            bytes[1..1 + field.len()].copy_from_slice(field);
            let input = &bytes[..1 + field.len()];
            assert_eq!(
                QuicFrame::parse(input),
                Err(QuicFrameParseError::Field {
                    field: QuicFrameField::MaximumStreams,
                    offset: 1,
                    error: QuicVarIntParseError::Incomplete {
                        required,
                        available: field.len(),
                    },
                })
            );
        }
    }
}

#[test]
fn stream_count_frames_accept_the_rfc_maximum_in_both_directions() {
    for frame_type in [0x12u8, 0x13, 0x16, 0x17] {
        let bytes = [frame_type, 0xd0, 0, 0, 0, 0, 0, 0, 0];
        let (frame, suffix) = QuicFrame::parse(&bytes).unwrap();
        assert!(suffix.is_empty());
        match frame {
            QuicFrame::MaxStreams(frame) => {
                assert_eq!(frame.maximum_streams().value(), 1u64 << 60)
            }
            QuicFrame::StreamsBlocked(frame) => {
                assert_eq!(frame.maximum_streams().value(), 1u64 << 60)
            }
            _ => panic!("unexpected stream-count frame variant"),
        }
    }
}

#[test]
fn stream_count_frames_reject_out_of_range_values_at_absolute_offsets() {
    for (value, encoded) in [
        (1u64 << 60 | 1, &[0xd0, 0, 0, 0, 0, 0, 0, 1][..]),
        (
            (1u64 << 62) - 1,
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..],
        ),
    ] {
        for frame_type in [0x12u8, 0x13, 0x16, 0x17] {
            let mut bytes = [0; 9];
            bytes[0] = frame_type;
            bytes[1..].copy_from_slice(encoded);
            assert_eq!(
                QuicFrame::parse(&bytes),
                Err(QuicFrameParseError::FieldValueOutOfRange {
                    field: QuicFrameField::MaximumStreams,
                    offset: 1,
                    value,
                    maximum: 1u64 << 60,
                })
            );
        }
    }

    let bytes = [1, 0x16, 0xd0, 0, 0, 0, 0, 0, 0, 1];
    let expected = QuicFrameParseError::FieldValueOutOfRange {
        field: QuicFrameField::MaximumStreams,
        offset: 2,
        value: 1u64 << 60 | 1,
        maximum: 1u64 << 60,
    };
    assert_eq!(QuicFrames::parse(&bytes), Err(expected));
    let mut iter = QuicFrameIter::new(&bytes);
    assert!(matches!(iter.next(), Some(Ok(QuicFrame::Ping(_)))));
    assert_eq!(iter.next(), Some(Err(expected)));
    assert_eq!(iter.next(), None);
    assert_eq!(iter.next(), None);
}

#[test]
fn stream_count_frames_mix_at_exact_boundaries_and_reexport_from_root() {
    let bytes = [0, 0x12, 1, 0x13, 2, 0x16, 3, 0x17, 4, 1];
    let frames = QuicFrames::parse(&bytes).unwrap();
    let mut iter = frames.iter();
    for (length, kind) in [(1usize, 0), (2, 1), (2, 2), (2, 3), (2, 4), (1, 5)] {
        let frame = iter.next().unwrap().unwrap();
        assert_eq!(frame.as_bytes().len(), length);
        match kind {
            0 => assert!(matches!(frame, QuicFrame::Padding(_))),
            1 | 2 => assert!(matches!(frame, QuicFrame::MaxStreams(_))),
            3 | 4 => assert!(matches!(frame, QuicFrame::StreamsBlocked(_))),
            _ => assert!(matches!(frame, QuicFrame::Ping(_))),
        }
    }
    assert_eq!(iter.next(), None);

    let _max: Option<QuicMaxStreamsFrame<'_>> = None;
    let _blocked: Option<QuicStreamsBlockedFrame<'_>> = None;
    assert_eq!(
        QuicStreamDirection::Bidirectional,
        QuicStreamDirection::Bidirectional
    );
}

#[test]
fn new_token_and_handshake_done_preserve_exact_views_and_suffixes() {
    let new_token = [0x07, 3, 0, 0x80, 0xff, 0xfe];
    let (QuicFrame::NewToken(frame), suffix) = QuicFrame::parse(&new_token).unwrap() else {
        panic!("expected NEW_TOKEN")
    };
    assert_eq!(frame.as_bytes(), &new_token[..5]);
    assert_eq!(frame.frame_type().as_bytes(), &[0x07]);
    assert_eq!(frame.token_length().as_bytes(), &[3]);
    assert_eq!(frame.token(), &[0, 0x80, 0xff]);
    assert_eq!(suffix, &[0xfe]);

    let handshake_done = [0x1e, 0xfe];
    let (QuicFrame::HandshakeDone(frame), suffix) = QuicFrame::parse(&handshake_done).unwrap()
    else {
        panic!("expected HANDSHAKE_DONE")
    };
    assert_eq!(frame.as_bytes(), &[0x1e]);
    assert_eq!(frame.frame_type().as_bytes(), &[0x1e]);
    assert_eq!(suffix, &[0xfe]);
}

#[test]
fn new_token_and_handshake_done_preserve_noncanonical_type_and_length_widths() {
    let new_token = [0x40, 0x07, 0x80, 0, 0, 2, 0xaa, 0xbb];
    let (QuicFrame::NewToken(frame), suffix) = QuicFrame::parse(&new_token).unwrap() else {
        panic!("expected NEW_TOKEN")
    };
    assert!(suffix.is_empty());
    assert_eq!(frame.frame_type().as_bytes(), &[0x40, 0x07]);
    assert_eq!(frame.token_length().as_bytes(), &[0x80, 0, 0, 2]);
    assert_eq!(frame.token(), &[0xaa, 0xbb]);

    for (bytes, encoded_length) in [
        (&[7, 0x40, 1, 0xaa][..], &[0x40, 1][..]),
        (
            &[7, 0xc0, 0, 0, 0, 0, 0, 0, 1, 0xaa][..],
            &[0xc0, 0, 0, 0, 0, 0, 0, 1][..],
        ),
    ] {
        let (QuicFrame::NewToken(frame), suffix) = QuicFrame::parse(bytes).unwrap() else {
            panic!("expected NEW_TOKEN")
        };
        assert!(suffix.is_empty());
        assert_eq!(frame.token_length().as_bytes(), encoded_length);
        assert_eq!(frame.token(), &[0xaa]);
    }

    let (QuicFrame::HandshakeDone(frame), suffix) = QuicFrame::parse(&[0x40, 0x1e, 0]).unwrap()
    else {
        panic!("expected HANDSHAKE_DONE")
    };
    assert_eq!(frame.as_bytes(), &[0x40, 0x1e]);
    assert_eq!(suffix, &[0]);
}

#[test]
fn new_token_reports_token_length_and_bounded_byte_errors() {
    for (prefix, required) in [
        (&[][..], 1),
        (&[0x40][..], 2),
        (&[0x80, 0, 0][..], 4),
        (&[0xc0, 0, 0, 0, 0, 0, 0][..], 8),
    ] {
        let mut bytes = [0; 9];
        bytes[0] = 7;
        bytes[1..1 + prefix.len()].copy_from_slice(prefix);
        assert_eq!(
            QuicFrame::parse(&bytes[..1 + prefix.len()]),
            Err(QuicFrameParseError::Field {
                field: QuicFrameField::TokenLength,
                offset: 1,
                error: QuicVarIntParseError::Incomplete {
                    required,
                    available: prefix.len(),
                },
            })
        );
    }

    for (bytes, offset) in [(&[7, 0][..], 2), (&[0x40, 7, 0x40, 0][..], 4)] {
        assert_eq!(
            QuicFrame::parse(bytes),
            Err(QuicFrameParseError::EmptyField {
                field: QuicFrameField::Token,
                offset,
            })
        );
    }

    for (bytes, required, available) in [(&[7, 1][..], 1, 0), (&[7, 3, 0xaa][..], 3, 1)] {
        assert_eq!(
            QuicFrame::parse(bytes),
            Err(QuicFrameParseError::IncompleteBytes {
                field: QuicFrameField::Token,
                offset: 2,
                required,
                available,
            })
        );
    }
}

#[cfg(target_pointer_width = "32")]
#[test]
fn new_token_rejects_unrepresentable_token_lengths() {
    let bytes = [7, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert_eq!(
        QuicFrame::parse(&bytes),
        Err(QuicFrameParseError::LengthNotRepresentable {
            field: QuicFrameField::TokenLength,
            offset: 1,
            value: (1u64 << 62) - 1,
        })
    );
}

#[test]
fn new_token_fails_closed_at_absolute_offsets_and_mixes_with_other_frames() {
    let malformed = [1, 7, 3, 0xaa];
    let expected = QuicFrameParseError::IncompleteBytes {
        field: QuicFrameField::Token,
        offset: 3,
        required: 3,
        available: 1,
    };
    assert_eq!(QuicFrames::parse(&malformed), Err(expected));
    let mut iter = QuicFrameIter::new(&malformed);
    assert!(matches!(iter.next(), Some(Ok(QuicFrame::Ping(_)))));
    assert_eq!(iter.next(), Some(Err(expected)));
    assert_eq!(iter.next(), None);
    assert_eq!(iter.next(), None);

    let bytes = [0, 7, 1, 0xaa, 0x1e, 1];
    let frames = QuicFrames::parse(&bytes).unwrap();
    let mut iter = frames.iter();
    for expected_len in [1, 3, 1, 1] {
        assert_eq!(iter.next().unwrap().unwrap().as_bytes().len(), expected_len);
    }
    assert_eq!(iter.next(), None);
}

#[test]
fn new_token_and_handshake_done_views_are_reexported_from_the_crate_root() {
    let _new_token: Option<QuicNewTokenFrame<'_>> = None;
    let _handshake_done: Option<QuicHandshakeDoneFrame<'_>> = None;
    assert_eq!(QuicFrameField::Token, QuicFrameField::Token);
}

#[test]
fn path_frames_parse_exact_canonical_layouts_and_opaque_data() {
    for (bytes, response, data) in [
        (
            &[0x1a, 0, 1, 2, 3, 4, 5, 6, 7, 0xfe][..],
            false,
            &[0, 1, 2, 3, 4, 5, 6, 7],
        ),
        (
            &[0x1b, 0xff, 0, 0x80, 1, 2, 3, 4, 5, 0xfe][..],
            true,
            &[0xff, 0, 0x80, 1, 2, 3, 4, 5],
        ),
    ] {
        let (frame, suffix) = QuicFrame::parse(bytes).unwrap();
        assert_eq!(frame.as_bytes(), &bytes[..9]);
        assert_eq!(frame.frame_type().as_bytes(), &bytes[..1]);
        assert_eq!(suffix, &[0xfe]);
        match (frame, response) {
            (QuicFrame::PathChallenge(frame), false) => assert_eq!(frame.data(), data),
            (QuicFrame::PathResponse(frame), true) => assert_eq!(frame.data(), data),
            _ => panic!("unexpected path frame variant"),
        }
    }
}

#[test]
fn path_frames_preserve_noncanonical_type_widths_and_boundaries() {
    for (type_bytes, response) in [
        (&[0x40, 0x1a][..], false),
        (&[0x80, 0, 0, 0x1a][..], false),
        (&[0xc0, 0, 0, 0, 0, 0, 0, 0x1a][..], false),
        (&[0x40, 0x1b][..], true),
        (&[0x80, 0, 0, 0x1b][..], true),
        (&[0xc0, 0, 0, 0, 0, 0, 0, 0x1b][..], true),
    ] {
        let mut bytes = [0; 17];
        bytes[..type_bytes.len()].copy_from_slice(type_bytes);
        bytes[type_bytes.len()..type_bytes.len() + 8].copy_from_slice(&[9; 8]);
        bytes[type_bytes.len() + 8] = 0xfe;
        let input = &bytes[..type_bytes.len() + 9];
        let (frame, suffix) = QuicFrame::parse(input).unwrap();
        assert_eq!(frame.as_bytes(), &input[..type_bytes.len() + 8]);
        assert_eq!(frame.frame_type().as_bytes(), type_bytes);
        assert_eq!(suffix, &[0xfe]);
        assert!(matches!(frame, QuicFrame::PathResponse(_)) == response);
    }
}

#[test]
fn path_frames_report_every_incomplete_data_length() {
    for frame_type in [0x1a, 0x1b] {
        for available in 0..8 {
            let mut bytes = [0; 9];
            bytes[0] = frame_type;
            assert_eq!(
                QuicFrame::parse(&bytes[..available + 1]),
                Err(QuicFrameParseError::IncompleteBytes {
                    field: QuicFrameField::PathData,
                    offset: 1,
                    required: 8,
                    available,
                })
            );
        }
    }
}

#[test]
fn malformed_later_path_frame_has_absolute_offset_and_fused_iterator() {
    let bytes = [1, 0x1a, 0, 0, 0];
    let expected = QuicFrameParseError::IncompleteBytes {
        field: QuicFrameField::PathData,
        offset: 2,
        required: 8,
        available: 3,
    };
    assert_eq!(QuicFrames::parse(&bytes), Err(expected));
    let mut iter = QuicFrameIter::new(&bytes);
    assert!(matches!(iter.next(), Some(Ok(QuicFrame::Ping(_)))));
    assert_eq!(iter.next(), Some(Err(expected)));
    assert_eq!(iter.next(), None);
    assert_eq!(iter.next(), None);
}

#[test]
fn path_frames_mix_at_exact_boundaries_with_existing_frames() {
    let bytes = [
        0, 0x1a, 0, 1, 2, 3, 4, 5, 6, 7, 1, 0x1b, 8, 9, 10, 11, 12, 13, 14, 15, 0x1e,
    ];
    let frames = QuicFrames::parse(&bytes).unwrap();
    let mut iter = frames.iter();
    for (length, kind) in [(1, 0), (9, 1), (1, 2), (9, 3), (1, 4)] {
        let frame = iter.next().unwrap().unwrap();
        assert_eq!(frame.as_bytes().len(), length);
        match kind {
            0 => assert!(matches!(frame, QuicFrame::Padding(_))),
            1 => assert!(matches!(frame, QuicFrame::PathChallenge(_))),
            2 => assert!(matches!(frame, QuicFrame::Ping(_))),
            3 => assert!(matches!(frame, QuicFrame::PathResponse(_))),
            _ => assert!(matches!(frame, QuicFrame::HandshakeDone(_))),
        }
    }
    assert_eq!(iter.next(), None);
}

#[test]
fn path_frames_accept_arbitrary_opaque_data_and_reexport_from_root() {
    for (frame_type, data, response) in [
        (0x1a, [0; 8], false),
        (0x1b, [0xff; 8], true),
        (0x1a, [0, 0xff, 0x80, 0x7f, 1, 2, 3, 4], false),
    ] {
        let mut bytes = [0; 9];
        bytes[0] = frame_type;
        bytes[1..].copy_from_slice(&data);
        let (frame, suffix) = QuicFrame::parse(&bytes).unwrap();
        assert!(suffix.is_empty());
        match (frame, response) {
            (QuicFrame::PathChallenge(frame), false) => assert_eq!(frame.data(), &data),
            (QuicFrame::PathResponse(frame), true) => assert_eq!(frame.data(), &data),
            _ => panic!("unexpected path frame variant"),
        }
    }

    let _challenge: Option<QuicPathChallengeFrame<'_>> = None;
    let _response: Option<QuicPathResponseFrame<'_>> = None;
    assert_eq!(QuicFrameField::PathData, QuicFrameField::PathData);
}

#[test]
fn connection_id_frames_parse_exact_views_suffixes_and_root_exports() {
    let bytes = [
        0x18, 3, 2, 3, 0xa1, 0xa2, 0xa3, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0xfe,
    ];
    let (QuicFrame::NewConnectionId(frame), suffix) = QuicFrame::parse(&bytes).unwrap() else {
        panic!("expected NEW_CONNECTION_ID")
    };
    assert_eq!(frame.as_bytes(), &bytes[..23]);
    assert_eq!(frame.sequence_number().value(), 3);
    assert_eq!(frame.retire_prior_to().value(), 2);
    assert_eq!(frame.connection_id_length(), 3);
    assert_eq!(frame.connection_id().as_bytes(), &[0xa1, 0xa2, 0xa3]);
    assert_eq!(
        frame.stateless_reset_token(),
        &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    );
    assert_eq!(suffix, &[0xfe]);

    let retire = [0xc0, 0, 0, 0, 0, 0, 0, 0x19, 0x40, 7, 0xfe];
    let (QuicFrame::RetireConnectionId(frame), suffix) = QuicFrame::parse(&retire).unwrap() else {
        panic!("expected RETIRE_CONNECTION_ID")
    };
    assert_eq!(frame.as_bytes(), &retire[..10]);
    assert_eq!(frame.frame_type().as_bytes(), &retire[..8]);
    assert_eq!(frame.sequence_number().as_bytes(), &[0x40, 7]);
    assert_eq!(suffix, &[0xfe]);
    let _new: Option<QuicNewConnectionIdFrame<'_>> = None;
    let _retire: Option<QuicRetireConnectionIdFrame<'_>> = None;
}

#[test]
fn connection_id_frames_preserve_widths_and_maximum_values() {
    let bytes = [
        0x80, 0, 0, 0x18, 0x40, 1, 0x80, 0, 0, 1, 1, 0xaa, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    ];
    let (QuicFrame::NewConnectionId(frame), suffix) = QuicFrame::parse(&bytes).unwrap() else {
        panic!("expected NEW_CONNECTION_ID")
    };
    assert!(suffix.is_empty());
    assert_eq!(frame.frame_type().as_bytes(), &[0x80, 0, 0, 0x18]);
    assert_eq!(frame.sequence_number().as_bytes(), &[0x40, 1]);
    assert_eq!(frame.retire_prior_to().as_bytes(), &[0x80, 0, 0, 1]);

    let two_byte_type = [
        0x40, 0x18, 0x80, 0, 0, 1, 0x40, 1, 1, 0xaa, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    ];
    let (QuicFrame::NewConnectionId(frame), suffix) = QuicFrame::parse(&two_byte_type).unwrap()
    else {
        panic!("expected NEW_CONNECTION_ID")
    };
    assert!(suffix.is_empty());
    assert_eq!(frame.frame_type().as_bytes(), &[0x40, 0x18]);
    assert_eq!(frame.sequence_number().as_bytes(), &[0x80, 0, 0, 1]);
    assert_eq!(frame.retire_prior_to().as_bytes(), &[0x40, 1]);

    let maximum = [0xff; 8];
    let mut maximum_new = [0; 42];
    maximum_new[..8].copy_from_slice(&[0xc0, 0, 0, 0, 0, 0, 0, 0x18]);
    maximum_new[8..16].copy_from_slice(&maximum);
    maximum_new[16..24].copy_from_slice(&maximum);
    maximum_new[24] = 1;
    maximum_new[25] = 0xaa;
    maximum_new[26..].fill(0x55);
    let (QuicFrame::NewConnectionId(frame), _) = QuicFrame::parse(&maximum_new).unwrap() else {
        panic!("expected NEW_CONNECTION_ID")
    };
    assert_eq!(frame.frame_type().as_bytes(), &maximum_new[..8]);
    assert_eq!(frame.sequence_number().value(), (1u64 << 62) - 1);
    assert_eq!(frame.retire_prior_to().value(), (1u64 << 62) - 1);
    assert_eq!(frame.stateless_reset_token(), &[0x55; 16]);

    for type_bytes in [
        &[0x40, 0x19][..],
        &[0x80, 0, 0, 0x19][..],
        &[0xc0, 0, 0, 0, 0, 0, 0, 0x19][..],
    ] {
        let mut retire = [0; 9];
        retire[..type_bytes.len()].copy_from_slice(type_bytes);
        let (QuicFrame::RetireConnectionId(frame), suffix) =
            QuicFrame::parse(&retire[..type_bytes.len() + 1]).unwrap()
        else {
            panic!("expected RETIRE_CONNECTION_ID")
        };
        assert!(suffix.is_empty());
        assert_eq!(frame.frame_type().as_bytes(), type_bytes);
    }
}

#[test]
fn connection_id_frames_report_semantic_errors_and_absolute_offsets() {
    for (bytes, field, offset, required, available) in [
        (&[0x18][..], QuicFrameField::SequenceNumber, 1, 1, 0),
        (&[0x18, 0x40][..], QuicFrameField::SequenceNumber, 1, 2, 1),
        (
            &[0x18, 0x80, 0, 0][..],
            QuicFrameField::SequenceNumber,
            1,
            4,
            3,
        ),
        (
            &[0x18, 0xc0, 0, 0, 0, 0, 0, 0][..],
            QuicFrameField::SequenceNumber,
            1,
            8,
            7,
        ),
        (&[0x18, 0][..], QuicFrameField::RetirePriorTo, 2, 1, 0),
        (&[0x18, 0, 0x40][..], QuicFrameField::RetirePriorTo, 2, 2, 1),
        (
            &[0x18, 0, 0x80, 0, 0][..],
            QuicFrameField::RetirePriorTo,
            2,
            4,
            3,
        ),
        (
            &[0x18, 0, 0xc0, 0, 0, 0, 0, 0, 0][..],
            QuicFrameField::RetirePriorTo,
            2,
            8,
            7,
        ),
        (
            &[0x19, 0xc0, 0, 0, 0, 0, 0, 0][..],
            QuicFrameField::SequenceNumber,
            1,
            8,
            7,
        ),
    ] {
        assert_eq!(
            QuicFrame::parse(bytes),
            Err(QuicFrameParseError::Field {
                field,
                offset,
                error: QuicVarIntParseError::Incomplete {
                    required,
                    available
                },
            })
        );
    }
    assert_eq!(
        QuicFrame::parse(&[0x18, 0, 0]),
        Err(QuicFrameParseError::IncompleteBytes {
            field: QuicFrameField::ConnectionIdLength,
            offset: 3,
            required: 1,
            available: 0,
        })
    );
    assert_eq!(
        QuicFrame::parse(&[0x18, 0, 0, 0]),
        Err(QuicFrameParseError::EmptyField {
            field: QuicFrameField::ConnectionId,
            offset: 4,
        })
    );
    assert_eq!(
        QuicFrame::parse(&[0x18, 0, 0, 21]),
        Err(QuicFrameParseError::FieldValueOutOfRange {
            field: QuicFrameField::ConnectionIdLength,
            offset: 3,
            value: 21,
            maximum: 20,
        })
    );
    assert_eq!(
        QuicFrames::parse(&[1, 0x40, 0x18, 0x40, 1, 0x80, 0, 0, 2]),
        Err(QuicFrameParseError::FieldValueExceedsField {
            field: QuicFrameField::RetirePriorTo,
            offset: 5,
            value: 2,
            maximum_field: QuicFrameField::SequenceNumber,
            maximum: 1,
        })
    );
}

#[test]
fn connection_id_frames_bound_cid_token_and_fail_closed() {
    assert_eq!(
        QuicFrame::parse(&[0x18, 0, 0, 3]),
        Err(QuicFrameParseError::IncompleteBytes {
            field: QuicFrameField::ConnectionId,
            offset: 4,
            required: 3,
            available: 0,
        })
    );
    assert_eq!(
        QuicFrame::parse(&[0x18, 0, 0, 3, 0xaa]),
        Err(QuicFrameParseError::IncompleteBytes {
            field: QuicFrameField::ConnectionId,
            offset: 4,
            required: 3,
            available: 1,
        })
    );
    for available in 0..16 {
        let mut bytes = [0; 20];
        bytes[..4].copy_from_slice(&[0x18, 0, 0, 1]);
        bytes[4] = 0xaa;
        assert_eq!(
            QuicFrame::parse(&bytes[..5 + available]),
            Err(QuicFrameParseError::IncompleteBytes {
                field: QuicFrameField::StatelessResetToken,
                offset: 5,
                required: 16,
                available,
            })
        );
    }
    let mut maximum_connection_id = [0; 40];
    maximum_connection_id[..4].copy_from_slice(&[0x18, 0, 0, 20]);
    maximum_connection_id[4..24].fill(0xaa);
    maximum_connection_id[24..].fill(0x55);
    let (QuicFrame::NewConnectionId(frame), suffix) =
        QuicFrame::parse(&maximum_connection_id).unwrap()
    else {
        panic!("expected NEW_CONNECTION_ID")
    };
    assert!(suffix.is_empty());
    assert_eq!(frame.connection_id().len(), 20);
    assert_eq!(frame.connection_id().as_bytes(), &[0xaa; 20]);

    let bytes = [1, 0x19, 2, 0x18, 0, 0, 1, 0xaa];
    let expected = QuicFrameParseError::IncompleteBytes {
        field: QuicFrameField::StatelessResetToken,
        offset: 8,
        required: 16,
        available: 0,
    };
    assert_eq!(QuicFrames::parse(&bytes), Err(expected));
    let mut iter = QuicFrameIter::new(&bytes);
    assert!(matches!(iter.next(), Some(Ok(QuicFrame::Ping(_)))));
    assert!(matches!(
        iter.next(),
        Some(Ok(QuicFrame::RetireConnectionId(_)))
    ));
    assert_eq!(iter.next(), Some(Err(expected)));
    assert_eq!(iter.next(), None);

    let complete = [
        1, 0x19, 2, 0x18, 1, 0, 1, 0xaa, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0x1e,
    ];
    let frames = QuicFrames::parse(&complete).unwrap();
    let mut iter = frames.iter();
    assert!(matches!(iter.next(), Some(Ok(QuicFrame::Ping(_)))));
    assert!(matches!(
        iter.next(),
        Some(Ok(QuicFrame::RetireConnectionId(_)))
    ));
    assert!(matches!(
        iter.next(),
        Some(Ok(QuicFrame::NewConnectionId(_)))
    ));
    assert!(matches!(iter.next(), Some(Ok(QuicFrame::HandshakeDone(_)))));
    assert_eq!(iter.next(), None);
}

#[test]
fn crypto_frames_preserve_exact_boundaries_and_varint_encodings() {
    let bytes = [6, 2, 3, 0xaa, 0xbb, 0xcc, 0xfe];
    let (QuicFrame::Crypto(frame), suffix) = QuicFrame::parse(&bytes).unwrap() else {
        panic!("expected CRYPTO")
    };
    assert_eq!(frame.as_bytes(), &bytes[..6]);
    assert_eq!(frame.frame_type().as_bytes(), &[6]);
    assert_eq!(frame.offset().as_bytes(), &[2]);
    assert_eq!(frame.length().as_bytes(), &[3]);
    assert_eq!(frame.crypto_data(), &[0xaa, 0xbb, 0xcc]);
    assert_eq!(suffix, &[0xfe]);

    let zero = [6, 63, 0, 0xfe];
    let (QuicFrame::Crypto(frame), suffix) = QuicFrame::parse(&zero).unwrap() else {
        panic!("expected CRYPTO")
    };
    assert_eq!(frame.as_bytes(), &zero[..3]);
    assert_eq!(frame.crypto_data(), &[]);
    assert_eq!(suffix, &[0xfe]);

    for (bytes, type_bytes, offset_bytes, length_bytes) in [
        (
            &[0x40, 6, 0x40, 1, 0x40, 1, 0xaa][..],
            &[0x40, 6][..],
            &[0x40, 1][..],
            &[0x40, 1][..],
        ),
        (
            &[0x80, 0, 0, 6, 0x80, 0, 0, 2, 0x80, 0, 0, 1, 0xaa][..],
            &[0x80, 0, 0, 6][..],
            &[0x80, 0, 0, 2][..],
            &[0x80, 0, 0, 1][..],
        ),
        (
            &[
                0xc0, 0, 0, 0, 0, 0, 0, 6, 0xc0, 0, 0, 0, 0, 0, 0, 3, 0xc0, 0, 0, 0, 0, 0, 0, 1,
                0xaa,
            ][..],
            &[0xc0, 0, 0, 0, 0, 0, 0, 6][..],
            &[0xc0, 0, 0, 0, 0, 0, 0, 3][..],
            &[0xc0, 0, 0, 0, 0, 0, 0, 1][..],
        ),
    ] {
        let (QuicFrame::Crypto(frame), suffix) = QuicFrame::parse(bytes).unwrap() else {
            panic!("expected CRYPTO")
        };
        assert!(suffix.is_empty());
        assert_eq!(frame.as_bytes(), bytes);
        assert_eq!(frame.frame_type().as_bytes(), type_bytes);
        assert_eq!(frame.offset().as_bytes(), offset_bytes);
        assert_eq!(frame.length().as_bytes(), length_bytes);
        assert_eq!(frame.crypto_data(), &[0xaa]);
    }
}

#[test]
fn crypto_frames_validate_ranges_and_report_all_bounds() {
    let maximum = (1u64 << 62) - 1;
    for bytes in [
        &[6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0][..],
        &[6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 1, 0xaa][..],
    ] {
        assert!(matches!(
            QuicFrame::parse(bytes),
            Ok((QuicFrame::Crypto(_), _))
        ));
    }
    for (bytes, start, length) in [
        (
            &[6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1][..],
            maximum,
            1,
        ),
        (
            &[6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 2][..],
            maximum - 1,
            2,
        ),
    ] {
        assert_eq!(
            QuicFrame::parse(bytes),
            Err(QuicFrameParseError::FieldRangeOutOfRange {
                field: QuicFrameField::CryptoOffset,
                offset: 1,
                start,
                length,
                maximum,
            })
        );
    }

    for (field, offset) in [
        (QuicFrameField::CryptoOffset, 1),
        (QuicFrameField::CryptoLength, 2),
    ] {
        for (first, required) in [(0, 1), (0x40, 2), (0x80, 4), (0xc0, 8)] {
            for available in 0..required {
                let mut bytes = [0; 10];
                bytes[0] = 6;
                if field == QuicFrameField::CryptoLength {
                    bytes[1] = 0;
                }
                if available != 0 {
                    bytes[offset] = first;
                }
                let expected_required = if available == 0 { 1 } else { required };
                assert_eq!(
                    QuicFrame::parse(&bytes[..offset + available]),
                    Err(QuicFrameParseError::Field {
                        field,
                        offset,
                        error: QuicVarIntParseError::Incomplete {
                            required: expected_required,
                            available,
                        },
                    })
                );
            }
        }
    }

    for (bytes, required, available) in [(&[6, 0, 1][..], 1, 0), (&[6, 0, 3, 0xaa][..], 3, 1)] {
        assert_eq!(
            QuicFrame::parse(bytes),
            Err(QuicFrameParseError::IncompleteBytes {
                field: QuicFrameField::CryptoData,
                offset: 3,
                required,
                available,
            })
        );
    }
}

#[cfg(target_pointer_width = "32")]
#[test]
fn crypto_frames_reject_unrepresentable_lengths() {
    let bytes = [6, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert_eq!(
        QuicFrame::parse(&bytes),
        Err(QuicFrameParseError::LengthNotRepresentable {
            field: QuicFrameField::CryptoLength,
            offset: 2,
            value: (1u64 << 62) - 1,
        })
    );
}

#[test]
fn crypto_frames_mix_at_exact_boundaries_and_are_reexported_from_root() {
    let malformed = [1, 6, 0, 3, 0xaa];
    let expected = QuicFrameParseError::IncompleteBytes {
        field: QuicFrameField::CryptoData,
        offset: 4,
        required: 3,
        available: 1,
    };
    assert_eq!(QuicFrames::parse(&malformed), Err(expected));
    let mut failed = QuicFrameIter::new(&malformed);
    assert!(matches!(failed.next(), Some(Ok(QuicFrame::Ping(_)))));
    assert_eq!(failed.next(), Some(Err(expected)));
    assert_eq!(failed.next(), None);
    assert_eq!(failed.next(), None);

    let bytes = [0, 6, 0, 1, 0xaa, 1, 6, 1, 0, 0x1e];
    let frames = QuicFrames::parse(&bytes).unwrap();
    let mut iter = frames.iter();
    for (length, kind) in [(1, 0), (4, 1), (1, 2), (3, 1), (1, 3)] {
        let frame = iter.next().unwrap().unwrap();
        assert_eq!(frame.as_bytes().len(), length);
        match kind {
            0 => assert!(matches!(frame, QuicFrame::Padding(_))),
            1 => assert!(matches!(frame, QuicFrame::Crypto(_))),
            2 => assert!(matches!(frame, QuicFrame::Ping(_))),
            _ => assert!(matches!(frame, QuicFrame::HandshakeDone(_))),
        }
    }
    assert_eq!(iter.next(), None);
    let _crypto: Option<QuicCryptoFrame<'_>> = None;
    assert_eq!(QuicFrameField::CryptoData, QuicFrameField::CryptoData);
}

#[test]
fn stream_frames_cover_all_flag_layouts_and_terminal_implicit_data() {
    for (frame_type, offset, length, fin, expected_data, suffix) in [
        (0x08, None, None, false, &[0xaa, 1, 0][..], &[][..]),
        (0x09, None, None, true, &[0xaa, 1, 0][..], &[][..]),
        (0x0a, None, Some(2), false, &[0xaa, 0xbb][..], &[1][..]),
        (0x0b, None, Some(2), true, &[0xaa, 0xbb][..], &[1][..]),
        (0x0c, Some(3), None, false, &[0xaa, 1, 0][..], &[][..]),
        (0x0d, Some(3), None, true, &[0xaa, 1, 0][..], &[][..]),
        (0x0e, Some(3), Some(2), false, &[0xaa, 0xbb][..], &[1][..]),
        (0x0f, Some(3), Some(2), true, &[0xaa, 0xbb][..], &[1][..]),
    ] {
        let mut bytes = [0; 8];
        bytes[0] = frame_type;
        bytes[1] = 7;
        let mut end = 2;
        if let Some(value) = offset {
            bytes[end] = value;
            end += 1;
        }
        if let Some(value) = length {
            bytes[end] = value;
            end += 1;
            bytes[end..end + 2].copy_from_slice(&[0xaa, 0xbb]);
            end += 2;
            bytes[end] = 1;
            end += 1;
        } else {
            bytes[end..end + 3].copy_from_slice(&[0xaa, 1, 0]);
            end += 3;
        }
        let (QuicFrame::Stream(frame), actual_suffix) = QuicFrame::parse(&bytes[..end]).unwrap()
        else {
            panic!("expected STREAM")
        };
        assert_eq!(frame.frame_type().value(), frame_type as u64);
        assert_eq!(frame.stream_id().value(), 7);
        assert_eq!(frame.offset().map(QuicVarInt::value), offset.map(u64::from));
        assert_eq!(frame.length().map(QuicVarInt::value), length.map(u64::from));
        assert_eq!(frame.fin(), fin);
        assert_eq!(frame.stream_data(), expected_data);
        assert_eq!(actual_suffix, suffix);
    }

    let terminal = [0x08, 1, 1, 0, 0x1e];
    let frames = QuicFrames::parse(&terminal).unwrap();
    let mut iter = frames.iter();
    assert!(matches!(iter.next(), Some(Ok(QuicFrame::Stream(_)))));
    assert_eq!(iter.next(), None);

    for bytes in [
        &[0x08, 1][..],
        &[0x09, 1][..],
        &[0x0a, 1, 0][..],
        &[0x0b, 1, 0][..],
        &[0x0c, 1, 0][..],
        &[0x0d, 1, 0][..],
        &[0x0e, 1, 0, 0][..],
        &[0x0f, 1, 0, 0][..],
    ] {
        let (QuicFrame::Stream(frame), suffix) = QuicFrame::parse(bytes).unwrap() else {
            panic!("expected STREAM")
        };
        assert!(frame.stream_data().is_empty());
        assert!(suffix.is_empty());
    }

    let explicit = [0x0a, 1, 1, 0xaa, 1, 0];
    let frames = QuicFrames::parse(&explicit).unwrap();
    assert_eq!(
        frames.iter().next().unwrap().unwrap().as_bytes(),
        &explicit[..4]
    );
}

#[test]
fn stream_frames_preserve_noncanonical_encodings_and_explicit_boundaries() {
    for bytes in [
        &[0x40, 0x0e, 0x40, 1, 0x40, 2, 0x40, 1, 0xaa, 1][..],
        &[
            0x80, 0, 0, 0x0e, 0x80, 0, 0, 1, 0x80, 0, 0, 2, 0x80, 0, 0, 1, 0xaa, 1,
        ][..],
        &[
            0xc0, 0, 0, 0, 0, 0, 0, 0x0e, 0xc0, 0, 0, 0, 0, 0, 0, 1, 0xc0, 0, 0, 0, 0, 0, 0, 2,
            0xc0, 0, 0, 0, 0, 0, 0, 1, 0xaa, 1,
        ][..],
    ] {
        let (QuicFrame::Stream(frame), suffix) = QuicFrame::parse(bytes).unwrap() else {
            panic!("expected STREAM")
        };
        assert_eq!(suffix, &[1]);
        assert_eq!(
            frame.frame_type().as_bytes(),
            &bytes[..frame.frame_type().byte_len()]
        );
        assert_eq!(
            frame.stream_id().encoded_len(),
            frame.frame_type().encoded_len()
        );
        assert_eq!(
            frame.offset().unwrap().encoded_len(),
            frame.frame_type().encoded_len()
        );
        assert_eq!(
            frame.length().unwrap().encoded_len(),
            frame.frame_type().encoded_len()
        );
        assert_eq!(frame.stream_data(), &[0xaa]);
    }
}

#[test]
fn stream_frames_report_range_and_truncation_diagnostics_exactly() {
    let maximum = (1u64 << 62) - 1;
    for bytes in [
        &[0x0e, 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0][..],
        &[
            0x0e, 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 1, 0xaa,
        ][..],
    ] {
        assert!(matches!(
            QuicFrame::parse(bytes),
            Ok((QuicFrame::Stream(_), _))
        ));
    }
    for (bytes, start, length, diagnostic_offset) in [
        (
            &[0x0e, 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1][..],
            maximum,
            1,
            2,
        ),
        (
            &[0x0e, 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 2][..],
            maximum - 1,
            2,
            2,
        ),
    ] {
        assert_eq!(
            QuicFrame::parse(bytes),
            Err(QuicFrameParseError::FieldRangeOutOfRange {
                field: QuicFrameField::StreamOffset,
                offset: diagnostic_offset,
                start,
                length,
                maximum,
            })
        );
    }
    for (type_byte, field, field_offset) in [
        (0x08, QuicFrameField::StreamId, 1),
        (0x0c, QuicFrameField::StreamOffset, 2),
        (0x0e, QuicFrameField::StreamLength, 3),
    ] {
        for (prefix, required) in [
            (&[][..], 1),
            (&[0x40][..], 2),
            (&[0x80, 0, 0][..], 4),
            (&[0xc0, 0, 0, 0, 0, 0, 0][..], 8),
        ] {
            let mut bytes = [0; 11];
            bytes[0] = type_byte;
            bytes[1..field_offset].fill(0);
            bytes[field_offset..field_offset + prefix.len()].copy_from_slice(prefix);
            assert_eq!(
                QuicFrame::parse(&bytes[..field_offset + prefix.len()]),
                Err(QuicFrameParseError::Field {
                    field,
                    offset: field_offset,
                    error: QuicVarIntParseError::Incomplete {
                        required,
                        available: prefix.len(),
                    },
                })
            );
        }
    }
    for available in 0..3 {
        let bytes = [0x0a, 1, 3, 0xaa, 0xbb];
        assert_eq!(
            QuicFrame::parse(&bytes[..3 + available]),
            Err(QuicFrameParseError::IncompleteBytes {
                field: QuicFrameField::StreamData,
                offset: 3,
                required: 3,
                available,
            })
        );
    }
}

#[test]
fn stream_frames_fail_closed_later_and_are_reexported_from_root() {
    let bytes = [1, 0x0e, 1, 0, 0x80, 0];
    let expected = QuicFrameParseError::Field {
        field: QuicFrameField::StreamLength,
        offset: 4,
        error: QuicVarIntParseError::Incomplete {
            required: 4,
            available: 2,
        },
    };
    assert_eq!(QuicFrames::parse(&bytes), Err(expected));
    let mut iter = QuicFrameIter::new(&bytes);
    assert!(matches!(iter.next(), Some(Ok(QuicFrame::Ping(_)))));
    assert_eq!(iter.next(), Some(Err(expected)));
    assert_eq!(iter.next(), None);
    let _stream: Option<QuicStreamFrame<'_>> = None;
    assert_eq!(QuicFrameField::StreamData, QuicFrameField::StreamData);
}

#[test]
fn ack_zero_ranges_preserves_headers_and_valid_looking_suffix() {
    let bytes = [2, 10, 1, 0, 2, 1];
    let (QuicFrame::Ack(frame), suffix) = QuicFrame::parse(&bytes).unwrap() else {
        panic!("expected ACK");
    };
    assert_eq!(frame.as_bytes(), &bytes[..5]);
    assert_eq!(suffix, &[1]);
    for (field, raw, value) in [
        (frame.frame_type(), &[2][..], 2),
        (frame.largest_acknowledged(), &[10][..], 10),
        (frame.ack_delay(), &[1][..], 1),
        (frame.ack_range_count(), &[0][..], 0),
        (frame.first_ack_range(), &[2][..], 2),
    ] {
        assert_eq!(field.as_bytes(), raw);
        assert_eq!(field.value(), value);
        assert_eq!(field.encoded_len(), QuicVarIntLen::One);
    }
    assert_eq!(frame.first_smallest_acknowledged(), 8);
    assert_eq!(frame.ranges().next(), None);
    assert!(frame.ecn_counts().is_none());
}

#[test]
fn ack_ecn_zero_ranges_preserves_counts_and_suffix() {
    let bytes = [3, 4, 0, 0, 0, 1, 2, 3, 0];
    let (QuicFrame::Ack(frame), suffix) = QuicFrame::parse(&bytes).unwrap() else {
        panic!("expected ACK_ECN");
    };
    assert_eq!(frame.as_bytes(), &bytes[..8]);
    assert_eq!(suffix, &[0]);
    let counts = frame.ecn_counts().unwrap();
    assert_eq!(counts.as_bytes(), &[1, 2, 3]);
    for (field, raw, value) in [
        (counts.ect0_count(), &[1][..], 1),
        (counts.ect1_count(), &[2][..], 2),
        (counts.ecn_ce_count(), &[3][..], 3),
    ] {
        assert_eq!(field.as_bytes(), raw);
        assert_eq!(field.value(), value);
    }
}

#[test]
fn ack_additional_ranges_are_descending_clonable_and_fused() {
    let bytes = [2, 20, 0, 2, 2, 0, 1, 2, 0];
    let (QuicFrame::Ack(frame), suffix) = QuicFrame::parse(&bytes).unwrap() else {
        panic!("expected ACK");
    };
    assert!(suffix.is_empty());
    assert_eq!(frame.ack_range_count().value(), 2);
    assert_eq!(frame.first_smallest_acknowledged(), 18);

    let mut ranges = frame.ranges();
    let mut clone = ranges.clone();
    let first = ranges.next().unwrap();
    let cloned_first = clone.next().unwrap();
    assert_eq!(first, cloned_first);
    assert_eq!(first.as_bytes(), &[0, 1]);
    assert_eq!(first.gap().value(), 0);
    assert_eq!(first.ack_range_length().value(), 1);
    assert_eq!(
        (first.largest_acknowledged(), first.smallest_acknowledged()),
        (16, 15)
    );

    let second = ranges.next().unwrap();
    assert_eq!(second.as_bytes(), &[2, 0]);
    assert_eq!(second.gap().value(), 2);
    assert_eq!(second.ack_range_length().value(), 0);
    assert_eq!(
        (
            second.largest_acknowledged(),
            second.smallest_acknowledged()
        ),
        (11, 11)
    );
    assert_eq!(ranges.next(), None);
    assert_eq!(ranges.next(), None);
    assert_eq!(clone.next().unwrap(), second);
    assert_eq!(clone.next(), None);
}

#[test]
fn ack_noncanonical_widths_preserve_every_accessor() {
    let bytes = [
        0x40, 3, // ACK_ECN type, two-byte encoding
        0x80, 0, 0, 10, // largest acknowledged, four-byte encoding
        0xc0, 0, 0, 0, 0, 0, 0, 1, // ACK delay, eight-byte encoding
        0x40, 1, // range count, two-byte encoding
        0x80, 0, 0, 0, // first range, four-byte encoding
        0x40, 0, // Gap, two-byte encoding
        0xc0, 0, 0, 0, 0, 0, 0, 0, // ACK Range Length, eight-byte encoding
        0x40, 1, // ECT(0), two-byte encoding
        0x80, 0, 0, 2, // ECT(1), four-byte encoding
        0xc0, 0, 0, 0, 0, 0, 0, 3, // ECN-CE, eight-byte encoding
    ];
    let (QuicFrame::Ack(frame), suffix) = QuicFrame::parse(&bytes).unwrap() else {
        panic!("expected ACK_ECN");
    };
    assert!(suffix.is_empty());
    for (field, raw, width, value) in [
        (frame.frame_type(), &[0x40, 3][..], QuicVarIntLen::Two, 3),
        (
            frame.largest_acknowledged(),
            &[0x80, 0, 0, 10][..],
            QuicVarIntLen::Four,
            10,
        ),
        (
            frame.ack_delay(),
            &[0xc0, 0, 0, 0, 0, 0, 0, 1][..],
            QuicVarIntLen::Eight,
            1,
        ),
        (
            frame.ack_range_count(),
            &[0x40, 1][..],
            QuicVarIntLen::Two,
            1,
        ),
        (
            frame.first_ack_range(),
            &[0x80, 0, 0, 0][..],
            QuicVarIntLen::Four,
            0,
        ),
    ] {
        assert_eq!(
            (field.as_bytes(), field.encoded_len(), field.value()),
            (raw, width, value)
        );
    }
    let range = frame.ranges().next().unwrap();
    for (field, raw, width, value) in [
        (range.gap(), &[0x40, 0][..], QuicVarIntLen::Two, 0),
        (
            range.ack_range_length(),
            &[0xc0, 0, 0, 0, 0, 0, 0, 0][..],
            QuicVarIntLen::Eight,
            0,
        ),
    ] {
        assert_eq!(
            (field.as_bytes(), field.encoded_len(), field.value()),
            (raw, width, value)
        );
    }
    let counts = frame.ecn_counts().unwrap();
    for (field, raw, width, value) in [
        (counts.ect0_count(), &[0x40, 1][..], QuicVarIntLen::Two, 1),
        (
            counts.ect1_count(),
            &[0x80, 0, 0, 2][..],
            QuicVarIntLen::Four,
            2,
        ),
        (
            counts.ecn_ce_count(),
            &[0xc0, 0, 0, 0, 0, 0, 0, 3][..],
            QuicVarIntLen::Eight,
            3,
        ),
    ] {
        assert_eq!(
            (field.as_bytes(), field.encoded_len(), field.value()),
            (raw, width, value)
        );
    }
}

#[test]
fn ack_arithmetic_boundaries_and_underflows_are_exact() {
    let maximum = [0xff; 8];
    let mut bytes = [0; 19];
    bytes[0] = 2;
    bytes[1..9].copy_from_slice(&maximum);
    bytes[11..19].copy_from_slice(&maximum);
    let (QuicFrame::Ack(frame), suffix) = QuicFrame::parse(&bytes).unwrap() else {
        panic!("expected ACK");
    };
    assert!(suffix.is_empty());
    assert_eq!(frame.first_smallest_acknowledged(), 0);

    assert_eq!(
        QuicFrame::parse(&[2, 1, 0, 0, 2]),
        Err(QuicFrameParseError::AckRangeUnderflow {
            field: QuicFrameField::FirstAckRange,
            offset: 4,
            base: 1,
            value: 2,
            adjustment: 0,
        })
    );
    let (QuicFrame::Ack(frame), _) = QuicFrame::parse(&[2, 2, 0, 1, 0, 0, 0]).unwrap() else {
        panic!("expected ACK");
    };
    let range = frame.ranges().next().unwrap();
    assert_eq!(
        (range.largest_acknowledged(), range.smallest_acknowledged()),
        (0, 0)
    );
    assert_eq!(
        QuicFrame::parse(&[2, 1, 0, 1, 0, 0, 0]),
        Err(QuicFrameParseError::AckRangeUnderflow {
            field: QuicFrameField::AckGap,
            offset: 5,
            base: 1,
            value: 0,
            adjustment: 2,
        })
    );
    assert_eq!(
        QuicFrame::parse(&[2, 3, 0, 1, 0, 0, 2]),
        Err(QuicFrameParseError::AckRangeUnderflow {
            field: QuicFrameField::AckRangeLength,
            offset: 6,
            base: 1,
            value: 2,
            adjustment: 0,
        })
    );
}

#[test]
fn ack_range_counts_fail_at_the_first_missing_range_field() {
    assert_eq!(
        QuicFrame::parse(&[2, 10, 0, 1, 0]),
        Err(QuicFrameParseError::Field {
            field: QuicFrameField::AckGap,
            offset: 5,
            error: QuicVarIntParseError::Incomplete {
                required: 1,
                available: 0,
            },
        })
    );
    assert_eq!(
        QuicFrame::parse(&[2, 10, 0, 1, 0, 0]),
        Err(QuicFrameParseError::Field {
            field: QuicFrameField::AckRangeLength,
            offset: 6,
            error: QuicVarIntParseError::Incomplete {
                required: 1,
                available: 0,
            },
        })
    );
    assert_eq!(
        QuicFrame::parse(&[2, 10, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]),
        Err(QuicFrameParseError::Field {
            field: QuicFrameField::AckGap,
            offset: 12,
            error: QuicVarIntParseError::Incomplete {
                required: 1,
                available: 0,
            },
        })
    );
}

#[test]
fn ack_varint_truncations_name_each_field_and_absolute_offset() {
    for (bytes, field, offset, required, available) in [
        (&[2][..], QuicFrameField::LargestAcknowledged, 1, 1, 0),
        (&[2, 0, 0x40][..], QuicFrameField::AckDelay, 2, 2, 1),
        (
            &[2, 0, 0, 0x80, 0, 0][..],
            QuicFrameField::AckRangeCount,
            3,
            4,
            3,
        ),
        (
            &[2, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0][..],
            QuicFrameField::FirstAckRange,
            4,
            8,
            7,
        ),
        (&[3, 0, 0, 0, 0][..], QuicFrameField::Ect0Count, 5, 1, 0),
        (
            &[3, 0, 0, 0, 0, 0, 0x40][..],
            QuicFrameField::Ect1Count,
            6,
            2,
            1,
        ),
        (
            &[3, 0, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0][..],
            QuicFrameField::EcnCeCount,
            7,
            8,
            7,
        ),
        (
            &[2, 2, 0, 1, 0, 0x80, 0, 0][..],
            QuicFrameField::AckGap,
            5,
            4,
            3,
        ),
        (
            &[2, 2, 0, 1, 0, 0][..],
            QuicFrameField::AckRangeLength,
            6,
            1,
            0,
        ),
    ] {
        assert_eq!(
            QuicFrame::parse(bytes),
            Err(QuicFrameParseError::Field {
                field,
                offset,
                error: QuicVarIntParseError::Incomplete {
                    required,
                    available,
                },
            })
        );
    }
}

#[test]
fn ack_sequences_preserve_boundaries_fail_closed_and_export_root_types() {
    let bytes = [1, 2, 5, 0, 0, 0, 0];
    let frames = QuicFrames::parse(&bytes).unwrap();
    let mut iter = frames.iter();
    assert_eq!(iter.next().unwrap().unwrap().as_bytes(), &[1]);
    assert_eq!(iter.next().unwrap().unwrap().as_bytes(), &[2, 5, 0, 0, 0]);
    assert_eq!(iter.next().unwrap().unwrap().as_bytes(), &[0]);
    assert_eq!(iter.next(), None);

    let malformed = [1, 2, 5, 0, 1, 0];
    let expected = QuicFrameParseError::Field {
        field: QuicFrameField::AckGap,
        offset: 6,
        error: QuicVarIntParseError::Incomplete {
            required: 1,
            available: 0,
        },
    };
    assert_eq!(QuicFrames::parse(&malformed), Err(expected));
    let mut iter = QuicFrameIter::new(&malformed);
    assert!(matches!(iter.next(), Some(Ok(QuicFrame::Ping(_)))));
    assert_eq!(iter.next(), Some(Err(expected)));
    assert_eq!(iter.next(), None);
    assert_eq!(iter.next(), None);

    let _: Option<QuicAckFrame<'_>> = None;
    let _: Option<QuicAckRange<'_>> = None;
    let _: Option<QuicAckRanges<'_>> = None;
    let _: Option<QuicEcnCounts<'_>> = None;
    let _: Option<QuicFrame<'_>> = None;
}

#[test]
fn connection_close_frames_preserve_transport_and_application_layouts() {
    let transport = [0x1c, 0x2a, 0x06, 3, 0xff, 0, 0x80, 1];
    let (QuicFrame::ConnectionClose(frame), suffix) = QuicFrame::parse(&transport).unwrap() else {
        panic!("expected CONNECTION_CLOSE")
    };
    assert_eq!(frame.as_bytes(), &transport[..7]);
    assert_eq!(frame.frame_type().as_bytes(), &[0x1c]);
    assert_eq!(frame.error_code().value(), 42);
    assert_eq!(frame.triggering_frame_type().unwrap().value(), 6);
    assert_eq!(frame.reason_phrase_length().as_bytes(), &[3]);
    assert_eq!(frame.reason_phrase(), &[0xff, 0, 0x80]);
    assert_eq!(suffix, &[1]);

    for (application, reason, suffix) in [
        (&[0x1d, 9, 0, 0x1e][..], &[][..], &[0x1e][..]),
        (
            &[0x1d, 9, 2, 0xff, 0x80, 1][..],
            &[0xff, 0x80][..],
            &[1][..],
        ),
    ] {
        let (QuicFrame::ConnectionClose(frame), actual_suffix) =
            QuicFrame::parse(application).unwrap()
        else {
            panic!("expected application CONNECTION_CLOSE")
        };
        assert_eq!(frame.frame_type().value(), 0x1d);
        assert_eq!(frame.error_code().value(), 9);
        assert_eq!(frame.triggering_frame_type(), None);
        assert_eq!(frame.reason_phrase(), reason);
        assert_eq!(actual_suffix, suffix);
    }

    let maximum = [0xff; 8];
    let mut extreme = [0; 18];
    extreme[0] = 0x1c;
    extreme[1..9].copy_from_slice(&maximum);
    extreme[9..17].copy_from_slice(&maximum);
    extreme[17] = 0;
    let (QuicFrame::ConnectionClose(frame), suffix) = QuicFrame::parse(&extreme).unwrap() else {
        panic!("expected maximum CONNECTION_CLOSE")
    };
    assert!(suffix.is_empty());
    assert_eq!(frame.error_code().value(), (1u64 << 62) - 1);
    assert_eq!(
        frame.triggering_frame_type().unwrap().value(),
        (1u64 << 62) - 1
    );
    assert_eq!(frame.reason_phrase_length().value(), 0);
}

#[test]
fn connection_close_frames_preserve_noncanonical_widths_and_exact_boundaries() {
    let transport = [
        0x40, 0x1c, // type
        0x40, 1, // error code
        0x80, 0, 0, 2, // triggering type
        0xc0, 0, 0, 0, 0, 0, 0, 1, // reason length
        0xaa, 1,
    ];
    let (QuicFrame::ConnectionClose(frame), suffix) = QuicFrame::parse(&transport).unwrap() else {
        panic!("expected CONNECTION_CLOSE")
    };
    assert_eq!(suffix, &[1]);
    for (field, bytes, width) in [
        (frame.frame_type(), &[0x40, 0x1c][..], QuicVarIntLen::Two),
        (frame.error_code(), &[0x40, 1][..], QuicVarIntLen::Two),
        (
            frame.triggering_frame_type().unwrap(),
            &[0x80, 0, 0, 2][..],
            QuicVarIntLen::Four,
        ),
        (
            frame.reason_phrase_length(),
            &[0xc0, 0, 0, 0, 0, 0, 0, 1][..],
            QuicVarIntLen::Eight,
        ),
    ] {
        assert_eq!((field.as_bytes(), field.encoded_len()), (bytes, width));
        assert!(!field.is_canonical());
    }
    assert_eq!(frame.reason_phrase(), &[0xaa]);

    let application = [0x80, 0, 0, 0x1d, 0, 1, 0];
    let (QuicFrame::ConnectionClose(frame), suffix) = QuicFrame::parse(&application).unwrap()
    else {
        panic!("expected application CONNECTION_CLOSE")
    };
    assert_eq!(frame.frame_type().encoded_len(), QuicVarIntLen::Four);
    assert_eq!(frame.error_code().value(), 0);
    assert_eq!(frame.reason_phrase_length().value(), 1);
    assert_eq!(frame.reason_phrase(), &[0]);
    assert!(suffix.is_empty());
}

#[test]
fn connection_close_fields_and_reason_bounds_report_exact_errors() {
    for (bytes, field, offset, required, available) in [
        (
            &[0x1c][..],
            QuicFrameField::ConnectionCloseErrorCode,
            1,
            1,
            0,
        ),
        (
            &[0x1c, 0x40][..],
            QuicFrameField::ConnectionCloseErrorCode,
            1,
            2,
            1,
        ),
        (&[0x1c, 0][..], QuicFrameField::TriggeringFrameType, 2, 1, 0),
        (
            &[0x1c, 0, 0x80, 0, 0][..],
            QuicFrameField::TriggeringFrameType,
            2,
            4,
            3,
        ),
        (
            &[0x1c, 0, 0][..],
            QuicFrameField::ReasonPhraseLength,
            3,
            1,
            0,
        ),
        (
            &[0x1c, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0][..],
            QuicFrameField::ReasonPhraseLength,
            3,
            8,
            7,
        ),
        (
            &[0x1d][..],
            QuicFrameField::ConnectionCloseErrorCode,
            1,
            1,
            0,
        ),
        (
            &[0x1d, 0x80, 0, 0][..],
            QuicFrameField::ConnectionCloseErrorCode,
            1,
            4,
            3,
        ),
        (&[0x1d, 0][..], QuicFrameField::ReasonPhraseLength, 2, 1, 0),
        (
            &[0x1d, 0, 0x40][..],
            QuicFrameField::ReasonPhraseLength,
            2,
            2,
            1,
        ),
    ] {
        assert_eq!(
            QuicFrame::parse(bytes),
            Err(QuicFrameParseError::Field {
                field,
                offset,
                error: QuicVarIntParseError::Incomplete {
                    required,
                    available,
                },
            })
        );
    }

    for available in 0..3 {
        let bytes = [0x1c, 0, 0, 3, 0xaa, 0xbb];
        assert_eq!(
            QuicFrame::parse(&bytes[..4 + available]),
            Err(QuicFrameParseError::IncompleteBytes {
                field: QuicFrameField::ReasonPhrase,
                offset: 4,
                required: 3,
                available,
            })
        );
    }
    let (QuicFrame::ConnectionClose(frame), suffix) = QuicFrame::parse(&[0x1d, 0, 0, 1]).unwrap()
    else {
        panic!("expected empty CONNECTION_CLOSE")
    };
    assert!(frame.reason_phrase().is_empty());
    assert_eq!(suffix, &[1]);
}

#[cfg(target_pointer_width = "32")]
#[test]
fn connection_close_rejects_an_unrepresentable_reason_length() {
    let bytes = [0x1d, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert_eq!(
        QuicFrame::parse(&bytes),
        Err(QuicFrameParseError::LengthNotRepresentable {
            field: QuicFrameField::ReasonPhraseLength,
            offset: 2,
            value: (1u64 << 62) - 1,
        })
    );
}

#[cfg(target_pointer_width = "64")]
#[test]
fn connection_close_reports_huge_representable_reason_length_as_incomplete() {
    let bytes = [0x1d, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert_eq!(
        QuicFrame::parse(&bytes),
        Err(QuicFrameParseError::IncompleteBytes {
            field: QuicFrameField::ReasonPhrase,
            offset: 10,
            required: (1usize << 62) - 1,
            available: 0,
        })
    );
}

#[test]
fn connection_close_frames_mix_and_fail_closed_at_absolute_offsets() {
    let bytes = [0, 1, 0x1c, 2, 3, 1, 0xaa, 0x1d, 4, 0, 0];
    let frames = QuicFrames::parse(&bytes).unwrap();
    let mut iter = frames.iter();
    for (length, close) in [
        (1usize, false),
        (1, false),
        (5, true),
        (3, true),
        (1, false),
    ] {
        let frame = iter.next().unwrap().unwrap();
        assert_eq!(frame.as_bytes().len(), length);
        assert_eq!(matches!(frame, QuicFrame::ConnectionClose(_)), close);
    }
    assert_eq!(iter.next(), None);

    let malformed = [1, 0x1d, 0, 3, 0xaa];
    let expected = QuicFrameParseError::IncompleteBytes {
        field: QuicFrameField::ReasonPhrase,
        offset: 4,
        required: 3,
        available: 1,
    };
    assert_eq!(QuicFrames::parse(&malformed), Err(expected));
    let mut raw = QuicFrameIter::new(&malformed);
    assert!(matches!(raw.next(), Some(Ok(QuicFrame::Ping(_)))));
    assert_eq!(raw.next(), Some(Err(expected)));
    assert_eq!(raw.next(), None);
    assert_eq!(raw.next(), None);

    let _close: Option<QuicConnectionCloseFrame<'_>> = None;
    let (frame, _) = QuicFrame::parse(&[0x1c, 0, 0, 0]).unwrap();
    match frame {
        QuicFrame::ConnectionClose(frame) => {
            assert_eq!(frame.error_code().value(), 0);
            assert_eq!(frame.triggering_frame_type().unwrap().value(), 0);
        }
        _ => panic!("expected CONNECTION_CLOSE"),
    }
}

#[test]
fn transport_parameters_preserve_empty_tuples_boundaries_and_raw_varints() {
    let empty = QuicTransportParameters::parse(&[]).unwrap();
    assert_eq!(empty.as_bytes(), &[]);
    assert_eq!(empty.iter().next(), None);

    let bytes = [
        0x01, 0x00, 0x40, 0x25, 0x40, 0x02, 0xaa, 0xbb, 0x1b, 0x01, 0xcc,
    ];
    let parameters = QuicTransportParameters::parse(&bytes).unwrap();
    assert_eq!(parameters.as_bytes(), &bytes);
    let mut iter = parameters.iter();
    let first = iter.next().unwrap().unwrap();
    assert_eq!(first.as_bytes(), &[0x01, 0x00]);
    assert_eq!(
        first.parameter_id(),
        QuicTransportParameterId::MAX_IDLE_TIMEOUT
    );
    assert_eq!(first.value(), &[]);
    let second = iter.next().unwrap().unwrap();
    assert_eq!(second.as_bytes(), &[0x40, 0x25, 0x40, 0x02, 0xaa, 0xbb]);
    assert_eq!(second.id().as_bytes(), &[0x40, 0x25]);
    assert_eq!(second.id().value(), 37);
    assert_eq!(second.length().as_bytes(), &[0x40, 0x02]);
    assert_eq!(second.value(), &[0xaa, 0xbb]);
    let third = iter.next().unwrap().unwrap();
    assert!(third.parameter_id().is_reserved());
    assert_eq!(third.value(), &[0xcc]);
    assert_eq!(iter.next(), None);
}

#[test]
fn transport_parameter_varint_widths_and_reserved_ids_are_exact() {
    let bytes = [
        0x01, 0x00, 0x40, 0x40, 0x40, 0x00, 0x80, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0xc0,
        0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let parameters = QuicTransportParameters::parse(&bytes).unwrap();
    let mut iter = parameters.iter();
    let one = iter.next().unwrap().unwrap();
    assert_eq!(one.id().as_bytes(), &[0x01]);
    assert_eq!(one.length().as_bytes(), &[0x00]);
    let two = iter.next().unwrap().unwrap();
    assert_eq!(two.id().as_bytes(), &[0x40, 0x40]);
    assert_eq!(two.length().as_bytes(), &[0x40, 0x00]);
    let four = iter.next().unwrap().unwrap();
    assert_eq!(four.id().as_bytes(), &[0x80, 0x00, 0x40, 0x00]);
    assert_eq!(four.length().as_bytes(), &[0x80, 0x00, 0x00, 0x00]);
    let eight = iter.next().unwrap().unwrap();
    assert_eq!(
        eight.id().as_bytes(),
        &[0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        eight.length().as_bytes(),
        &[0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );
    assert_eq!(iter.next(), None);

    for id in [
        QuicTransportParameterId::new(27),
        QuicTransportParameterId::new(58),
        QuicTransportParameterId::new(((1u64 << 62) - 1) - 7),
        QuicTransportParameterId::new(u64::MAX - 19),
    ] {
        assert!(id.is_reserved());
    }
    for id in [26, 28, 57, 59, (1u64 << 62) - 1, u64::MAX] {
        assert!(!QuicTransportParameterId::new(id).is_reserved());
    }
}

#[test]
fn transport_parameter_errors_report_absolute_fields_and_value_boundaries() {
    for (bytes, required) in [
        (&[0x40][..], 2),
        (&[0x80, 0][..], 4),
        (&[0xc0, 0, 0][..], 8),
    ] {
        assert_eq!(
            QuicTransportParameters::parse(bytes),
            Err(QuicTransportParameterParseError::IncompleteVarInt {
                field: QuicTransportParameterField::Id,
                offset: 0,
                error: QuicVarIntParseError::Incomplete {
                    required,
                    available: bytes.len(),
                },
            })
        );
    }
    for (bytes, required) in [
        (&[1, 0x40][..], 2),
        (&[1, 0x80, 0][..], 4),
        (&[1, 0xc0, 0, 0][..], 8),
    ] {
        assert_eq!(
            QuicTransportParameters::parse(bytes),
            Err(QuicTransportParameterParseError::IncompleteVarInt {
                field: QuicTransportParameterField::Length,
                offset: 1,
                error: QuicVarIntParseError::Incomplete {
                    required,
                    available: bytes.len() - 1,
                },
            })
        );
    }
    for (bytes, available) in [(&[1, 2][..], 0), (&[1, 2, 0xaa][..], 1)] {
        assert_eq!(
            QuicTransportParameters::parse(bytes),
            Err(QuicTransportParameterParseError::IncompleteValue {
                offset: 2,
                required: 2,
                available,
            })
        );
    }

    let huge = [1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    match usize::try_from((1u64 << 62) - 1) {
        Ok(required) => assert_eq!(
            QuicTransportParameters::parse(&huge),
            Err(QuicTransportParameterParseError::IncompleteValue {
                offset: 9,
                required,
                available: 0,
            })
        ),
        Err(_) => assert_eq!(
            QuicTransportParameters::parse(&huge),
            Err(QuicTransportParameterParseError::LengthNotRepresentable {
                offset: 1,
                value: (1u64 << 62) - 1,
            })
        ),
    }
}

#[test]
fn transport_parameter_duplicates_and_iteration_are_validated() {
    let duplicate = [1, 0, 2, 0, 1, 0];
    assert_eq!(
        QuicTransportParameters::parse(&duplicate),
        Err(QuicTransportParameterParseError::DuplicateId {
            id: QuicTransportParameterId::new(1),
            first_offset: 0,
            duplicate_offset: 4,
        })
    );
    let noncanonical_duplicate = [1, 0, 37, 0, 0x40, 1, 0];
    assert_eq!(
        QuicTransportParameters::parse(&noncanonical_duplicate),
        Err(QuicTransportParameterParseError::DuplicateId {
            id: QuicTransportParameterId::new(1),
            first_offset: 0,
            duplicate_offset: 4,
        })
    );
    assert_eq!(
        QuicTransportParameters::parse(&[1, 0, 0x40, 1, 2, 0xaa]),
        Err(QuicTransportParameterParseError::IncompleteValue {
            offset: 5,
            required: 2,
            available: 1,
        })
    );

    let validated = QuicTransportParameters::parse(&[1, 0, 2, 1, 0xaa]).unwrap();
    let mut left = validated.iter();
    let mut right = left.clone();
    assert_eq!(left.next().unwrap().unwrap().parameter_id().raw(), 1);
    assert_eq!(right.next().unwrap().unwrap().parameter_id().raw(), 1);
    assert_eq!(left.next().unwrap().unwrap().value(), &[0xaa]);
    assert_eq!(left.next(), None);
    assert_eq!(left.next(), None);
    let _: Option<QuicTransportParameterIter<'_>> = Some(right);
    let _: Option<QuicTransportParameter<'_>> = None;
}

#[test]
fn transport_parameter_typed_integer_views_preserve_width_and_reject_other_layouts() {
    for id in [
        0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0e,
    ] {
        let bytes = [id, 1, 2];
        let parameter = QuicTransportParameters::parse(&bytes)
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(parameter.integer().unwrap().value(), 2);
    }
    let parameters = QuicTransportParameters::parse(&[0x01, 0x02, 0x40, 0x25]).unwrap();
    let parameter = parameters.iter().next().unwrap().unwrap();
    let integer = parameter.integer().unwrap();
    assert_eq!(integer.as_bytes(), &[0x40, 0x25]);
    assert_eq!(integer.value(), 37);
    assert!(!integer.is_canonical());

    for (value, expected) in [
        (
            &[][..],
            QuicTransportParameterValueError::MalformedInteger {
                error: QuicVarIntParseError::Incomplete {
                    required: 1,
                    available: 0,
                },
            },
        ),
        (
            &[0x40][..],
            QuicTransportParameterValueError::MalformedInteger {
                error: QuicVarIntParseError::Incomplete {
                    required: 2,
                    available: 1,
                },
            },
        ),
        (
            &[0x01, 0xaa][..],
            QuicTransportParameterValueError::TrailingIntegerBytes {
                parsed: 1,
                available: 2,
            },
        ),
    ] {
        let mut bytes = [0u8; 4];
        bytes[0] = 0x01;
        bytes[1] = value.len() as u8;
        bytes[2..2 + value.len()].copy_from_slice(value);
        let parameter = QuicTransportParameters::parse(&bytes[..2 + value.len()])
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(parameter.integer(), Err(expected));
    }
    let parameter = QuicTransportParameters::parse(&[0x02, 0])
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(
        parameter.integer(),
        Err(QuicTransportParameterValueError::WrongId {
            kind: QuicTransportParameterValueKind::Integer,
            actual: QuicTransportParameterId::STATELESS_RESET_TOKEN,
        })
    );
}

#[test]
fn transport_parameter_typed_connection_token_and_empty_views_are_bounded() {
    for id in [0x00, 0x0f, 0x10] {
        let bytes = [id, 0];
        let parameter = QuicTransportParameters::parse(&bytes)
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .unwrap();
        assert!(parameter.connection_id().unwrap().is_empty());
    }
    let mut maximum_cid = [0u8; 22];
    maximum_cid[0] = 0x0f;
    maximum_cid[1] = 20;
    maximum_cid[2..].fill(0x33);
    assert_eq!(
        QuicTransportParameters::parse(&maximum_cid)
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .unwrap()
            .connection_id()
            .unwrap()
            .len(),
        20
    );
    let mut cid = [0u8; 23];
    cid[0] = 0x0f;
    cid[1] = 21;
    assert_eq!(
        QuicTransportParameters::parse(&cid)
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .unwrap()
            .connection_id(),
        Err(QuicTransportParameterValueError::ConnectionIdTooLong {
            maximum: 20,
            actual: 21
        })
    );
    let parameter = QuicTransportParameters::parse(&[0x02, 0])
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(
        parameter.connection_id(),
        Err(QuicTransportParameterValueError::WrongId {
            kind: QuicTransportParameterValueKind::ConnectionId,
            actual: QuicTransportParameterId::STATELESS_RESET_TOKEN,
        })
    );

    let token = [
        0x02, 16, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa,
    ];
    assert_eq!(
        QuicTransportParameters::parse(&token)
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .unwrap()
            .stateless_reset_token()
            .unwrap(),
        &[0xaa; 16]
    );
    for length in [15, 17] {
        let mut bytes = [0u8; 19];
        bytes[0] = 0x02;
        bytes[1] = length;
        let parameter = QuicTransportParameters::parse(&bytes[..2 + usize::from(length)])
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(
            parameter.stateless_reset_token(),
            Err(QuicTransportParameterValueError::WrongLength {
                kind: QuicTransportParameterValueKind::StatelessResetToken,
                expected: 16,
                actual: usize::from(length),
            })
        );
    }
    let parameter = QuicTransportParameters::parse(&[0x01, 0])
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(
        parameter.stateless_reset_token(),
        Err(QuicTransportParameterValueError::WrongId {
            kind: QuicTransportParameterValueKind::StatelessResetToken,
            actual: QuicTransportParameterId::MAX_IDLE_TIMEOUT,
        })
    );
    let parameter = QuicTransportParameters::parse(&[0x0c, 0])
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(parameter.disable_active_migration(), Ok(()));
    let parameter = QuicTransportParameters::parse(&[0x0c, 1, 0])
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(
        parameter.disable_active_migration(),
        Err(QuicTransportParameterValueError::WrongLength {
            kind: QuicTransportParameterValueKind::DisableActiveMigration,
            expected: 0,
            actual: 1,
        })
    );
    let parameter = QuicTransportParameters::parse(&[0x01, 0])
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(
        parameter.disable_active_migration(),
        Err(QuicTransportParameterValueError::WrongId {
            kind: QuicTransportParameterValueKind::DisableActiveMigration,
            actual: QuicTransportParameterId::MAX_IDLE_TIMEOUT,
        })
    );
}

#[test]
fn transport_parameter_preferred_address_exposes_exact_borrowed_fields() {
    let _: Option<QuicPreferredAddress<'_>> = None;
    let _: QuicTransportParameterValueError = QuicTransportParameterValueError::WrongLength {
        kind: QuicTransportParameterValueKind::PreferredAddress,
        expected: 0,
        actual: 0,
    };
    let mut bytes = [0u8; 45];
    bytes[..3].copy_from_slice(&[0x0d, 0x40, 42]);
    bytes[3..7].copy_from_slice(&[192, 0, 2, 1]);
    bytes[7..9].copy_from_slice(&443u16.to_be_bytes());
    bytes[9..25].copy_from_slice(&[0x20; 16]);
    bytes[25..27].copy_from_slice(&8443u16.to_be_bytes());
    bytes[27] = 1;
    bytes[28] = 0x44;
    bytes[29..].copy_from_slice(&[0x55; 16]);
    let parameter = QuicTransportParameters::parse(&bytes)
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .unwrap();
    let preferred = parameter.preferred_address().unwrap();
    assert_eq!(preferred.as_bytes(), &bytes[3..]);
    assert_eq!(preferred.ipv4_address(), &[192, 0, 2, 1]);
    assert_eq!(preferred.ipv4_port(), 443);
    assert_eq!(preferred.ipv6_address(), &[0x20; 16]);
    assert_eq!(preferred.ipv6_port(), 8443);
    assert_eq!(preferred.connection_id().as_bytes(), &[0x44]);
    assert_eq!(preferred.stateless_reset_token(), &[0x55; 16]);

    let mut twenty = [0u8; 64];
    twenty[0] = 0x0d;
    twenty[1] = 61;
    twenty[26] = 20;
    twenty[27..47].fill(0x66);
    twenty[47..63].fill(0x77);
    assert_eq!(
        QuicTransportParameters::parse(&twenty[..63])
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .unwrap()
            .preferred_address()
            .unwrap()
            .connection_id()
            .len(),
        20
    );
}

#[test]
fn transport_parameter_preferred_address_reports_value_relative_bounds() {
    for (length, offset, required) in [
        (0usize, 0, 4),
        (3, 0, 4),
        (5, 4, 6),
        (21, 6, 22),
        (23, 22, 24),
        (24, 24, 25),
        (25, 25, 26),
        (40, 26, 42),
    ] {
        let mut bytes = [0u8; 65];
        bytes[0] = 0x0d;
        bytes[1] = length as u8;
        if length > 24 {
            bytes[26] = 1;
        }
        let parameter = QuicTransportParameters::parse(&bytes[..2 + length])
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(
            parameter.preferred_address(),
            Err(
                QuicTransportParameterValueError::PreferredAddressIncomplete {
                    offset,
                    required,
                    available: length,
                }
            )
        );
    }
    for connection_id_length in [0u8, 21] {
        let mut bytes = [0u8; 63];
        bytes[0] = 0x0d;
        bytes[1] = 61;
        bytes[26] = connection_id_length;
        let parameter = QuicTransportParameters::parse(&bytes)
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(
            parameter.preferred_address(),
            Err(
                QuicTransportParameterValueError::PreferredAddressConnectionIdLength {
                    actual: connection_id_length,
                }
            )
        );
    }
    let mut token_truncated = [0u8; 43];
    token_truncated[0] = 0x0d;
    token_truncated[1] = 41;
    token_truncated[26] = 1;
    let parameter = QuicTransportParameters::parse(&token_truncated)
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(
        parameter.preferred_address(),
        Err(
            QuicTransportParameterValueError::PreferredAddressIncomplete {
                offset: 26,
                required: 42,
                available: 41,
            }
        )
    );
    let mut trailing = [0u8; 45];
    trailing[0] = 0x0d;
    trailing[1] = 43;
    trailing[26] = 1;
    let parameter = QuicTransportParameters::parse(&trailing)
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(
        parameter.preferred_address(),
        Err(
            QuicTransportParameterValueError::PreferredAddressTrailingBytes {
                offset: 42,
                available: 1,
            }
        )
    );
    let parameter = QuicTransportParameters::parse(&[0x01, 0])
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(
        parameter.preferred_address(),
        Err(QuicTransportParameterValueError::WrongId {
            kind: QuicTransportParameterValueKind::PreferredAddress,
            actual: QuicTransportParameterId::MAX_IDLE_TIMEOUT,
        })
    );
}

#[test]
fn transport_parameter_v1_semantics_bound_present_integers_and_preserve_raw_views() {
    let bytes = [
        0x03, 0x02, 0x44, 0xb0, // max_udp_payload_size = 1200
        0x08, 0x08, 0xd0, 0, 0, 0, 0, 0, 0, 0, // initial_max_streams_bidi = 2^60
        0x09, 0x08, 0xd0, 0, 0, 0, 0, 0, 0, 0, // initial_max_streams_uni = 2^60
        0x0a, 0x01, 20, // ack_delay_exponent
        0x0b, 0x02, 0x7f, 0xff, // max_ack_delay = 2^14 - 1
        0x0e, 0x01, 2, // active_connection_id_limit
        0x01, 0x02, 0x40, 0x25, // max_idle_timeout = 37 in two-byte width
        0x04, 0x04, 0x80, 0, 0, 0x25, // initial_max_data = 37 in four-byte width
        0x05, 0x08, 0xc0, 0, 0, 0, 0, 0, 0,
        0x25, // initial_max_stream_data_bidi_local = 37 in eight-byte width
        0x1b, 0x03, 0xaa, 0xbb, 0xcc, // reserved opaque parameter
        0x20, 0x02, 0xdd, 0xee, // unknown opaque parameter
    ];
    let raw = QuicTransportParameters::parse(&bytes).unwrap();
    let checked: QuicTransportParametersV1<'_> = raw
        .validate_v1(QuicTransportParameterSender::Client)
        .unwrap();
    let _: QuicTransportParameterSender = QuicTransportParameterSender::Client;
    let _: QuicTransportParameterSemanticError =
        QuicTransportParameterSemanticError::ForbiddenSender {
            id: QuicTransportParameterId::ORIGINAL_DESTINATION_CONNECTION_ID,
            offset: 0,
        };
    assert_eq!(checked.as_bytes(), &bytes);
    assert_eq!(checked.sender(), QuicTransportParameterSender::Client);
    assert_eq!(
        checked.iter().nth(1).unwrap().unwrap().value(),
        &[0xd0, 0, 0, 0, 0, 0, 0, 0]
    );
    for (index, encoded) in [
        (6, &[0x40, 0x25][..]),
        (7, &[0x80, 0, 0, 0x25][..]),
        (8, &[0xc0, 0, 0, 0, 0, 0, 0, 0x25][..]),
    ] {
        let integer = checked
            .iter()
            .nth(index)
            .unwrap()
            .unwrap()
            .integer()
            .unwrap();
        assert_eq!(integer.as_bytes(), encoded);
        assert_eq!(integer.value(), 37);
        assert!(!integer.is_canonical());
    }
    let reserved = checked.iter().nth(9).unwrap().unwrap();
    assert_eq!(reserved.as_bytes(), &[0x1b, 0x03, 0xaa, 0xbb, 0xcc]);
    assert_eq!(reserved.parameter_id().raw(), 0x1b);
    let unknown = checked.iter().nth(10).unwrap().unwrap();
    assert_eq!(unknown.as_bytes(), &[0x20, 0x02, 0xdd, 0xee]);
    assert_eq!(unknown.parameter_id().raw(), 0x20);
    assert_eq!(raw.as_bytes(), &bytes);

    for (bytes, id, value, maximum) in [
        (
            &[0x08, 0x08, 0xd0, 0, 0, 0, 0, 0, 0, 1][..],
            0x08,
            (1u64 << 60) + 1,
            1u64 << 60,
        ),
        (
            &[0x09, 0x08, 0xd0, 0, 0, 0, 0, 0, 0, 1][..],
            0x09,
            (1u64 << 60) + 1,
            1u64 << 60,
        ),
        (&[0x0a, 0x01, 21][..], 0x0a, 21, 20),
        (
            &[0x0b, 0x04, 0x80, 0, 0x40, 0][..],
            0x0b,
            1 << 14,
            (1 << 14) - 1,
        ),
    ] {
        assert_eq!(
            QuicTransportParameters::parse(bytes)
                .unwrap()
                .validate_v1(QuicTransportParameterSender::Client),
            Err(QuicTransportParameterSemanticError::AboveMaximum {
                id: QuicTransportParameterId::new(id),
                offset: 0,
                value,
                maximum,
            })
        );
    }
    for (bytes, id, value, minimum) in [
        (&[0x03, 0x02, 0x44, 0xaf][..], 0x03, 1199, 1200),
        (&[0x0e, 0x01, 1][..], 0x0e, 1, 2),
    ] {
        assert_eq!(
            QuicTransportParameters::parse(bytes)
                .unwrap()
                .validate_v1(QuicTransportParameterSender::Client),
            Err(QuicTransportParameterSemanticError::BelowMinimum {
                id: QuicTransportParameterId::new(id),
                offset: 0,
                value,
                minimum,
            })
        );
    }
}

#[test]
fn transport_parameter_v1_semantics_enforce_roles_and_typed_layouts() {
    let prefix = [0x01, 0x01, 0];
    let mut malformed_original = [0u8; 26];
    malformed_original[..3].copy_from_slice(&prefix);
    malformed_original[3] = 0x00;
    malformed_original[4] = 21;
    let original = QuicTransportParameters::parse(&malformed_original).unwrap();
    assert_eq!(
        original.validate_v1(QuicTransportParameterSender::Client),
        Err(QuicTransportParameterSemanticError::ForbiddenSender {
            id: QuicTransportParameterId::ORIGINAL_DESTINATION_CONNECTION_ID,
            offset: 3,
        })
    );
    assert_eq!(original.as_bytes(), &malformed_original);
    assert_eq!(
        original.iter().nth(1).unwrap().unwrap().as_bytes(),
        &malformed_original[3..]
    );
    assert_eq!(
        original.validate_v1(QuicTransportParameterSender::Server),
        Err(QuicTransportParameterSemanticError::Value {
            id: QuicTransportParameterId::ORIGINAL_DESTINATION_CONNECTION_ID,
            offset: 3,
            error: QuicTransportParameterValueError::ConnectionIdTooLong {
                maximum: 20,
                actual: 21,
            },
        })
    );

    let mut malformed_retry = [0u8; 26];
    malformed_retry[..3].copy_from_slice(&prefix);
    malformed_retry[3] = 0x10;
    malformed_retry[4] = 21;
    for (bytes, id) in [
        (&[0x01, 0x01, 0, 0x02, 0][..], 0x02),
        (&[0x01, 0x01, 0, 0x0d, 0][..], 0x0d),
        (&malformed_retry[..], 0x10),
    ] {
        let parameters = QuicTransportParameters::parse(bytes).unwrap();
        assert_eq!(
            parameters.validate_v1(QuicTransportParameterSender::Client),
            Err(QuicTransportParameterSemanticError::ForbiddenSender {
                id: QuicTransportParameterId::new(id),
                offset: 3,
            })
        );
    }

    let mut original_connection_id = [0u8; 22];
    original_connection_id[1] = 20;
    assert!(
        QuicTransportParameters::parse(&original_connection_id)
            .unwrap()
            .validate_v1(QuicTransportParameterSender::Server)
            .is_ok()
    );
    let mut stateless_reset_token = [0u8; 18];
    stateless_reset_token[0] = 0x02;
    stateless_reset_token[1] = 16;
    assert!(
        QuicTransportParameters::parse(&stateless_reset_token)
            .unwrap()
            .validate_v1(QuicTransportParameterSender::Server)
            .is_ok()
    );
    let mut preferred_address = [0u8; 45];
    preferred_address[..3].copy_from_slice(&[0x0d, 0x40, 42]);
    preferred_address[27] = 1;
    assert!(
        QuicTransportParameters::parse(&preferred_address)
            .unwrap()
            .validate_v1(QuicTransportParameterSender::Server)
            .is_ok()
    );
    let mut retry_source_connection_id = [0u8; 22];
    retry_source_connection_id[0] = 0x10;
    retry_source_connection_id[1] = 20;
    assert!(
        QuicTransportParameters::parse(&retry_source_connection_id)
            .unwrap()
            .validate_v1(QuicTransportParameterSender::Server)
            .is_ok()
    );

    let mut malformed_token = [0u8; 20];
    malformed_token[..3].copy_from_slice(&prefix);
    malformed_token[3] = 0x02;
    malformed_token[4] = 15;
    assert_eq!(
        QuicTransportParameters::parse(&malformed_token)
            .unwrap()
            .validate_v1(QuicTransportParameterSender::Server),
        Err(QuicTransportParameterSemanticError::Value {
            id: QuicTransportParameterId::STATELESS_RESET_TOKEN,
            offset: 3,
            error: QuicTransportParameterValueError::WrongLength {
                kind: QuicTransportParameterValueKind::StatelessResetToken,
                expected: 16,
                actual: 15,
            },
        })
    );

    for (bytes, id, error) in [
        (
            &[0x04, 0x01, 0, 0x01, 0x02, 1, 0xaa][..],
            QuicTransportParameterId::MAX_IDLE_TIMEOUT,
            QuicTransportParameterValueError::TrailingIntegerBytes {
                parsed: 1,
                available: 2,
            },
        ),
        (
            &[0x01, 0x01, 0, 0x03, 0x01, 0x40][..],
            QuicTransportParameterId::MAX_UDP_PAYLOAD_SIZE,
            QuicTransportParameterValueError::MalformedInteger {
                error: QuicVarIntParseError::Incomplete {
                    required: 2,
                    available: 1,
                },
            },
        ),
        (
            &[0x01, 0x01, 0, 0x0c, 0x01, 0][..],
            QuicTransportParameterId::DISABLE_ACTIVE_MIGRATION,
            QuicTransportParameterValueError::WrongLength {
                kind: QuicTransportParameterValueKind::DisableActiveMigration,
                expected: 0,
                actual: 1,
            },
        ),
        (
            &[0x01, 0x01, 0, 0x0d, 0][..],
            QuicTransportParameterId::PREFERRED_ADDRESS,
            QuicTransportParameterValueError::PreferredAddressIncomplete {
                offset: 0,
                required: 4,
                available: 0,
            },
        ),
    ] {
        assert_eq!(
            QuicTransportParameters::parse(bytes)
                .unwrap()
                .validate_v1(QuicTransportParameterSender::Server),
            Err(QuicTransportParameterSemanticError::Value {
                id,
                offset: 3,
                error,
            })
        );
    }
}

#[test]
fn transport_parameter_handshake_client_cids_are_exact_and_reusable() {
    let _: QuicTransportParameterHandshakeContext<'_> =
        QuicTransportParameterHandshakeContext::Client {
            initial_source_connection_id: b"cid",
        };
    let _: QuicTransportParameterHandshakeError = QuicTransportParameterHandshakeError::Missing {
        id: QuicTransportParameterId::INITIAL_SOURCE_CONNECTION_ID,
    };
    let structural = QuicTransportParameterHandshakeError::Structural {
        error: QuicTransportParameterParseError::IncompleteValue {
            offset: 1,
            required: 2,
            available: 1,
        },
    };
    assert_eq!(
        structural.to_string(),
        "QUIC handshake transport parameters are not structural: QUIC transport parameter value at offset 1 is incomplete: need 2 bytes, have 1"
    );
    let zero = QuicTransportParameters::parse(&[0x0f, 0]).unwrap();
    let checked = zero
        .validate_v1(QuicTransportParameterSender::Client)
        .unwrap();
    assert_eq!(
        checked.validate_handshake(QuicTransportParameterHandshakeContext::Client {
            initial_source_connection_id: &[],
        }),
        Ok(())
    );

    let bytes = [0x01, 0x01, 0, 0x40, 0x0f, 0x40, 0x03, b'c', b'i', b'd'];
    let checked = QuicTransportParameters::parse(&bytes)
        .unwrap()
        .validate_v1(QuicTransportParameterSender::Client)
        .unwrap();
    assert_eq!(
        checked.validate_handshake(QuicTransportParameterHandshakeContext::Client {
            initial_source_connection_id: b"bad",
        }),
        Err(QuicTransportParameterHandshakeError::ConnectionIdMismatch {
            id: QuicTransportParameterId::INITIAL_SOURCE_CONNECTION_ID,
            offset: 3,
        })
    );
    assert_eq!(checked.as_bytes(), &bytes);
    assert_eq!(
        checked.validate_handshake(QuicTransportParameterHandshakeContext::Client {
            initial_source_connection_id: b"cid",
        }),
        Ok(())
    );
    assert_eq!(
        QuicTransportParameters::parse(&[])
            .unwrap()
            .validate_v1(QuicTransportParameterSender::Client)
            .unwrap()
            .validate_handshake(QuicTransportParameterHandshakeContext::Client {
                initial_source_connection_id: b"cid",
            }),
        Err(QuicTransportParameterHandshakeError::Missing {
            id: QuicTransportParameterId::INITIAL_SOURCE_CONNECTION_ID,
        })
    );
}

#[test]
fn transport_parameter_handshake_server_cids_retry_and_precedence_are_exact() {
    let no_retry = [0x0f, 0, 0x00, 0x02, b'o', b'd'];
    let checked = QuicTransportParameters::parse(&no_retry)
        .unwrap()
        .validate_v1(QuicTransportParameterSender::Server)
        .unwrap();
    let context = QuicTransportParameterHandshakeContext::Server {
        initial_source_connection_id: &[],
        original_destination_connection_id: b"od",
        retry_source_connection_id: None,
    };
    assert_eq!(checked.validate_handshake(context), Ok(()));

    let retry = [0x0f, 0x01, b'i', 0x00, 0, 0x10, 0x01, b'r'];
    let checked = QuicTransportParameters::parse(&retry)
        .unwrap()
        .validate_v1(QuicTransportParameterSender::Server)
        .unwrap();
    assert_eq!(
        checked.validate_handshake(QuicTransportParameterHandshakeContext::Server {
            initial_source_connection_id: b"i",
            original_destination_connection_id: &[],
            retry_source_connection_id: Some(b"r"),
        }),
        Ok(())
    );
    assert_eq!(
        checked.validate_handshake(QuicTransportParameterHandshakeContext::Server {
            initial_source_connection_id: b"i",
            original_destination_connection_id: &[],
            retry_source_connection_id: None,
        }),
        Err(QuicTransportParameterHandshakeError::Unexpected {
            id: QuicTransportParameterId::RETRY_SOURCE_CONNECTION_ID,
            offset: 5,
        })
    );
    for (initial, original, retry, id, offset) in [
        (b"x" as &[u8], &[][..], Some(b"r" as &[u8]), 0x0f, 0),
        (b"i" as &[u8], b"x" as &[u8], Some(b"r" as &[u8]), 0x00, 3),
        (b"i" as &[u8], &[][..], Some(b"x" as &[u8]), 0x10, 5),
    ] {
        assert_eq!(
            checked.validate_handshake(QuicTransportParameterHandshakeContext::Server {
                initial_source_connection_id: initial,
                original_destination_connection_id: original,
                retry_source_connection_id: retry,
            }),
            Err(QuicTransportParameterHandshakeError::ConnectionIdMismatch {
                id: QuicTransportParameterId::new(id),
                offset,
            })
        );
    }
    for (bytes, expected) in [
        (
            &[][..],
            QuicTransportParameterId::INITIAL_SOURCE_CONNECTION_ID,
        ),
        (
            &[0x0f, 0][..],
            QuicTransportParameterId::ORIGINAL_DESTINATION_CONNECTION_ID,
        ),
        (
            &[0x0f, 0, 0x00, 0][..],
            QuicTransportParameterId::RETRY_SOURCE_CONNECTION_ID,
        ),
    ] {
        assert_eq!(
            QuicTransportParameters::parse(bytes)
                .unwrap()
                .validate_v1(QuicTransportParameterSender::Server)
                .unwrap()
                .validate_handshake(QuicTransportParameterHandshakeContext::Server {
                    initial_source_connection_id: &[],
                    original_destination_connection_id: &[],
                    retry_source_connection_id: Some(b"r"),
                }),
            Err(QuicTransportParameterHandshakeError::Missing { id: expected })
        );
    }
}

#[test]
fn transport_parameter_handshake_context_sender_mismatch_precedes_tuple_scanning() {
    let client = QuicTransportParameters::parse(&[])
        .unwrap()
        .validate_v1(QuicTransportParameterSender::Client)
        .unwrap();
    assert_eq!(
        client.validate_handshake(QuicTransportParameterHandshakeContext::Server {
            initial_source_connection_id: &[],
            original_destination_connection_id: &[],
            retry_source_connection_id: None,
        }),
        Err(
            QuicTransportParameterHandshakeError::SenderContextMismatch {
                sender: QuicTransportParameterSender::Client,
                context_sender: QuicTransportParameterSender::Server,
            }
        )
    );
    let server = QuicTransportParameters::parse(&[])
        .unwrap()
        .validate_v1(QuicTransportParameterSender::Server)
        .unwrap();
    assert_eq!(
        server.validate_handshake(QuicTransportParameterHandshakeContext::Client {
            initial_source_connection_id: &[],
        }),
        Err(
            QuicTransportParameterHandshakeError::SenderContextMismatch {
                sender: QuicTransportParameterSender::Server,
                context_sender: QuicTransportParameterSender::Client,
            }
        )
    );
}
