use net_wire::quic::*;

#[test]
fn protected_long_builders_map_versions_low_bits_and_exact_fields() {
    use net_wire::quic::{
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
