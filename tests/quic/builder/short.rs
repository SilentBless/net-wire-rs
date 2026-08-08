use net_wire::quic::*;

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
fn short_packet_builder_synthesizes_a_minimal_packet() {
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
