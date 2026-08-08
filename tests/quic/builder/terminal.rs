use net_wire::quic::*;

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
