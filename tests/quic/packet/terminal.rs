use net_wire::quic::*;

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
