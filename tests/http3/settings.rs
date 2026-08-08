use net_wire::http3::{
    Http3FrameBuildError, Http3FramePayloadField, Http3FramePayloadParseError, Http3PeerSettings,
    Http3Setting, Http3SettingId, Http3SettingValue, Http3Settings, Http3SettingsBuildError,
    Http3SettingsBuilder, Http3SettingsIter, Http3SettingsSemanticError,
};
use net_wire::quic::{QuicVarIntBuildError, QuicVarIntParseError};

#[test]
fn typed_settings_eagerly_validate_and_iterate_exact_wire_order() {
    let empty: Http3Settings<'_> = Http3Settings::parse(&[0x04, 0x00], 0).unwrap();
    assert_eq!(empty.settings().next(), None);

    let settings: Http3Settings<'_> = Http3Settings::parse(
        &[
            0x04, 0x0f, 0x40, 0x01, 0x80, 0x00, 0x00, 0x02, 0x01, 0x40, 0x03, 0x80, 0x00, 0x00,
            0x21, 0x40, 0x00,
        ],
        15,
    )
    .unwrap();
    let mut iter: Http3SettingsIter<'_> = settings.settings();
    let first: Http3Setting<'_> = iter.next().unwrap();
    assert_eq!(first.as_bytes(), &[0x40, 0x01, 0x80, 0x00, 0x00, 0x02]);
    assert_eq!(first.id(), Http3SettingId::new(1));
    assert_eq!(first.id_varint().as_bytes(), &[0x40, 0x01]);
    assert_eq!(first.value(), 2);
    assert_eq!(first.value_varint().as_bytes(), &[0x80, 0x00, 0x00, 0x02]);

    let second: Http3Setting<'_> = iter.next().unwrap();
    assert_eq!(second.as_bytes(), &[0x01, 0x40, 0x03]);
    assert_eq!(second.id().value(), 1);
    assert_eq!(second.value(), 3);
    let third = iter.next().unwrap();
    assert_eq!(third.as_bytes(), &[0x80, 0x00, 0x00, 0x21, 0x40, 0x00]);
    assert_eq!(third.id().value(), 33);
    assert_eq!(third.value(), 0);
    assert_eq!(iter.next(), None);
    assert_eq!(iter.next(), None);
}

#[test]
fn settings_semantic_empty_defaults_are_available() {
    let settings = Http3Settings::parse(&[0x04, 0x00], 0).unwrap();
    let peer = settings.validate_semantics().unwrap();
    assert_eq!(peer, Http3PeerSettings::default());
    assert_eq!(peer.qpack_max_table_capacity(), 0);
    assert_eq!(peer.maximum_field_section_size(), None);
    assert_eq!(peer.qpack_blocked_streams(), 0);
}

#[test]
fn settings_semantics_interpret_known_peer_values() {
    let settings = Http3Settings::parse(
        &[
            0x04, 0x0a, 0x01, 0x40, 0x40, 0x06, 0x00, 0x07, 0x80, 0x00, 0x40, 0x00,
        ],
        10,
    )
    .unwrap();

    let peer = settings.validate_semantics().unwrap();
    assert_eq!(peer.qpack_max_table_capacity(), 64);
    assert_eq!(peer.maximum_field_section_size(), Some(0));
    assert_eq!(peer.qpack_blocked_streams(), 16_384);
}

#[test]
fn settings_semantics_ignore_extensions_without_mutating_raw_views() {
    let wire = [
        0x04, 0x0c, 0x40, 0x22, 0x80, 0x00, 0x00, 0x02, 0x80, 0x00, 0x00, 0x21, 0x40, 0x00,
    ];
    let settings = Http3Settings::parse(&wire, 12).unwrap();
    let raw = settings;

    assert_eq!(
        settings.validate_semantics().unwrap(),
        Http3PeerSettings::default()
    );
    assert_eq!(raw.as_bytes(), &wire);
    assert_eq!(
        raw.settings()
            .map(|setting| (
                setting.as_bytes(),
                setting.id_varint().as_bytes(),
                setting.value_varint().as_bytes(),
            ))
            .collect::<Vec<_>>(),
        [
            (
                &[0x40, 0x22, 0x80, 0x00, 0x00, 0x02][..],
                &[0x40, 0x22][..],
                &[0x80, 0x00, 0x00, 0x02][..]
            ),
            (
                &[0x80, 0x00, 0x00, 0x21, 0x40, 0x00][..],
                &[0x80, 0x00, 0x00, 0x21][..],
                &[0x40, 0x00][..]
            ),
        ]
    );
}

#[test]
fn settings_semantics_reject_each_http2_reserved_identifier() {
    for id in [0x00, 0x02, 0x03, 0x04, 0x05] {
        let wire = [0x04, 0x04, 0x21, 0x00, id, 0x00];
        let settings = Http3Settings::parse(&wire, 4).unwrap();
        assert_eq!(
            settings.validate_semantics(),
            Err(Http3SettingsSemanticError::ProhibitedSetting {
                id: Http3SettingId::new(u64::from(id)),
                offset: 2,
            })
        );
    }
}

#[test]
fn settings_semantics_reject_duplicates_at_the_second_identifier_offset() {
    let cases = [
        (&[0x04, 0x05, 0x01, 0x00, 0x40, 0x01, 0x00][..], 5, 1, 2),
        (
            &[
                0x04, 0x0b, 0x40, 0x22, 0x80, 0x00, 0x00, 0x02, 0x80, 0x00, 0x00, 0x22, 0x00,
            ][..],
            11,
            0x22,
            6,
        ),
        (
            &[0x04, 0x06, 0x40, 0x21, 0x40, 0x00, 0x21, 0x00][..],
            6,
            0x21,
            4,
        ),
    ];
    for (wire, payload_length, id, offset) in cases {
        let settings = Http3Settings::parse(wire, payload_length).unwrap();
        assert_eq!(
            settings.validate_semantics(),
            Err(Http3SettingsSemanticError::DuplicateSetting {
                id: Http3SettingId::new(id),
                offset,
            })
        );
    }
}

#[test]
fn settings_semantics_report_the_first_offending_entry_without_mutating_raw_views() {
    let wire = [0x04, 0x06, 0x21, 0x00, 0x21, 0x00, 0x00, 0x00];
    let settings = Http3Settings::parse(&wire, 6).unwrap();
    let raw = settings;

    assert_eq!(
        settings.validate_semantics(),
        Err(Http3SettingsSemanticError::DuplicateSetting {
            id: Http3SettingId::new(0x21),
            offset: 2,
        })
    );
    assert_eq!(raw.as_bytes(), &wire);
    assert_eq!(
        raw.settings()
            .map(|setting| (setting.as_bytes(), setting.id(), setting.value()))
            .collect::<Vec<_>>(),
        [
            (&[0x21, 0x00][..], Http3SettingId::new(0x21), 0),
            (&[0x21, 0x00][..], Http3SettingId::new(0x21), 0),
            (&[0x00, 0x00][..], Http3SettingId::new(0), 0),
        ]
    );
}

#[test]
fn typed_settings_report_the_first_payload_error_with_its_offset() {
    let cases = [
        (
            &[0x04, 0x01, 0x40][..],
            Http3FramePayloadField::SettingIdentifier,
            0,
            2,
            1,
        ),
        (
            &[0x04, 0x01, 0x01][..],
            Http3FramePayloadField::SettingValue,
            1,
            1,
            0,
        ),
        (
            &[0x04, 0x04, 0x01, 0x80, 0x00, 0x00][..],
            Http3FramePayloadField::SettingValue,
            1,
            4,
            3,
        ),
        (
            &[0x04, 0x05, 0x01, 0x02, 0x80, 0x00, 0x00][..],
            Http3FramePayloadField::SettingIdentifier,
            2,
            4,
            3,
        ),
        (
            &[0x04, 0x06, 0x01, 0x02, 0x03, 0x80, 0x00, 0x00][..],
            Http3FramePayloadField::SettingValue,
            3,
            4,
            3,
        ),
    ];
    for (wire, field, offset, required, available) in cases {
        assert_eq!(
            Http3Settings::parse(wire, 6),
            Err(Http3FramePayloadParseError::PayloadVarInt {
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
fn settings_builder_canonically_preserves_values_order_and_empty_frames() {
    let setting = Http3SettingValue::new(Http3SettingId::new(0x40), 64);
    assert_eq!(setting.id(), Http3SettingId::new(0x40));
    assert_eq!(setting.value(), 64);

    let mut empty_destination = [0xaa; 3];
    let mut empty_scratch = [0; 0];
    let empty = Http3SettingsBuilder::new(&mut empty_destination, &mut empty_scratch, &[])
        .build()
        .unwrap();
    assert_eq!(empty.as_bytes(), &[0x04, 0x00]);
    assert_eq!(empty.settings().next(), None);
    assert_eq!(&empty_destination[2..], &[0xaa]);

    let settings = [
        Http3SettingValue::new(Http3SettingId::QPACK_MAX_TABLE_CAPACITY, 64),
        Http3SettingValue::new(Http3SettingId::MAX_FIELD_SECTION_SIZE, 16_384),
        Http3SettingValue::new(Http3SettingId::new(0x21), 0),
        Http3SettingValue::new(Http3SettingId::new(0x40), 64),
    ];
    let mut destination = [0xaa; 18];
    let mut scratch = [0xbb; 16];
    let frame = Http3SettingsBuilder::new(&mut destination, &mut scratch, &settings)
        .build()
        .unwrap();
    let payload = [
        0x01, 0x40, 0x40, 0x06, 0x80, 0x00, 0x40, 0x00, 0x21, 0x00, 0x40, 0x40, 0x40, 0x40,
    ];
    let expected = [
        0x04, 0x0e, 0x01, 0x40, 0x40, 0x06, 0x80, 0x00, 0x40, 0x00, 0x21, 0x00, 0x40, 0x40, 0x40,
        0x40,
    ];
    assert_eq!(frame.as_bytes(), &expected);
    assert_eq!(
        frame
            .settings()
            .map(|entry| (entry.id(), entry.value()))
            .collect::<Vec<_>>(),
        [
            (Http3SettingId::QPACK_MAX_TABLE_CAPACITY, 64),
            (Http3SettingId::MAX_FIELD_SECTION_SIZE, 16_384),
            (Http3SettingId::new(0x21), 0),
            (Http3SettingId::new(0x40), 64),
        ]
    );
    assert_eq!(&scratch[..14], &payload);
    assert_eq!(scratch[14], 0xbb);
    assert_eq!(&destination[16..], &[0xaa, 0xaa]);
}

#[test]
fn settings_builder_rejects_invalid_inputs_atomically_and_emits_before_destination_failure() {
    let duplicate = [
        Http3SettingValue::new(Http3SettingId::new(0x21), 0),
        Http3SettingValue::new(Http3SettingId::new(0x21), 1),
    ];
    let mut destination = [0xaa; 8];
    let mut scratch = [0xbb; 8];
    assert_eq!(
        Http3SettingsBuilder::new(&mut destination, &mut scratch, &duplicate).build(),
        Err(Http3SettingsBuildError::DuplicateSetting {
            id: Http3SettingId::new(0x21),
        })
    );
    assert_eq!(destination, [0xaa; 8]);
    assert_eq!(scratch, [0xbb; 8]);

    for id in [0x00, 0x02, 0x03, 0x04, 0x05] {
        let settings = [Http3SettingValue::new(Http3SettingId::new(id), 0)];
        let mut destination = [0xaa; 4];
        let mut scratch = [0xbb; 2];
        assert_eq!(
            Http3SettingsBuilder::new(&mut destination, &mut scratch, &settings).build(),
            Err(Http3SettingsBuildError::ProhibitedSetting {
                id: Http3SettingId::new(id),
            })
        );
        assert_eq!(destination, [0xaa; 4]);
        assert_eq!(scratch, [0xbb; 2]);
    }

    let mut identifier_destination = [0xaa; 4];
    let mut identifier_scratch = [0xbb; 2];
    assert_eq!(
        Http3SettingsBuilder::new(
            &mut identifier_destination,
            &mut identifier_scratch,
            &[Http3SettingValue::new(Http3SettingId::new(u64::MAX), 0)],
        )
        .build(),
        Err(Http3SettingsBuildError::SettingVarInt {
            field: Http3FramePayloadField::SettingIdentifier,
            error: QuicVarIntBuildError::ValueTooLarge { value: u64::MAX },
        })
    );
    assert_eq!(identifier_destination, [0xaa; 4]);
    assert_eq!(identifier_scratch, [0xbb; 2]);

    let mut value_destination = [0xaa; 4];
    let mut value_scratch = [0xbb; 2];
    assert_eq!(
        Http3SettingsBuilder::new(
            &mut value_destination,
            &mut value_scratch,
            &[Http3SettingValue::new(Http3SettingId::new(1), u64::MAX)],
        )
        .build(),
        Err(Http3SettingsBuildError::SettingVarInt {
            field: Http3FramePayloadField::SettingValue,
            error: QuicVarIntBuildError::ValueTooLarge { value: u64::MAX },
        })
    );
    assert_eq!(value_destination, [0xaa; 4]);
    assert_eq!(value_scratch, [0xbb; 2]);

    let settings = [Http3SettingValue::new(Http3SettingId::new(1), 64)];
    let mut scratch_short_destination = [0xaa; 5];
    let mut short_scratch = [0xbb; 2];
    assert_eq!(
        Http3SettingsBuilder::new(
            &mut scratch_short_destination,
            &mut short_scratch,
            &settings
        )
        .build(),
        Err(Http3SettingsBuildError::ScratchTooShort {
            required: 3,
            available: 2,
        })
    );
    assert_eq!(scratch_short_destination, [0xaa; 5]);
    assert_eq!(short_scratch, [0xbb; 2]);

    let mut short_destination = [0xaa; 4];
    let mut destination_short_scratch = [0xbb; 3];
    assert_eq!(
        Http3SettingsBuilder::new(
            &mut short_destination,
            &mut destination_short_scratch,
            &settings
        )
        .build(),
        Err(Http3SettingsBuildError::Frame(
            Http3FrameBuildError::BufferTooShort {
                required: 5,
                available: 4,
            }
        ))
    );
    assert_eq!(short_destination, [0xaa; 4]);
    assert_eq!(destination_short_scratch, [0x01, 0x40, 0x40]);
}

#[test]
fn settings_builder_exposes_its_own_error_contract() {
    fn assert_result(_: Result<Http3Settings<'_>, Http3SettingsBuildError>) {}

    let settings = [Http3SettingValue::new(Http3SettingId::new(1), 0)];
    let mut destination = [0; 4];
    let mut scratch = [0; 2];
    assert_result(Http3SettingsBuilder::new(&mut destination, &mut scratch, &settings).build());

    let duplicate = Http3SettingsBuildError::DuplicateSetting {
        id: Http3SettingId::new(0x21),
    };
    assert_eq!(
        duplicate.to_string(),
        "HTTP/3 SETTINGS contains duplicate identifier 33"
    );
    assert!(core::error::Error::source(&duplicate).is_none());

    let frame = Http3SettingsBuildError::Frame(Http3FrameBuildError::BufferTooShort {
        required: 1,
        available: 0,
    });
    assert!(core::error::Error::source(&frame).is_some());
}
