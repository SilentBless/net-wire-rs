use net_wire::http2::{
    Http2BuildError, Http2FrameType, Http2ParseError, Http2Setting, Http2SettingId, Http2Settings,
    Http2SettingsBuilder,
};

#[test]
fn typed_settings_accepts_empty_non_ack_and_ack_frames() {
    let non_ack = [0, 0, 0, 4, 0x80, 0, 0, 0, 0];
    let settings = Http2Settings::parse(&non_ack, 0).unwrap();
    assert_eq!(settings.frame().as_bytes(), non_ack);
    assert_eq!(settings.as_bytes(), non_ack);
    assert!(!settings.is_ack());
    assert_eq!(settings.settings().next(), None);

    let ack = [0, 0, 0, 4, 0x81, 0, 0, 0, 0];
    let settings = Http2Settings::parse(&ack, 0).unwrap();
    assert!(settings.is_ack());
    assert_eq!(settings.settings().next(), None);
}

#[test]
fn typed_settings_preserves_order_duplicates_unknown_ids_and_raw_values() {
    let wire = [
        0, 0, 18, 4, 0x80, 0, 0, 0, 0, 0, 1, 0, 0, 0, 9, 0, 1, 0, 0, 0, 3, 0xfe, 0xed, 0xde, 0xad,
        0xbe, 0xef,
    ];
    let settings = Http2Settings::parse(&wire, 18).unwrap();
    assert_eq!(settings.frame().flags(), 0x80);
    let mut entries = settings.settings();
    let first = entries.next().unwrap();
    assert_eq!(first.id(), Http2SettingId::HEADER_TABLE_SIZE);
    assert_eq!(first.value(), 9);
    let repeated = entries.next().unwrap();
    assert_eq!(repeated.id(), Http2SettingId::HEADER_TABLE_SIZE);
    assert_eq!(repeated.value(), 3);
    let unknown = entries.next().unwrap();
    assert_eq!(unknown.id(), Http2SettingId::new(0xfeed));
    assert_eq!(unknown.value(), 0xdead_beef);
    assert_eq!(entries.next(), None);
    assert_eq!(entries.next(), None);
}

#[test]
fn typed_settings_validates_intrinsic_known_values() {
    for (id, value) in [
        (Http2SettingId::ENABLE_PUSH, 0_u32),
        (Http2SettingId::ENABLE_PUSH, 1),
        (Http2SettingId::ENABLE_CONNECT_PROTOCOL, 0),
        (Http2SettingId::ENABLE_CONNECT_PROTOCOL, 1),
        (Http2SettingId::INITIAL_WINDOW_SIZE, 0),
        (Http2SettingId::INITIAL_WINDOW_SIZE, 0x7fff_ffff),
        (Http2SettingId::MAX_FRAME_SIZE, 0x4000),
        (Http2SettingId::MAX_FRAME_SIZE, 0x00ff_ffff),
    ] {
        let id_bytes = id.raw().to_be_bytes();
        let value_bytes = value.to_be_bytes();
        let wire = [
            0,
            0,
            6,
            4,
            0,
            0,
            0,
            0,
            0,
            id_bytes[0],
            id_bytes[1],
            value_bytes[0],
            value_bytes[1],
            value_bytes[2],
            value_bytes[3],
        ];
        let settings = Http2Settings::parse(&wire, 6).unwrap();
        assert_eq!(settings.as_bytes(), wire);

        let setting = Http2Setting::new(id, value);
        let mut destination = [0xaa; 16];
        let frame = Http2SettingsBuilder::new(&mut destination, 0, &[setting])
            .build()
            .unwrap();
        assert_eq!(frame.settings().collect::<Vec<_>>(), [setting]);
    }

    for (id, value) in [
        (Http2SettingId::ENABLE_PUSH, 2_u32),
        (Http2SettingId::ENABLE_CONNECT_PROTOCOL, 2_u32),
        (Http2SettingId::INITIAL_WINDOW_SIZE, 0x8000_0000),
        (Http2SettingId::MAX_FRAME_SIZE, 0x3fff),
        (Http2SettingId::MAX_FRAME_SIZE, 0x0100_0000),
    ] {
        let id_bytes = id.raw().to_be_bytes();
        let value_bytes = value.to_be_bytes();
        let wire = [
            0,
            0,
            6,
            4,
            0,
            0,
            0,
            0,
            0,
            id_bytes[0],
            id_bytes[1],
            value_bytes[0],
            value_bytes[1],
            value_bytes[2],
            value_bytes[3],
        ];
        assert_eq!(
            Http2Settings::parse(&wire, 6),
            Err(Http2ParseError::InvalidSettingValue { id, value })
        );
    }
}

#[test]
fn typed_settings_rejects_non_multiple_payload_lengths() {
    let short = [0, 0, 5, 4, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 9];
    assert_eq!(
        Http2Settings::parse(&short, 5),
        Err(Http2ParseError::SettingsPayloadLength { actual: 5 })
    );

    let extra = [0, 0, 7, 4, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 9, 0xaa];
    assert_eq!(
        Http2Settings::parse(&extra, 7),
        Err(Http2ParseError::SettingsPayloadLength { actual: 7 })
    );
}

#[test]
fn typed_settings_rejects_ack_payload_and_nonzero_stream() {
    let ack_with_setting = [0, 0, 6, 4, 0x1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 1];
    assert_eq!(
        Http2Settings::parse(&ack_with_setting, 6),
        Err(Http2ParseError::SettingsAckPayload { actual: 6 })
    );

    let nonzero_stream = [0, 0, 0, 4, 0, 0, 0, 0, 1];
    assert_eq!(
        Http2Settings::parse(&nonzero_stream, 0),
        Err(Http2ParseError::ExpectedZeroStreamId)
    );
}

#[test]
fn typed_settings_distinguishes_wrong_frame_type() {
    let wire = [0, 0, 0, 7, 0, 0, 0, 0, 0];
    assert_eq!(
        Http2Settings::parse(&wire, 0),
        Err(Http2ParseError::WrongFrameType {
            expected: Http2FrameType::SETTINGS,
            actual: Http2FrameType::GOAWAY,
        })
    );
}

#[test]
fn typed_settings_builder_writes_empty_and_raw_ordered_settings() {
    let mut empty_destination = [0xaa; 12];
    let empty = Http2SettingsBuilder::new(&mut empty_destination, 0x80, &[])
        .build()
        .unwrap();
    assert_eq!(empty.as_bytes(), &[0, 0, 0, 4, 0x80, 0, 0, 0, 0]);
    assert!(!empty.is_ack());
    assert!(empty_destination[9..].iter().all(|byte| *byte == 0xaa));

    let mut ack_destination = [0xaa; 12];
    let ack = Http2SettingsBuilder::new(&mut ack_destination, 0x81, &[])
        .build()
        .unwrap();
    assert_eq!(ack.as_bytes(), &[0, 0, 0, 4, 0x81, 0, 0, 0, 0]);
    assert!(ack.is_ack());

    let settings = [
        Http2Setting::new(Http2SettingId::HEADER_TABLE_SIZE, 9),
        Http2Setting::new(Http2SettingId::HEADER_TABLE_SIZE, 3),
        Http2Setting::new(Http2SettingId::new(0xfeed), 0xdead_beef),
    ];
    let mut destination = [0xaa; 32];
    let frame = Http2SettingsBuilder::new(&mut destination, 0x80, &settings)
        .build()
        .unwrap();
    assert_eq!(
        frame.as_bytes(),
        &[
            0, 0, 18, 4, 0x80, 0, 0, 0, 0, 0, 1, 0, 0, 0, 9, 0, 1, 0, 0, 0, 3, 0xfe, 0xed, 0xde,
            0xad, 0xbe, 0xef,
        ]
    );
    assert_eq!(frame.settings().collect::<Vec<_>>(), settings);
    assert!(destination[27..].iter().all(|byte| *byte == 0xaa));
}

#[test]
fn typed_settings_builder_failures_are_atomic() {
    let setting = [Http2Setting::new(Http2SettingId::ENABLE_PUSH, 1)];
    let mut ack_destination = [0xaa; 16];
    let before = ack_destination;
    assert_eq!(
        Http2SettingsBuilder::new(&mut ack_destination, 0x1, &setting).build(),
        Err(Http2BuildError::SettingsAckPayload { actual: 6 })
    );
    assert_eq!(ack_destination, before);

    for setting in [
        Http2Setting::new(Http2SettingId::ENABLE_PUSH, 2),
        Http2Setting::new(Http2SettingId::ENABLE_CONNECT_PROTOCOL, 2),
        Http2Setting::new(Http2SettingId::INITIAL_WINDOW_SIZE, 0x8000_0000),
        Http2Setting::new(Http2SettingId::MAX_FRAME_SIZE, 0x3fff),
        Http2Setting::new(Http2SettingId::MAX_FRAME_SIZE, 0x0100_0000),
    ] {
        let mut destination = [0xaa; 16];
        let before = destination;
        assert_eq!(
            Http2SettingsBuilder::new(&mut destination, 0, &[setting]).build(),
            Err(Http2BuildError::InvalidSettingValue {
                id: setting.id(),
                value: setting.value(),
            })
        );
        assert_eq!(destination, before);
    }

    let mut maximum_destination = [0xaa; 16];
    let before = maximum_destination;
    assert_eq!(
        Http2SettingsBuilder::new(&mut maximum_destination, 0, &setting).build_with_maximum(5),
        Err(Http2BuildError::PayloadTooLarge {
            maximum: 5,
            actual: 6,
        })
    );
    assert_eq!(maximum_destination, before);

    let mut short_destination = [0xaa; 14];
    let before = short_destination;
    assert_eq!(
        Http2SettingsBuilder::new(&mut short_destination, 0, &setting).build(),
        Err(Http2BuildError::BufferTooShort {
            required: 15,
            available: 14,
        })
    );
    assert_eq!(short_destination, before);

    let oversized = vec![Http2Setting::new(Http2SettingId::new(0), 0); 0x2a_aaab];
    let mut oversized_destination = [0xaa; 9];
    let before = oversized_destination;
    assert_eq!(
        Http2SettingsBuilder::new(&mut oversized_destination, 0, &oversized).build(),
        Err(Http2BuildError::PayloadTooLarge {
            maximum: 0x00ff_ffff,
            actual: 0x0100_0002,
        })
    );
    assert_eq!(oversized_destination, before);
}
