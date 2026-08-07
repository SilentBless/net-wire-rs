use net_wire::*;

#[test]
fn raw_scalars_preserve_unknown_values_through_both_facades() {
    let unknown = u64::MAX;

    assert_eq!(http3::Http3FrameType::new(unknown).value(), unknown);
    assert_eq!(Http3FrameType::new(unknown).value(), unknown);
    assert_eq!(http3::Http3SettingId::new(unknown).value(), unknown);
    assert_eq!(Http3SettingId::new(unknown).value(), unknown);
    assert_eq!(http3::Http3StreamType::new(unknown).value(), unknown);
    assert_eq!(Http3StreamType::new(unknown).value(), unknown);
    assert_eq!(http3::Http3StreamId::new(unknown).value(), unknown);
    assert_eq!(Http3StreamId::new(unknown).value(), unknown);
    assert_eq!(http3::Http3PushId::new(unknown).value(), unknown);
    assert_eq!(Http3PushId::new(unknown).value(), unknown);
    assert_eq!(http3::Http3ErrorCode::new(unknown).value(), unknown);
    assert_eq!(Http3ErrorCode::new(unknown).value(), unknown);

    assert_eq!(http3::Http3FrameType::SETTINGS, Http3FrameType::SETTINGS);
    assert_eq!(
        http3::Http3SettingId::MAX_FIELD_SECTION_SIZE,
        Http3SettingId::MAX_FIELD_SECTION_SIZE
    );
    assert_eq!(
        http3::Http3StreamType::QPACK_ENCODER,
        Http3StreamType::QPACK_ENCODER
    );
    assert_eq!(
        http3::Http3ErrorCode::QPACK_DECODER_STREAM_ERROR,
        Http3ErrorCode::QPACK_DECODER_STREAM_ERROR
    );
}

#[test]
fn raw_frame_parses_exact_noncanonical_varints_and_excludes_suffix() {
    let wire = [0x40, 0x21, 0x80, 0x00, 0x00, 0x02, 0xde, 0xad, 0xfa];
    let frame = http3::Http3Frame::parse(&wire, 2).unwrap();

    assert_eq!(frame.frame_type(), Http3FrameType::new(0x21));
    assert_eq!(frame.frame_type_varint().as_bytes(), &[0x40, 0x21]);
    assert_eq!(
        frame.payload_length_varint().as_bytes(),
        &[0x80, 0x00, 0x00, 0x02]
    );
    assert_eq!(frame.payload(), &[0xde, 0xad]);
    assert_eq!(frame.as_bytes(), &wire[..8]);
    assert_eq!(&wire[frame.as_bytes().len()..], &[0xfa]);
}

#[test]
fn raw_frame_reports_exact_structural_errors() {
    assert_eq!(
        Http3Frame::parse(&[], 0),
        Err(Http3FrameParseError::TypeVarInt(
            QuicVarIntParseError::Incomplete {
                required: 1,
                available: 0,
            }
        ))
    );
    assert_eq!(
        Http3Frame::parse(&[0x80, 0x00, 0x00], 0),
        Err(Http3FrameParseError::TypeVarInt(
            QuicVarIntParseError::Incomplete {
                required: 4,
                available: 3,
            }
        ))
    );
    assert_eq!(
        Http3Frame::parse(&[0x01], 0),
        Err(Http3FrameParseError::LengthVarInt(
            QuicVarIntParseError::Incomplete {
                required: 1,
                available: 0,
            }
        ))
    );
    assert_eq!(
        Http3Frame::parse(&[0x01, 0x40], 0),
        Err(Http3FrameParseError::LengthVarInt(
            QuicVarIntParseError::Incomplete {
                required: 2,
                available: 1,
            }
        ))
    );
    assert_eq!(
        Http3Frame::parse(&[0x01, 0x03], 2),
        Err(Http3FrameParseError::PayloadTooLarge {
            maximum: 2,
            actual: 3,
        })
    );
    assert_eq!(
        Http3Frame::parse(&[0x01, 0x03, 0xaa], 3),
        Err(Http3FrameParseError::IncompletePayload {
            required: 5,
            available: 3,
        })
    );
}

#[test]
fn mutable_raw_frame_bounds_one_prefix_and_preserves_its_suffix() {
    let mut wire = [0x40, 0x21, 0x80, 0x00, 0x00, 0x02, 0xde, 0xad, 0xfa];
    {
        let mut frame = Http3FrameMut::parse(&mut wire, 2).unwrap();

        assert_eq!(frame.frame_type(), Http3FrameType::new(0x21));
        assert_eq!(frame.payload_length(), 2);
        assert_eq!(
            frame.as_bytes(),
            &[0x40, 0x21, 0x80, 0x00, 0x00, 0x02, 0xde, 0xad]
        );
        frame.payload_mut()[1] = 0xbe;
        assert_eq!(frame.payload(), &[0xde, 0xbe]);
    }

    assert_eq!(wire, [0x40, 0x21, 0x80, 0x00, 0x00, 0x02, 0xde, 0xbe, 0xfa]);
}

#[test]
fn raw_builder_canonically_writes_a_destination_backed_frame() {
    let mut destination = [0xaa; 8];
    {
        let frame: http3::Http3Frame<'_> =
            Http3FrameBuilder::new(&mut destination, Http3FrameType::new(0x40), &[0xde, 0xad])
                .build()
                .unwrap();

        assert!(frame.frame_type_varint().is_canonical());
        assert!(frame.payload_length_varint().is_canonical());
        assert_eq!(frame.frame_type_varint().as_bytes(), &[0x40, 0x40]);
        assert_eq!(frame.payload_length_varint().as_bytes(), &[0x02]);
        assert_eq!(frame.frame_type(), http3::Http3FrameType::new(0x40));
        assert_eq!(frame.payload(), &[0xde, 0xad]);
        assert_eq!(frame.as_bytes(), &[0x40, 0x40, 0x02, 0xde, 0xad]);
    }
    assert_eq!(&destination[5..], &[0xaa, 0xaa, 0xaa]);
}

#[test]
fn raw_builder_failures_are_atomic() {
    let mut too_large_destination = [0xaa; 8];
    assert_eq!(
        Http3FrameBuilder::new(
            &mut too_large_destination,
            Http3FrameType::new(u64::MAX),
            &[],
        )
        .build(),
        Err(Http3FrameBuildError::TypeVarInt(
            QuicVarIntBuildError::ValueTooLarge { value: u64::MAX }
        ))
    );
    assert_eq!(too_large_destination, [0xaa; 8]);

    let mut short_destination = [0xaa; 4];
    assert_eq!(
        Http3FrameBuilder::new(
            &mut short_destination,
            Http3FrameType::new(0x40),
            &[0xde, 0xad],
        )
        .build(),
        Err(Http3FrameBuildError::BufferTooShort {
            required: 5,
            available: 4,
        })
    );
    assert_eq!(short_destination, [0xaa; 4]);
}

#[test]
fn typed_data_and_headers_preserve_opaque_payloads_and_frame_bounds() {
    let data: Http3Data<'_> =
        http3::Http3Data::parse(&[0x00, 0x03, 0xde, 0xad, 0xbe, 0xfa], 3).unwrap();
    assert_eq!(data.data(), &[0xde, 0xad, 0xbe]);
    assert_eq!(data.as_bytes(), &[0x00, 0x03, 0xde, 0xad, 0xbe]);

    let empty_data: http3::Http3Data<'_> = Http3Data::parse(&[0x00, 0x00], 0).unwrap();
    assert_eq!(empty_data.data(), &[]);

    let headers: http3::Http3Headers<'_> =
        Http3Headers::parse(&[0x01, 0x02, 0xff, 0x00], 2).unwrap();
    assert_eq!(headers.encoded_field_section(), &[0xff, 0x00]);
    assert_eq!(headers.as_bytes(), &[0x01, 0x02, 0xff, 0x00]);

    let empty_headers: Http3Headers<'_> = http3::Http3Headers::parse(&[0x01, 0x00], 0).unwrap();
    assert_eq!(empty_headers.encoded_field_section(), &[]);
}

#[test]
fn typed_exact_push_id_views_preserve_noncanonical_varints_and_reject_bad_layouts() {
    let cancel: Http3CancelPush<'_> =
        http3::Http3CancelPush::parse(&[0x03, 0x02, 0x40, 0x2a], 2).unwrap();
    assert_eq!(cancel.push_id(), Http3PushId::new(42));
    assert_eq!(cancel.push_id_varint().as_bytes(), &[0x40, 0x2a]);

    let maximum: http3::Http3MaxPushId<'_> =
        Http3MaxPushId::parse(&[0x0d, 0x02, 0x40, 0x2a], 2).unwrap();
    assert_eq!(maximum.push_id().value(), 42);
    assert_eq!(maximum.push_id_varint().as_bytes(), &[0x40, 0x2a]);

    let empty_push_id = Http3FramePayloadParseError::PayloadVarInt {
        field: Http3FramePayloadField::PushId,
        offset: 0,
        error: QuicVarIntParseError::Incomplete {
            required: 1,
            available: 0,
        },
    };
    assert_eq!(Http3CancelPush::parse(&[0x03, 0x00], 2), Err(empty_push_id));
    assert_eq!(Http3MaxPushId::parse(&[0x0d, 0x00], 2), Err(empty_push_id));

    let truncated_push_id = Http3FramePayloadParseError::PayloadVarInt {
        field: Http3FramePayloadField::PushId,
        offset: 0,
        error: QuicVarIntParseError::Incomplete {
            required: 2,
            available: 1,
        },
    };
    assert_eq!(
        Http3CancelPush::parse(&[0x03, 0x01, 0x40], 2),
        Err(truncated_push_id)
    );
    assert_eq!(
        Http3MaxPushId::parse(&[0x0d, 0x01, 0x40], 2),
        Err(truncated_push_id)
    );
    assert_eq!(
        Http3MaxPushId::parse(&[0x0d, 0x03, 0x40, 0x2a, 0xff], 3),
        Err(Http3FramePayloadParseError::TrailingPayload {
            consumed: 2,
            actual: 3,
        })
    );
}

#[test]
fn typed_goaway_and_push_promise_preserve_layout_without_role_or_qpack_decoding() {
    let goaway: Http3Goaway<'_> = http3::Http3Goaway::parse(&[0x07, 0x02, 0x40, 0x2a], 2).unwrap();
    assert_eq!(goaway.identifier(), 42);
    assert_eq!(goaway.identifier_varint().as_bytes(), &[0x40, 0x2a]);
    assert_eq!(
        Http3Goaway::parse(&[0x07, 0x03, 0x40, 0x2a, 0xff], 3),
        Err(Http3FramePayloadParseError::TrailingPayload {
            consumed: 2,
            actual: 3,
        })
    );
    assert_eq!(
        Http3Goaway::parse(&[0x07, 0x01, 0x40], 2),
        Err(Http3FramePayloadParseError::PayloadVarInt {
            field: Http3FramePayloadField::GoawayIdentifier,
            offset: 0,
            error: QuicVarIntParseError::Incomplete {
                required: 2,
                available: 1,
            },
        })
    );

    let promise: http3::Http3PushPromise<'_> =
        Http3PushPromise::parse(&[0x05, 0x04, 0x40, 0x2a, 0xaa, 0xbb], 4).unwrap();
    assert_eq!(promise.push_id(), Http3PushId::new(42));
    assert_eq!(promise.push_id_varint().as_bytes(), &[0x40, 0x2a]);
    assert_eq!(promise.encoded_field_section(), &[0xaa, 0xbb]);

    let empty_section: Http3PushPromise<'_> =
        http3::Http3PushPromise::parse(&[0x05, 0x02, 0x40, 0x2a], 2).unwrap();
    assert_eq!(empty_section.encoded_field_section(), &[]);
    assert_eq!(
        Http3PushPromise::parse(&[0x05, 0x00], 2),
        Err(Http3FramePayloadParseError::PayloadVarInt {
            field: Http3FramePayloadField::PushId,
            offset: 0,
            error: QuicVarIntParseError::Incomplete {
                required: 1,
                available: 0,
            },
        })
    );
    assert_eq!(
        Http3PushPromise::parse(&[0x05, 0x01, 0x40], 2),
        Err(Http3FramePayloadParseError::PayloadVarInt {
            field: Http3FramePayloadField::PushId,
            offset: 0,
            error: QuicVarIntParseError::Incomplete {
                required: 2,
                available: 1,
            },
        })
    );
}

#[test]
fn typed_settings_eagerly_validate_and_iterate_exact_wire_order() {
    let empty: Http3Settings<'_> = http3::Http3Settings::parse(&[0x04, 0x00], 0).unwrap();
    assert_eq!(empty.settings().next(), None);

    let settings: http3::Http3Settings<'_> = Http3Settings::parse(
        &[
            0x04, 0x0f, 0x40, 0x01, 0x80, 0x00, 0x00, 0x02, 0x01, 0x40, 0x03, 0x80, 0x00, 0x00,
            0x21, 0x40, 0x00,
        ],
        15,
    )
    .unwrap();
    let mut iter: Http3SettingsIter<'_> = settings.settings();
    let first: http3::Http3Setting<'_> = iter.next().unwrap();
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
fn settings_semantic_public_facades_and_empty_defaults_are_available() {
    let _: http3::Http3PeerSettings = Http3PeerSettings::default();
    let _: Http3PeerSettings = http3::Http3PeerSettings::default();
    let _: http3::Http3SettingsSemanticError = Http3SettingsSemanticError::DuplicateSetting {
        id: Http3SettingId::new(0),
        offset: 0,
    };
    let _: Http3SettingsSemanticError = http3::Http3SettingsSemanticError::ProhibitedSetting {
        id: Http3SettingId::new(0),
        offset: 0,
    };

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
fn typed_views_wrap_envelope_errors_and_check_type_before_payload() {
    assert_eq!(
        Http3Data::parse(&[0x00], 0),
        Err(Http3FramePayloadParseError::Frame(
            Http3FrameParseError::LengthVarInt(QuicVarIntParseError::Incomplete {
                required: 1,
                available: 0,
            })
        ))
    );
    let frame = Http3Frame::parse(&[0x00, 0x01, 0x40], 1).unwrap();
    assert_eq!(
        Http3CancelPush::from_frame(frame),
        Err(Http3FramePayloadParseError::WrongFrameType {
            expected: Http3FrameType::CANCEL_PUSH,
            actual: Http3FrameType::DATA,
        })
    );
}

#[test]
fn typed_standard_builders_are_available_through_both_public_facades() {
    {
        let mut destination = [0; 8];
        let _: http3::Http3DataBuilder<'_, '_> = Http3DataBuilder::new(&mut destination, &[]);
    }
    {
        let mut destination = [0; 8];
        let _: http3::Http3HeadersBuilder<'_, '_> = Http3HeadersBuilder::new(&mut destination, &[]);
    }
    {
        let mut destination = [0; 8];
        let _: http3::Http3CancelPushBuilder<'_> =
            Http3CancelPushBuilder::new(&mut destination, Http3PushId::new(0));
    }
    {
        let mut destination = [0; 8];
        let _: http3::Http3PushPromiseBuilder<'_, '_> =
            Http3PushPromiseBuilder::new(&mut destination, Http3PushId::new(0), &[]);
    }
    {
        let mut destination = [0; 8];
        let _: http3::Http3GoawayBuilder<'_> = Http3GoawayBuilder::new(&mut destination, 0);
    }
    {
        let mut destination = [0; 8];
        let _: http3::Http3MaxPushIdBuilder<'_> =
            Http3MaxPushIdBuilder::new(&mut destination, Http3PushId::new(0));
    }
    let settings = [Http3SettingValue::new(Http3SettingId::new(1), 0)];
    let mut destination = [0; 8];
    let mut scratch = [0; 2];
    let _: http3::Http3SettingsBuilder<'_, '_, '_> =
        Http3SettingsBuilder::new(&mut destination, &mut scratch, &settings);
    let _: http3::Http3SettingValue = Http3SettingValue::new(Http3SettingId::new(1), 64);
    let _: http3::Http3FramePayloadBuildError =
        Http3FramePayloadBuildError::Frame(Http3FrameBuildError::BufferTooShort {
            required: 1,
            available: 0,
        });
}

#[test]
fn typed_standard_builders_canonically_construct_frames_and_preserve_suffixes() {
    let mut data_destination = [0xaa; 6];
    let data = Http3DataBuilder::new(&mut data_destination, &[0xde, 0xad])
        .build()
        .unwrap();
    assert_eq!(data.data(), &[0xde, 0xad]);
    assert_eq!(data.as_bytes(), &[0x00, 0x02, 0xde, 0xad]);
    assert_eq!(&data_destination[4..], &[0xaa, 0xaa]);

    let mut headers_destination = [0xaa; 5];
    let headers = Http3HeadersBuilder::new(&mut headers_destination, &[0xff, 0x00])
        .build()
        .unwrap();
    assert_eq!(headers.encoded_field_section(), &[0xff, 0x00]);
    assert_eq!(headers.as_bytes(), &[0x01, 0x02, 0xff, 0x00]);
    assert_eq!(&headers_destination[4..], &[0xaa]);

    let mut cancel_destination = [0xaa; 5];
    let cancel = Http3CancelPushBuilder::new(&mut cancel_destination, Http3PushId::new(64))
        .build()
        .unwrap();
    assert_eq!(cancel.push_id(), Http3PushId::new(64));
    assert_eq!(cancel.push_id_varint().as_bytes(), &[0x40, 0x40]);
    assert_eq!(cancel.as_bytes(), &[0x03, 0x02, 0x40, 0x40]);
    assert_eq!(&cancel_destination[4..], &[0xaa]);

    let mut promise_destination = [0xaa; 7];
    let promise = Http3PushPromiseBuilder::new(
        &mut promise_destination,
        Http3PushId::new(64),
        &[0xa0, 0xb0],
    )
    .build()
    .unwrap();
    assert_eq!(promise.push_id(), Http3PushId::new(64));
    assert_eq!(promise.encoded_field_section(), &[0xa0, 0xb0]);
    assert_eq!(promise.as_bytes(), &[0x05, 0x04, 0x40, 0x40, 0xa0, 0xb0]);
    assert_eq!(&promise_destination[6..], &[0xaa]);

    let mut empty_promise_destination = [0xaa; 5];
    let empty_promise =
        Http3PushPromiseBuilder::new(&mut empty_promise_destination, Http3PushId::new(64), &[])
            .build()
            .unwrap();
    assert_eq!(empty_promise.encoded_field_section(), &[]);
    assert_eq!(empty_promise.as_bytes(), &[0x05, 0x02, 0x40, 0x40]);

    let mut goaway_destination = [0xaa; 5];
    let goaway = Http3GoawayBuilder::new(&mut goaway_destination, 64)
        .build()
        .unwrap();
    assert_eq!(goaway.identifier(), 64);
    assert_eq!(goaway.identifier_varint().as_bytes(), &[0x40, 0x40]);
    assert_eq!(goaway.as_bytes(), &[0x07, 0x02, 0x40, 0x40]);
    assert_eq!(&goaway_destination[4..], &[0xaa]);

    let mut maximum_destination = [0xaa; 5];
    let maximum = Http3MaxPushIdBuilder::new(&mut maximum_destination, Http3PushId::new(64))
        .build()
        .unwrap();
    assert_eq!(maximum.push_id(), Http3PushId::new(64));
    assert_eq!(maximum.push_id_varint().as_bytes(), &[0x40, 0x40]);
    assert_eq!(maximum.as_bytes(), &[0x0d, 0x02, 0x40, 0x40]);
    assert_eq!(&maximum_destination[4..], &[0xaa]);
}

#[test]
fn composite_typed_builders_report_atomic_field_and_capacity_failures() {
    let mut push_destination = [0xaa; 4];
    assert_eq!(
        Http3CancelPushBuilder::new(&mut push_destination, Http3PushId::new(u64::MAX)).build(),
        Err(Http3FramePayloadBuildError::PayloadVarInt {
            field: Http3FramePayloadField::PushId,
            error: QuicVarIntBuildError::ValueTooLarge { value: u64::MAX },
        })
    );
    assert_eq!(push_destination, [0xaa; 4]);

    let mut goaway_destination = [0xaa; 4];
    assert_eq!(
        Http3GoawayBuilder::new(&mut goaway_destination, u64::MAX).build(),
        Err(Http3FramePayloadBuildError::PayloadVarInt {
            field: Http3FramePayloadField::GoawayIdentifier,
            error: QuicVarIntBuildError::ValueTooLarge { value: u64::MAX },
        })
    );
    assert_eq!(goaway_destination, [0xaa; 4]);

    let mut short_destination = [0xaa; 3];
    assert_eq!(
        Http3MaxPushIdBuilder::new(&mut short_destination, Http3PushId::new(64)).build(),
        Err(Http3FramePayloadBuildError::Frame(
            Http3FrameBuildError::BufferTooShort {
                required: 4,
                available: 3,
            }
        ))
    );
    assert_eq!(short_destination, [0xaa; 3]);
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
        Err(Http3FramePayloadBuildError::DuplicateSetting {
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
            Err(Http3FramePayloadBuildError::ProhibitedSetting {
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
        Err(Http3FramePayloadBuildError::PayloadVarInt {
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
        Err(Http3FramePayloadBuildError::PayloadVarInt {
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
        Err(Http3FramePayloadBuildError::SettingsScratchTooShort {
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
        Err(Http3FramePayloadBuildError::Frame(
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
fn unidirectional_stream_header_public_facades_are_available() {
    let _: http3::Http3UniStreamHeader<'_> = Http3UniStreamHeader::parse(&[0]).unwrap();
    let _: http3::Http3UniStreamKind = Http3UniStreamKind::Control;
    let mut destination = [0; 1];
    let _: http3::Http3UniStreamHeaderBuilder<'_> =
        Http3UniStreamHeaderBuilder::new(&mut destination, Http3UniStreamKind::Control);
    let _: http3::Http3UniStreamField = Http3UniStreamField::StreamType;
    let _: http3::Http3UniStreamParseError = Http3UniStreamParseError::VarInt {
        field: Http3UniStreamField::StreamType,
        offset: 0,
        error: QuicVarIntParseError::Incomplete {
            required: 1,
            available: 0,
        },
    };
    let _: http3::Http3UniStreamBuildError = Http3UniStreamBuildError::BufferTooShort {
        required: 1,
        available: 0,
    };
}

#[test]
fn unidirectional_stream_header_parses_all_kinds() {
    let cases = [
        (
            &[0x00][..],
            Http3UniStreamKind::Control,
            Http3StreamType::CONTROL,
            None,
        ),
        (
            &[0x01, 0x40, 0x2a],
            Http3UniStreamKind::Push(Http3PushId::new(42)),
            Http3StreamType::PUSH,
            Some(Http3PushId::new(42)),
        ),
        (
            &[0x02],
            Http3UniStreamKind::QpackEncoder,
            Http3StreamType::QPACK_ENCODER,
            None,
        ),
        (
            &[0x03],
            Http3UniStreamKind::QpackDecoder,
            Http3StreamType::QPACK_DECODER,
            None,
        ),
        (
            &[0x22],
            Http3UniStreamKind::Unknown(Http3StreamType::new(0x22)),
            Http3StreamType::new(0x22),
            None,
        ),
        (
            &[0x21],
            Http3UniStreamKind::Unknown(Http3StreamType::new(0x21)),
            Http3StreamType::new(0x21),
            None,
        ),
    ];
    for (wire, kind, stream_type, push_id) in cases {
        let header = Http3UniStreamHeader::parse(wire).unwrap();
        assert_eq!(header.kind(), kind);
        assert_eq!(header.stream_type(), stream_type);
        assert_eq!(header.push_id(), push_id);
    }
}

#[test]
fn unidirectional_stream_header_preserves_exact_varints_and_excludes_suffixes() {
    let control_wire = [0x40, 0x00, 0x80, 0x00, 0x00, 0x02];
    let control = Http3UniStreamHeader::parse(&control_wire).unwrap();
    assert_eq!(control.stream_type_varint().as_bytes(), &[0x40, 0x00]);
    assert_eq!(control.as_bytes(), &[0x40, 0x00]);
    assert_eq!(
        &control_wire[control.as_bytes().len()..],
        &[0x80, 0x00, 0x00, 0x02]
    );

    let push_wire = [0x40, 0x01, 0x80, 0x00, 0x00, 0x2a, 0xfa];
    let push = Http3UniStreamHeader::parse(&push_wire).unwrap();
    assert_eq!(push.stream_type_varint().as_bytes(), &[0x40, 0x01]);
    assert_eq!(
        push.push_id_varint().unwrap().as_bytes(),
        &[0x80, 0x00, 0x00, 0x2a]
    );
    assert_eq!(push.as_bytes(), &push_wire[..6]);
    assert_eq!(&push_wire[push.as_bytes().len()..], &[0xfa]);

    for wire in [&[0x02, 0x40, 0x01][..], &[0x21, 0x80, 0x00, 0x00, 0x02][..]] {
        let header = Http3UniStreamHeader::parse(wire).unwrap();
        assert_eq!(header.as_bytes(), &wire[..1]);
        assert_eq!(&wire[header.as_bytes().len()..], &wire[1..]);
    }
}

#[test]
fn unidirectional_stream_header_reports_exact_parse_errors() {
    let stream_type_errors = [(&[][..], 1, 0), (&[0x40][..], 2, 1)];
    for (wire, required, available) in stream_type_errors {
        assert_eq!(
            Http3UniStreamHeader::parse(wire),
            Err(Http3UniStreamParseError::VarInt {
                field: Http3UniStreamField::StreamType,
                offset: 0,
                error: QuicVarIntParseError::Incomplete {
                    required,
                    available
                },
            })
        );
    }
    let push_id_errors = [
        (&[0x01][..], 1, 0, 1),
        (&[0x01, 0x40][..], 2, 1, 1),
        (&[0x40, 0x01, 0x80, 0x00, 0x00][..], 4, 3, 2),
    ];
    for (wire, required, available, offset) in push_id_errors {
        assert_eq!(
            Http3UniStreamHeader::parse(wire),
            Err(Http3UniStreamParseError::VarInt {
                field: Http3UniStreamField::PushId,
                offset,
                error: QuicVarIntParseError::Incomplete {
                    required,
                    available
                },
            })
        );
    }
}

#[test]
fn unidirectional_stream_header_builder_writes_canonical_headers() {
    let mut control_destination = [0xaa; 2];
    let control =
        Http3UniStreamHeaderBuilder::new(&mut control_destination, Http3UniStreamKind::Control)
            .build()
            .unwrap();
    assert_eq!(control.kind(), Http3UniStreamKind::Control);
    assert_eq!(control.stream_type(), Http3StreamType::CONTROL);
    assert_eq!(control.stream_type_varint().as_bytes(), &[0]);
    assert_eq!(control.push_id(), None);
    assert_eq!(control.as_bytes(), &[0]);
    assert_eq!(&control_destination[1..], &[0xaa]);

    let mut push_destination = [0xaa; 4];
    let push = Http3UniStreamHeaderBuilder::new(
        &mut push_destination,
        Http3UniStreamKind::Push(Http3PushId::new(64)),
    )
    .build()
    .unwrap();
    assert_eq!(push.kind(), Http3UniStreamKind::Push(Http3PushId::new(64)));
    assert_eq!(push.stream_type_varint().as_bytes(), &[0x01]);
    assert_eq!(push.push_id_varint().unwrap().as_bytes(), &[0x40, 0x40]);
    assert_eq!(push.as_bytes(), &[0x01, 0x40, 0x40]);
    assert_eq!(&push_destination[3..], &[0xaa]);

    let cases = [
        (
            Http3UniStreamKind::QpackEncoder,
            Http3StreamType::QPACK_ENCODER,
            &[0x02][..],
        ),
        (
            Http3UniStreamKind::QpackDecoder,
            Http3StreamType::QPACK_DECODER,
            &[0x03][..],
        ),
        (
            Http3UniStreamKind::Unknown(Http3StreamType::new(0x40)),
            Http3StreamType::new(0x40),
            &[0x40, 0x40],
        ),
        (
            Http3UniStreamKind::Unknown(Http3StreamType::new(0x21)),
            Http3StreamType::new(0x21),
            &[0x21],
        ),
    ];
    for (kind, stream_type, expected) in cases {
        let mut destination = [0xaa; 3];
        let header = Http3UniStreamHeaderBuilder::new(&mut destination, kind)
            .build()
            .unwrap();
        assert_eq!(header.kind(), kind);
        assert_eq!(header.stream_type(), stream_type);
        assert_eq!(header.stream_type_varint().as_bytes(), expected);
        assert_eq!(header.push_id(), None);
        assert_eq!(header.as_bytes(), expected);
        assert_eq!(&destination[expected.len()..], &[0xaa; 3][expected.len()..]);
    }
}

#[test]
fn unidirectional_stream_header_builder_rejects_invalid_inputs_atomically() {
    for value in 0..=3 {
        let mut destination = [0xaa; 3];
        let stream_type = Http3StreamType::new(value);
        assert_eq!(
            Http3UniStreamHeaderBuilder::new(
                &mut destination,
                Http3UniStreamKind::Unknown(stream_type),
            )
            .build(),
            Err(Http3UniStreamBuildError::KnownTypeMarkedUnknown { stream_type })
        );
        assert_eq!(destination, [0xaa; 3]);
    }

    let mut stream_type_destination = [0xaa; 8];
    assert_eq!(
        Http3UniStreamHeaderBuilder::new(
            &mut stream_type_destination,
            Http3UniStreamKind::Unknown(Http3StreamType::new(u64::MAX)),
        )
        .build(),
        Err(Http3UniStreamBuildError::VarInt {
            field: Http3UniStreamField::StreamType,
            error: QuicVarIntBuildError::ValueTooLarge { value: u64::MAX },
        })
    );
    assert_eq!(stream_type_destination, [0xaa; 8]);

    let mut push_id_destination = [0xaa; 8];
    assert_eq!(
        Http3UniStreamHeaderBuilder::new(
            &mut push_id_destination,
            Http3UniStreamKind::Push(Http3PushId::new(u64::MAX)),
        )
        .build(),
        Err(Http3UniStreamBuildError::VarInt {
            field: Http3UniStreamField::PushId,
            error: QuicVarIntBuildError::ValueTooLarge { value: u64::MAX },
        })
    );
    assert_eq!(push_id_destination, [0xaa; 8]);

    let mut short_destination = [0xaa; 2];
    assert_eq!(
        Http3UniStreamHeaderBuilder::new(
            &mut short_destination,
            Http3UniStreamKind::Push(Http3PushId::new(64)),
        )
        .build(),
        Err(Http3UniStreamBuildError::BufferTooShort {
            required: 3,
            available: 2,
        })
    );
    assert_eq!(short_destination, [0xaa; 2]);
}

#[test]
fn control_stream_public_facades_expose_empty_role_specific_state() {
    let client: http3::Http3ControlStreamState =
        Http3ControlStreamState::new(Http3EndpointRole::Client);
    let server: Http3ControlStreamState =
        http3::Http3ControlStreamState::new(http3::Http3EndpointRole::Server);
    let _: http3::Http3ControlFrame<'_> =
        Http3ControlFrame::Unknown(Http3Frame::parse(&[0x21, 0x00], 0).unwrap());
    let _: http3::Http3ControlStreamError = Http3ControlStreamError::MissingSettings {
        actual: Http3FrameType::DATA,
    };

    for (state, role) in [
        (client, Http3EndpointRole::Client),
        (server, Http3EndpointRole::Server),
    ] {
        assert_eq!(state.role(), role);
        assert_eq!(state.settings(), None);
        assert_eq!(state.last_goaway_identifier(), None);
        assert_eq!(state.maximum_push_id(), None);
    }
}

#[test]
fn control_stream_requires_and_commits_one_valid_settings_frame_atomically() {
    let mut state = Http3ControlStreamState::new(Http3EndpointRole::Client);
    let before = state;
    let malformed_data = Http3Frame::parse(&[0x00, 0x01, 0x40], 1).unwrap();
    let error = state.receive(malformed_data).unwrap_err();
    assert_eq!(
        error,
        Http3ControlStreamError::MissingSettings {
            actual: Http3FrameType::DATA,
        }
    );
    assert_eq!(error.error_code(), Http3ErrorCode::MISSING_SETTINGS);
    assert_eq!(state, before);

    let unknown = Http3Frame::parse(&[0x21, 0x00], 0).unwrap();
    let error = state.receive(unknown).unwrap_err();
    assert_eq!(
        error,
        Http3ControlStreamError::MissingSettings {
            actual: Http3FrameType::new(0x21),
        }
    );
    assert_eq!(error.error_code(), Http3ErrorCode::MISSING_SETTINGS);
    assert_eq!(state, before);

    let settings = Http3Frame::parse(
        &[
            0x04, 0x0a, 0x01, 0x40, 0x40, 0x06, 0x00, 0x07, 0x80, 0x00, 0x40, 0x00,
        ],
        10,
    )
    .unwrap();
    match state.receive(settings).unwrap() {
        Http3ControlFrame::Settings {
            frame,
            peer_settings,
        } => {
            assert_eq!(frame.frame().frame_type(), Http3FrameType::SETTINGS);
            assert_eq!(
                frame.as_bytes(),
                &[
                    0x04, 0x0a, 0x01, 0x40, 0x40, 0x06, 0x00, 0x07, 0x80, 0x00, 0x40, 0x00
                ]
            );
            assert_eq!(peer_settings.qpack_max_table_capacity(), 64);
            assert_eq!(peer_settings.maximum_field_section_size(), Some(0));
            assert_eq!(peer_settings.qpack_blocked_streams(), 16_384);
            assert_ne!(peer_settings, Http3PeerSettings::default());
        }
        event => panic!("expected SETTINGS, got {event:?}"),
    }
    assert_eq!(state.settings().unwrap().qpack_max_table_capacity(), 64);
    assert_eq!(
        state.settings().unwrap().maximum_field_section_size(),
        Some(0)
    );
    assert_eq!(state.settings().unwrap().qpack_blocked_streams(), 16_384);

    let before = state;
    let second_malformed_settings = Http3Frame::parse(&[0x04, 0x01, 0x40], 1).unwrap();
    let error = state.receive(second_malformed_settings).unwrap_err();
    assert_eq!(
        error,
        Http3ControlStreamError::UnexpectedFrame {
            frame_type: Http3FrameType::SETTINGS,
        }
    );
    assert_eq!(error.error_code(), Http3ErrorCode::FRAME_UNEXPECTED);
    assert_eq!(state, before);
}

#[test]
fn control_stream_settings_failures_map_errors_and_leave_state_unchanged() {
    let mut state = Http3ControlStreamState::new(Http3EndpointRole::Server);
    let before = state;
    let malformed = Http3Frame::parse(&[0x04, 0x01, 0x40], 1).unwrap();
    let error = state.receive(malformed).unwrap_err();
    assert_eq!(
        error,
        Http3ControlStreamError::FramePayload {
            frame_type: Http3FrameType::SETTINGS,
            error: Http3FramePayloadParseError::PayloadVarInt {
                field: Http3FramePayloadField::SettingIdentifier,
                offset: 0,
                error: QuicVarIntParseError::Incomplete {
                    required: 2,
                    available: 1,
                },
            },
        }
    );
    assert_eq!(error.error_code(), Http3ErrorCode::FRAME_ERROR);
    assert_eq!(state, before);

    let duplicate = Http3Frame::parse(&[0x04, 0x04, 0x21, 0x00, 0x21, 0x00], 4).unwrap();
    let error = state.receive(duplicate).unwrap_err();
    assert_eq!(
        error,
        Http3ControlStreamError::Settings(Http3SettingsSemanticError::DuplicateSetting {
            id: Http3SettingId::new(0x21),
            offset: 2,
        })
    );
    assert_eq!(error.error_code(), Http3ErrorCode::SETTINGS_ERROR);
    assert_eq!(state, before);

    let prohibited = Http3Frame::parse(&[0x04, 0x02, 0x00, 0x00], 2).unwrap();
    let error = state.receive(prohibited).unwrap_err();
    assert_eq!(
        error,
        Http3ControlStreamError::Settings(Http3SettingsSemanticError::ProhibitedSetting {
            id: Http3SettingId::new(0),
            offset: 0,
        })
    );
    assert_eq!(error.error_code(), Http3ErrorCode::SETTINGS_ERROR);
    assert_eq!(state, before);
}

#[test]
fn control_stream_rejects_forbidden_frames_and_preserves_unknown_wire_bytes() {
    let mut state = Http3ControlStreamState::new(Http3EndpointRole::Client);
    state
        .receive(Http3Frame::parse(&[0x04, 0x00], 0).unwrap())
        .unwrap();

    for (wire, frame_type) in [
        (&[0x00, 0x00][..], Http3FrameType::DATA),
        (&[0x01, 0x00][..], Http3FrameType::HEADERS),
        (&[0x05, 0x00][..], Http3FrameType::PUSH_PROMISE),
        (&[0x02, 0x00][..], Http3FrameType::new(0x02)),
        (&[0x06, 0x00][..], Http3FrameType::new(0x06)),
        (&[0x08, 0x00][..], Http3FrameType::new(0x08)),
        (&[0x09, 0x00][..], Http3FrameType::new(0x09)),
    ] {
        let before = state;
        let error = state
            .receive(Http3Frame::parse(wire, 0).unwrap())
            .unwrap_err();
        assert_eq!(
            error,
            Http3ControlStreamError::UnexpectedFrame { frame_type }
        );
        assert_eq!(error.error_code(), Http3ErrorCode::FRAME_UNEXPECTED);
        assert_eq!(state, before);
    }

    for wire in [
        &[0x40, 0x40, 0x80, 0x00, 0x00, 0x02, 0xde, 0xad][..],
        &[0x40, 0x21, 0x80, 0x00, 0x00, 0x02, 0xbe, 0xef][..],
    ] {
        let before = state;
        match state.receive(Http3Frame::parse(wire, 2).unwrap()).unwrap() {
            Http3ControlFrame::Unknown(frame) => {
                assert_eq!(frame.as_bytes(), wire);
                assert_eq!(frame.frame_type_varint().as_bytes(), &wire[..2]);
                assert_eq!(frame.payload_length_varint().as_bytes(), &wire[2..6]);
            }
            event => panic!("expected unknown control frame, got {event:?}"),
        }
        assert_eq!(state, before);
    }
}

#[test]
fn control_stream_enforces_push_role_and_maximum_monotonicity_atomically() {
    let mut client = Http3ControlStreamState::new(Http3EndpointRole::Client);
    client
        .receive(Http3Frame::parse(&[0x04, 0x00], 0).unwrap())
        .unwrap();
    for (wire, frame_type) in [
        (&[0x03, 0x01, 0x40][..], Http3FrameType::CANCEL_PUSH),
        (&[0x0d, 0x01, 0x40][..], Http3FrameType::MAX_PUSH_ID),
    ] {
        let before = client;
        let error = client
            .receive(Http3Frame::parse(wire, 1).unwrap())
            .unwrap_err();
        assert_eq!(
            error,
            Http3ControlStreamError::UnexpectedFrame { frame_type }
        );
        assert_eq!(error.error_code(), Http3ErrorCode::FRAME_UNEXPECTED);
        assert_eq!(client, before);
    }

    let mut server = Http3ControlStreamState::new(Http3EndpointRole::Server);
    server
        .receive(Http3Frame::parse(&[0x04, 0x00], 0).unwrap())
        .unwrap();
    let before_cancel = server;
    match server
        .receive(Http3Frame::parse(&[0x03, 0x01, 0x2a], 1).unwrap())
        .unwrap()
    {
        Http3ControlFrame::CancelPush(cancel) => assert_eq!(cancel.push_id(), Http3PushId::new(42)),
        event => panic!("expected CANCEL_PUSH, got {event:?}"),
    }
    assert_eq!(server, before_cancel);

    for wire in [&[0x0d, 0x02, 0x40, 0x40][..], &[0x0d, 0x02, 0x40, 0x40][..]] {
        match server.receive(Http3Frame::parse(wire, 2).unwrap()).unwrap() {
            Http3ControlFrame::MaxPushId(maximum) => {
                assert_eq!(maximum.push_id(), Http3PushId::new(64));
            }
            event => panic!("expected MAX_PUSH_ID, got {event:?}"),
        }
    }
    match server
        .receive(Http3Frame::parse(&[0x0d, 0x04, 0x80, 0x00, 0x40, 0x00], 4).unwrap())
        .unwrap()
    {
        Http3ControlFrame::MaxPushId(maximum) => {
            assert_eq!(maximum.push_id(), Http3PushId::new(16_384));
        }
        event => panic!("expected MAX_PUSH_ID, got {event:?}"),
    }
    assert_eq!(server.maximum_push_id(), Some(Http3PushId::new(16_384)));

    let before = server;
    let error = server
        .receive(Http3Frame::parse(&[0x0d, 0x02, 0x40, 0x40], 2).unwrap())
        .unwrap_err();
    assert_eq!(
        error,
        Http3ControlStreamError::ReducedMaximumPushId {
            previous: Http3PushId::new(16_384),
            current: Http3PushId::new(64),
        }
    );
    assert_eq!(error.error_code(), Http3ErrorCode::ID_ERROR);
    assert_eq!(server, before);
}

#[test]
fn control_stream_goaway_role_semantics_are_monotonic_and_atomic() {
    let mut client = Http3ControlStreamState::new(Http3EndpointRole::Client);
    client
        .receive(Http3Frame::parse(&[0x04, 0x00], 0).unwrap())
        .unwrap();
    for identifier in [8, 8, 4] {
        let mut destination = [0; 10];
        let frame = Http3GoawayBuilder::new(&mut destination, identifier)
            .build()
            .unwrap();
        match client
            .receive(Http3Frame::parse(frame.as_bytes(), 8).unwrap())
            .unwrap()
        {
            Http3ControlFrame::Goaway(goaway) => assert_eq!(goaway.identifier(), identifier),
            event => panic!("expected GOAWAY, got {event:?}"),
        }
    }
    assert_eq!(client.last_goaway_identifier(), Some(4));
    let before = client;
    let error = client
        .receive(Http3Frame::parse(&[0x07, 0x01, 0x05], 1).unwrap())
        .unwrap_err();
    assert_eq!(
        error,
        Http3ControlStreamError::InvalidGoawayStreamId { identifier: 5 }
    );
    assert_eq!(error.error_code(), Http3ErrorCode::ID_ERROR);
    assert_eq!(client, before);
    let error = client
        .receive(Http3Frame::parse(&[0x07, 0x01, 0x08], 1).unwrap())
        .unwrap_err();
    assert_eq!(
        error,
        Http3ControlStreamError::IncreasedGoawayIdentifier {
            previous: 4,
            current: 8,
        }
    );
    assert_eq!(error.error_code(), Http3ErrorCode::ID_ERROR);
    assert_eq!(client, before);

    let mut server = Http3ControlStreamState::new(Http3EndpointRole::Server);
    server
        .receive(Http3Frame::parse(&[0x04, 0x00], 0).unwrap())
        .unwrap();
    let maximum = 0x3fff_ffff_ffff_ffff;
    match server
        .receive(
            Http3Frame::parse(
                &[0x07, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                8,
            )
            .unwrap(),
        )
        .unwrap()
    {
        Http3ControlFrame::Goaway(goaway) => assert_eq!(goaway.identifier(), maximum),
        event => panic!("expected GOAWAY, got {event:?}"),
    }
    match server
        .receive(Http3Frame::parse(&[0x07, 0x01, 0x2a], 1).unwrap())
        .unwrap()
    {
        Http3ControlFrame::Goaway(goaway) => assert_eq!(goaway.identifier(), 42),
        event => panic!("expected GOAWAY, got {event:?}"),
    }
    let before = server;
    let error = server
        .receive(Http3Frame::parse(&[0x07, 0x01, 0x2b], 1).unwrap())
        .unwrap_err();
    assert_eq!(
        error,
        Http3ControlStreamError::IncreasedGoawayIdentifier {
            previous: 42,
            current: 43,
        }
    );
    assert_eq!(error.error_code(), Http3ErrorCode::ID_ERROR);
    assert_eq!(server, before);
    let error = server
        .receive(Http3Frame::parse(&[0x07, 0x03, 0x40, 0x2a, 0xff], 3).unwrap())
        .unwrap_err();
    assert_eq!(
        error,
        Http3ControlStreamError::FramePayload {
            frame_type: Http3FrameType::GOAWAY,
            error: Http3FramePayloadParseError::TrailingPayload {
                consumed: 2,
                actual: 3,
            },
        }
    );
    assert_eq!(error.error_code(), Http3ErrorCode::FRAME_ERROR);
    assert_eq!(server, before);
}

#[test]
fn control_stream_errors_describe_the_failure_and_expose_only_nested_sources() {
    let mut state = Http3ControlStreamState::new(Http3EndpointRole::Server);
    let missing = state
        .receive(Http3Frame::parse(&[0x00, 0x00], 0).unwrap())
        .unwrap_err();
    assert!(missing.to_string().contains("starts with frame type 0"));
    assert!(core::error::Error::source(&missing).is_none());

    let payload = state
        .receive(Http3Frame::parse(&[0x04, 0x01, 0x40], 1).unwrap())
        .unwrap_err();
    assert!(payload.to_string().contains("SETTINGS identifier"));
    assert!(core::error::Error::source(&payload).is_some());

    let semantic = state
        .receive(Http3Frame::parse(&[0x04, 0x04, 0x21, 0x00, 0x21, 0x00], 4).unwrap())
        .unwrap_err();
    assert!(
        semantic
            .to_string()
            .contains("duplicates an earlier identifier")
    );
    assert!(core::error::Error::source(&semantic).is_some());

    let mut ready = Http3ControlStreamState::new(Http3EndpointRole::Client);
    ready
        .receive(Http3Frame::parse(&[0x04, 0x00], 0).unwrap())
        .unwrap();
    let unexpected = ready
        .receive(Http3Frame::parse(&[0x00, 0x00], 0).unwrap())
        .unwrap_err();
    assert!(
        unexpected
            .to_string()
            .contains("unexpected on the control stream")
    );
    assert!(core::error::Error::source(&unexpected).is_none());
}

#[test]
fn message_stream_public_facades_initial_states_and_incomplete_errors_are_exact() {
    let _: http3::Http3MessageStreamState =
        Http3MessageStreamState::new(Http3MessageStreamKind::Request);
    let _: Http3MessageStreamState =
        http3::Http3MessageStreamState::new(http3::Http3MessageStreamKind::Response);
    let mut pending_state = Http3MessageStreamState::new(Http3MessageStreamKind::Request);
    let _: http3::Http3PendingHeaders<'_, '_> = match pending_state
        .receive(Http3Frame::parse(&[0x01, 0x00], 0).unwrap())
        .unwrap()
    {
        Http3MessageFrame::Headers(headers) => headers,
        event => panic!("expected HEADERS, got {event:?}"),
    };
    let _: http3::Http3MessageStreamError = Http3MessageStreamError::IncompleteMessage {
        stream_kind: Http3MessageStreamKind::Request,
        position: Http3MessagePosition::BeforeHeaders,
    };

    for (kind, position, error_code) in [
        (
            Http3MessageStreamKind::Request,
            Http3MessagePosition::BeforeHeaders,
            Http3ErrorCode::REQUEST_INCOMPLETE,
        ),
        (
            Http3MessageStreamKind::Response,
            Http3MessagePosition::BeforeFinalResponse,
            Http3ErrorCode::MESSAGE_ERROR,
        ),
        (
            Http3MessageStreamKind::Push,
            Http3MessagePosition::BeforeFinalResponse,
            Http3ErrorCode::MESSAGE_ERROR,
        ),
    ] {
        let state = Http3MessageStreamState::new(kind);
        assert_eq!(state.kind(), kind);
        assert_eq!(state.position(), position);
        assert_eq!(state, state);
        assert_eq!(
            state.finish(),
            Err(Http3MessageStreamError::IncompleteMessage {
                stream_kind: kind,
                position,
            })
        );
        assert_eq!(state.finish().unwrap_err().error_code(), error_code);
    }
}

#[test]
fn request_message_stream_guards_headers_and_enforces_transitions_atomically() {
    let mut state = Http3MessageStreamState::new(Http3MessageStreamKind::Request);
    let before = state;
    let error = state
        .receive(Http3Frame::parse(&[0x00, 0x01, 0xaa], 1).unwrap())
        .unwrap_err();
    assert_eq!(
        error,
        Http3MessageStreamError::UnexpectedFrame {
            frame_type: Http3FrameType::DATA,
            position: Http3MessagePosition::BeforeHeaders,
        }
    );
    assert_eq!(error.error_code(), Http3ErrorCode::FRAME_UNEXPECTED);
    assert_eq!(state, before);

    let unknown = [0x40, 0x22, 0x80, 0x00, 0x00, 0x02, 0xde, 0xad];
    match state
        .receive(Http3Frame::parse(&unknown, 2).unwrap())
        .unwrap()
    {
        Http3MessageFrame::Unknown(frame) => {
            assert_eq!(frame.as_bytes(), &unknown);
            assert_eq!(frame.frame_type_varint().as_bytes(), &unknown[..2]);
            assert_eq!(frame.payload_length_varint().as_bytes(), &unknown[2..6]);
        }
        event => panic!("expected unknown extension, got {event:?}"),
    }
    assert_eq!(state, before);

    {
        let pending = match state
            .receive(Http3Frame::parse(&[0x01, 0x02, 0xff, 0x00], 2).unwrap())
            .unwrap()
        {
            Http3MessageFrame::Headers(pending) => pending,
            event => panic!("expected HEADERS, got {event:?}"),
        };
        assert_eq!(pending.headers().encoded_field_section(), &[0xff, 0x00]);
    }
    assert_eq!(state, before);

    let pending = match state
        .receive(Http3Frame::parse(&[0x01, 0x00], 0).unwrap())
        .unwrap()
    {
        Http3MessageFrame::Headers(pending) => pending,
        event => panic!("expected HEADERS, got {event:?}"),
    };
    let error = pending
        .accept(Http3HeaderSectionKind::FinalResponse)
        .unwrap_err();
    assert_eq!(
        error,
        Http3MessageStreamError::InvalidHeaderSection {
            stream_kind: Http3MessageStreamKind::Request,
            position: Http3MessagePosition::BeforeHeaders,
            section_kind: Http3HeaderSectionKind::FinalResponse,
        }
    );
    assert_eq!(error.error_code(), Http3ErrorCode::MESSAGE_ERROR);
    assert!(core::error::Error::source(&error).is_none());
    assert_eq!(state, before);

    let pending = match state
        .receive(Http3Frame::parse(&[0x01, 0x02, 0xaa, 0xbb], 2).unwrap())
        .unwrap()
    {
        Http3MessageFrame::Headers(pending) => pending,
        event => panic!("expected HEADERS, got {event:?}"),
    };
    assert_eq!(
        pending
            .accept(Http3HeaderSectionKind::Request)
            .unwrap()
            .encoded_field_section(),
        &[0xaa, 0xbb]
    );
    assert_eq!(state.position(), Http3MessagePosition::Content);
    match state
        .receive(Http3Frame::parse(&[0x00, 0x02, 0xde, 0xad], 2).unwrap())
        .unwrap()
    {
        Http3MessageFrame::Data(data) => assert_eq!(data.data(), &[0xde, 0xad]),
        event => panic!("expected DATA, got {event:?}"),
    }
    let pending = match state
        .receive(Http3Frame::parse(&[0x01, 0x01, 0xcc], 1).unwrap())
        .unwrap()
    {
        Http3MessageFrame::Headers(pending) => pending,
        event => panic!("expected HEADERS, got {event:?}"),
    };
    pending.accept(Http3HeaderSectionKind::Trailers).unwrap();
    assert_eq!(state.position(), Http3MessagePosition::Trailers);
    for frame_type in [Http3FrameType::DATA, Http3FrameType::HEADERS] {
        let before = state;
        let error = state
            .receive(Http3Frame::parse(&[frame_type.value() as u8, 0x00], 0).unwrap())
            .unwrap_err();
        assert_eq!(
            error,
            Http3MessageStreamError::UnexpectedFrame {
                frame_type,
                position: Http3MessagePosition::Trailers,
            }
        );
        assert_eq!(state, before);
    }
    for wire in [
        &[0x40, 0x22, 0x80, 0x00, 0x00, 0x02, 0xde, 0xad][..],
        &[0x40, 0x21, 0x80, 0x00, 0x00, 0x02, 0xbe, 0xef][..],
    ] {
        let before = state;
        match state.receive(Http3Frame::parse(wire, 2).unwrap()).unwrap() {
            Http3MessageFrame::Unknown(frame) => assert_eq!(frame.as_bytes(), wire),
            event => panic!("expected unknown extension or GREASE, got {event:?}"),
        }
        assert_eq!(state, before);
    }
    assert_eq!(state.finish(), Ok(()));
}

#[test]
fn response_and_push_message_streams_use_response_header_semantics() {
    let mut response = Http3MessageStreamState::new(Http3MessageStreamKind::Response);
    for section_kind in [
        Http3HeaderSectionKind::InformationalResponse,
        Http3HeaderSectionKind::InformationalResponse,
    ] {
        let pending = match response
            .receive(Http3Frame::parse(&[0x01, 0x01, 0x11], 1).unwrap())
            .unwrap()
        {
            Http3MessageFrame::Headers(pending) => pending,
            event => panic!("expected HEADERS, got {event:?}"),
        };
        assert_eq!(
            pending
                .accept(section_kind)
                .unwrap()
                .encoded_field_section(),
            &[0x11]
        );
        assert_eq!(
            response.position(),
            Http3MessagePosition::BeforeFinalResponse
        );
    }
    let before = response;
    assert_eq!(
        response.finish(),
        Err(Http3MessageStreamError::IncompleteMessage {
            stream_kind: Http3MessageStreamKind::Response,
            position: Http3MessagePosition::BeforeFinalResponse,
        })
    );
    assert_eq!(response, before);
    let error = response
        .receive(Http3Frame::parse(&[0x00, 0x00], 0).unwrap())
        .unwrap_err();
    assert_eq!(
        error,
        Http3MessageStreamError::UnexpectedFrame {
            frame_type: Http3FrameType::DATA,
            position: Http3MessagePosition::BeforeFinalResponse,
        }
    );
    assert_eq!(error.error_code(), Http3ErrorCode::FRAME_UNEXPECTED);
    assert_eq!(response, before);
    let pending = match response
        .receive(Http3Frame::parse(&[0x01, 0x00], 0).unwrap())
        .unwrap()
    {
        Http3MessageFrame::Headers(pending) => pending,
        event => panic!("expected HEADERS, got {event:?}"),
    };
    pending
        .accept(Http3HeaderSectionKind::FinalResponse)
        .unwrap();
    assert_eq!(response.position(), Http3MessagePosition::Content);
    match response
        .receive(Http3Frame::parse(&[0x00, 0x01, 0x42], 1).unwrap())
        .unwrap()
    {
        Http3MessageFrame::Data(data) => assert_eq!(data.data(), &[0x42]),
        event => panic!("expected DATA, got {event:?}"),
    }
    let before = response;
    let pending = match response
        .receive(Http3Frame::parse(&[0x01, 0x00], 0).unwrap())
        .unwrap()
    {
        Http3MessageFrame::Headers(pending) => pending,
        event => panic!("expected HEADERS, got {event:?}"),
    };
    let error = pending
        .accept(Http3HeaderSectionKind::FinalResponse)
        .unwrap_err();
    assert_eq!(
        error,
        Http3MessageStreamError::InvalidHeaderSection {
            stream_kind: Http3MessageStreamKind::Response,
            position: Http3MessagePosition::Content,
            section_kind: Http3HeaderSectionKind::FinalResponse,
        }
    );
    assert_eq!(response, before);
    let pending = match response
        .receive(Http3Frame::parse(&[0x01, 0x00], 0).unwrap())
        .unwrap()
    {
        Http3MessageFrame::Headers(pending) => pending,
        event => panic!("expected HEADERS, got {event:?}"),
    };
    pending.accept(Http3HeaderSectionKind::Trailers).unwrap();
    assert_eq!(response.finish(), Ok(()));

    let mut empty_final = Http3MessageStreamState::new(Http3MessageStreamKind::Response);
    let pending = match empty_final
        .receive(Http3Frame::parse(&[0x01, 0x00], 0).unwrap())
        .unwrap()
    {
        Http3MessageFrame::Headers(pending) => pending,
        event => panic!("expected HEADERS, got {event:?}"),
    };
    pending
        .accept(Http3HeaderSectionKind::FinalResponse)
        .unwrap();
    assert_eq!(empty_final.finish(), Ok(()));

    let mut push = Http3MessageStreamState::new(Http3MessageStreamKind::Push);
    for section_kind in [
        Http3HeaderSectionKind::InformationalResponse,
        Http3HeaderSectionKind::FinalResponse,
        Http3HeaderSectionKind::Trailers,
    ] {
        let pending = match push
            .receive(Http3Frame::parse(&[0x01, 0x00], 0).unwrap())
            .unwrap()
        {
            Http3MessageFrame::Headers(pending) => pending,
            event => panic!("expected HEADERS, got {event:?}"),
        };
        pending.accept(section_kind).unwrap();
    }
    assert_eq!(push.position(), Http3MessagePosition::Trailers);
    assert_eq!(push.finish(), Ok(()));
}

#[test]
fn message_stream_push_promises_forbidden_frames_extensions_and_errors_are_exact() {
    let malformed_promise = Http3Frame::parse(&[0x05, 0x00], 0).unwrap();
    for kind in [
        Http3MessageStreamKind::Request,
        Http3MessageStreamKind::Push,
    ] {
        let mut state = Http3MessageStreamState::new(kind);
        let before = state;
        let error = state.receive(malformed_promise).unwrap_err();
        assert_eq!(
            error,
            Http3MessageStreamError::UnexpectedFrame {
                frame_type: Http3FrameType::PUSH_PROMISE,
                position: state.position(),
            }
        );
        assert_eq!(error.error_code(), Http3ErrorCode::FRAME_UNEXPECTED);
        assert!(core::error::Error::source(&error).is_none());
        assert_eq!(state, before);
    }

    let promise_wire = [0x05, 0x03, 0x2a, 0xaa, 0xbb];
    let mut response = Http3MessageStreamState::new(Http3MessageStreamKind::Response);
    for expected_position in [
        Http3MessagePosition::BeforeFinalResponse,
        Http3MessagePosition::Content,
        Http3MessagePosition::Trailers,
    ] {
        match response
            .receive(Http3Frame::parse(&promise_wire, 3).unwrap())
            .unwrap()
        {
            Http3MessageFrame::PushPromise(promise) => {
                assert_eq!(promise.push_id(), Http3PushId::new(42));
                assert_eq!(promise.encoded_field_section(), &[0xaa, 0xbb]);
            }
            event => panic!("expected PUSH_PROMISE, got {event:?}"),
        }
        assert_eq!(response.position(), expected_position);
        if expected_position == Http3MessagePosition::BeforeFinalResponse {
            let pending = match response
                .receive(Http3Frame::parse(&[0x01, 0x00], 0).unwrap())
                .unwrap()
            {
                Http3MessageFrame::Headers(pending) => pending,
                event => panic!("expected HEADERS, got {event:?}"),
            };
            pending
                .accept(Http3HeaderSectionKind::FinalResponse)
                .unwrap();
        } else if expected_position == Http3MessagePosition::Content {
            let pending = match response
                .receive(Http3Frame::parse(&[0x01, 0x00], 0).unwrap())
                .unwrap()
            {
                Http3MessageFrame::Headers(pending) => pending,
                event => panic!("expected HEADERS, got {event:?}"),
            };
            pending.accept(Http3HeaderSectionKind::Trailers).unwrap();
        }
    }

    let mut malformed_allowed = Http3MessageStreamState::new(Http3MessageStreamKind::Response);
    let before = malformed_allowed;
    let error = malformed_allowed
        .receive(Http3Frame::parse(&[0x05, 0x00], 0).unwrap())
        .unwrap_err();
    assert_eq!(
        error,
        Http3MessageStreamError::FramePayload {
            frame_type: Http3FrameType::PUSH_PROMISE,
            error: Http3FramePayloadParseError::PayloadVarInt {
                field: Http3FramePayloadField::PushId,
                offset: 0,
                error: QuicVarIntParseError::Incomplete {
                    required: 1,
                    available: 0,
                },
            },
        }
    );
    assert_eq!(error.error_code(), Http3ErrorCode::FRAME_ERROR);
    assert!(core::error::Error::source(&error).is_some());
    assert!(error.to_string().contains("message frame type 5 payload"));
    assert_eq!(malformed_allowed, before);

    let mut request = Http3MessageStreamState::new(Http3MessageStreamKind::Request);
    let pending = match request
        .receive(Http3Frame::parse(&[0x01, 0x00], 0).unwrap())
        .unwrap()
    {
        Http3MessageFrame::Headers(pending) => pending,
        event => panic!("expected HEADERS, got {event:?}"),
    };
    pending.accept(Http3HeaderSectionKind::Request).unwrap();
    for frame_type in [
        Http3FrameType::CANCEL_PUSH,
        Http3FrameType::SETTINGS,
        Http3FrameType::GOAWAY,
        Http3FrameType::MAX_PUSH_ID,
        Http3FrameType::new(0x02),
        Http3FrameType::new(0x06),
        Http3FrameType::new(0x08),
        Http3FrameType::new(0x09),
    ] {
        let before = request;
        let error = request
            .receive(Http3Frame::parse(&[frame_type.value() as u8, 0x00], 0).unwrap())
            .unwrap_err();
        assert_eq!(
            error,
            Http3MessageStreamError::UnexpectedFrame {
                frame_type,
                position: Http3MessagePosition::Content,
            }
        );
        assert_eq!(error.error_code(), Http3ErrorCode::FRAME_UNEXPECTED);
        assert!(core::error::Error::source(&error).is_none());
        assert_eq!(request, before);
    }

    for wire in [
        &[0x40, 0x22, 0x80, 0x00, 0x00, 0x02, 0xde, 0xad][..],
        &[0x40, 0x21, 0x80, 0x00, 0x00, 0x02, 0xbe, 0xef][..],
    ] {
        let before = request;
        match request
            .receive(Http3Frame::parse(wire, 2).unwrap())
            .unwrap()
        {
            Http3MessageFrame::Unknown(frame) => assert_eq!(frame.as_bytes(), wire),
            event => panic!("expected unknown extension or GREASE, got {event:?}"),
        }
        assert_eq!(request, before);
    }

    let incomplete = Http3MessageStreamState::new(Http3MessageStreamKind::Response)
        .finish()
        .unwrap_err();
    assert!(
        incomplete
            .to_string()
            .contains("Response message is incomplete")
    );
    assert!(core::error::Error::source(&incomplete).is_none());
}

#[test]
fn http3_qpack_field_section_handoff_decodes_headers_and_push_promise() {
    let root_error: Http3QpackFieldSectionError = Http3QpackFieldSectionError::OutputProvisioning(
        QpackFieldSectionDecodeError::OutputBytesTooShort {
            required: 1,
            available: 0,
        },
    );
    assert_eq!(Http3QpackFieldSectionError::error_code(root_error), None);
    let module_error: http3::Http3QpackFieldSectionError =
        http3::Http3QpackFieldSectionError::DecompressionFailed(
            QpackFieldSectionDecodeError::StaticIndexOutOfRange { index: 99 },
        );
    assert_eq!(
        http3::Http3QpackFieldSectionError::error_code(module_error),
        Some(Http3ErrorCode::QPACK_DECOMPRESSION_FAILED)
    );

    let mut storage = [];
    let mut table_entries = [];
    let table = QpackDynamicTable::new(&mut storage, &mut table_entries);
    let decoder = QpackFieldSectionDecoder::new(128);

    let headers_wire = [0x01, 0x03, 0x00, 0x00, 0xc0];
    let headers = Http3Headers::parse(&headers_wire, 3).unwrap();
    let mut header_bytes = [0xaa; 10];
    let mut header_fields = [QpackDecodedFieldEntry::EMPTY; 1];
    {
        let mut output = QpackFieldSectionOutput::new(&mut header_bytes, &mut header_fields);
        let decoded = match headers
            .decode_field_section(&decoder, &table, &mut output)
            .unwrap()
        {
            QpackFieldSectionDecodeOutcome::Decoded(decoded) => decoded,
            QpackFieldSectionDecodeOutcome::Blocked(_) => panic!("static section is ready"),
        };
        assert_eq!((decoded.required_insert_count(), decoded.base()), (0, 0));
        assert_eq!(
            decoded.get(0).map(|field| (field.name(), field.value())),
            Some((b":authority" as &[u8], b"" as &[u8]))
        );
        assert_eq!(decoded.get(1), None);
    }
    assert_eq!(headers.as_bytes(), &headers_wire);
    assert_eq!(headers.encoded_field_section(), &[0x00, 0x00, 0xc0]);

    let promise_wire = [0x05, 0x04, 0x2a, 0x00, 0x00, 0xc0];
    let promise: http3::Http3PushPromise<'_> = Http3PushPromise::parse(&promise_wire, 4).unwrap();
    let mut promise_bytes = [0xaa; 10];
    let mut promise_fields = [QpackDecodedFieldEntry::EMPTY; 1];
    {
        let mut output = QpackFieldSectionOutput::new(&mut promise_bytes, &mut promise_fields);
        let decoded = match promise
            .decode_field_section(&decoder, &table, &mut output)
            .unwrap()
        {
            QpackFieldSectionDecodeOutcome::Decoded(decoded) => decoded,
            QpackFieldSectionDecodeOutcome::Blocked(_) => panic!("push ID is not QPACK input"),
        };
        assert_eq!(
            decoded.get(0).map(|field| (field.name(), field.value())),
            Some((b":authority" as &[u8], b"" as &[u8]))
        );
    }
    assert_eq!(promise.push_id(), Http3PushId::new(42));
    assert_eq!(promise.as_bytes(), &promise_wire);
    assert_eq!(promise.encoded_field_section(), &[0x00, 0x00, 0xc0]);
}

#[test]
fn http3_qpack_field_section_blocking_and_peer_decompression_errors_are_exact() {
    let mut storage = [0; 36];
    let mut table_entries = [QpackDynamicTableEntry::EMPTY; 2];
    let mut table = QpackDynamicTable::new(&mut storage, &mut table_entries);
    assert_eq!(table.set_capacity(68, |_| true), Ok(()));
    let decoder = QpackFieldSectionDecoder::new(128);

    let blocked_wire = [0x01, 0x03, 0x02, 0x00, 0x80];
    let blocked = Http3Headers::parse(&blocked_wire, 3).unwrap();
    let mut blocked_bytes = [0xaa; 16];
    let mut blocked_fields = [QpackDecodedFieldEntry::EMPTY; 2];
    let before_blocked_bytes = blocked_bytes;
    let before_blocked_fields = blocked_fields;
    {
        let mut output = QpackFieldSectionOutput::new(&mut blocked_bytes, &mut blocked_fields);
        assert!(matches!(
            blocked.decode_field_section(&decoder, &table, &mut output),
            Ok(QpackFieldSectionDecodeOutcome::Blocked(blocked))
                if blocked.required_insert_count() == 1 && blocked.base() == 1
        ));
        assert_eq!(output.len(), 0);
    }
    assert_eq!(
        (blocked_bytes, blocked_fields),
        (before_blocked_bytes, before_blocked_fields)
    );

    for (wire, expected) in [
        (
            &[0x01, 0x01, 0x00][..],
            QpackFieldSectionDecodeError::Prefix(QpackFieldSectionPrefixParseError::DeltaBase(
                QpackIntegerParseError::Incomplete {
                    required: 1,
                    available: 0,
                },
            )),
        ),
        (
            &[0x01, 0x04, 0x00, 0x00, 0xff, 0x24][..],
            QpackFieldSectionDecodeError::StaticIndexOutOfRange { index: 99 },
        ),
    ] {
        let headers = Http3Headers::parse(wire, wire.len() - 2).unwrap();
        let mut bytes = [0xaa; 16];
        let mut fields = [QpackDecodedFieldEntry::EMPTY; 2];
        let error = {
            let mut output = QpackFieldSectionOutput::new(&mut bytes, &mut fields);
            headers
                .decode_field_section(&decoder, &table, &mut output)
                .unwrap_err()
        };
        assert_eq!(
            error,
            Http3QpackFieldSectionError::DecompressionFailed(expected)
        );
        assert_eq!(
            error.error_code(),
            Some(Http3ErrorCode::QPACK_DECOMPRESSION_FAILED)
        );
        assert_eq!(
            core::error::Error::source(&error)
                .and_then(|source| source.downcast_ref::<QpackFieldSectionDecodeError>()),
            Some(&expected)
        );
        assert!(error.to_string().contains("decompression failed"));
        assert!(!error.to_string().contains("failed locally"));
    }
}

#[test]
fn http3_qpack_field_section_output_provisioning_is_local_and_atomic() {
    let mut storage = [];
    let mut table_entries = [];
    let table = QpackDynamicTable::new(&mut storage, &mut table_entries);
    let decoder = QpackFieldSectionDecoder::new(128);
    let wire = [0x05, 0x04, 0x2a, 0x00, 0x00, 0xc0];
    let promise = Http3PushPromise::parse(&wire, 4).unwrap();

    for (byte_len, field_len, expected) in [
        (
            9,
            1,
            QpackFieldSectionDecodeError::OutputBytesTooShort {
                required: 10,
                available: 9,
            },
        ),
        (
            10,
            0,
            QpackFieldSectionDecodeError::OutputFieldsTooShort {
                required: 1,
                available: 0,
            },
        ),
    ] {
        let mut bytes = [0xaa; 10];
        let mut fields = [QpackDecodedFieldEntry::EMPTY; 1];
        let before_bytes = bytes;
        let before_fields = fields;
        let error = {
            let mut output =
                QpackFieldSectionOutput::new(&mut bytes[..byte_len], &mut fields[..field_len]);
            promise
                .decode_field_section(&decoder, &table, &mut output)
                .unwrap_err()
        };
        assert_eq!(
            error,
            Http3QpackFieldSectionError::OutputProvisioning(expected)
        );
        assert_eq!(error.error_code(), None);
        assert_eq!(
            core::error::Error::source(&error)
                .and_then(|source| source.downcast_ref::<QpackFieldSectionDecodeError>()),
            Some(&expected)
        );
        assert!(
            error
                .to_string()
                .contains("output provisioning failed locally")
        );
        assert!(!error.to_string().contains("decompression failed"));
        assert_eq!((bytes, fields), (before_bytes, before_fields));
    }
}

type DecodedFieldSpec<'a> = (&'a [u8], &'a [u8], bool);
type HeaderSectionErrorCase<'a> = (&'a [DecodedFieldSpec<'a>], Http3HeaderSectionError);

fn with_decoded_fields<R>(
    fields: &[DecodedFieldSpec<'_>],
    check: impl FnOnce(QpackDecodedFieldSection<'_>) -> R,
) -> R {
    let mut wire = [0_u8; 512];
    wire[..2].copy_from_slice(&[0, 0]);
    let mut wire_len = 2;
    for &(name, value, never_indexed) in fields {
        let line = QpackLiteralNameFieldLineBuilder::new(
            &mut wire[wire_len..],
            never_indexed,
            false,
            name,
            false,
            value,
        )
        .build()
        .unwrap();
        wire_len += line.as_bytes().len();
    }
    let mut storage = [];
    let mut entries = [];
    let table = QpackDynamicTable::new(&mut storage, &mut entries);
    let decoder = QpackFieldSectionDecoder::new(0);
    let mut bytes = [0_u8; 512];
    let mut metadata = [QpackDecodedFieldEntry::EMPTY; 16];
    let mut output = QpackFieldSectionOutput::new(&mut bytes, &mut metadata);
    let decoded = match decoder
        .decode(&wire[..wire_len], &table, &mut output)
        .unwrap()
    {
        QpackFieldSectionDecodeOutcome::Decoded(section) => section,
        QpackFieldSectionDecodeOutcome::Blocked(_) => panic!("literal field section is ready"),
    };
    check(decoded)
}

#[test]
fn decoded_header_analysis_facades_preserve_qpack_and_handoff() {
    let fields = [
        (b":method" as &[u8], b"GET" as &[u8], false),
        (b":scheme", b"https", false),
        (b":authority", b"example.com", true),
        (b":path", b"/", false),
        (b"host", b"example.com", false),
    ];
    with_decoded_fields(&fields, |section| {
        let _: http3::Http3HeaderSectionContext = Http3HeaderSectionContext::Trailers;
        let _: Http3HeaderSectionError = http3::Http3HeaderSectionError::MissingAuthorityOrHost;
        let analyzed = analyze_decoded_header_section(
            section,
            Http3HeaderSectionContext::Request {
                extended_connect_enabled: false,
            },
        )
        .unwrap();
        let module = http3::analyze_decoded_header_section(
            section,
            http3::Http3HeaderSectionContext::Request {
                extended_connect_enabled: false,
            },
        )
        .unwrap();
        assert_eq!(analyzed, module);
        assert_eq!(analyzed.section(), section);
        assert_eq!(analyzed.kind(), Http3HeaderSectionKind::Request);
        assert_eq!(analyzed.field_section_size(), 224);
        assert!(analyzed.section().get(2).unwrap().never_indexed());
        assert_eq!(
            analyzed.section().iter().collect::<Vec<_>>(),
            section.iter().collect::<Vec<_>>()
        );

        let mut state = Http3MessageStreamState::new(Http3MessageStreamKind::Request);
        let pending = match state
            .receive(Http3Frame::parse(&[0x01, 0x00], 0).unwrap())
            .unwrap()
        {
            Http3MessageFrame::Headers(pending) => pending,
            event => panic!("expected HEADERS, got {event:?}"),
        };
        pending.accept(analyzed.kind()).unwrap();
        assert_eq!(state.position(), Http3MessagePosition::Content);
    });
    with_decoded_fields(
        &[
            (b":method", b"GET", false),
            (b":scheme", b"custom", false),
            (b":path", b"opaque", false),
        ],
        |section| {
            assert!(
                analyze_decoded_header_section(
                    section,
                    Http3HeaderSectionContext::Request {
                        extended_connect_enabled: false
                    }
                )
                .is_ok()
            )
        },
    );
}

#[test]
fn decoded_request_analysis_reports_exact_errors_and_te_rules() {
    let cases: &[HeaderSectionErrorCase<'_>] = &[
        (
            &[
                (b":scheme", b"https", false),
                (b":path", b"/", false),
                (b":authority", b"x", false),
            ],
            Http3HeaderSectionError::MissingPseudoField { name: b":method" },
        ),
        (
            &[
                (b":method", b"GET", false),
                (b":scheme", b"https", false),
                (b":authority", b"x", false),
                (b":authority", b"x", false),
                (b":path", b"/", false),
            ],
            Http3HeaderSectionError::DuplicatePseudoField { field_index: 3 },
        ),
        (
            &[(b"x", b"v", false), (b":method", b"GET", false)],
            Http3HeaderSectionError::PseudoFieldAfterRegular { field_index: 1 },
        ),
        (
            &[
                (b":method", b"GET", false),
                (b":scheme", b"https", false),
                (b":authority", b"x", false),
                (b":path", b"/", false),
                (b"Host", b"x", false),
            ],
            Http3HeaderSectionError::UppercaseFieldName { field_index: 4 },
        ),
        (
            &[
                (b":method", b"GET", false),
                (b":scheme", b"https", false),
                (b":authority", b"x", false),
                (b":path", b"/", false),
                (b"bad name", b"x", false),
            ],
            Http3HeaderSectionError::InvalidFieldName { field_index: 4 },
        ),
        (
            &[
                (b":method", b"GET", false),
                (b":scheme", b"https", false),
                (b":authority", b"x", false),
                (b":path", b"/", false),
                (b"x", b"bad ", false),
            ],
            Http3HeaderSectionError::InvalidFieldValue { field_index: 4 },
        ),
        (
            &[
                (b":method", b"GET", false),
                (b":scheme", b"https", false),
                (b":authority", b"x", false),
                (b":path", b"/", false),
                (b"x", b"bad\n", false),
            ],
            Http3HeaderSectionError::InvalidFieldValue { field_index: 4 },
        ),
        (
            &[
                (b":method", b"GET", false),
                (b":scheme", b"https", false),
                (b":authority", b"x", false),
                (b":path", b"/", false),
                (b"connection", b"close", false),
            ],
            Http3HeaderSectionError::ConnectionSpecificField { field_index: 4 },
        ),
        (
            &[
                (b":method", b"GET", false),
                (b":scheme", b"https", false),
                (b":authority", b"x", false),
                (b":path", b"/", false),
                (b"host", b"x", false),
                (b"host", b"x", false),
            ],
            Http3HeaderSectionError::DuplicateHost { field_index: 5 },
        ),
        (
            &[
                (b":method", b"GET", false),
                (b":scheme", b"https", false),
                (b":authority", b"x", false),
                (b":path", b"/", false),
                (b"host", b"", false),
            ],
            Http3HeaderSectionError::InvalidHost { field_index: 4 },
        ),
        (
            &[
                (b":method", b"GET", false),
                (b":scheme", b"https", false),
                (b":authority", b"x", false),
                (b":path", b"/", false),
                (b"host", b"y", false),
            ],
            Http3HeaderSectionError::AuthorityHostMismatch {
                authority_field_index: 2,
                host_field_index: 4,
            },
        ),
    ];
    for &(fields, expected) in cases {
        with_decoded_fields(fields, |section| {
            let error = analyze_decoded_header_section(
                section,
                Http3HeaderSectionContext::Request {
                    extended_connect_enabled: false,
                },
            )
            .unwrap_err();
            assert_eq!(error, expected);
            assert_eq!(error.error_code(), Http3ErrorCode::MESSAGE_ERROR);
            assert!(core::error::Error::source(&error).is_none());
        });
    }
    for value in [b"trailers" as &[u8], b"Trailers ,\tTRAILERS"] {
        with_decoded_fields(
            &[
                (b":method", b"GET", false),
                (b":scheme", b"https", false),
                (b":authority", b"x", false),
                (b":path", b"/", false),
                (b"te", value, false),
            ],
            |section| {
                assert!(
                    analyze_decoded_header_section(
                        section,
                        Http3HeaderSectionContext::Request {
                            extended_connect_enabled: false
                        }
                    )
                    .is_ok()
                )
            },
        );
    }
    for value in [b"gzip" as &[u8], b","] {
        with_decoded_fields(
            &[
                (b":method", b"GET", false),
                (b":scheme", b"https", false),
                (b":authority", b"x", false),
                (b":path", b"/", false),
                (b"te", value, false),
            ],
            |section| {
                assert_eq!(
                    analyze_decoded_header_section(
                        section,
                        Http3HeaderSectionContext::Request {
                            extended_connect_enabled: false
                        }
                    ),
                    Err(Http3HeaderSectionError::InvalidTe { field_index: 4 })
                )
            },
        );
    }
}

#[test]
fn decoded_response_and_trailer_analysis_cover_status_and_forbidden_fields() {
    for (status, kind) in [
        (
            b"100" as &[u8],
            Http3HeaderSectionKind::InformationalResponse,
        ),
        (b"199", Http3HeaderSectionKind::InformationalResponse),
        (b"200", Http3HeaderSectionKind::FinalResponse),
        (b"599", Http3HeaderSectionKind::FinalResponse),
    ] {
        with_decoded_fields(&[(b":status", status, false)], |section| {
            assert_eq!(
                analyze_decoded_header_section(section, Http3HeaderSectionContext::Response)
                    .unwrap()
                    .kind(),
                kind
            )
        });
    }
    for status in [b"101" as &[u8], b"099", b"600", b"20", b"2x0"] {
        with_decoded_fields(&[(b":status", status, false)], |section| {
            assert_eq!(
                analyze_decoded_header_section(section, Http3HeaderSectionContext::Response),
                Err(Http3HeaderSectionError::InvalidStatus { field_index: 0 })
            )
        });
    }
    for (context, fields, error) in [
        (
            Http3HeaderSectionContext::Response,
            &[
                (b":status" as &[u8], b"200" as &[u8], false),
                (b"te", b"trailers", false),
            ][..],
            Http3HeaderSectionError::InvalidTe { field_index: 1 },
        ),
        (
            Http3HeaderSectionContext::Trailers,
            &[(b":status" as &[u8], b"200" as &[u8], false)][..],
            Http3HeaderSectionError::PseudoFieldInTrailers { field_index: 0 },
        ),
        (
            Http3HeaderSectionContext::Trailers,
            &[(b"connection" as &[u8], b"close" as &[u8], false)][..],
            Http3HeaderSectionError::ConnectionSpecificField { field_index: 0 },
        ),
    ] {
        with_decoded_fields(fields, |section| {
            assert_eq!(analyze_decoded_header_section(section, context), Err(error))
        });
    }
    with_decoded_fields(&[(b"x", b"v", false)], |section| {
        assert_eq!(
            analyze_decoded_header_section(section, Http3HeaderSectionContext::Trailers)
                .unwrap()
                .kind(),
            Http3HeaderSectionKind::Trailers
        )
    });
}

#[test]
fn decoded_connect_analysis_covers_ordinary_and_extended_forms() {
    for authority in [b"example.com:443" as &[u8], b"[::1]:443"] {
        with_decoded_fields(
            &[
                (b":method", b"CONNECT", false),
                (b":authority", authority, false),
                (b"host", authority, false),
            ],
            |section| {
                assert!(
                    analyze_decoded_header_section(
                        section,
                        Http3HeaderSectionContext::Request {
                            extended_connect_enabled: false
                        }
                    )
                    .is_ok()
                )
            },
        );
    }
    for authority in [
        b"example.com" as &[u8],
        b"::1:443",
        b"example.com:x",
        b"example.com:65536",
    ] {
        with_decoded_fields(
            &[
                (b":method", b"CONNECT", false),
                (b":authority", authority, false),
            ],
            |section| {
                assert_eq!(
                    analyze_decoded_header_section(
                        section,
                        Http3HeaderSectionContext::Request {
                            extended_connect_enabled: false
                        }
                    ),
                    Err(Http3HeaderSectionError::InvalidAuthority { field_index: 1 })
                )
            },
        );
    }
    for name in [b":scheme" as &[u8], b":path"] {
        with_decoded_fields(
            &[
                (b":method", b"CONNECT", false),
                (b":authority", b"x:443", false),
                (name, b"x", false),
            ],
            |section| {
                assert_eq!(
                    analyze_decoded_header_section(
                        section,
                        Http3HeaderSectionContext::Request {
                            extended_connect_enabled: false
                        }
                    ),
                    Err(Http3HeaderSectionError::InvalidConnectPseudoFields { field_index: 2 })
                )
            },
        );
    }
    let extended = &[
        (b":method" as &[u8], b"CONNECT" as &[u8], false),
        (b":protocol", b"websocket", false),
        (b":scheme", b"https", false),
        (b":authority", b"x", false),
        (b":path", b"/", false),
    ];
    with_decoded_fields(extended, |section| {
        assert!(
            analyze_decoded_header_section(
                section,
                Http3HeaderSectionContext::Request {
                    extended_connect_enabled: true
                }
            )
            .is_ok()
        )
    });
    with_decoded_fields(extended, |section| {
        assert_eq!(
            analyze_decoded_header_section(
                section,
                Http3HeaderSectionContext::Request {
                    extended_connect_enabled: false
                }
            ),
            Err(Http3HeaderSectionError::InvalidProtocol { field_index: 1 })
        )
    });
    for fields in [
        &[
            (b":method" as &[u8], b"CONNECT" as &[u8], false),
            (b":protocol", b"bad protocol", false),
            (b":scheme", b"https", false),
            (b":authority", b"x", false),
            (b":path", b"/", false),
        ][..],
        &[
            (b":method" as &[u8], b"GET" as &[u8], false),
            (b":protocol", b"websocket", false),
            (b":scheme", b"https", false),
            (b":authority", b"x", false),
            (b":path", b"/", false),
        ][..],
    ] {
        with_decoded_fields(fields, |section| {
            assert_eq!(
                analyze_decoded_header_section(
                    section,
                    Http3HeaderSectionContext::Request {
                        extended_connect_enabled: true
                    }
                ),
                Err(Http3HeaderSectionError::InvalidProtocol { field_index: 1 })
            )
        });
    }
}

#[test]
fn decoded_push_promise_reuses_request_syntax_without_headers_kind() {
    let fields = [
        (b":method" as &[u8], b"GET" as &[u8], false),
        (b":scheme", b"https", false),
        (b":authority", b"x", false),
        (b":path", b"/", false),
    ];
    with_decoded_fields(&fields, |section| {
        let promise: http3::Http3DecodedPushPromise<'_> =
            analyze_decoded_push_promise(section, false).unwrap();
        assert_eq!(promise.section(), section);
        assert_eq!(promise.field_section_size(), 167);
        assert_eq!(
            http3::analyze_decoded_push_promise(section, false).unwrap(),
            promise
        );
    });
    with_decoded_fields(
        &[
            (b":method", b"GET", false),
            (b":scheme", b"https", false),
            (b":path", b"/", false),
        ],
        |section| {
            let error = analyze_decoded_push_promise(section, false).unwrap_err();
            assert_eq!(error, Http3HeaderSectionError::MissingAuthorityOrHost);
            assert_eq!(error.error_code(), Http3ErrorCode::MESSAGE_ERROR);
            assert!(error.to_string().contains("missing :authority and Host"));
            assert!(core::error::Error::source(&error).is_none());
        },
    );
}

#[test]
fn peer_unidirectional_stream_state_public_facades_start_empty() {
    let client: http3::Http3PeerUniStreamState =
        Http3PeerUniStreamState::new(Http3EndpointRole::Client);
    let server: Http3PeerUniStreamState =
        http3::Http3PeerUniStreamState::new(http3::Http3EndpointRole::Server);
    let _: http3::Http3CriticalUniStreamKind = Http3CriticalUniStreamKind::Control;
    let _: http3::Http3PeerUniStreamEvent = Http3PeerUniStreamEvent::Control {
        stream_id: Http3StreamId::new(3),
    };
    let _: http3::Http3PeerUniStreamError =
        Http3PeerUniStreamError::InvalidPeerUnidirectionalStream {
            stream_id: Http3StreamId::new(0),
        };

    for (state, role) in [
        (client, Http3EndpointRole::Client),
        (server, Http3EndpointRole::Server),
    ] {
        assert_eq!(state.role(), role);
        assert_eq!(state.control_stream_id(), None);
        assert_eq!(state.qpack_encoder_stream_id(), None);
        assert_eq!(state.qpack_decoder_stream_id(), None);
    }
}

#[test]
fn peer_unidirectional_stream_state_registers_critical_streams_for_each_role() {
    for (role, stream_ids) in [
        (Http3EndpointRole::Client, [3, 7, 11]),
        (Http3EndpointRole::Server, [2, 6, 10]),
    ] {
        let mut state = Http3PeerUniStreamState::new(role);
        let cases = [
            (
                Http3CriticalUniStreamKind::Control,
                stream_ids[0],
                &[0x00][..],
                Http3PeerUniStreamEvent::Control {
                    stream_id: Http3StreamId::new(stream_ids[0]),
                },
            ),
            (
                Http3CriticalUniStreamKind::QpackEncoder,
                stream_ids[1],
                &[0x02][..],
                Http3PeerUniStreamEvent::QpackEncoder {
                    stream_id: Http3StreamId::new(stream_ids[1]),
                },
            ),
            (
                Http3CriticalUniStreamKind::QpackDecoder,
                stream_ids[2],
                &[0x03][..],
                Http3PeerUniStreamEvent::QpackDecoder {
                    stream_id: Http3StreamId::new(stream_ids[2]),
                },
            ),
        ];

        for (kind, raw_stream_id, wire, event) in cases {
            let stream_id = Http3StreamId::new(raw_stream_id);
            assert_eq!(
                state.receive_header(stream_id, Http3UniStreamHeader::parse(wire).unwrap()),
                Ok(event)
            );
            match kind {
                Http3CriticalUniStreamKind::Control => {
                    assert_eq!(state.control_stream_id(), Some(stream_id));
                }
                Http3CriticalUniStreamKind::QpackEncoder => {
                    assert_eq!(state.qpack_encoder_stream_id(), Some(stream_id));
                }
                Http3CriticalUniStreamKind::QpackDecoder => {
                    assert_eq!(state.qpack_decoder_stream_id(), Some(stream_id));
                }
            }
        }
    }
}

#[test]
fn peer_unidirectional_stream_state_rejections_are_exact_and_transactional() {
    let mut state = Http3PeerUniStreamState::new(Http3EndpointRole::Client);
    for (kind, existing, received, wire) in [
        (Http3CriticalUniStreamKind::Control, 3, 15, &[0x00][..]),
        (Http3CriticalUniStreamKind::QpackEncoder, 7, 19, &[0x02][..]),
        (
            Http3CriticalUniStreamKind::QpackDecoder,
            11,
            23,
            &[0x03][..],
        ),
    ] {
        let existing = Http3StreamId::new(existing);
        state
            .receive_header(existing, Http3UniStreamHeader::parse(wire).unwrap())
            .unwrap();
        let before = state;
        let error = state
            .receive_header(
                Http3StreamId::new(received),
                Http3UniStreamHeader::parse(wire).unwrap(),
            )
            .unwrap_err();
        assert_eq!(
            error,
            Http3PeerUniStreamError::DuplicateCriticalStream {
                kind,
                existing,
                received: Http3StreamId::new(received),
            }
        );
        assert_eq!(
            error.error_code(),
            Some(Http3ErrorCode::STREAM_CREATION_ERROR)
        );
        assert!(
            error.to_string().contains("Control")
                || error.to_string().contains("QpackEncoder")
                || error.to_string().contains("QpackDecoder")
        );
        assert!(error.to_string().contains("duplicates stream"));
        assert!(core::error::Error::source(&error).is_none());
        assert_eq!(state, before);
    }

    for (role, invalid_ids) in [
        (Http3EndpointRole::Client, [0, 1, 2, 0x4000_0000_0000_0003]),
        (Http3EndpointRole::Server, [0, 1, 3, 0x4000_0000_0000_0002]),
    ] {
        for raw_stream_id in invalid_ids {
            let mut state = Http3PeerUniStreamState::new(role);
            let before = state;
            let stream_id = Http3StreamId::new(raw_stream_id);
            let error = state
                .receive_header(stream_id, Http3UniStreamHeader::parse(&[0x00]).unwrap())
                .unwrap_err();
            assert_eq!(
                error,
                Http3PeerUniStreamError::InvalidPeerUnidirectionalStream { stream_id }
            );
            assert_eq!(error.error_code(), None);
            assert_eq!(state, before);
        }
    }
}

#[test]
fn peer_unidirectional_stream_state_handles_push_extensions_and_closures() {
    let mut client = Http3PeerUniStreamState::new(Http3EndpointRole::Client);
    client
        .receive_header(
            Http3StreamId::new(3),
            Http3UniStreamHeader::parse(&[0x00]).unwrap(),
        )
        .unwrap();
    let before_push = client;
    assert_eq!(
        client.receive_header(
            Http3StreamId::new(7),
            Http3UniStreamHeader::parse(&[0x01, 0x2a]).unwrap(),
        ),
        Ok(Http3PeerUniStreamEvent::Push {
            stream_id: Http3StreamId::new(7),
            push_id: Http3PushId::new(42),
        })
    );
    assert_eq!(client, before_push);

    for (stream_id, wire, stream_type) in [
        (11, &[0x22][..], Http3StreamType::new(0x22)),
        (15, &[0x21][..], Http3StreamType::new(0x21)),
    ] {
        let before = client;
        assert_eq!(
            client.receive_header(
                Http3StreamId::new(stream_id),
                Http3UniStreamHeader::parse(wire).unwrap(),
            ),
            Ok(Http3PeerUniStreamEvent::Unknown {
                stream_id: Http3StreamId::new(stream_id),
                stream_type,
            })
        );
        assert_eq!(client, before);
    }

    let mut server = Http3PeerUniStreamState::new(Http3EndpointRole::Server);
    let before = server;
    let error = server
        .receive_header(
            Http3StreamId::new(2),
            Http3UniStreamHeader::parse(&[0x01, 0x2a]).unwrap(),
        )
        .unwrap_err();
    assert_eq!(
        error,
        Http3PeerUniStreamError::ClientInitiatedPushStream {
            stream_id: Http3StreamId::new(2),
            push_id: Http3PushId::new(42),
        }
    );
    assert_eq!(
        error.error_code(),
        Some(Http3ErrorCode::STREAM_CREATION_ERROR)
    );
    assert_eq!(server, before);

    assert_eq!(
        Http3PeerUniStreamState::new(Http3EndpointRole::Client)
            .receive_closed(Http3StreamId::new(3)),
        Ok(())
    );
    assert_eq!(client.receive_closed(Http3StreamId::new(7)), Ok(()));
    assert_eq!(client.receive_closed(Http3StreamId::new(11)), Ok(()));

    for (kind, stream_id, wire) in [
        (Http3CriticalUniStreamKind::Control, 3, &[0x00][..]),
        (Http3CriticalUniStreamKind::QpackEncoder, 7, &[0x02][..]),
        (Http3CriticalUniStreamKind::QpackDecoder, 11, &[0x03][..]),
    ] {
        let stream_id = Http3StreamId::new(stream_id);
        let mut state = Http3PeerUniStreamState::new(Http3EndpointRole::Client);
        state
            .receive_header(stream_id, Http3UniStreamHeader::parse(wire).unwrap())
            .unwrap();
        let error = state.receive_closed(stream_id).unwrap_err();
        assert_eq!(
            error,
            Http3PeerUniStreamError::ClosedCriticalStream { kind, stream_id }
        );
        assert_eq!(
            error.error_code(),
            Some(Http3ErrorCode::CLOSED_CRITICAL_STREAM)
        );
    }
}

#[test]
fn message_content_public_facades_defaults_and_local_errors_are_exact() {
    let _: http3::Http3MessageContentState =
        Http3MessageContentState::new(Http3MessageContentKind::Request);
    let _: Http3MessageContentKind = http3::Http3MessageContentKind::Request;
    let _: http3::Http3ResponseRequestContext = Http3ResponseRequestContext::Ordinary;
    let _: Http3MessageContentDisposition = http3::Http3MessageContentDisposition::HttpMessage;
    let _: http3::Http3MessageContentOperation = Http3MessageContentOperation::Data;
    let _: Http3MessageContentError = http3::Http3MessageContentError::IncompleteMessage;

    let mut state = Http3MessageContentState::new(Http3MessageContentKind::Request);
    assert_eq!(state.kind(), Http3MessageContentKind::Request);
    assert_eq!(state.declared_length(), None);
    assert_eq!(state.received_length(), 0);
    assert_eq!(
        state.finish(),
        Err(Http3MessageContentError::IncompleteMessage)
    );
    assert_eq!(
        state.finish().unwrap_err().error_code(),
        Some(Http3ErrorCode::MESSAGE_ERROR)
    );

    let before = state;
    assert_eq!(
        state.receive_data(Http3Data::parse(&[0, 0], 0).unwrap()),
        Err(Http3MessageContentError::OperationNotReady {
            operation: Http3MessageContentOperation::Data,
        })
    );
    let error = state
        .receive_data(Http3Data::parse(&[0, 0], 0).unwrap())
        .unwrap_err();
    assert_eq!(error.error_code(), None);
    assert!(error.to_string().contains("Data operation is not ready"));
    assert!(core::error::Error::source(&error).is_none());
    assert_eq!(state, before);

    with_decoded_fields(&[(b"x", b"v", false)], |section| {
        let trailers =
            analyze_decoded_header_section(section, Http3HeaderSectionContext::Trailers).unwrap();
        let error = state.accept_trailers(trailers).unwrap_err();
        assert_eq!(
            error,
            Http3MessageContentError::OperationNotReady {
                operation: Http3MessageContentOperation::Trailers,
            }
        );
        assert_eq!(error.error_code(), None);
        assert_eq!(state, before);
    });

    let peer = Http3MessageContentError::InvalidContentLength {
        field_index: 4,
        member_index: 1,
    };
    assert!(peer.to_string().contains("field 4 member 1 is invalid"));
    assert_eq!(peer.error_code(), Some(Http3ErrorCode::MESSAGE_ERROR));
    assert!(core::error::Error::source(&peer).is_none());
}

#[test]
fn message_content_request_normalizes_and_accounts_real_data_frames() {
    let fields = [
        (b":method" as &[u8], b"POST" as &[u8], false),
        (b":scheme", b"https", false),
        (b":authority", b"x", false),
        (b":path", b"/", false),
        (b"content-length", b"004, 4", false),
        (b"content-length", b"4", false),
    ];
    with_decoded_fields(&fields, |section| {
        let headers = analyze_decoded_header_section(
            section,
            Http3HeaderSectionContext::Request {
                extended_connect_enabled: false,
            },
        )
        .unwrap();
        let mut state = Http3MessageContentState::new(Http3MessageContentKind::Request);
        assert_eq!(
            state.accept_initial_headers(headers),
            Ok(Http3MessageContentDisposition::HttpMessage)
        );
        assert_eq!(state.declared_length(), Some(4));
        assert_eq!(state.received_length(), 0);

        let mut first_destination = [0; 4];
        let first = Http3DataBuilder::new(&mut first_destination, &[0xaa, 0xbb])
            .build()
            .unwrap();
        let first = Http3Data::parse(first.as_bytes(), 2).unwrap();
        state.receive_data(first).unwrap();
        assert_eq!(state.received_length(), 2);

        let mut second_destination = [0; 4];
        let second = Http3DataBuilder::new(&mut second_destination, &[0xcc, 0xdd])
            .build()
            .unwrap();
        let second = Http3Data::parse(second.as_bytes(), 2).unwrap();
        state.receive_data(second).unwrap();
        assert_eq!(state.received_length(), 4);
        state
            .receive_data(Http3Data::parse(&[0, 0], 0).unwrap())
            .unwrap();
        assert_eq!(state.received_length(), 4);
        assert_eq!(state.finish(), Ok(()));
    });
}

#[test]
fn message_content_length_parse_failures_are_exact_and_atomic() {
    for (value, extra, expected) in [
        (
            b"4," as &[u8],
            None,
            Http3MessageContentError::InvalidContentLength {
                field_index: 4,
                member_index: 1,
            },
        ),
        (
            b"4, x",
            None,
            Http3MessageContentError::InvalidContentLength {
                field_index: 4,
                member_index: 1,
            },
        ),
        (
            b"18446744073709551616",
            None,
            Http3MessageContentError::ContentLengthOverflow {
                field_index: 4,
                member_index: 0,
            },
        ),
        (
            b"4, 4",
            Some(b"5" as &[u8]),
            Http3MessageContentError::ConflictingContentLength {
                field_index: 5,
                member_index: 0,
                expected: 4,
                actual: 5,
            },
        ),
    ] {
        let fields = [
            (b":method" as &[u8], b"POST" as &[u8], false),
            (b":scheme", b"https", false),
            (b":authority", b"x", false),
            (b":path", b"/", false),
            (b"content-length", value, false),
        ];
        with_decoded_fields(&fields, |section| {
            let headers = analyze_decoded_header_section(
                section,
                Http3HeaderSectionContext::Request {
                    extended_connect_enabled: false,
                },
            )
            .unwrap();
            let mut state = Http3MessageContentState::new(Http3MessageContentKind::Request);
            let before = state;
            let error = if let Some(extra) = extra {
                with_decoded_fields(
                    &[
                        (b":method" as &[u8], b"POST" as &[u8], false),
                        (b":scheme", b"https", false),
                        (b":authority", b"x", false),
                        (b":path", b"/", false),
                        (b"content-length", value, false),
                        (b"content-length", extra, false),
                    ],
                    |section| {
                        state
                            .accept_initial_headers(
                                analyze_decoded_header_section(
                                    section,
                                    Http3HeaderSectionContext::Request {
                                        extended_connect_enabled: false,
                                    },
                                )
                                .unwrap(),
                            )
                            .unwrap_err()
                    },
                )
            } else {
                state.accept_initial_headers(headers).unwrap_err()
            };
            assert_eq!(error, expected);
            assert_eq!(error.error_code(), Some(Http3ErrorCode::MESSAGE_ERROR));
            assert_eq!(state, before);
        });
    }
}

#[test]
fn message_content_mismatch_and_trailers_preserve_atomicity() {
    with_decoded_fields(
        &[
            (b":method" as &[u8], b"POST" as &[u8], false),
            (b":scheme", b"https", false),
            (b":authority", b"x", false),
            (b":path", b"/", false),
            (b"content-length", b"3", false),
        ],
        |section| {
            let mut state = Http3MessageContentState::new(Http3MessageContentKind::Request);
            state
                .accept_initial_headers(
                    analyze_decoded_header_section(
                        section,
                        Http3HeaderSectionContext::Request {
                            extended_connect_enabled: false,
                        },
                    )
                    .unwrap(),
                )
                .unwrap();
            state
                .receive_data(Http3Data::parse(&[0, 2, 1, 2], 2).unwrap())
                .unwrap();
            let before = state;
            assert_eq!(
                state.receive_data(Http3Data::parse(&[0, 2, 3, 4], 2).unwrap()),
                Err(Http3MessageContentError::ContentLengthMismatch {
                    declared: 3,
                    received: 4
                })
            );
            assert_eq!(state, before);
            assert_eq!(
                state.finish(),
                Err(Http3MessageContentError::ContentLengthMismatch {
                    declared: 3,
                    received: 2
                })
            );
            with_decoded_fields(&[(b"x", b"v", false)], |trailers| {
                let error = state
                    .accept_trailers(
                        analyze_decoded_header_section(
                            trailers,
                            Http3HeaderSectionContext::Trailers,
                        )
                        .unwrap(),
                    )
                    .unwrap_err();
                assert_eq!(
                    error,
                    Http3MessageContentError::ContentLengthMismatch {
                        declared: 3,
                        received: 2
                    }
                );
                assert_eq!(error.error_code(), Some(Http3ErrorCode::MESSAGE_ERROR));
                assert_eq!(state, before);
            });
        },
    );

    with_decoded_fields(
        &[
            (b":method" as &[u8], b"POST" as &[u8], false),
            (b":scheme", b"https", false),
            (b":authority", b"x", false),
            (b":path", b"/", false),
            (b"content-length", b"2", false),
        ],
        |section| {
            let mut state = Http3MessageContentState::new(Http3MessageContentKind::Request);
            state
                .accept_initial_headers(
                    analyze_decoded_header_section(
                        section,
                        Http3HeaderSectionContext::Request {
                            extended_connect_enabled: false,
                        },
                    )
                    .unwrap(),
                )
                .unwrap();
            state
                .receive_data(Http3Data::parse(&[0, 2, 1, 2], 2).unwrap())
                .unwrap();
            with_decoded_fields(&[(b"content-length", b"2", false)], |trailers| {
                let before = state;
                let error = state
                    .accept_trailers(
                        analyze_decoded_header_section(
                            trailers,
                            Http3HeaderSectionContext::Trailers,
                        )
                        .unwrap(),
                    )
                    .unwrap_err();
                assert_eq!(
                    error,
                    Http3MessageContentError::ContentLengthInTrailers { field_index: 0 }
                );
                assert_eq!(state, before);
            });
            with_decoded_fields(&[(b"x", b"v", false)], |trailers| {
                state
                    .accept_trailers(
                        analyze_decoded_header_section(
                            trailers,
                            Http3HeaderSectionContext::Trailers,
                        )
                        .unwrap(),
                    )
                    .unwrap();
            });
            assert_eq!(state.finish(), Ok(()));
        },
    );
}

#[test]
fn message_content_response_status_matrix_keeps_no_content_rules_separate() {
    let mut ordinary = Http3MessageContentState::new(Http3MessageContentKind::Response(
        Http3ResponseRequestContext::Ordinary,
    ));
    let before_information = ordinary;
    for _ in 0..2 {
        with_decoded_fields(&[(b":status", b"100", false)], |section| {
            assert_eq!(
                ordinary.accept_initial_headers(
                    analyze_decoded_header_section(section, Http3HeaderSectionContext::Response)
                        .unwrap()
                ),
                Ok(Http3MessageContentDisposition::AwaitingFinalResponse)
            );
            assert_eq!(ordinary, before_information);
        });
    }
    with_decoded_fields(
        &[
            (b":status", b"103", false),
            (b"content-length", b"1", false),
        ],
        |section| {
            let before = ordinary;
            let error = ordinary
                .accept_initial_headers(
                    analyze_decoded_header_section(section, Http3HeaderSectionContext::Response)
                        .unwrap(),
                )
                .unwrap_err();
            assert_eq!(
                error,
                Http3MessageContentError::ProhibitedContentLength { field_index: 1 }
            );
            assert_eq!(error.error_code(), Some(Http3ErrorCode::MESSAGE_ERROR));
            assert_eq!(ordinary, before);
        },
    );
    with_decoded_fields(
        &[
            (b":status", b"200", false),
            (b"content-length", b"2", false),
        ],
        |section| {
            assert_eq!(
                ordinary.accept_initial_headers(
                    analyze_decoded_header_section(section, Http3HeaderSectionContext::Response)
                        .unwrap()
                ),
                Ok(Http3MessageContentDisposition::HttpMessage)
            );
        },
    );
    assert_eq!(ordinary.declared_length(), Some(2));

    for (kind, status) in [
        (
            Http3MessageContentKind::Response(Http3ResponseRequestContext::Head),
            b"200" as &[u8],
        ),
        (
            Http3MessageContentKind::Response(Http3ResponseRequestContext::Head),
            b"304",
        ),
        (
            Http3MessageContentKind::Response(Http3ResponseRequestContext::Ordinary),
            b"304",
        ),
        (
            Http3MessageContentKind::Response(Http3ResponseRequestContext::Ordinary),
            b"205",
        ),
    ] {
        with_decoded_fields(
            &[
                (b":status", status, false),
                (b"content-length", b"7", false),
            ],
            |section| {
                let mut state = Http3MessageContentState::new(kind);
                state
                    .accept_initial_headers(
                        analyze_decoded_header_section(
                            section,
                            Http3HeaderSectionContext::Response,
                        )
                        .unwrap(),
                    )
                    .unwrap();
                assert_eq!(state.declared_length(), Some(7));
                let before = state;
                state
                    .receive_data(Http3Data::parse(&[0, 0], 0).unwrap())
                    .unwrap();
                assert_eq!(state, before);
                let error = state
                    .receive_data(Http3Data::parse(&[0, 1, 1], 1).unwrap())
                    .unwrap_err();
                assert_eq!(
                    error,
                    Http3MessageContentError::ContentNotAllowed { data_length: 1 }
                );
                assert_eq!(error.error_code(), Some(Http3ErrorCode::MESSAGE_ERROR));
                assert_eq!(state, before);
                with_decoded_fields(&[(b"x", b"v", false)], |trailers| {
                    state
                        .accept_trailers(
                            analyze_decoded_header_section(
                                trailers,
                                Http3HeaderSectionContext::Trailers,
                            )
                            .unwrap(),
                        )
                        .unwrap();
                });
                assert_eq!(state.finish(), Ok(()));
            },
        );
    }

    for kind in [
        Http3MessageContentKind::Response(Http3ResponseRequestContext::Ordinary),
        Http3MessageContentKind::Response(Http3ResponseRequestContext::Head),
        Http3MessageContentKind::Push,
    ] {
        with_decoded_fields(
            &[
                (b":status", b"204", false),
                (b"content-length", b"0", false),
            ],
            |section| {
                let mut state = Http3MessageContentState::new(kind);
                let before = state;
                assert_eq!(
                    state.accept_initial_headers(
                        analyze_decoded_header_section(
                            section,
                            Http3HeaderSectionContext::Response
                        )
                        .unwrap()
                    ),
                    Err(Http3MessageContentError::ProhibitedContentLength { field_index: 1 })
                );
                assert_eq!(state, before);
            },
        );
        with_decoded_fields(&[(b":status", b"204", false)], |section| {
            let mut state = Http3MessageContentState::new(kind);
            state
                .accept_initial_headers(
                    analyze_decoded_header_section(section, Http3HeaderSectionContext::Response)
                        .unwrap(),
                )
                .unwrap();
            let before = state;
            state
                .receive_data(Http3Data::parse(&[0, 0], 0).unwrap())
                .unwrap();
            assert_eq!(state, before);
            assert_eq!(
                state.receive_data(Http3Data::parse(&[0, 1, 1], 1).unwrap()),
                Err(Http3MessageContentError::ContentNotAllowed { data_length: 1 })
            );
            assert_eq!(state, before);
            with_decoded_fields(&[(b"x", b"v", false)], |trailers| {
                assert_eq!(
                    state.accept_trailers(
                        analyze_decoded_header_section(
                            trailers,
                            Http3HeaderSectionContext::Trailers
                        )
                        .unwrap()
                    ),
                    Err(Http3MessageContentError::OperationNotReady {
                        operation: Http3MessageContentOperation::Trailers
                    })
                );
            });
            assert_eq!(state, before);
        });
    }
}

#[test]
fn message_content_connect_tunnels_do_not_account_http_bytes() {
    for (fields, enabled) in [
        (
            &[
                (b":method" as &[u8], b"CONNECT" as &[u8], false),
                (b":authority", b"x:443", false),
                (b"content-length", b"9", false),
            ][..],
            false,
        ),
        (
            &[
                (b":method" as &[u8], b"CONNECT" as &[u8], false),
                (b":protocol", b"websocket", false),
                (b":scheme", b"https", false),
                (b":authority", b"x", false),
                (b":path", b"/", false),
                (b"content-length", b"9", false),
            ][..],
            true,
        ),
    ] {
        with_decoded_fields(fields, |section| {
            let mut state = Http3MessageContentState::new(Http3MessageContentKind::Request);
            assert_eq!(
                state.accept_initial_headers(
                    analyze_decoded_header_section(
                        section,
                        Http3HeaderSectionContext::Request {
                            extended_connect_enabled: enabled
                        }
                    )
                    .unwrap()
                ),
                Ok(Http3MessageContentDisposition::ConnectTunnel)
            );
            assert_eq!(state.declared_length(), Some(9));
            let before = state;
            let error = state
                .receive_data(Http3Data::parse(&[0, 1, 1], 1).unwrap())
                .unwrap_err();
            assert_eq!(error, Http3MessageContentError::NotHttpMessageContent);
            assert_eq!(error.error_code(), None);
            assert_eq!(state, before);
            with_decoded_fields(&[(b"x", b"v", false)], |trailers| {
                assert_eq!(
                    state.accept_trailers(
                        analyze_decoded_header_section(
                            trailers,
                            Http3HeaderSectionContext::Trailers
                        )
                        .unwrap()
                    ),
                    Err(Http3MessageContentError::NotHttpMessageContent)
                );
                assert_eq!(state, before);
            });
            assert_eq!(state.finish(), Ok(()));
        });
    }

    with_decoded_fields(
        &[
            (b":status", b"205", false),
            (b"content-length", b"1", false),
        ],
        |section| {
            let mut state = Http3MessageContentState::new(Http3MessageContentKind::Response(
                Http3ResponseRequestContext::Connect,
            ));
            assert_eq!(
                state.accept_initial_headers(
                    analyze_decoded_header_section(section, Http3HeaderSectionContext::Response)
                        .unwrap()
                ),
                Err(Http3MessageContentError::ProhibitedContentLength { field_index: 1 })
            );
        },
    );
    with_decoded_fields(&[(b":status", b"205", false)], |section| {
        let mut state = Http3MessageContentState::new(Http3MessageContentKind::Response(
            Http3ResponseRequestContext::Connect,
        ));
        assert_eq!(
            state.accept_initial_headers(
                analyze_decoded_header_section(section, Http3HeaderSectionContext::Response)
                    .unwrap()
            ),
            Ok(Http3MessageContentDisposition::ConnectTunnel)
        );
        let before = state;
        assert_eq!(
            state.receive_data(Http3Data::parse(&[0, 1, 1], 1).unwrap()),
            Err(Http3MessageContentError::NotHttpMessageContent)
        );
        assert_eq!(state, before);
    });
    with_decoded_fields(
        &[
            (b":status", b"404", false),
            (b"content-length", b"2", false),
        ],
        |section| {
            let mut state = Http3MessageContentState::new(Http3MessageContentKind::Response(
                Http3ResponseRequestContext::Connect,
            ));
            assert_eq!(
                state.accept_initial_headers(
                    analyze_decoded_header_section(section, Http3HeaderSectionContext::Response)
                        .unwrap()
                ),
                Ok(Http3MessageContentDisposition::HttpMessage)
            );
            state
                .receive_data(Http3Data::parse(&[0, 2, 1, 2], 2).unwrap())
                .unwrap();
            assert_eq!(state.finish(), Ok(()));
        },
    );
}
