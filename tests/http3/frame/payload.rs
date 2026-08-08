use net_wire::http3::{
    Http3CancelPush, Http3CancelPushBuilder, Http3Data, Http3DataBuilder, Http3Frame,
    Http3FrameBuildError, Http3FrameParseError, Http3FramePayloadBuildError,
    Http3FramePayloadField, Http3FramePayloadParseError, Http3FrameType, Http3Goaway,
    Http3GoawayBuilder, Http3Headers, Http3HeadersBuilder, Http3MaxPushId, Http3MaxPushIdBuilder,
    Http3PushId, Http3PushPromise, Http3PushPromiseBuilder, Http3SettingId, Http3SettingValue,
    Http3SettingsBuilder,
};
use net_wire::quic::{QuicVarIntBuildError, QuicVarIntParseError};

#[test]
fn typed_data_and_headers_preserve_opaque_payloads_and_frame_bounds() {
    let data: Http3Data<'_> = Http3Data::parse(&[0x00, 0x03, 0xde, 0xad, 0xbe, 0xfa], 3).unwrap();
    assert_eq!(data.data(), &[0xde, 0xad, 0xbe]);
    assert_eq!(data.as_bytes(), &[0x00, 0x03, 0xde, 0xad, 0xbe]);

    let empty_data: Http3Data<'_> = Http3Data::parse(&[0x00, 0x00], 0).unwrap();
    assert_eq!(empty_data.data(), &[]);

    let headers: Http3Headers<'_> = Http3Headers::parse(&[0x01, 0x02, 0xff, 0x00], 2).unwrap();
    assert_eq!(headers.encoded_field_section(), &[0xff, 0x00]);
    assert_eq!(headers.as_bytes(), &[0x01, 0x02, 0xff, 0x00]);

    let empty_headers: Http3Headers<'_> = Http3Headers::parse(&[0x01, 0x00], 0).unwrap();
    assert_eq!(empty_headers.encoded_field_section(), &[]);
}

#[test]
fn typed_exact_push_id_views_preserve_noncanonical_varints_and_reject_bad_layouts() {
    let cancel: Http3CancelPush<'_> = Http3CancelPush::parse(&[0x03, 0x02, 0x40, 0x2a], 2).unwrap();
    assert_eq!(cancel.push_id(), Http3PushId::new(42));
    assert_eq!(cancel.push_id_varint().as_bytes(), &[0x40, 0x2a]);

    let maximum: Http3MaxPushId<'_> = Http3MaxPushId::parse(&[0x0d, 0x02, 0x40, 0x2a], 2).unwrap();
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
    let goaway: Http3Goaway<'_> = Http3Goaway::parse(&[0x07, 0x02, 0x40, 0x2a], 2).unwrap();
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

    let promise: Http3PushPromise<'_> =
        Http3PushPromise::parse(&[0x05, 0x04, 0x40, 0x2a, 0xaa, 0xbb], 4).unwrap();
    assert_eq!(promise.push_id(), Http3PushId::new(42));
    assert_eq!(promise.push_id_varint().as_bytes(), &[0x40, 0x2a]);
    assert_eq!(promise.encoded_field_section(), &[0xaa, 0xbb]);

    let empty_promise: Http3PushPromise<'_> =
        Http3PushPromise::parse(&[0x05, 0x02, 0x40, 0x2a], 2).unwrap();
    assert_eq!(empty_promise.encoded_field_section(), &[]);
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
fn typed_standard_builders_public_namespace_is_available() {
    {
        let mut destination = [0; 8];
        let _: net_wire::http3::Http3DataBuilder<'_, '_> =
            Http3DataBuilder::new(&mut destination, &[]);
    }
    {
        let mut destination = [0; 8];
        let _: net_wire::http3::Http3HeadersBuilder<'_, '_> =
            Http3HeadersBuilder::new(&mut destination, &[]);
    }
    {
        let mut destination = [0; 8];
        let _: net_wire::http3::Http3CancelPushBuilder<'_> =
            Http3CancelPushBuilder::new(&mut destination, Http3PushId::new(0));
    }
    {
        let mut destination = [0; 8];
        let _: net_wire::http3::Http3PushPromiseBuilder<'_, '_> =
            Http3PushPromiseBuilder::new(&mut destination, Http3PushId::new(0), &[]);
    }
    {
        let mut destination = [0; 8];
        let _: net_wire::http3::Http3GoawayBuilder<'_> =
            Http3GoawayBuilder::new(&mut destination, 0);
    }
    {
        let mut destination = [0; 8];
        let _: net_wire::http3::Http3MaxPushIdBuilder<'_> =
            Http3MaxPushIdBuilder::new(&mut destination, Http3PushId::new(0));
    }
    let settings = [Http3SettingValue::new(Http3SettingId::new(1), 0)];
    let mut destination = [0; 8];
    let mut scratch = [0; 2];
    let _: net_wire::http3::Http3SettingsBuilder<'_, '_, '_> =
        Http3SettingsBuilder::new(&mut destination, &mut scratch, &settings);
    let _: net_wire::http3::Http3SettingValue = Http3SettingValue::new(Http3SettingId::new(1), 64);
    let _: net_wire::http3::Http3FramePayloadBuildError =
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
