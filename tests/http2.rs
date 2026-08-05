use net_wire::*;

#[test]
fn client_preface_is_exact_and_bounded() {
    let wire = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nnext";
    let preface = Http2ClientPreface::parse(wire).unwrap();
    assert_eq!(preface.as_bytes(), HTTP2_CLIENT_PREFACE);
    assert_eq!(preface.as_bytes(), &wire[..24]);

    assert_eq!(
        Http2ClientPreface::parse(&HTTP2_CLIENT_PREFACE[..23]),
        Err(Http2ParseError::Incomplete {
            required: 24,
            available: 23,
        })
    );
    assert_eq!(
        Http2ClientPreface::parse(b"PRI * HTTP/2.0\r\n\r\nSN\r\n\r\n"),
        Err(Http2ParseError::ClientPrefaceMismatch {
            offset: 19,
            expected: b'M',
            actual: b'N',
        })
    );
}

#[test]
fn raw_frame_distinguishes_incomplete_header_and_payload() {
    assert_eq!(
        Http2Frame::parse(&[0, 0, 0, 0, 0, 0, 0, 0], 10),
        Err(Http2ParseError::Incomplete {
            required: 9,
            available: 8,
        })
    );
    assert_eq!(
        Http2Frame::parse(&[0, 0, 3, 0, 0, 0, 0, 0, 0, 1, 2], 3),
        Err(Http2ParseError::Incomplete {
            required: 12,
            available: 11,
        })
    );
}

#[test]
fn raw_frame_preserves_unknown_values_reserved_bit_and_suffix() {
    let wire = [
        0, 0, 2, 0xfe, 0xa5, 0x80, 0x00, 0x00, 0x07, 0xde, 0xad, 0xfa,
    ];
    let frame = Http2Frame::parse(&wire, 2).unwrap();
    assert_eq!(frame.as_bytes(), &wire[..11]);
    assert_eq!(frame.payload_length(), 2);
    assert_eq!(frame.frame_type(), Http2FrameType::new(0xfe));
    assert_eq!(frame.flags(), 0xa5);
    assert_eq!(frame.stream_id().raw(), 0x8000_0007);
    assert_eq!(frame.stream_id().value(), 7);
    assert!(frame.stream_id().has_reserved_bit());
    assert_eq!(frame.payload(), [0xde, 0xad]);
}

#[test]
fn raw_frame_uses_the_callers_payload_maximum() {
    let wire = [0, 0, 2, 0, 0, 0, 0, 0, 0, 1, 2];
    assert_eq!(
        Http2Frame::parse(&wire, 1),
        Err(Http2ParseError::PayloadTooLarge {
            maximum: 1,
            actual: 2,
        })
    );
    assert!(Http2Frame::parse(&wire, 2).is_ok());
}

#[test]
fn mutable_frame_has_the_same_bound_and_mutable_payload() {
    let mut wire = [
        0, 0, 2, 0xfe, 0xa5, 0x80, 0x00, 0x00, 0x07, 0xde, 0xad, 0xfa,
    ];
    assert_eq!(
        Http2FrameMut::parse(&mut wire, 1),
        Err(Http2ParseError::PayloadTooLarge {
            maximum: 1,
            actual: 2,
        })
    );
    let mut frame = Http2FrameMut::parse(&mut wire, 2).unwrap();
    assert_eq!(
        frame.as_bytes(),
        &[0, 0, 2, 0xfe, 0xa5, 0x80, 0x00, 0x00, 0x07, 0xde, 0xad]
    );
    frame.payload_mut()[1] = 0xbe;
    assert_eq!(frame.payload(), [0xde, 0xbe]);
    assert_eq!(
        frame.as_bytes(),
        &[0, 0, 2, 0xfe, 0xa5, 0x80, 0x00, 0x00, 0x07, 0xde, 0xbe]
    );
}

#[test]
fn raw_builder_writes_exact_bytes_and_preserves_suffix() {
    let mut destination = [0xaa; 16];
    let frame = Http2FrameBuilder::new(
        &mut destination,
        Http2FrameType::new(0xfe),
        0xa5,
        Http2StreamId::from_value(7).unwrap(),
        &[0xde, 0xad],
    )
    .build()
    .unwrap();
    assert_eq!(
        frame.as_bytes(),
        &[0, 0, 2, 0xfe, 0xa5, 0, 0, 0, 7, 0xde, 0xad]
    );
    assert!(destination[11..].iter().all(|byte| *byte == 0xaa));
}

#[test]
fn typed_standard_builders_write_exact_payloads_and_preserve_suffixes() {
    let mut unpadded_destination = [0xaa; 16];
    let unpadded = Http2DataBuilder::new(
        &mut unpadded_destination,
        Http2StreamId::from_value(1).unwrap(),
        0x81,
        &[0xde, 0xad],
        None,
    )
    .build()
    .unwrap();
    assert_eq!(
        unpadded.as_bytes(),
        &[0, 0, 2, 0, 0x81, 0, 0, 0, 1, 0xde, 0xad]
    );
    assert_eq!(unpadded.data(), [0xde, 0xad]);
    assert_eq!(unpadded.pad_length(), None);
    assert!(unpadded_destination[11..].iter().all(|byte| *byte == 0xaa));

    let mut padded_zero_destination = [0xaa; 16];
    let padded_zero = Http2DataBuilder::new(
        &mut padded_zero_destination,
        Http2StreamId::from_value(3).unwrap(),
        0,
        &[],
        Some(0),
    )
    .build()
    .unwrap();
    assert_eq!(padded_zero.as_bytes(), &[0, 0, 1, 0, 0x08, 0, 0, 0, 3, 0]);
    assert_eq!(padded_zero.data(), []);
    assert_eq!(padded_zero.pad_length(), Some(0));
    assert!(
        padded_zero_destination[10..]
            .iter()
            .all(|byte| *byte == 0xaa)
    );

    let mut padded_destination = [0xaa; 20];
    let padded = Http2DataBuilder::new(
        &mut padded_destination,
        Http2StreamId::from_value(5).unwrap(),
        0x81,
        &[0xbe],
        Some(2),
    )
    .build()
    .unwrap();
    assert_eq!(
        padded.as_bytes(),
        &[0, 0, 4, 0, 0x89, 0, 0, 0, 5, 2, 0xbe, 0, 0]
    );
    assert_eq!(padded.data(), [0xbe]);
    assert_eq!(padded.padding(), [0, 0]);
    assert!(padded_destination[13..].iter().all(|byte| *byte == 0xaa));
}

#[test]
fn typed_continuation_builder_writes_exact_payload_and_preserves_suffix() {
    let mut destination = [0xaa; 16];
    let continuation = Http2ContinuationBuilder::new(
        &mut destination,
        Http2StreamId::from_value(7).unwrap(),
        0x84,
        &[0xde, 0xad],
    )
    .build()
    .unwrap();
    assert_eq!(
        continuation.as_bytes(),
        &[0, 0, 2, 9, 0x84, 0, 0, 0, 7, 0xde, 0xad]
    );
    assert_eq!(continuation.field_block_fragment(), [0xde, 0xad]);
    assert!(destination[11..].iter().all(|byte| *byte == 0xaa));
}

#[test]
fn typed_standard_builders_fail_atomically() {
    let mut zero = [0xaa; 16];
    let before = zero;
    assert_eq!(
        Http2DataBuilder::new(
            &mut zero,
            Http2StreamId::from_value(0).unwrap(),
            0,
            &[],
            None
        )
        .build(),
        Err(Http2BuildError::ZeroStreamId)
    );
    assert_eq!(zero, before);

    let mut reserved = [0xaa; 16];
    let before = reserved;
    assert_eq!(
        Http2ContinuationBuilder::new(&mut reserved, Http2StreamId::new(0x8000_0001), 0, &[])
            .build(),
        Err(Http2BuildError::ReservedStreamId)
    );
    assert_eq!(reserved, before);

    let mut padded_flag = [0xaa; 16];
    let before = padded_flag;
    assert_eq!(
        Http2DataBuilder::new(
            &mut padded_flag,
            Http2StreamId::from_value(1).unwrap(),
            0x08,
            &[],
            None,
        )
        .build(),
        Err(Http2BuildError::DataPaddedFlagSet)
    );
    assert_eq!(padded_flag, before);

    let mut maximum = [0xaa; 16];
    let before = maximum;
    assert_eq!(
        Http2DataBuilder::new(
            &mut maximum,
            Http2StreamId::from_value(1).unwrap(),
            0,
            &[1, 2],
            Some(1),
        )
        .build_with_maximum(3),
        Err(Http2BuildError::PayloadTooLarge {
            maximum: 3,
            actual: 4,
        })
    );
    assert_eq!(maximum, before);

    let mut short = [0xaa; 11];
    let before = short;
    assert_eq!(
        Http2ContinuationBuilder::new(
            &mut short,
            Http2StreamId::from_value(1).unwrap(),
            0,
            &[1, 2, 3],
        )
        .build(),
        Err(Http2BuildError::BufferTooShort {
            required: 12,
            available: 11,
        })
    );
    assert_eq!(short, before);
}

#[test]
fn typed_standard_builders_enforce_the_24_bit_payload_limit() {
    let payload = vec![0; 0x0100_0000];
    let mut destination = [0xaa; 9];
    let before = destination;
    assert_eq!(
        Http2ContinuationBuilder::new(
            &mut destination,
            Http2StreamId::from_value(1).unwrap(),
            0,
            &payload,
        )
        .build(),
        Err(Http2BuildError::PayloadTooLarge {
            maximum: 0x00ff_ffff,
            actual: 0x0100_0000,
        })
    );
    assert_eq!(destination, before);
}

#[test]
fn typed_data_exposes_unpadded_and_empty_padded_payloads() {
    let unpadded = [0, 0, 2, 0, 0x80, 0, 0, 0, 1, 0xde, 0xad];
    let data = Http2Data::parse(&unpadded, 2).unwrap();
    assert_eq!(data.frame().as_bytes(), unpadded);
    assert_eq!(data.as_bytes(), unpadded);
    assert_eq!(data.data(), [0xde, 0xad]);
    assert_eq!(data.padding(), []);
    assert_eq!(data.pad_length(), None);

    let padded_empty = [0, 0, 1, 0, 0x08, 0, 0, 0, 1, 0];
    let data = Http2Data::parse(&padded_empty, 1).unwrap();
    assert_eq!(data.data(), []);
    assert_eq!(data.padding(), []);
    assert_eq!(data.pad_length(), Some(0));
}

#[test]
fn typed_data_rejects_invalid_padding() {
    let wire = [0, 0, 1, 0, 0x08, 0, 0, 0, 1, 1];
    assert_eq!(
        Http2Data::parse(&wire, 1),
        Err(Http2ParseError::InvalidPadding {
            padding_length: 1,
            payload_length: 1,
        })
    );
}

#[test]
fn typed_headers_exposes_exact_optional_sections() {
    let unpadded = [0, 0, 2, 1, 0x80, 0, 0, 0, 1, 0xaa, 0xbb];
    let headers = Http2Headers::parse(&unpadded, 2).unwrap();
    assert_eq!(headers.frame().as_bytes(), unpadded);
    assert_eq!(headers.as_bytes(), unpadded);
    assert_eq!(headers.field_block_fragment(), [0xaa, 0xbb]);
    assert_eq!(headers.padding(), []);
    assert_eq!(headers.pad_length(), None);
    assert_eq!(headers.priority(), None);

    let padded_priority = [
        0, 0, 10, 1, 0x68, 0, 0, 0, 1, 2, 0x80, 0, 0, 3, 0x7f, 0xaa, 0xbb, 0xcc, 0xdd,
    ];
    let headers = Http2Headers::parse(&padded_priority, 10).unwrap();
    let priority = headers.priority().unwrap();
    assert!(priority.is_exclusive());
    assert_eq!(priority.raw_dependency(), 0x8000_0003);
    assert_eq!(priority.dependency(), 3);
    assert_eq!(priority.weight(), 0x7f);
    assert_eq!(headers.field_block_fragment(), [0xaa, 0xbb]);
    assert_eq!(headers.padding(), [0xcc, 0xdd]);
    assert_eq!(headers.pad_length(), Some(2));
}

#[test]
fn typed_headers_rejects_truncated_optional_sections() {
    let priority = [0, 0, 4, 1, 0x20, 0, 0, 0, 1, 0, 0, 0, 3];
    assert_eq!(
        Http2Headers::parse(&priority, 4),
        Err(Http2ParseError::MalformedPayload {
            required: 5,
            available: 4,
        })
    );

    let padded_priority = [0, 0, 1, 1, 0x28, 0, 0, 0, 1, 0];
    assert_eq!(
        Http2Headers::parse(&padded_priority, 1),
        Err(Http2ParseError::MalformedPayload {
            required: 5,
            available: 0,
        })
    );
}

#[test]
fn typed_push_promise_preserves_promised_reserved_bit_and_padding() {
    let wire = [
        0, 0, 8, 5, 0x08, 0, 0, 0, 1, 1, 0x80, 0, 0, 2, 0xaa, 0xbb, 0xcc,
    ];
    let promise = Http2PushPromise::parse(&wire, 8).unwrap();
    assert_eq!(promise.frame().as_bytes(), wire);
    assert_eq!(promise.as_bytes(), wire);
    assert_eq!(promise.promised_stream_id().raw(), 0x8000_0002);
    assert!(promise.promised_stream_id().has_reserved_bit());
    assert_eq!(promise.field_block_fragment(), [0xaa, 0xbb]);
    assert_eq!(promise.padding(), [0xcc]);
    assert_eq!(promise.pad_length(), Some(1));
}

#[test]
fn typed_push_promise_rejects_truncated_promised_stream_id() {
    let wire = [0, 0, 4, 5, 0x08, 0, 0, 0, 1, 0, 0, 0, 1];
    assert_eq!(
        Http2PushPromise::parse(&wire, 4),
        Err(Http2ParseError::MalformedPayload {
            required: 4,
            available: 3,
        })
    );
}

#[test]
fn typed_push_promise_rejects_zero_promised_stream_id() {
    let zero = [0, 0, 4, 5, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    assert_eq!(
        Http2PushPromise::parse(&zero, 4),
        Err(Http2ParseError::ZeroPromisedStreamId)
    );

    let reserved_zero = [0, 0, 4, 5, 0, 0, 0, 0, 1, 0x80, 0, 0, 0];
    assert_eq!(
        Http2PushPromise::parse(&reserved_zero, 4),
        Err(Http2ParseError::ZeroPromisedStreamId)
    );
}

#[test]
fn typed_continuation_exposes_its_complete_payload() {
    let wire = [0, 0, 3, 9, 0x84, 0, 0, 0, 1, 0xaa, 0xbb, 0xcc];
    let continuation = Http2Continuation::parse(&wire, 3).unwrap();
    assert_eq!(continuation.frame().as_bytes(), wire);
    assert_eq!(continuation.as_bytes(), wire);
    assert_eq!(continuation.field_block_fragment(), [0xaa, 0xbb, 0xcc]);
}

#[test]
fn typed_views_distinguish_wrong_type_and_zero_stream_id() {
    let wrong_type = [0, 0, 0, 9, 0, 0, 0, 0, 1];
    assert_eq!(
        Http2Data::parse(&wrong_type, 0),
        Err(Http2ParseError::WrongFrameType {
            expected: Http2FrameType::DATA,
            actual: Http2FrameType::CONTINUATION,
        })
    );

    let zero_data = [0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(
        Http2Data::parse(&zero_data, 0),
        Err(Http2ParseError::ZeroStreamId)
    );
    let zero_headers = [0, 0, 0, 1, 0, 0, 0, 0, 0];
    assert_eq!(
        Http2Headers::parse(&zero_headers, 0),
        Err(Http2ParseError::ZeroStreamId)
    );
    let zero_promise = [0, 0, 0, 5, 0, 0, 0, 0, 0];
    assert_eq!(
        Http2PushPromise::parse(&zero_promise, 0),
        Err(Http2ParseError::ZeroStreamId)
    );
    let zero_continuation = [0, 0, 0, 9, 0, 0, 0, 0, 0];
    assert_eq!(
        Http2Continuation::parse(&zero_continuation, 0),
        Err(Http2ParseError::ZeroStreamId)
    );
}

#[test]
fn raw_builder_failures_leave_the_whole_destination_unchanged() {
    let mut reserved = [0xaa; 16];
    let before = reserved;
    assert_eq!(
        Http2FrameBuilder::new(
            &mut reserved,
            Http2FrameType::DATA,
            0,
            Http2StreamId::new(0x8000_0001),
            &[],
        )
        .build(),
        Err(Http2BuildError::ReservedStreamId)
    );
    assert_eq!(reserved, before);

    let mut oversized = [0xaa; 16];
    let before = oversized;
    assert_eq!(
        Http2FrameBuilder::new(
            &mut oversized,
            Http2FrameType::DATA,
            0,
            Http2StreamId::from_value(1).unwrap(),
            &[1, 2],
        )
        .build_with_maximum(1),
        Err(Http2BuildError::PayloadTooLarge {
            maximum: 1,
            actual: 2,
        })
    );
    assert_eq!(oversized, before);

    let mut short = [0xaa; 10];
    let before = short;
    assert_eq!(
        Http2FrameBuilder::new(
            &mut short,
            Http2FrameType::DATA,
            0,
            Http2StreamId::from_value(1).unwrap(),
            &[1, 2],
        )
        .build(),
        Err(Http2BuildError::BufferTooShort {
            required: 11,
            available: 10,
        })
    );
    assert_eq!(short, before);
}

#[test]
fn typed_fixed_layout_control_frames_expose_exact_payloads_and_unknown_flags() {
    let priority_wire = [0, 0, 5, 2, 0xa0, 0x80, 0, 0, 3, 0x80, 0, 0, 7, 0x1f];
    let priority = Http2PriorityFrame::parse(&priority_wire, 5).unwrap();
    assert_eq!(priority.frame().as_bytes(), priority_wire);
    assert_eq!(priority.as_bytes(), priority_wire);
    assert_eq!(priority.frame().flags(), 0xa0);
    assert_eq!(priority.priority().raw_dependency(), 0x8000_0007);
    assert_eq!(priority.priority().dependency(), 7);
    assert!(priority.priority().is_exclusive());
    assert_eq!(priority.priority().weight(), 0x1f);

    let rst_wire = [0, 0, 4, 3, 0x80, 0, 0, 0, 9, 0xde, 0xad, 0xbe, 0xef];
    let rst = Http2RstStream::parse(&rst_wire, 4).unwrap();
    assert_eq!(rst.frame().as_bytes(), rst_wire);
    assert_eq!(rst.as_bytes(), rst_wire);
    assert_eq!(rst.frame().flags(), 0x80);
    assert_eq!(rst.error_code().raw(), 0xdead_beef);

    let ping_wire = [0, 0, 8, 6, 0x81, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7];
    let ping = Http2Ping::from_frame(Http2Frame::parse(&ping_wire, 8).unwrap()).unwrap();
    assert_eq!(ping.frame().as_bytes(), ping_wire);
    assert_eq!(ping.as_bytes(), ping_wire);
    assert_eq!(ping.frame().flags(), 0x81);
    assert!(ping.is_ack());
    assert_eq!(ping.opaque_data(), &[0, 1, 2, 3, 4, 5, 6, 7]);

    let window_wire = [0, 0, 4, 8, 0x80, 0x80, 0, 0, 3, 0x80, 0, 0, 5];
    let window = Http2WindowUpdate::parse(&window_wire, 4).unwrap();
    assert_eq!(window.frame().as_bytes(), window_wire);
    assert_eq!(window.as_bytes(), window_wire);
    assert_eq!(window.frame().flags(), 0x80);
    assert_eq!(window.increment().raw(), 0x8000_0005);
    assert_eq!(window.increment().value(), 5);
    assert!(window.increment().has_reserved_bit());
}

#[test]
fn typed_fixed_layout_control_frames_reject_wrong_sizes() {
    let priority_short = [0, 0, 4, 2, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    let priority_long = [0, 0, 6, 2, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    let rst_short = [0, 0, 3, 3, 0, 0, 0, 0, 1, 0, 0, 0];
    let rst_long = [0, 0, 5, 3, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0];
    assert_eq!(
        Http2PriorityFrame::parse(&priority_short, 4),
        Err(Http2ParseError::FrameSizeMismatch {
            expected: 5,
            actual: 4
        })
    );
    assert_eq!(
        Http2PriorityFrame::parse(&priority_long, 6),
        Err(Http2ParseError::FrameSizeMismatch {
            expected: 5,
            actual: 6
        })
    );
    assert_eq!(
        Http2RstStream::parse(&rst_short, 3),
        Err(Http2ParseError::FrameSizeMismatch {
            expected: 4,
            actual: 3
        })
    );
    assert_eq!(
        Http2RstStream::parse(&rst_long, 5),
        Err(Http2ParseError::FrameSizeMismatch {
            expected: 4,
            actual: 5
        })
    );

    let ping_short = [0, 0, 7, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let ping_long = [0, 0, 9, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(
        Http2Ping::parse(&ping_short, 7),
        Err(Http2ParseError::FrameSizeMismatch {
            expected: 8,
            actual: 7
        })
    );
    assert_eq!(
        Http2Ping::parse(&ping_long, 9),
        Err(Http2ParseError::FrameSizeMismatch {
            expected: 8,
            actual: 9
        })
    );

    let window_short = [0, 0, 3, 8, 0, 0, 0, 0, 0, 0, 0, 1];
    let window_long = [0, 0, 5, 8, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0];
    assert_eq!(
        Http2WindowUpdate::parse(&window_short, 3),
        Err(Http2ParseError::FrameSizeMismatch {
            expected: 4,
            actual: 3
        })
    );
    assert_eq!(
        Http2WindowUpdate::parse(&window_long, 5),
        Err(Http2ParseError::FrameSizeMismatch {
            expected: 4,
            actual: 5
        })
    );
}

#[test]
fn typed_fixed_layout_control_frames_enforce_stream_and_increment_rules() {
    let zero_priority = [0, 0, 5, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1];
    assert_eq!(
        Http2PriorityFrame::parse(&zero_priority, 5),
        Err(Http2ParseError::ZeroStreamId)
    );
    let zero_rst = [0, 0, 4, 3, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    assert_eq!(
        Http2RstStream::parse(&zero_rst, 4),
        Err(Http2ParseError::ZeroStreamId)
    );
    let nonzero_ping = [0, 0, 8, 6, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(
        Http2Ping::parse(&nonzero_ping, 8),
        Err(Http2ParseError::ExpectedZeroStreamId)
    );
    let zero_increment = [0, 0, 4, 8, 0, 0, 0, 0, 0, 0x80, 0, 0, 0];
    assert_eq!(
        Http2WindowUpdate::parse(&zero_increment, 4),
        Err(Http2ParseError::ZeroWindowIncrement)
    );
}

#[test]
fn typed_fixed_layout_control_frames_distinguish_wrong_type() {
    let wire = [0, 0, 4, 3, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    assert_eq!(
        Http2PriorityFrame::parse(&wire, 4),
        Err(Http2ParseError::WrongFrameType {
            expected: Http2FrameType::PRIORITY,
            actual: Http2FrameType::RST_STREAM,
        })
    );
}

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
fn typed_goaway_exposes_minimum_layout_and_debug_data() {
    let minimum = [0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    let goaway = Http2Goaway::parse(&minimum, 8).unwrap();
    assert_eq!(goaway.frame().as_bytes(), minimum);
    assert_eq!(goaway.as_bytes(), minimum);
    assert_eq!(goaway.last_stream_id().raw(), 1);
    assert_eq!(goaway.error_code(), Http2ErrorCode::NO_ERROR);
    assert_eq!(goaway.additional_debug_data(), []);

    let with_debug = [
        0, 0, 11, 7, 0xa0, 0, 0, 0, 0, 0x80, 0, 0, 7, 0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce, 0x42,
    ];
    let goaway = Http2Goaway::parse(&with_debug, 11).unwrap();
    assert_eq!(goaway.frame().flags(), 0xa0);
    assert_eq!(goaway.last_stream_id().raw(), 0x8000_0007);
    assert!(goaway.last_stream_id().has_reserved_bit());
    assert_eq!(goaway.error_code().raw(), 0xdead_beef);
    assert_eq!(goaway.additional_debug_data(), [0xfa, 0xce, 0x42]);
}

#[test]
fn typed_goaway_rejects_truncation_and_nonzero_stream() {
    let truncated = [0, 0, 7, 7, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0];
    assert_eq!(
        Http2Goaway::parse(&truncated, 7),
        Err(Http2ParseError::MalformedPayload {
            required: 8,
            available: 7,
        })
    );

    let nonzero_stream = [0, 0, 8, 7, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0];
    assert_eq!(
        Http2Goaway::parse(&nonzero_stream, 8),
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
fn typed_headers_builder_writes_optional_layouts_and_preserves_suffix() {
    let mut plain_destination = [0xaa; 16];
    let plain = Http2HeadersBuilder::new(
        &mut plain_destination,
        Http2StreamId::from_value(1).unwrap(),
        0x81,
        &[0xde, 0xad],
        None,
        None,
    )
    .build()
    .unwrap();
    assert_eq!(
        plain.as_bytes(),
        &[0, 0, 2, 1, 0x81, 0, 0, 0, 1, 0xde, 0xad]
    );
    assert_eq!(plain.field_block_fragment(), [0xde, 0xad]);
    assert_eq!(plain.priority(), None);
    assert_eq!(plain.pad_length(), None);
    assert!(plain_destination[11..].iter().all(|byte| *byte == 0xaa));

    let mut priority_destination = [0xaa; 20];
    let priority = Http2HeadersBuilder::new(
        &mut priority_destination,
        Http2StreamId::from_value(3).unwrap(),
        0x84,
        &[0xbe],
        Some(Http2Priority::new(0x8000_0007, 0x1f)),
        None,
    )
    .build()
    .unwrap();
    assert_eq!(
        priority.as_bytes(),
        &[0, 0, 6, 1, 0xa4, 0, 0, 0, 3, 0x80, 0, 0, 7, 0x1f, 0xbe]
    );
    assert_eq!(
        priority.priority(),
        Some(Http2Priority::new(0x8000_0007, 0x1f))
    );
    assert_eq!(priority.field_block_fragment(), [0xbe]);
    assert!(priority_destination[15..].iter().all(|byte| *byte == 0xaa));

    let mut padded_destination = [0xaa; 24];
    let padded = Http2HeadersBuilder::new(
        &mut padded_destination,
        Http2StreamId::from_value(5).unwrap(),
        0xc1,
        &[0xfa, 0xce],
        Some(Http2Priority::new(9, 0)),
        Some(2),
    )
    .build()
    .unwrap();
    assert_eq!(
        padded.as_bytes(),
        &[
            0, 0, 10, 1, 0xe9, 0, 0, 0, 5, 2, 0, 0, 0, 9, 0, 0xfa, 0xce, 0, 0
        ]
    );
    assert_eq!(padded.field_block_fragment(), [0xfa, 0xce]);
    assert_eq!(padded.priority(), Some(Http2Priority::new(9, 0)));
    assert_eq!(padded.pad_length(), Some(2));
    assert_eq!(padded.padding(), [0, 0]);
    assert!(padded_destination[19..].iter().all(|byte| *byte == 0xaa));
}

#[test]
fn typed_push_promise_builder_writes_padded_layouts_and_preserves_suffix() {
    let mut plain_destination = [0xaa; 20];
    let plain = Http2PushPromiseBuilder::new(
        &mut plain_destination,
        Http2StreamId::from_value(1).unwrap(),
        0x84,
        Http2StreamId::from_value(2).unwrap(),
        &[0xde, 0xad],
        None,
    )
    .build()
    .unwrap();
    assert_eq!(
        plain.as_bytes(),
        &[0, 0, 6, 5, 0x84, 0, 0, 0, 1, 0, 0, 0, 2, 0xde, 0xad]
    );
    assert_eq!(plain.promised_stream_id().value(), 2);
    assert_eq!(plain.field_block_fragment(), [0xde, 0xad]);
    assert_eq!(plain.pad_length(), None);
    assert!(plain_destination[15..].iter().all(|byte| *byte == 0xaa));

    let mut padded_destination = [0xaa; 24];
    let padded = Http2PushPromiseBuilder::new(
        &mut padded_destination,
        Http2StreamId::from_value(3).unwrap(),
        0xc4,
        Http2StreamId::from_value(4).unwrap(),
        &[0xbe],
        Some(2),
    )
    .build()
    .unwrap();
    assert_eq!(
        padded.as_bytes(),
        &[0, 0, 8, 5, 0xcc, 0, 0, 0, 3, 2, 0, 0, 0, 4, 0xbe, 0, 0]
    );
    assert_eq!(padded.promised_stream_id().value(), 4);
    assert_eq!(padded.field_block_fragment(), [0xbe]);
    assert_eq!(padded.pad_length(), Some(2));
    assert_eq!(padded.padding(), [0, 0]);
    assert!(padded_destination[17..].iter().all(|byte| *byte == 0xaa));
}

#[test]
fn typed_headers_and_push_promise_builder_failures_are_atomic() {
    let mut headers_zero = [0xaa; 16];
    let before = headers_zero;
    assert_eq!(
        Http2HeadersBuilder::new(
            &mut headers_zero,
            Http2StreamId::from_value(0).unwrap(),
            0,
            &[],
            None,
            None,
        )
        .build(),
        Err(Http2BuildError::ZeroStreamId)
    );
    assert_eq!(headers_zero, before);

    let mut headers_reserved = [0xaa; 16];
    let before = headers_reserved;
    assert_eq!(
        Http2HeadersBuilder::new(
            &mut headers_reserved,
            Http2StreamId::new(0x8000_0001),
            0,
            &[],
            None,
            None,
        )
        .build(),
        Err(Http2BuildError::ReservedStreamId)
    );
    assert_eq!(headers_reserved, before);

    let mut promise_outer_zero = [0xaa; 16];
    let before = promise_outer_zero;
    assert_eq!(
        Http2PushPromiseBuilder::new(
            &mut promise_outer_zero,
            Http2StreamId::from_value(0).unwrap(),
            0,
            Http2StreamId::from_value(2).unwrap(),
            &[],
            None,
        )
        .build(),
        Err(Http2BuildError::ZeroStreamId)
    );
    assert_eq!(promise_outer_zero, before);

    let mut promise_outer_reserved = [0xaa; 16];
    let before = promise_outer_reserved;
    assert_eq!(
        Http2PushPromiseBuilder::new(
            &mut promise_outer_reserved,
            Http2StreamId::new(0x8000_0001),
            0,
            Http2StreamId::from_value(2).unwrap(),
            &[],
            None,
        )
        .build(),
        Err(Http2BuildError::ReservedStreamId)
    );
    assert_eq!(promise_outer_reserved, before);

    let mut headers_padded = [0xaa; 16];
    let before = headers_padded;
    assert_eq!(
        Http2HeadersBuilder::new(
            &mut headers_padded,
            Http2StreamId::from_value(1).unwrap(),
            0x08,
            &[],
            None,
            None,
        )
        .build(),
        Err(Http2BuildError::HeadersPaddedFlagSet)
    );
    assert_eq!(headers_padded, before);

    let mut headers_priority = [0xaa; 16];
    let before = headers_priority;
    assert_eq!(
        Http2HeadersBuilder::new(
            &mut headers_priority,
            Http2StreamId::from_value(1).unwrap(),
            0x20,
            &[],
            None,
            None,
        )
        .build(),
        Err(Http2BuildError::HeadersPriorityFlagSet)
    );
    assert_eq!(headers_priority, before);

    let mut promise_padded = [0xaa; 16];
    let before = promise_padded;
    assert_eq!(
        Http2PushPromiseBuilder::new(
            &mut promise_padded,
            Http2StreamId::from_value(1).unwrap(),
            0x08,
            Http2StreamId::from_value(2).unwrap(),
            &[],
            None,
        )
        .build(),
        Err(Http2BuildError::PushPromisePaddedFlagSet)
    );
    assert_eq!(promise_padded, before);

    let mut promised_zero = [0xaa; 16];
    let before = promised_zero;
    assert_eq!(
        Http2PushPromiseBuilder::new(
            &mut promised_zero,
            Http2StreamId::from_value(1).unwrap(),
            0,
            Http2StreamId::from_value(0).unwrap(),
            &[],
            None,
        )
        .build(),
        Err(Http2BuildError::ZeroPromisedStreamId)
    );
    assert_eq!(promised_zero, before);

    let mut promised_reserved = [0xaa; 16];
    let before = promised_reserved;
    assert_eq!(
        Http2PushPromiseBuilder::new(
            &mut promised_reserved,
            Http2StreamId::from_value(1).unwrap(),
            0,
            Http2StreamId::new(0x8000_0002),
            &[],
            None,
        )
        .build(),
        Err(Http2BuildError::ReservedPromisedStreamId)
    );
    assert_eq!(promised_reserved, before);

    let mut maximum = [0xaa; 16];
    let before = maximum;
    assert_eq!(
        Http2HeadersBuilder::new(
            &mut maximum,
            Http2StreamId::from_value(1).unwrap(),
            0,
            &[1],
            Some(Http2Priority::new(0, 0)),
            None,
        )
        .build_with_maximum(5),
        Err(Http2BuildError::PayloadTooLarge {
            maximum: 5,
            actual: 6,
        })
    );
    assert_eq!(maximum, before);

    let mut short = [0xaa; 13];
    let before = short;
    assert_eq!(
        Http2PushPromiseBuilder::new(
            &mut short,
            Http2StreamId::from_value(1).unwrap(),
            0,
            Http2StreamId::from_value(2).unwrap(),
            &[1],
            None,
        )
        .build(),
        Err(Http2BuildError::BufferTooShort {
            required: 14,
            available: 13,
        })
    );
    assert_eq!(short, before);
}

#[test]
fn typed_fixed_layout_control_builders_write_exact_bytes_and_preserve_suffixes() {
    let mut priority_destination = [0xaa; 16];
    let priority = Http2PriorityFrameBuilder::new(
        &mut priority_destination,
        Http2StreamId::from_value(3).unwrap(),
        0xa0,
        Http2Priority::new(0x8000_0007, 0x1f),
    )
    .build()
    .unwrap();
    assert_eq!(
        priority.as_bytes(),
        &[0, 0, 5, 2, 0xa0, 0, 0, 0, 3, 0x80, 0, 0, 7, 0x1f]
    );
    assert!(priority.priority().is_exclusive());
    assert_eq!(priority.priority().weight(), 0x1f);
    assert!(priority_destination[14..].iter().all(|byte| *byte == 0xaa));

    let mut rst_destination = [0xaa; 16];
    let rst = Http2RstStreamBuilder::new(
        &mut rst_destination,
        Http2StreamId::from_value(9).unwrap(),
        0x80,
        Http2ErrorCode::new(0xdead_beef),
    )
    .build()
    .unwrap();
    assert_eq!(
        rst.as_bytes(),
        &[0, 0, 4, 3, 0x80, 0, 0, 0, 9, 0xde, 0xad, 0xbe, 0xef]
    );
    assert_eq!(rst.error_code().raw(), 0xdead_beef);
    assert!(rst_destination[13..].iter().all(|byte| *byte == 0xaa));

    let mut ping_destination = [0xaa; 20];
    let ping = Http2PingBuilder::new(&mut ping_destination, 0x81, &[0, 1, 2, 3, 4, 5, 6, 7])
        .build()
        .unwrap();
    assert_eq!(
        ping.as_bytes(),
        &[0, 0, 8, 6, 0x81, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7]
    );
    assert!(ping.is_ack());
    assert_eq!(ping.opaque_data(), &[0, 1, 2, 3, 4, 5, 6, 7]);
    assert!(ping_destination[17..].iter().all(|byte| *byte == 0xaa));

    let mut connection_window_destination = [0xaa; 16];
    let connection_window = Http2WindowUpdateBuilder::new(
        &mut connection_window_destination,
        Http2StreamId::from_value(0).unwrap(),
        0x80,
        Http2WindowIncrement::new(5),
    )
    .build()
    .unwrap();
    assert_eq!(
        connection_window.as_bytes(),
        &[0, 0, 4, 8, 0x80, 0, 0, 0, 0, 0, 0, 0, 5]
    );
    assert_eq!(connection_window.increment().value(), 5);
    assert!(
        connection_window_destination[13..]
            .iter()
            .all(|byte| *byte == 0xaa)
    );

    let mut stream_window_destination = [0xaa; 16];
    let stream_window = Http2WindowUpdateBuilder::new(
        &mut stream_window_destination,
        Http2StreamId::from_value(1).unwrap(),
        0x40,
        Http2WindowIncrement::new(7),
    )
    .build()
    .unwrap();
    assert_eq!(stream_window.frame().stream_id().value(), 1);
    assert_eq!(stream_window.increment().raw(), 7);
}

#[test]
fn typed_fixed_layout_control_builder_failures_are_atomic() {
    let mut zero_stream = [0xaa; 16];
    let before = zero_stream;
    assert_eq!(
        Http2PriorityFrameBuilder::new(
            &mut zero_stream,
            Http2StreamId::from_value(0).unwrap(),
            0,
            Http2Priority::new(0, 0),
        )
        .build(),
        Err(Http2BuildError::ZeroStreamId)
    );
    assert_eq!(zero_stream, before);

    let mut reserved_stream = [0xaa; 16];
    let before = reserved_stream;
    assert_eq!(
        Http2RstStreamBuilder::new(
            &mut reserved_stream,
            Http2StreamId::new(0x8000_0001),
            0,
            Http2ErrorCode::NO_ERROR,
        )
        .build(),
        Err(Http2BuildError::ReservedStreamId)
    );
    assert_eq!(reserved_stream, before);

    let mut reserved_window_stream = [0xaa; 16];
    let before = reserved_window_stream;
    assert_eq!(
        Http2WindowUpdateBuilder::new(
            &mut reserved_window_stream,
            Http2StreamId::new(0x8000_0001),
            0,
            Http2WindowIncrement::new(1),
        )
        .build(),
        Err(Http2BuildError::ReservedStreamId)
    );
    assert_eq!(reserved_window_stream, before);

    let mut zero_increment = [0xaa; 16];
    let before = zero_increment;
    assert_eq!(
        Http2WindowUpdateBuilder::new(
            &mut zero_increment,
            Http2StreamId::from_value(0).unwrap(),
            0,
            Http2WindowIncrement::new(0),
        )
        .build(),
        Err(Http2BuildError::ZeroWindowIncrement)
    );
    assert_eq!(zero_increment, before);

    let mut reserved_increment = [0xaa; 16];
    let before = reserved_increment;
    assert_eq!(
        Http2WindowUpdateBuilder::new(
            &mut reserved_increment,
            Http2StreamId::from_value(0).unwrap(),
            0,
            Http2WindowIncrement::new(0x8000_0001),
        )
        .build(),
        Err(Http2BuildError::ReservedWindowIncrement)
    );
    assert_eq!(reserved_increment, before);

    let mut maximum = [0xaa; 16];
    let before = maximum;
    assert_eq!(
        Http2PingBuilder::new(&mut maximum, 0, &[0; 8]).build_with_maximum(7),
        Err(Http2BuildError::PayloadTooLarge {
            maximum: 7,
            actual: 8,
        })
    );
    assert_eq!(maximum, before);

    let mut short = [0xaa; 12];
    let before = short;
    assert_eq!(
        Http2WindowUpdateBuilder::new(
            &mut short,
            Http2StreamId::from_value(0).unwrap(),
            0,
            Http2WindowIncrement::new(1),
        )
        .build(),
        Err(Http2BuildError::BufferTooShort {
            required: 13,
            available: 12,
        })
    );
    assert_eq!(short, before);
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

#[test]
fn typed_goaway_builder_writes_minimum_and_debug_data() {
    let mut minimum_destination = [0xaa; 20];
    let minimum = Http2GoawayBuilder::new(
        &mut minimum_destination,
        0,
        Http2StreamId::from_value(0).unwrap(),
        Http2ErrorCode::NO_ERROR,
        &[],
    )
    .build()
    .unwrap();
    assert_eq!(
        minimum.as_bytes(),
        &[0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(minimum.last_stream_id().value(), 0);
    assert!(minimum_destination[17..].iter().all(|byte| *byte == 0xaa));

    let mut debug_destination = [0xaa; 24];
    let debug = Http2GoawayBuilder::new(
        &mut debug_destination,
        0xa0,
        Http2StreamId::from_value(7).unwrap(),
        Http2ErrorCode::new(0xdead_beef),
        &[0xfa, 0xce, 0x42],
    )
    .build()
    .unwrap();
    assert_eq!(
        debug.as_bytes(),
        &[
            0, 0, 11, 7, 0xa0, 0, 0, 0, 0, 0, 0, 0, 7, 0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce, 0x42,
        ]
    );
    assert_eq!(debug.last_stream_id().value(), 7);
    assert_eq!(debug.error_code().raw(), 0xdead_beef);
    assert_eq!(debug.additional_debug_data(), [0xfa, 0xce, 0x42]);
    assert!(debug_destination[20..].iter().all(|byte| *byte == 0xaa));
}

#[test]
fn typed_goaway_builder_failures_are_atomic() {
    let mut reserved_destination = [0xaa; 20];
    let before = reserved_destination;
    assert_eq!(
        Http2GoawayBuilder::new(
            &mut reserved_destination,
            0,
            Http2StreamId::new(0x8000_0001),
            Http2ErrorCode::NO_ERROR,
            &[],
        )
        .build(),
        Err(Http2BuildError::ReservedLastStreamId)
    );
    assert_eq!(reserved_destination, before);

    let mut maximum_destination = [0xaa; 20];
    let before = maximum_destination;
    assert_eq!(
        Http2GoawayBuilder::new(
            &mut maximum_destination,
            0,
            Http2StreamId::from_value(1).unwrap(),
            Http2ErrorCode::new(0xfeed_face),
            &[1],
        )
        .build_with_maximum(8),
        Err(Http2BuildError::PayloadTooLarge {
            maximum: 8,
            actual: 9,
        })
    );
    assert_eq!(maximum_destination, before);

    let mut short_destination = [0xaa; 16];
    let before = short_destination;
    assert_eq!(
        Http2GoawayBuilder::new(
            &mut short_destination,
            0,
            Http2StreamId::from_value(1).unwrap(),
            Http2ErrorCode::NO_ERROR,
            &[],
        )
        .build(),
        Err(Http2BuildError::BufferTooShort {
            required: 17,
            available: 16,
        })
    );
    assert_eq!(short_destination, before);
}

fn header_block_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let length = payload.len();
    let mut bytes = vec![
        (length >> 16) as u8,
        (length >> 8) as u8,
        length as u8,
        frame_type,
        flags,
        (stream_id >> 24) as u8,
        (stream_id >> 16) as u8,
        (stream_id >> 8) as u8,
        stream_id as u8,
    ];
    bytes.extend_from_slice(payload);
    bytes
}

fn parsed_header_block_frame(bytes: &[u8]) -> Http2Frame<'_> {
    Http2Frame::parse(bytes, bytes.len() - 9).unwrap()
}

#[test]
fn header_block_sequence_ignores_idle_unrelated_frames_and_single_frame_headers() {
    let mut sequence = Http2HeaderBlockSequence::new();
    let data = header_block_frame(Http2FrameType::DATA.raw(), 0, 1, &[1]);
    assert_eq!(sequence.observe(parsed_header_block_frame(&data)), Ok(None));
    assert!(sequence.is_idle());
    assert_eq!(sequence.locked_stream_id(), None);

    let headers = header_block_frame(Http2FrameType::HEADERS.raw(), 0x84, 1, &[0xaa, 0xbb]);
    let fragment = sequence
        .observe(parsed_header_block_frame(&headers))
        .unwrap()
        .unwrap();
    assert!(matches!(fragment, Http2HeaderBlockFragment::Headers(_)));
    assert_eq!(fragment.frame().as_bytes(), headers);
    assert_eq!(fragment.field_block_fragment(), [0xaa, 0xbb]);
    assert!(fragment.is_end_headers());
    assert!(sequence.is_idle());
}

#[test]
fn header_block_sequence_accepts_multiframe_headers_and_preserves_views() {
    let mut sequence = Http2HeaderBlockSequence::default();
    let headers = header_block_frame(Http2FrameType::HEADERS.raw(), 0x80, 3, &[0xaa]);
    let first = sequence
        .observe(parsed_header_block_frame(&headers))
        .unwrap()
        .unwrap();
    assert!(matches!(first, Http2HeaderBlockFragment::Headers(_)));
    assert!(!first.is_end_headers());
    assert_eq!(sequence.locked_stream_id(), Some(3));

    let continuation = header_block_frame(Http2FrameType::CONTINUATION.raw(), 0x80, 3, &[0xbb]);
    let middle = sequence
        .observe(parsed_header_block_frame(&continuation))
        .unwrap()
        .unwrap();
    assert!(matches!(middle, Http2HeaderBlockFragment::Continuation(_)));
    assert_eq!(middle.field_block_fragment(), [0xbb]);
    assert!(sequence.is_open());

    let final_continuation =
        header_block_frame(Http2FrameType::CONTINUATION.raw(), 0x84, 3, &[0xcc]);
    let final_fragment = sequence
        .observe(parsed_header_block_frame(&final_continuation))
        .unwrap()
        .unwrap();
    assert_eq!(final_fragment.frame().flags(), 0x84);
    assert_eq!(final_fragment.field_block_fragment(), [0xcc]);
    assert!(final_fragment.is_end_headers());
    assert!(sequence.is_idle());
}

#[test]
fn header_block_sequence_preserves_push_promise_metadata() {
    let mut sequence = Http2HeaderBlockSequence::new();
    let promise = header_block_frame(
        Http2FrameType::PUSH_PROMISE.raw(),
        0,
        1,
        &[0x80, 0, 0, 2, 0xaa],
    );
    let fragment = sequence
        .observe(parsed_header_block_frame(&promise))
        .unwrap()
        .unwrap();
    match fragment {
        Http2HeaderBlockFragment::PushPromise(view) => {
            assert_eq!(view.promised_stream_id().raw(), 0x8000_0002);
            assert_eq!(view.field_block_fragment(), [0xaa]);
        }
        _ => panic!("expected PUSH_PROMISE fragment"),
    }
    assert_eq!(sequence.locked_stream_id(), Some(1));
}

#[test]
fn header_block_sequence_rejects_ordering_errors_without_mutating_state() {
    let mut sequence = Http2HeaderBlockSequence::new();
    let unexpected = header_block_frame(Http2FrameType::CONTINUATION.raw(), 0, 1, &[]);
    assert_eq!(
        sequence.observe(parsed_header_block_frame(&unexpected)),
        Err(Http2HeaderBlockSequenceError::UnexpectedContinuation {
            actual_stream_id: 1,
        })
    );
    assert!(sequence.is_idle());

    let headers = header_block_frame(Http2FrameType::HEADERS.raw(), 0, 1, &[]);
    sequence
        .observe(parsed_header_block_frame(&headers))
        .unwrap();
    let wrong = header_block_frame(Http2FrameType::CONTINUATION.raw(), 0, 2, &[]);
    assert_eq!(
        sequence.observe(parsed_header_block_frame(&wrong)),
        Err(Http2HeaderBlockSequenceError::WrongContinuationStream {
            expected_stream_id: 1,
            actual_stream_id: 2,
        })
    );
    assert_eq!(sequence.locked_stream_id(), Some(1));

    let data = header_block_frame(Http2FrameType::DATA.raw(), 0, 1, &[]);
    assert_eq!(
        sequence.observe(parsed_header_block_frame(&data)),
        Err(Http2HeaderBlockSequenceError::InterleavedFrame {
            expected_stream_id: 1,
            actual_stream_id: 1,
            actual_frame_type: Http2FrameType::DATA,
        })
    );
    let interleaved_headers = header_block_frame(Http2FrameType::HEADERS.raw(), 0, 3, &[]);
    assert_eq!(
        sequence.observe(parsed_header_block_frame(&interleaved_headers)),
        Err(Http2HeaderBlockSequenceError::InterleavedFrame {
            expected_stream_id: 1,
            actual_stream_id: 3,
            actual_frame_type: Http2FrameType::HEADERS,
        })
    );
    assert_eq!(sequence.locked_stream_id(), Some(1));

    let finish = header_block_frame(Http2FrameType::CONTINUATION.raw(), 0x04, 1, &[]);
    sequence
        .observe(parsed_header_block_frame(&finish))
        .unwrap();
    assert!(sequence.is_idle());
}

#[test]
fn header_block_sequence_rejects_malformed_fragments_without_mutating_state() {
    let mut sequence = Http2HeaderBlockSequence::new();
    let malformed_start = header_block_frame(Http2FrameType::PUSH_PROMISE.raw(), 0, 1, &[0, 0, 0]);
    assert_eq!(
        sequence.observe(parsed_header_block_frame(&malformed_start)),
        Err(Http2HeaderBlockSequenceError::MalformedFragment(
            Http2ParseError::MalformedPayload {
                required: 4,
                available: 3,
            }
        ))
    );
    assert!(sequence.is_idle());

    let headers = header_block_frame(Http2FrameType::HEADERS.raw(), 0, 0x8000_0001, &[]);
    sequence
        .observe(parsed_header_block_frame(&headers))
        .unwrap();
    assert_eq!(sequence.locked_stream_id(), Some(1));
    let malformed_continuation = header_block_frame(Http2FrameType::CONTINUATION.raw(), 0, 0, &[]);
    assert_eq!(
        sequence.observe(parsed_header_block_frame(&malformed_continuation)),
        Err(Http2HeaderBlockSequenceError::MalformedFragment(
            Http2ParseError::ZeroStreamId
        ))
    );
    assert_eq!(sequence.locked_stream_id(), Some(1));

    let finish = header_block_frame(Http2FrameType::CONTINUATION.raw(), 0x04, 1, &[]);
    sequence
        .observe(parsed_header_block_frame(&finish))
        .unwrap();
    assert!(sequence.is_idle());
}

#[test]
fn header_block_sequence_compares_reserved_stream_bits_semantically() {
    let mut sequence = Http2HeaderBlockSequence::new();
    let headers = header_block_frame(Http2FrameType::HEADERS.raw(), 0, 0x8000_0007, &[0xaa]);
    sequence
        .observe(parsed_header_block_frame(&headers))
        .unwrap();
    let continuation = header_block_frame(Http2FrameType::CONTINUATION.raw(), 0x04, 7, &[0xbb]);
    let fragment = sequence
        .observe(parsed_header_block_frame(&continuation))
        .unwrap()
        .unwrap();
    assert_eq!(fragment.frame().stream_id().raw(), 7);
    assert_eq!(fragment.field_block_fragment(), [0xbb]);
    assert!(sequence.is_idle());
}

#[test]
fn hpack_integer_parses_rfc_examples_and_exact_views() {
    let ten = HpackInteger::parse(&[0xea, 0xaa], 5).unwrap();
    assert_eq!(ten.value(), 10);
    assert_eq!(ten.as_bytes(), [0xea]);
    assert_eq!(ten.prefix_bits(), 5);
    assert_eq!(ten.high_bits(), 0xe0);

    let large = HpackInteger::parse(&[0xbf, 0x9a, 0x0a, 0xaa], 5).unwrap();
    assert_eq!(large.value(), 1337);
    assert_eq!(large.as_bytes(), [0xbf, 0x9a, 0x0a]);
    assert_eq!(large.high_bits(), 0xa0);

    let eight_bit = HpackInteger::parse(&[42, 0xaa], 8).unwrap();
    assert_eq!(eight_bit.value(), 42);
    assert_eq!(eight_bit.as_bytes(), [42]);
    assert_eq!(eight_bit.high_bits(), 0);
}

#[test]
fn hpack_integer_parses_saturated_and_overlong_representations() {
    let saturated = HpackInteger::parse(&[0x1f, 0x80, 0x01], 5).unwrap();
    assert_eq!(saturated.value(), 159);
    assert_eq!(saturated.as_bytes(), [0x1f, 0x80, 0x01]);

    let overlong = HpackInteger::parse(&[0x1f, 0x80, 0x00, 0xaa], 5).unwrap();
    assert_eq!(overlong.value(), 31);
    assert_eq!(overlong.as_bytes(), [0x1f, 0x80, 0x00]);
}

#[test]
fn hpack_integer_rejects_invalid_incomplete_and_overflow_representations() {
    assert_eq!(
        HpackInteger::parse(&[], 5),
        Err(HpackIntegerParseError::Incomplete {
            required: 1,
            available: 0,
        })
    );
    assert_eq!(
        HpackInteger::parse(&[0x1f], 5),
        Err(HpackIntegerParseError::Incomplete {
            required: 2,
            available: 1,
        })
    );
    assert_eq!(
        HpackInteger::parse(&[0], 0),
        Err(HpackIntegerParseError::InvalidPrefixBits { prefix_bits: 0 })
    );
    assert_eq!(
        HpackInteger::parse(&[0], 9),
        Err(HpackIntegerParseError::InvalidPrefixBits { prefix_bits: 9 })
    );
    assert_eq!(
        HpackInteger::parse(
            &[
                0x1f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02
            ],
            5,
        ),
        Err(HpackIntegerParseError::Overflow)
    );
    assert_eq!(
        HpackInteger::parse(
            &[
                0x1f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00
            ],
            5,
        ),
        Err(HpackIntegerParseError::Overflow)
    );
}

#[test]
fn hpack_integer_builder_writes_canonical_bytes_and_preserves_suffix() {
    let mut ten_destination = [0xaa; 4];
    let ten = HpackIntegerBuilder::new(&mut ten_destination, 5, 0xe0, 10)
        .build()
        .unwrap();
    assert_eq!(ten.as_bytes(), [0xea]);
    assert_eq!(ten_destination, [0xea, 0xaa, 0xaa, 0xaa]);

    let mut large_destination = [0xaa; 5];
    let large = HpackIntegerBuilder::new(&mut large_destination, 5, 0xa0, 1337)
        .build()
        .unwrap();
    assert_eq!(large.as_bytes(), [0xbf, 0x9a, 0x0a]);
    assert_eq!(large_destination, [0xbf, 0x9a, 0x0a, 0xaa, 0xaa]);

    let mut eight_bit_destination = [0xaa; 3];
    let eight_bit = HpackIntegerBuilder::new(&mut eight_bit_destination, 8, 0, 42)
        .build()
        .unwrap();
    assert_eq!(eight_bit.as_bytes(), [42]);
    assert_eq!(eight_bit_destination, [42, 0xaa, 0xaa]);
}

#[test]
fn hpack_integer_builder_is_atomic_and_round_trips_u64_max() {
    let mut invalid_prefix = [0xaa; 4];
    let before = invalid_prefix;
    assert_eq!(
        HpackIntegerBuilder::new(&mut invalid_prefix, 0, 0, 1).build(),
        Err(HpackIntegerBuildError::InvalidPrefixBits { prefix_bits: 0 })
    );
    assert_eq!(invalid_prefix, before);

    let mut invalid_high_bits = [0xaa; 4];
    let before = invalid_high_bits;
    assert_eq!(
        HpackIntegerBuilder::new(&mut invalid_high_bits, 5, 0xe1, 1).build(),
        Err(HpackIntegerBuildError::HighBitsOverlap {
            high_bits: 0xe1,
            prefix_bits: 5,
        })
    );
    assert_eq!(invalid_high_bits, before);

    let mut short = [0xaa; 2];
    let before = short;
    assert_eq!(
        HpackIntegerBuilder::new(&mut short, 5, 0xa0, 1337).build(),
        Err(HpackIntegerBuildError::BufferTooShort {
            required: 3,
            available: 2,
        })
    );
    assert_eq!(short, before);

    let mut maximum_destination = [0xaa; 12];
    let maximum = HpackIntegerBuilder::new(&mut maximum_destination, 5, 0xe0, u64::MAX)
        .build()
        .unwrap();
    assert_eq!(maximum.value(), u64::MAX);
    assert_eq!(maximum.high_bits(), 0xe0);
    assert_eq!(
        HpackInteger::parse(maximum.as_bytes(), 5).unwrap().value(),
        u64::MAX
    );
    let maximum_len = maximum.as_bytes().len();
    assert_eq!(maximum_destination[maximum_len..], [0xaa]);
}

#[test]
fn hpack_string_literal_parses_plain_and_huffman_opaque_payloads() {
    let plain_wire = b"\x0fwww.example.comsuffix";
    let plain = HpackStringLiteral::parse(plain_wire).unwrap();
    assert_eq!(plain.as_bytes(), b"\x0fwww.example.com");
    assert!(!plain.is_huffman());
    assert_eq!(plain.encoded_bytes(), b"www.example.com");
    assert_eq!(plain.length().as_bytes(), [0x0f]);
    assert_eq!(plain.length().value(), 15);

    let huffman_wire = [0x83, 0xff, 0x00, 0xa5, 0xde];
    let huffman = HpackStringLiteral::parse(&huffman_wire).unwrap();
    assert_eq!(huffman.as_bytes(), &huffman_wire[..4]);
    assert!(huffman.is_huffman());
    assert_eq!(huffman.encoded_bytes(), [0xff, 0x00, 0xa5]);
    assert_eq!(huffman.length().as_bytes(), [0x83]);
}

#[test]
fn hpack_string_literal_preserves_long_and_overlong_length_representations() {
    let long_payload = [0x5a; 127];
    let mut long_wire = vec![0x7f, 0x00];
    long_wire.extend_from_slice(&long_payload);
    long_wire.push(0xaa);
    let long = HpackStringLiteral::parse(&long_wire).unwrap();
    assert_eq!(long.as_bytes(), &long_wire[..129]);
    assert_eq!(long.length().as_bytes(), [0x7f, 0x00]);
    assert_eq!(long.encoded_bytes(), long_payload);

    let mut overlong_wire = vec![0x7f, 0x80, 0x00];
    overlong_wire.extend_from_slice(&long_payload);
    overlong_wire.push(0xaa);
    let overlong = HpackStringLiteral::parse(&overlong_wire).unwrap();
    assert_eq!(overlong.as_bytes(), &overlong_wire[..130]);
    assert_eq!(overlong.length().as_bytes(), [0x7f, 0x80, 0x00]);
    assert_eq!(overlong.length().value(), 127);
    assert_eq!(overlong.encoded_bytes(), long_payload);
}

#[test]
fn hpack_string_literal_propagates_length_errors_and_payload_truncation() {
    assert_eq!(
        HpackStringLiteral::parse(&[]),
        Err(HpackStringLiteralParseError::InvalidLength(
            HpackIntegerParseError::Incomplete {
                required: 1,
                available: 0,
            }
        ))
    );
    assert_eq!(
        HpackStringLiteral::parse(&[0x7f]),
        Err(HpackStringLiteralParseError::InvalidLength(
            HpackIntegerParseError::Incomplete {
                required: 2,
                available: 1,
            }
        ))
    );
    assert_eq!(
        HpackStringLiteral::parse(&[
            0x7f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02,
        ]),
        Err(HpackStringLiteralParseError::InvalidLength(
            HpackIntegerParseError::Overflow
        ))
    );
    assert_eq!(
        HpackStringLiteral::parse(&[0x03, 0xaa, 0xbb]),
        Err(HpackStringLiteralParseError::IncompleteEncodedPayload {
            required: 3,
            available: 2,
        })
    );
}

#[test]
fn hpack_string_literal_builder_writes_exact_bytes_and_preserves_suffix() {
    let mut plain_destination = [0xaa; 24];
    let plain =
        HpackStringLiteralBuilder::new_encoded(&mut plain_destination, false, b"www.example.com")
            .build()
            .unwrap();
    assert_eq!(plain.as_bytes(), b"\x0fwww.example.com");
    assert!(!plain.is_huffman());
    assert_eq!(plain_destination[16..], [0xaa; 8]);

    let mut huffman_destination = [0xaa; 8];
    let huffman =
        HpackStringLiteralBuilder::new_encoded(&mut huffman_destination, true, &[0xff, 0x00, 0xa5])
            .build()
            .unwrap();
    assert_eq!(huffman.as_bytes(), [0x83, 0xff, 0x00, 0xa5]);
    assert!(huffman.is_huffman());
    assert_eq!(huffman_destination[4..], [0xaa; 4]);

    let long_payload = [0x5a; 127];
    let mut long_destination = [0xaa; 132];
    let long = HpackStringLiteralBuilder::new_encoded(&mut long_destination, false, &long_payload)
        .build()
        .unwrap();
    assert_eq!(
        long.as_bytes(),
        [&[0x7f, 0x00][..], &long_payload[..]].concat()
    );
    assert_eq!(long_destination[129..], [0xaa; 3]);
}

#[test]
fn hpack_string_literal_builder_failures_are_atomic() {
    let mut destination = [0xaa; 3];
    let before = destination;
    assert_eq!(
        HpackStringLiteralBuilder::new_encoded(&mut destination, true, &[0xff, 0x00, 0xa5]).build(),
        Err(HpackStringLiteralBuildError::BufferTooShort {
            required: 4,
            available: 3,
        })
    );
    assert_eq!(destination, before);
}

#[test]
fn hpack_huffman_decodes_rfc_appendix_c_vectors() {
    for (encoded, expected) in [
        (
            &[
                0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
            ][..],
            b"www.example.com" as &[u8],
        ),
        (
            &[0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf][..],
            b"no-cache" as &[u8],
        ),
        (
            &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f][..],
            b"custom-key" as &[u8],
        ),
        (
            &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf][..],
            b"custom-value" as &[u8],
        ),
    ] {
        let mut destination = [0xaa; 32];
        let decoded = HpackHuffmanDecoder::new(encoded, &mut destination)
            .decode()
            .unwrap();
        assert_eq!(decoded, expected);
        assert!(
            destination[expected.len()..]
                .iter()
                .all(|byte| *byte == 0xaa)
        );
    }
}

#[test]
fn hpack_huffman_reports_validated_decoded_lengths() {
    for (encoded, expected) in [
        (
            &[
                0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
            ][..],
            15,
        ),
        (&[0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf][..], 8),
        (&[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f][..], 10),
        (
            &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf][..],
            12,
        ),
        (&[][..], 0),
        (&[0xff, 0xc7, 0xff, 0xff, 0xdd][..], 2),
    ] {
        assert_eq!(
            HpackHuffmanDecoder::required_decoded_len(encoded),
            Ok(expected)
        );
    }
}

#[test]
fn hpack_huffman_length_query_matches_decode_errors_and_exact_capacity() {
    for (encoded, error) in [
        (
            &[0xff, 0xff, 0xff, 0xff][..],
            HpackHuffmanDecodeError::EosSymbol,
        ),
        (&[0x00][..], HpackHuffmanDecodeError::InvalidPadding),
        (&[0xff][..], HpackHuffmanDecodeError::InvalidPadding),
    ] {
        let mut destination = [0xaa; 8];
        assert_eq!(
            HpackHuffmanDecoder::required_decoded_len(encoded),
            Err(error)
        );
        assert_eq!(
            HpackHuffmanDecoder::new(encoded, &mut destination).decode(),
            Err(error)
        );
    }

    let encoded = [
        0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
    ];
    let required = HpackHuffmanDecoder::required_decoded_len(&encoded).unwrap();
    let mut destination = [0xaa; 15];
    assert_eq!(destination.len(), required);
    assert_eq!(
        HpackHuffmanDecoder::new(&encoded, &mut destination).decode(),
        Ok(b"www.example.com" as &[u8])
    );
}

#[test]
fn hpack_huffman_handles_empty_and_binary_outputs() {
    let mut empty_destination = [0xaa; 3];
    assert_eq!(
        HpackHuffmanDecoder::new(&[], &mut empty_destination).decode(),
        Ok(&[][..])
    );
    assert_eq!(empty_destination, [0xaa; 3]);

    let mut binary_destination = [0xaa; 4];
    let decoded =
        HpackHuffmanDecoder::new(&[0xff, 0xc7, 0xff, 0xff, 0xdd], &mut binary_destination)
            .decode()
            .unwrap();
    assert_eq!(decoded, [0, 255]);
    assert_eq!(binary_destination, [0, 255, 0xaa, 0xaa]);
}

#[test]
fn hpack_huffman_rejects_malformed_data_atomically() {
    for (encoded, error) in [
        (
            &[0xff, 0xff, 0xff, 0xff][..],
            HpackHuffmanDecodeError::EosSymbol,
        ),
        (&[0x00][..], HpackHuffmanDecodeError::InvalidPadding),
        (&[0xff][..], HpackHuffmanDecodeError::InvalidPadding),
    ] {
        let mut destination = [0xaa; 8];
        let before = destination;
        assert_eq!(
            HpackHuffmanDecoder::new(encoded, &mut destination).decode(),
            Err(error)
        );
        assert_eq!(destination, before);
    }
}

#[test]
fn hpack_huffman_short_destination_is_atomic_and_reports_capacity() {
    let encoded = [
        0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
    ];
    let mut destination = [0xaa; 14];
    let before = destination;
    assert_eq!(
        HpackHuffmanDecoder::new(&encoded, &mut destination).decode(),
        Err(HpackHuffmanDecodeError::OutputTooShort {
            required: 15,
            available: 14,
        })
    );
    assert_eq!(destination, before);
}

#[test]
fn hpack_huffman_encodes_rfc_appendix_c_vectors() {
    for (decoded, expected) in [
        (
            b"www.example.com" as &[u8],
            &[
                0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
            ][..],
        ),
        (
            b"no-cache" as &[u8],
            &[0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf][..],
        ),
        (
            b"custom-key" as &[u8],
            &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f][..],
        ),
        (
            b"custom-value" as &[u8],
            &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf][..],
        ),
    ] {
        let mut destination = [0xaa; 32];
        let encoded = HpackHuffmanEncoder::new(decoded, &mut destination)
            .encode()
            .unwrap();
        assert_eq!(encoded, expected);
        let mut decoded_destination = [0; 32];
        assert_eq!(
            HpackHuffmanDecoder::new(encoded, &mut decoded_destination).decode(),
            Ok(decoded)
        );
    }
}

#[test]
fn hpack_huffman_encoder_handles_empty_and_binary_inputs() {
    let mut empty_destination = [0xaa; 3];
    assert_eq!(HpackHuffmanEncoder::required_encoded_len(&[]), Ok(0));
    assert_eq!(
        HpackHuffmanEncoder::new(&[], &mut empty_destination).encode(),
        Ok(&[][..])
    );
    assert_eq!(empty_destination, [0xaa; 3]);

    let mut binary_destination = [0xaa; 8];
    let encoded = HpackHuffmanEncoder::new(&[0, 255], &mut binary_destination)
        .encode()
        .unwrap();
    assert_eq!(encoded, [0xff, 0xc7, 0xff, 0xff, 0xdd]);
    assert_eq!(
        binary_destination,
        [0xff, 0xc7, 0xff, 0xff, 0xdd, 0xaa, 0xaa, 0xaa]
    );
}

#[test]
fn hpack_huffman_encoder_reports_exact_lengths_and_preserves_suffix() {
    assert_eq!(
        HpackHuffmanEncoder::required_encoded_len(b"www.example.com"),
        Ok(12)
    );
    assert_eq!(
        HpackHuffmanEncoder::required_encoded_len(b"no-cache"),
        Ok(6)
    );
    assert_eq!(
        HpackHuffmanEncoder::required_encoded_len(b"custom-key"),
        Ok(8)
    );
    assert_eq!(
        HpackHuffmanEncoder::required_encoded_len(b"custom-value"),
        Ok(9)
    );

    let mut destination = [0xaa; 16];
    let encoded = HpackHuffmanEncoder::new(b"no-cache", &mut destination)
        .encode()
        .unwrap();
    assert_eq!(encoded, [0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf]);
    assert_eq!(destination[6..], [0xaa; 10]);
}

#[test]
fn hpack_huffman_encoder_short_destination_is_atomic() {
    let mut destination = [0xaa; 11];
    let before = destination;
    assert_eq!(
        HpackHuffmanEncoder::new(b"www.example.com", &mut destination).encode(),
        Err(HpackHuffmanEncodeError::DestinationTooShort {
            required: 12,
            available: 11,
        })
    );
    assert_eq!(destination, before);
}

#[test]
fn hpack_huffman_encoder_round_trips_all_byte_values() {
    let input: Vec<u8> = (0..=255).collect();
    let required = HpackHuffmanEncoder::required_encoded_len(&input).unwrap();
    let mut encoded_destination = vec![0xaa; required + 3];
    let encoded = HpackHuffmanEncoder::new(&input, &mut encoded_destination)
        .encode()
        .unwrap();
    let mut decoded_destination = [0xaa; 256];
    let decoded = HpackHuffmanDecoder::new(encoded, &mut decoded_destination)
        .decode()
        .unwrap();
    assert_eq!(decoded, input);
    assert_eq!(encoded_destination[required..], [0xaa; 3]);
}

#[test]
fn hpack_static_table_has_rfc_boundaries_and_complete_index_space() {
    assert_eq!(HpackStaticTable::len(), HPACK_STATIC_TABLE_LEN);
    assert_eq!(HpackStaticTable::len(), 61);
    assert!(!HpackStaticTable::is_empty());
    assert_eq!(HpackStaticTable::get(0), None);
    assert_eq!(
        HpackStaticTable::get(1),
        Some(HpackHeaderFieldRef::new(b":authority", b""))
    );
    assert_eq!(
        HpackStaticTable::get(61),
        Some(HpackHeaderFieldRef::new(b"www-authenticate", b""))
    );
    assert_eq!(HpackStaticTable::get(62), None);
    assert!((1..=HpackStaticTable::len()).all(|index| HpackStaticTable::get(index).is_some()));
}

#[test]
fn hpack_static_table_preserves_rfc_representative_ordering_and_empty_values() {
    for (index, expected) in [
        (2, HpackHeaderFieldRef::new(b":method", b"GET")),
        (3, HpackHeaderFieldRef::new(b":method", b"POST")),
        (4, HpackHeaderFieldRef::new(b":path", b"/")),
        (5, HpackHeaderFieldRef::new(b":path", b"/index.html")),
        (8, HpackHeaderFieldRef::new(b":status", b"200")),
        (14, HpackHeaderFieldRef::new(b":status", b"500")),
        (
            16,
            HpackHeaderFieldRef::new(b"accept-encoding", b"gzip, deflate"),
        ),
        (15, HpackHeaderFieldRef::new(b"accept-charset", b"")),
        (28, HpackHeaderFieldRef::new(b"content-length", b"")),
        (61, HpackHeaderFieldRef::new(b"www-authenticate", b"")),
    ] {
        assert_eq!(HpackStaticTable::get(index), Some(expected));
    }
}

#[test]
fn hpack_header_field_ref_is_copyable_and_byte_oriented() {
    let field = HpackHeaderFieldRef::new(&[0x80, 0xff], &[0, 0xfe]);
    let copied = field;
    assert_eq!(field, copied);
    assert_eq!(copied.name(), [0x80, 0xff]);
    assert_eq!(copied.value(), [0, 0xfe]);
}

#[test]
fn hpack_dynamic_table_capacity_is_proven_without_mutating_rejected_stores() {
    let mut no_bytes = [];
    let mut no_entries = [];
    let table = HpackDynamicTable::new(&mut no_bytes, &mut no_entries, 31).unwrap();
    assert_eq!(table.capacity(), 31);

    let mut bytes = [0xa5; 1];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 1];
    let before_bytes = bytes;
    let before_entries = entries;
    assert!(matches!(
        HpackDynamicTable::new(&mut bytes, &mut entries, 34),
        Err(HpackDynamicTableError::MaximumSizeExceedsCapacity {
            requested: 34,
            capacity: 33,
        })
    ));
    assert_eq!(bytes, before_bytes);
    assert_eq!(entries, before_entries);
}

#[test]
fn hpack_dynamic_table_copies_binary_fields_and_indexes_newest_first() {
    let mut bytes = [0; 36];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let mut table = HpackDynamicTable::new(&mut bytes, &mut entries, 68).unwrap();
    let mut name = [0xff];
    assert_eq!(
        table.insert(&name, &[0, 0x80]),
        Ok(HpackDynamicTableInsertResult::Inserted)
    );
    name[0] = 0;
    assert_eq!(name, [0]);
    assert_eq!(
        table.insert(&[], &[]),
        Ok(HpackDynamicTableInsertResult::Inserted)
    );
    assert_eq!(table.len(), 2);
    assert_eq!(table.size(), 67);
    assert_eq!(table.get(1), Some(HpackHeaderFieldRef::new(&[], &[])));
    assert_eq!(
        table.get(2),
        Some(HpackHeaderFieldRef::new(&[0xff], &[0, 0x80]))
    );
    assert_eq!(table.get(0), None);
    assert_eq!(table.get(3), None);
}

#[test]
fn hpack_dynamic_table_evicts_oldest_and_handles_oversized_entries() {
    let mut bytes = [0xcc; 36];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let mut table = HpackDynamicTable::new(&mut bytes, &mut entries, 68).unwrap();
    table.insert(b"a", b"1").unwrap();
    table.insert(b"b", b"2").unwrap();
    table.insert(b"c", b"3").unwrap();
    assert_eq!(table.get(1), Some(HpackHeaderFieldRef::new(b"c", b"3")));
    assert_eq!(table.get(2), Some(HpackHeaderFieldRef::new(b"b", b"2")));
    assert_eq!(table.get(3), None);
    assert_eq!(
        table.insert(&[0; 37], b""),
        Ok(HpackDynamicTableInsertResult::NotInsertedOversized)
    );
    assert!(table.is_empty());
    assert_eq!(table.get(1), None);
}

#[test]
fn hpack_dynamic_table_preserves_variable_length_entries_across_shift_and_eviction() {
    let mut bytes = [0; 96];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 4];
    let mut table = HpackDynamicTable::new(&mut bytes, &mut entries, 128).unwrap();

    table.insert(b"a", b"111").unwrap();
    table.insert(b"bb", b"22").unwrap();
    table.insert(b"ccc", b"3").unwrap();
    table.insert(b"dddd", b"4444").unwrap();

    assert_eq!(table.size(), 112);
    assert_eq!(
        table.get(1),
        Some(HpackHeaderFieldRef::new(b"dddd", b"4444"))
    );
    assert_eq!(table.get(2), Some(HpackHeaderFieldRef::new(b"ccc", b"3")));
    assert_eq!(table.get(3), Some(HpackHeaderFieldRef::new(b"bb", b"22")));
    assert_eq!(table.get(4), None);

    table.set_maximum_size(76).unwrap();
    assert_eq!(table.size(), 76);
    assert_eq!(
        table.get(1),
        Some(HpackHeaderFieldRef::new(b"dddd", b"4444"))
    );
    assert_eq!(table.get(2), Some(HpackHeaderFieldRef::new(b"ccc", b"3")));
    assert_eq!(table.get(3), None);
}

#[test]
fn hpack_dynamic_table_resizes_and_rejects_excess_maximum_atomically() {
    let mut bytes = [0x5a; 36];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let mut table = HpackDynamicTable::new(&mut bytes, &mut entries, 68).unwrap();
    table.insert(b"a", b"1").unwrap();
    table.insert(b"b", b"2").unwrap();
    table.set_maximum_size(34).unwrap();
    assert_eq!(table.len(), 1);
    assert_eq!(table.get(1), Some(HpackHeaderFieldRef::new(b"b", b"2")));
    table.set_maximum_size(68).unwrap();
    assert_eq!(table.maximum_size(), 68);
    let before_size = table.size();
    assert_eq!(
        table.set_maximum_size(69),
        Err(HpackDynamicTableError::MaximumSizeExceedsCapacity {
            requested: 69,
            capacity: 68,
        })
    );
    assert_eq!(table.maximum_size(), 68);
    assert_eq!(table.size(), before_size);
    assert_eq!(table.get(1), Some(HpackHeaderFieldRef::new(b"b", b"2")));
}

#[test]
fn hpack_dynamic_table_exact_maximum_and_clear_do_not_expose_stale_storage() {
    let mut bytes = [0xaa; 1];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 1];
    {
        let mut table = HpackDynamicTable::new(&mut bytes, &mut entries, 33).unwrap();
        assert_eq!(
            table.insert(b"x", b""),
            Ok(HpackDynamicTableInsertResult::Inserted)
        );
        assert_eq!(table.size(), 33);
        table.clear();
        assert!(table.is_empty());
        assert_eq!(table.get(1), None);
    }
    assert_eq!(bytes[0], b'x');
}

#[test]
fn hpack_representations_parse_all_wire_forms_and_exact_boundaries() {
    let indexed = HpackRepresentation::parse(&[0x82, 0xaa]).unwrap();
    let HpackRepresentation::Indexed(indexed) = indexed else {
        panic!("expected indexed field");
    };
    assert_eq!(indexed.as_bytes(), [0x82]);
    assert_eq!(indexed.index().as_bytes(), [0x82]);
    assert_eq!(indexed.index_value(), 2);

    let wire = [0x42, 0x81, 0xfe, 0xaa];
    let literal = HpackRepresentation::parse(&wire).unwrap();
    let HpackRepresentation::Literal(literal) = literal else {
        panic!("expected literal field");
    };
    assert_eq!(literal.as_bytes(), &wire[..3]);
    assert_eq!(literal.mode(), HpackLiteralMode::IncrementalIndexing);
    assert_eq!(literal.name_index_value(), 2);
    assert_eq!(literal.name(), None);
    assert!(literal.value().is_huffman());
    assert_eq!(literal.value().encoded_bytes(), [0xfe]);

    let wire = [0x3f, 0x80, 0x00, 0xaa];
    let update = HpackRepresentation::parse(&wire).unwrap();
    let HpackRepresentation::DynamicTableSizeUpdate(update) = update else {
        panic!("expected table size update");
    };
    assert_eq!(update.as_bytes(), &wire[..3]);
    assert_eq!(update.size().as_bytes(), [0x3f, 0x80, 0x00]);
    assert_eq!(update.size_value(), 31);

    for (wire, mode) in [
        (
            &[0x10, 0x01, b'n', 0x81, 0xff, 0xaa][..],
            HpackLiteralMode::NeverIndexed,
        ),
        (
            &[0x00, 0x81, 0x00, 0x81, 0xfe, 0xaa][..],
            HpackLiteralMode::WithoutIndexing,
        ),
    ] {
        let literal = HpackRepresentation::parse(wire).unwrap();
        let HpackRepresentation::Literal(literal) = literal else {
            panic!("expected literal field");
        };
        assert_eq!(literal.as_bytes(), &wire[..wire.len() - 1]);
        assert_eq!(literal.mode(), mode);
        assert_eq!(literal.name_index_value(), 0);
        let name = literal.name().unwrap();
        assert!(literal.value().is_huffman());
        if mode == HpackLiteralMode::NeverIndexed {
            assert_eq!(name.as_bytes(), [0x01, b'n']);
            assert!(!name.is_huffman());
        } else {
            assert_eq!(name.as_bytes(), [0x81, 0x00]);
            assert!(name.is_huffman());
        }
    }

    for (wire, mode, has_name) in [
        (
            &[0x41, 0x00][..],
            HpackLiteralMode::IncrementalIndexing,
            false,
        ),
        (
            &[0x40, 0x00, 0x00][..],
            HpackLiteralMode::IncrementalIndexing,
            true,
        ),
        (&[0x11, 0x00][..], HpackLiteralMode::NeverIndexed, false),
        (
            &[0x10, 0x00, 0x00][..],
            HpackLiteralMode::NeverIndexed,
            true,
        ),
        (&[0x01, 0x00][..], HpackLiteralMode::WithoutIndexing, false),
        (
            &[0x00, 0x00, 0x00][..],
            HpackLiteralMode::WithoutIndexing,
            true,
        ),
    ] {
        let HpackRepresentation::Literal(literal) = HpackRepresentation::parse(wire).unwrap()
        else {
            panic!("expected literal field");
        };
        assert_eq!(literal.mode(), mode);
        assert_eq!(literal.name().is_some(), has_name);
        assert_eq!(literal.name_index_value() == 0, has_name);
    }
}

#[test]
fn hpack_representations_preserve_overlong_encodings_and_dispatch_boundaries() {
    for (wire, kind) in [
        (&[0x81][..], 0),
        (&[0x40, 0x00, 0x00][..], 1),
        (&[0x20][..], 2),
        (&[0x10, 0x00, 0x00][..], 3),
        (&[0x00, 0x00, 0x00][..], 4),
    ] {
        match (kind, HpackRepresentation::parse(wire).unwrap()) {
            (0, HpackRepresentation::Indexed(_))
            | (1 | 3 | 4, HpackRepresentation::Literal(_))
            | (2, HpackRepresentation::DynamicTableSizeUpdate(_)) => {}
            _ => panic!("wrong representation dispatch"),
        }
    }

    let wire = [0x7f, 0x80, 0x00, 0x00, 0xaa];
    let literal = HpackRepresentation::parse(&wire).unwrap();
    let HpackRepresentation::Literal(literal) = literal else {
        panic!("expected literal field");
    };
    assert_eq!(literal.as_bytes(), &wire[..4]);
    assert_eq!(literal.name_index().as_bytes(), [0x7f, 0x80, 0x00]);
    assert_eq!(literal.name_index_value(), 63);
    assert_eq!(literal.value().length().as_bytes(), [0x00]);
    assert_eq!(literal.value().encoded_bytes(), []);
}

#[test]
fn hpack_representations_distinguish_malformed_components() {
    assert_eq!(
        HpackRepresentation::parse(&[0xff]),
        Err(HpackRepresentationParseError::IndexedIndex(
            HpackIntegerParseError::Incomplete {
                required: 2,
                available: 1,
            }
        ))
    );
    assert_eq!(
        HpackRepresentation::parse(&[0x80, 0x00]),
        Err(HpackRepresentationParseError::IndexedFieldZero)
    );
    assert_eq!(
        HpackRepresentation::parse(&[0x7f]),
        Err(HpackRepresentationParseError::LiteralNameIndex(
            HpackIntegerParseError::Incomplete {
                required: 2,
                available: 1,
            }
        ))
    );
    assert!(matches!(
        HpackRepresentation::parse(&[0x00, 0x02, b'n']),
        Err(HpackRepresentationParseError::LiteralName(
            HpackStringLiteralParseError::IncompleteEncodedPayload { .. }
        ))
    ));
    assert!(matches!(
        HpackRepresentation::parse(&[0x42, 0x02, b'v']),
        Err(HpackRepresentationParseError::LiteralValue(
            HpackStringLiteralParseError::IncompleteEncodedPayload { .. }
        ))
    ));
}

#[test]
fn hpack_block_decoder_completes_and_resolves_static_indices() {
    let mut bytes = [0xaa; 64];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let table = HpackDynamicTable::new(&mut bytes, &mut entries, 64).unwrap();
    let mut context = HpackDecoderContext::new(table, 64).unwrap();

    let mut empty = context.decode_block(&[]);
    let mut output = [0xcc; 32];
    assert_eq!(
        empty.decode_next(&mut output),
        Ok(HpackDecodeStep::Complete)
    );
    assert_eq!(empty.remaining(), []);

    let block = [0x81, 0xbd];
    let mut decoder = context.decode_block(&block);
    let HpackDecodeStep::Field(first) = decoder.decode_next(&mut output).unwrap() else {
        panic!("expected indexed field");
    };
    assert_eq!(first.name(), b":authority");
    assert_eq!(first.value(), b"");
    assert!(output[10..].iter().all(|byte| *byte == 0xcc));
    let HpackDecodeStep::Field(last) = decoder.decode_next(&mut output).unwrap() else {
        panic!("expected indexed field");
    };
    assert_eq!(last.name(), b"www-authenticate");
    assert_eq!(last.value(), b"");
    assert_eq!(decoder.remaining(), []);
    let _ = decoder;

    let mut unavailable = context.decode_block(&[0xbe]);
    let before = output;
    assert_eq!(
        unavailable.decode_next(&mut output),
        Err(HpackDecodeError::UnavailableIndex { index: 62 })
    );
    assert_eq!(output, before);
    assert_eq!(unavailable.remaining(), [0xbe]);
}

#[test]
fn hpack_block_decoder_decodes_literals_and_dynamic_indices() {
    let mut bytes = [0; 80];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let table = HpackDynamicTable::new(&mut bytes, &mut entries, 70).unwrap();
    let block = [
        0x42, 0x01, b'a', 0x40, 0x01, b'b', 0x01, b'c', 0x00, 0x88, 0x25, 0xa8, 0x49, 0xe9, 0x5b,
        0xa9, 0x7d, 0x7f, 0x89, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf,
    ];
    let mut context = HpackDecoderContext::new(table, 70).unwrap();
    let mut decoder = context.decode_block(&block);
    let mut output = [0xcc; 32];
    for (name, value, mode) in [
        (
            b":method" as &[u8],
            b"a" as &[u8],
            HpackDecodedFieldMode::IncrementalIndexing,
        ),
        (
            b"b" as &[u8],
            b"c" as &[u8],
            HpackDecodedFieldMode::IncrementalIndexing,
        ),
        (
            b"custom-key" as &[u8],
            b"custom-value" as &[u8],
            HpackDecodedFieldMode::WithoutIndexing,
        ),
    ] {
        let HpackDecodeStep::Field(field) = decoder.decode_next(&mut output).unwrap() else {
            panic!("expected literal field");
        };
        assert_eq!(field.name(), name);
        assert_eq!(field.value(), value);
        assert_eq!(field.mode(), mode);
    }
    let _ = decoder;
    assert_eq!(
        context.dynamic_table().get(1),
        Some(HpackHeaderFieldRef::new(b"b", b"c"))
    );
    assert_eq!(context.dynamic_table().get(2), None);

    let mut indexed = context.decode_block(&[0xbe]);
    let HpackDecodeStep::Field(field) = indexed.decode_next(&mut output).unwrap() else {
        panic!("expected dynamic indexed field");
    };
    assert_eq!(field.name(), b"b");
    assert_eq!(field.value(), b"c");
    let _ = indexed;

    let mut never = context.decode_block(&[0x10, 0x01, b'n', 0x01, b'v']);
    assert!(matches!(
        never.decode_next(&mut output),
        Ok(HpackDecodeStep::Field(_))
    ));
    let _ = never;
    assert_eq!(context.dynamic_table().len(), 1);
}

#[test]
fn hpack_block_decoder_applies_only_leading_size_updates() {
    let mut bytes = [0; 64];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let table = HpackDynamicTable::new(&mut bytes, &mut entries, 33).unwrap();
    let mut context = HpackDecoderContext::new(table, 33).unwrap();
    let mut decoder = context.decode_block(&[0x3f, 0x01, 0x3f, 0x02]);
    let mut output = [];
    assert_eq!(
        decoder.decode_next(&mut output),
        Ok(HpackDecodeStep::DynamicTableSizeUpdate { maximum_size: 32 })
    );
    assert_eq!(
        decoder.decode_next(&mut output),
        Ok(HpackDecodeStep::DynamicTableSizeUpdate { maximum_size: 33 })
    );
    let _ = decoder;
    assert_eq!(context.dynamic_table().maximum_size(), 33);

    let mut after_field = context.decode_block(&[0x00, 0x00, 0x00, 0x20]);
    let mut field_output = [0; 1];
    assert!(matches!(
        after_field.decode_next(&mut field_output),
        Ok(HpackDecodeStep::Field(_))
    ));
    assert_eq!(
        after_field.decode_next(&mut field_output),
        Err(HpackDecodeError::DynamicTableSizeUpdateAfterField)
    );
    assert_eq!(after_field.remaining(), [0x20]);
    let _ = after_field;
    assert_eq!(context.dynamic_table().maximum_size(), 33);
    let mut table = context.into_dynamic_table();
    table.set_maximum_size(32).unwrap();
    let mut context = HpackDecoderContext::new(table, 32).unwrap();

    let mut above = context.decode_block(&[0x3f, 0x02]);
    assert_eq!(
        above.decode_next(&mut output),
        Err(HpackDecodeError::DynamicTableSizeUpdateExceedsAllowed {
            requested: 33,
            allowed: 32,
        })
    );
    assert_eq!(above.remaining(), [0x3f, 0x02]);
}

#[test]
fn hpack_block_decoder_requires_leading_size_update_after_policy_reduction() {
    let mut bytes = [0xaa; 64];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let table = HpackDynamicTable::new(&mut bytes, &mut entries, 64).unwrap();
    let mut context = HpackDecoderContext::new(table, 63).unwrap();
    let mut output = [0xcc; 32];

    let mut field_first = context.decode_block(&[0x81]);
    let before_output = output;
    assert_eq!(
        field_first.decode_next(&mut output),
        Err(HpackDecodeError::DynamicTableSizeUpdateRequired)
    );
    assert_eq!(field_first.remaining(), [0x81]);
    assert_eq!(output, before_output);
    let _ = field_first;
    assert_eq!(context.dynamic_table().maximum_size(), 64);

    let mut empty = context.decode_block(&[]);
    assert_eq!(
        empty.decode_next(&mut output),
        Err(HpackDecodeError::DynamicTableSizeUpdateRequired)
    );
    assert!(empty.is_complete());
    let _ = empty;

    let mut above = context.decode_block(&[0x3f, 0x21]);
    assert_eq!(
        above.decode_next(&mut output),
        Err(HpackDecodeError::DynamicTableSizeUpdateMismatch {
            expected: 63,
            requested: 64,
        })
    );
    assert_eq!(above.remaining(), [0x3f, 0x21]);
    assert_eq!(output, before_output);
    let _ = above;
    assert_eq!(context.dynamic_table().maximum_size(), 64);

    let mut decoder = context.decode_block(&[0x3f, 0x20, 0x81]);
    assert_eq!(
        decoder.decode_next(&mut output),
        Ok(HpackDecodeStep::DynamicTableSizeUpdate { maximum_size: 63 })
    );
    let HpackDecodeStep::Field(field) = decoder.decode_next(&mut output).unwrap() else {
        panic!("expected indexed field");
    };
    assert_eq!(field.name(), b":authority");
    assert_eq!(context.dynamic_table().maximum_size(), 63);
}

#[test]
fn hpack_block_decoder_failures_preserve_caller_stores_and_output() {
    let mut bytes = [0x5a; 80];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let mut table = HpackDynamicTable::new(&mut bytes, &mut entries, 70).unwrap();
    table.insert(b"old", b"entry").unwrap();
    let mut context = HpackDecoderContext::new(table, 70).unwrap();

    for (block, expected) in [
        (
            &[0xff][..],
            HpackDecodeError::Representation(HpackRepresentationParseError::IndexedIndex(
                HpackIntegerParseError::Incomplete {
                    required: 2,
                    available: 1,
                },
            )),
        ),
        (
            &[0x00, 0x81, 0x00, 0x00][..],
            HpackDecodeError::HuffmanName(HpackHuffmanDecodeError::InvalidPadding),
        ),
        (
            &[0x00, 0x01, b'n', 0x81, 0x00][..],
            HpackDecodeError::HuffmanValue(HpackHuffmanDecodeError::InvalidPadding),
        ),
        (
            &[0x0f, 0x30, 0x00][..],
            HpackDecodeError::UnavailableIndex { index: 63 },
        ),
    ] {
        let mut decoder = context.decode_block(block);
        let mut output = [0xcc; 8];
        let before_output = output;
        assert_eq!(decoder.decode_next(&mut output), Err(expected));
        assert_eq!(output, before_output);
        assert_eq!(decoder.remaining(), block);
        let _ = decoder;
        assert_eq!(
            context.dynamic_table().get(1),
            Some(HpackHeaderFieldRef::new(b"old", b"entry"))
        );
    }
    let mut short = context.decode_block(&[0x40, 0x01, b'n', 0x01, b'v']);
    let mut output = [0xcc; 1];
    assert_eq!(
        short.decode_next(&mut output),
        Err(HpackDecodeError::OutputTooShort {
            required: 2,
            available: 1,
        })
    );
    let _ = short;
    assert_eq!(
        context.dynamic_table().get(1),
        Some(HpackHeaderFieldRef::new(b"old", b"entry"))
    );

    let table = context.into_dynamic_table();
    assert!(matches!(
        HpackDecoderContext::new(table, 96),
        Err(HpackDecodeError::AllowedMaximumExceedsCapacity { .. })
    ));
    let _ = table;

    let mut empty_bytes = [0x3c; 64];
    let mut empty_entries = [HpackDynamicTableEntry::EMPTY; 2];
    let before_bytes = empty_bytes;
    let before_entries = empty_entries;
    {
        let empty_table = HpackDynamicTable::new(&mut empty_bytes, &mut empty_entries, 64).unwrap();
        let mut context = HpackDecoderContext::new(empty_table, 64).unwrap();
        let mut decoder = context.decode_block(&[0x40, 0x01, b'n', 0x01, b'v']);
        let mut short_output = [0xcc; 1];
        assert!(matches!(
            decoder.decode_next(&mut short_output),
            Err(HpackDecodeError::OutputTooShort { .. })
        ));
    }
    assert_eq!(empty_bytes, before_bytes);
    assert_eq!(empty_entries, before_entries);
}

#[test]
fn hpack_block_decoder_oversized_incremental_field_clears_and_emits() {
    let mut bytes = [0; 64];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let mut table = HpackDynamicTable::new(&mut bytes, &mut entries, 34).unwrap();
    table.insert(b"a", b"b").unwrap();
    let mut context = HpackDecoderContext::new(table, 34).unwrap();
    let mut decoder = context.decode_block(&[0x40, 0x03, b'n', b'a', b'm', 0x00]);
    let mut output = [0xcc; 8];
    let HpackDecodeStep::Field(field) = decoder.decode_next(&mut output).unwrap() else {
        panic!("expected oversized literal field");
    };
    assert_eq!(field.name(), b"nam");
    assert_eq!(field.value(), b"");
    let _ = decoder;
    assert!(context.dynamic_table().is_empty());
}

#[test]
fn hpack_representation_builders_emit_all_forms_and_round_trip() {
    let mut indexed_destination = [0xaa; 4];
    let indexed = HpackIndexedFieldBuilder::new(&mut indexed_destination, 2)
        .build()
        .unwrap();
    assert_eq!(indexed, [0x82]);
    let indexed = indexed.to_vec();
    assert_eq!(indexed_destination, [0x82, 0xaa, 0xaa, 0xaa]);
    assert!(matches!(
        HpackRepresentation::parse(&indexed),
        Ok(HpackRepresentation::Indexed(field)) if field.index_value() == 2
    ));

    let mut update_destination = [0xaa; 4];
    let update = HpackDynamicTableSizeUpdateBuilder::new(&mut update_destination, 31)
        .build()
        .unwrap();
    assert_eq!(update, [0x3f, 0x00]);
    assert!(matches!(
        HpackRepresentation::parse(update),
        Ok(HpackRepresentation::DynamicTableSizeUpdate(field)) if field.size_value() == 31
    ));

    for (mode, prefix) in [
        (HpackLiteralMode::IncrementalIndexing, 0x40),
        (HpackLiteralMode::WithoutIndexing, 0x00),
        (HpackLiteralMode::NeverIndexed, 0x10),
    ] {
        let mut destination = [0xaa; 8];
        let wire = HpackLiteralFieldBuilder::new(
            &mut destination,
            mode,
            HpackLiteralName::Literal {
                encoded_bytes: &[0, 0xff],
                huffman: true,
            },
            HpackLiteralValue::new_encoded(&[0x80], false),
        )
        .build()
        .unwrap();
        assert_eq!(wire, [prefix, 0x82, 0, 0xff, 0x01, 0x80]);
        let HpackRepresentation::Literal(field) = HpackRepresentation::parse(wire).unwrap() else {
            panic!("expected literal field");
        };
        assert_eq!(field.mode(), mode);
        assert_eq!(field.name().unwrap().encoded_bytes(), [0, 0xff]);
        assert!(field.name().unwrap().is_huffman());
        assert_eq!(field.value().encoded_bytes(), [0x80]);
        assert!(!field.value().is_huffman());
        assert_eq!(destination[6..], [0xaa; 2]);
    }
}

#[test]
fn hpack_literal_builders_cover_indices_string_boundaries_and_atomicity() {
    for (mode, index, expected) in [
        (
            HpackLiteralMode::IncrementalIndexing,
            63,
            vec![0x7f, 0x00, 0x00],
        ),
        (
            HpackLiteralMode::IncrementalIndexing,
            64,
            vec![0x7f, 0x01, 0x00],
        ),
        (
            HpackLiteralMode::WithoutIndexing,
            15,
            vec![0x0f, 0x00, 0x00],
        ),
        (
            HpackLiteralMode::WithoutIndexing,
            16,
            vec![0x0f, 0x01, 0x00],
        ),
        (HpackLiteralMode::NeverIndexed, 15, vec![0x1f, 0x00, 0x00]),
        (HpackLiteralMode::NeverIndexed, 16, vec![0x1f, 0x01, 0x00]),
    ] {
        let mut destination = [0xaa; 8];
        let wire = HpackLiteralFieldBuilder::new(
            &mut destination,
            mode,
            HpackLiteralName::Indexed(index),
            HpackLiteralValue::new_encoded(&[], false),
        )
        .build()
        .unwrap();
        assert_eq!(wire, expected);
        let HpackRepresentation::Literal(field) = HpackRepresentation::parse(wire).unwrap() else {
            panic!("expected literal field");
        };
        assert_eq!(field.name_index_value(), index);
        assert_eq!(field.name(), None);
    }
    for (index, expected) in [(127, vec![0xff, 0]), (128, vec![0xff, 1])] {
        let mut destination = [0xaa; 3];
        assert_eq!(
            HpackIndexedFieldBuilder::new(&mut destination, index)
                .build()
                .unwrap(),
            expected
        );
    }
    for (size, expected) in [(31, vec![0x3f, 0]), (32, vec![0x3f, 1])] {
        let mut destination = [0xaa; 3];
        assert_eq!(
            HpackDynamicTableSizeUpdateBuilder::new(&mut destination, size)
                .build()
                .unwrap(),
            expected
        );
    }
    let mut maximum_destination = [0xaa; 16];
    let maximum_index = HpackIndexedFieldBuilder::new(&mut maximum_destination, u64::MAX)
        .build()
        .unwrap();
    let HpackRepresentation::Indexed(maximum_index) =
        HpackRepresentation::parse(maximum_index).unwrap()
    else {
        panic!("expected indexed field");
    };
    assert_eq!(maximum_index.index_value(), u64::MAX);

    let maximum_update =
        HpackDynamicTableSizeUpdateBuilder::new(&mut maximum_destination, u64::MAX)
            .build()
            .unwrap();
    let HpackRepresentation::DynamicTableSizeUpdate(maximum_update) =
        HpackRepresentation::parse(maximum_update).unwrap()
    else {
        panic!("expected dynamic table size update");
    };
    assert_eq!(maximum_update.size_value(), u64::MAX);

    let maximum_literal = HpackLiteralFieldBuilder::new(
        &mut maximum_destination,
        HpackLiteralMode::IncrementalIndexing,
        HpackLiteralName::Indexed(u64::MAX),
        HpackLiteralValue::new_encoded(&[], false),
    )
    .build()
    .unwrap();
    let HpackRepresentation::Literal(maximum_literal) =
        HpackRepresentation::parse(maximum_literal).unwrap()
    else {
        panic!("expected literal field");
    };
    assert_eq!(maximum_literal.name_index_value(), u64::MAX);

    for length in [127, 128] {
        let value = vec![0x5a; length];
        let mut destination = vec![0xaa; length + 4];
        let wire = HpackLiteralFieldBuilder::new(
            &mut destination,
            HpackLiteralMode::WithoutIndexing,
            HpackLiteralName::Indexed(1),
            HpackLiteralValue::new_encoded(&value, true),
        )
        .build()
        .unwrap();
        assert_eq!(wire[1], 0xff);
        assert_eq!(wire[2], if length == 127 { 0 } else { 1 });
        assert!(
            matches!(HpackRepresentation::parse(wire), Ok(HpackRepresentation::Literal(field)) if field.value().is_huffman())
        );
    }

    let name = [0x80, 0xff];
    let value = [0, 0xfe];
    let mut full_destination = [0xaa; 16];
    let full = HpackLiteralFieldBuilder::new(
        &mut full_destination,
        HpackLiteralMode::IncrementalIndexing,
        HpackLiteralName::Literal {
            encoded_bytes: &name,
            huffman: true,
        },
        HpackLiteralValue::new_encoded(&value, false),
    )
    .build()
    .unwrap()
    .to_vec();
    for available in 0..full.len() {
        let mut destination = vec![0xaa; available];
        let before = destination.clone();
        assert_eq!(
            HpackLiteralFieldBuilder::new(
                &mut destination,
                HpackLiteralMode::IncrementalIndexing,
                HpackLiteralName::Literal {
                    encoded_bytes: &name,
                    huffman: true
                },
                HpackLiteralValue::new_encoded(&value, false),
            )
            .build(),
            Err(HpackRepresentationBuildError::BufferTooShort {
                required: full.len(),
                available
            })
        );
        assert_eq!(destination, before);
    }
    let mut zero_destination = [0xaa; 4];
    let before = zero_destination;
    assert_eq!(
        HpackIndexedFieldBuilder::new(&mut zero_destination, 0).build(),
        Err(HpackRepresentationBuildError::IndexedFieldZero)
    );
    assert_eq!(zero_destination, before);

    for mode in [
        HpackLiteralMode::IncrementalIndexing,
        HpackLiteralMode::WithoutIndexing,
        HpackLiteralMode::NeverIndexed,
    ] {
        let mut destination = [0xaa; 4];
        let before = destination;
        assert_eq!(
            HpackLiteralFieldBuilder::new(
                &mut destination,
                mode,
                HpackLiteralName::Indexed(0),
                HpackLiteralValue::new_encoded(&[], false),
            )
            .build(),
            Err(HpackRepresentationBuildError::LiteralNameIndexZero)
        );
        assert_eq!(destination, before);
    }
}

#[test]
fn hpack_representation_builder_output_does_not_borrow_inputs() {
    let mut source_name = *b"n";
    let mut source_value = *b"v";
    let mut destination = [0xaa; 8];
    let output = HpackLiteralFieldBuilder::new(
        &mut destination,
        HpackLiteralMode::WithoutIndexing,
        HpackLiteralName::Literal {
            encoded_bytes: &source_name,
            huffman: false,
        },
        HpackLiteralValue::new_encoded(&source_value, false),
    )
    .build()
    .unwrap();
    source_name[0] = b'x';
    source_value[0] = b'y';
    assert_eq!(source_name, *b"x");
    assert_eq!(source_value, *b"y");
    let HpackRepresentation::Literal(field) = HpackRepresentation::parse(output).unwrap() else {
        panic!("expected literal field");
    };
    assert_eq!(field.name().unwrap().encoded_bytes(), b"n");
    assert_eq!(field.value().encoded_bytes(), b"v");
}

#[test]
fn hpack_contexts_preserve_pending_size_history_without_redundant_updates() {
    let mut encoder_bytes = [0; 128];
    let mut encoder_entries = [HpackDynamicTableEntry::EMPTY; 4];
    let encoder_table =
        HpackDynamicTable::new(&mut encoder_bytes, &mut encoder_entries, 64).unwrap();
    let mut encoder = HpackEncoderContext::new(encoder_table, 64).unwrap();
    assert_eq!(encoder.next_required_size_update(), None);
    encoder.set_allowed_maximum_size(64).unwrap();
    assert_eq!(encoder.next_required_size_update(), None);
    encoder.set_allowed_maximum_size(128).unwrap();
    assert_eq!(encoder.next_required_size_update(), Some(128));

    let mut decreasing_bytes = [0; 128];
    let mut decreasing_entries = [HpackDynamicTableEntry::EMPTY; 4];
    let decreasing_table =
        HpackDynamicTable::new(&mut decreasing_bytes, &mut decreasing_entries, 64).unwrap();
    let mut decreasing = HpackEncoderContext::new(decreasing_table, 64).unwrap();
    decreasing.set_allowed_maximum_size(48).unwrap();
    decreasing.set_allowed_maximum_size(40).unwrap();
    assert_eq!(decreasing.next_required_size_update(), Some(40));

    let mut history_bytes = [0; 128];
    let mut history_entries = [HpackDynamicTableEntry::EMPTY; 4];
    let history_table =
        HpackDynamicTable::new(&mut history_bytes, &mut history_entries, 64).unwrap();
    let mut history = HpackEncoderContext::new(history_table, 64).unwrap();
    history.set_allowed_maximum_size(32).unwrap();
    history.set_allowed_maximum_size(64).unwrap();
    assert_eq!(history.next_required_size_update(), Some(32));
    {
        let mut block = history.begin_block();
        let mut destination = [0xaa; 2];
        assert_eq!(
            block
                .encode_dynamic_table_size_update(&mut destination, 32)
                .unwrap(),
            [0x3f, 0x01]
        );
    }
    assert_eq!(history.next_required_size_update(), Some(64));

    let mut collapsed_bytes = [0; 128];
    let mut collapsed_entries = [HpackDynamicTableEntry::EMPTY; 4];
    let collapsed_table =
        HpackDynamicTable::new(&mut collapsed_bytes, &mut collapsed_entries, 64).unwrap();
    let mut collapsed = HpackEncoderContext::new(collapsed_table, 64).unwrap();
    collapsed.set_allowed_maximum_size(128).unwrap();
    collapsed.set_allowed_maximum_size(64).unwrap();
    assert_eq!(collapsed.next_required_size_update(), Some(64));

    let mut decoder_bytes = [0; 128];
    let mut decoder_entries = [HpackDynamicTableEntry::EMPTY; 4];
    let decoder_table =
        HpackDynamicTable::new(&mut decoder_bytes, &mut decoder_entries, 64).unwrap();
    let mut decoder = HpackDecoderContext::new(decoder_table, 64).unwrap();
    decoder.set_allowed_maximum_size(64).unwrap();
    assert_eq!(decoder.next_required_size_update(), None);
    decoder.set_allowed_maximum_size(128).unwrap();
    assert_eq!(decoder.next_required_size_update(), Some(128));
    decoder.set_allowed_maximum_size(64).unwrap();
    assert_eq!(decoder.next_required_size_update(), Some(64));
}

#[test]
fn hpack_encoder_two_pending_size_updates_are_atomic_and_complete() {
    let mut bytes = [0; 128];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 4];
    let mut table = HpackDynamicTable::new(&mut bytes, &mut entries, 64).unwrap();
    table.insert(b"a", b"b").unwrap();
    let mut context = HpackEncoderContext::new(table, 64).unwrap();
    context.set_allowed_maximum_size(32).unwrap();
    context.set_allowed_maximum_size(64).unwrap();
    assert_eq!(context.next_required_size_update(), Some(32));

    assert_eq!(
        context.begin_block().finish(),
        Err(HpackEncodeError::DynamicTableSizeUpdateRequired)
    );
    assert_eq!(context.next_required_size_update(), Some(32));
    assert_eq!(context.dynamic_table().maximum_size(), 64);
    assert_eq!(
        context.dynamic_table().get(1),
        Some(HpackHeaderFieldRef::new(b"a", b"b"))
    );

    {
        let mut block = context.begin_block();
        let mut wrong = [0xaa; 4];
        let before_wrong = wrong;
        assert_eq!(
            block.encode_dynamic_table_size_update(&mut wrong, 64),
            Err(HpackEncodeError::DynamicTableSizeUpdateMismatch {
                expected: 32,
                requested: 64,
            })
        );
        assert_eq!(wrong, before_wrong);

        let mut short = [0xaa; 1];
        let before_short = short;
        assert!(matches!(
            block.encode_dynamic_table_size_update(&mut short, 32),
            Err(HpackEncodeError::Representation(
                HpackRepresentationBuildError::BufferTooShort {
                    required: 2,
                    available: 1,
                }
            ))
        ));
        assert_eq!(short, before_short);
    }
    assert_eq!(context.next_required_size_update(), Some(32));
    assert_eq!(context.dynamic_table().maximum_size(), 64);
    assert_eq!(
        context.dynamic_table().get(1),
        Some(HpackHeaderFieldRef::new(b"a", b"b"))
    );

    {
        let mut block = context.begin_block();
        let mut first_destination = [0xaa; 4];
        assert_eq!(
            block
                .encode_dynamic_table_size_update(&mut first_destination, 32)
                .unwrap(),
            [0x3f, 0x01]
        );
        assert_eq!(first_destination[2..], [0xaa; 2]);

        let mut second_destination = [0xaa; 4];
        assert_eq!(
            block
                .encode_dynamic_table_size_update(&mut second_destination, 64)
                .unwrap(),
            [0x3f, 0x21]
        );
        assert_eq!(second_destination[2..], [0xaa; 2]);
        block.finish().unwrap();
    }
    assert_eq!(context.next_required_size_update(), None);
    assert_eq!(context.dynamic_table().maximum_size(), 64);
    assert!(context.dynamic_table().is_empty());
    context.begin_block().finish().unwrap();
}

#[test]
fn hpack_decoder_two_pending_size_updates_are_atomic_and_complete() {
    let mut bytes = [0; 128];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 4];
    let mut table = HpackDynamicTable::new(&mut bytes, &mut entries, 64).unwrap();
    table.insert(b"a", b"b").unwrap();
    let mut context = HpackDecoderContext::new(table, 64).unwrap();
    context.set_allowed_maximum_size(32).unwrap();
    context.set_allowed_maximum_size(64).unwrap();
    let mut output = [0xcc; 16];
    let before_output = output;

    {
        let mut empty = context.decode_block(&[]);
        assert_eq!(
            empty.decode_next(&mut output),
            Err(HpackDecodeError::DynamicTableSizeUpdateRequired)
        );
    }
    {
        let mut field_first = context.decode_block(&[0x81]);
        assert_eq!(
            field_first.decode_next(&mut output),
            Err(HpackDecodeError::DynamicTableSizeUpdateRequired)
        );
        assert_eq!(field_first.remaining(), [0x81]);
    }
    {
        let mut wrong = context.decode_block(&[0x3f, 0x21]);
        assert_eq!(
            wrong.decode_next(&mut output),
            Err(HpackDecodeError::DynamicTableSizeUpdateMismatch {
                expected: 32,
                requested: 64,
            })
        );
        assert_eq!(wrong.remaining(), [0x3f, 0x21]);
    }
    assert_eq!(output, before_output);
    assert_eq!(context.next_required_size_update(), Some(32));
    assert_eq!(context.dynamic_table().maximum_size(), 64);
    assert_eq!(
        context.dynamic_table().get(1),
        Some(HpackHeaderFieldRef::new(b"a", b"b"))
    );

    let mut decoder = context.decode_block(&[0x3f, 0x01, 0x3f, 0x21, 0x81]);
    assert_eq!(
        decoder.decode_next(&mut output),
        Ok(HpackDecodeStep::DynamicTableSizeUpdate { maximum_size: 32 })
    );
    assert_eq!(
        decoder.decode_next(&mut output),
        Ok(HpackDecodeStep::DynamicTableSizeUpdate { maximum_size: 64 })
    );
    let HpackDecodeStep::Field(field) = decoder.decode_next(&mut output).unwrap() else {
        panic!("expected static indexed field");
    };
    assert_eq!(field.name(), b":authority");
    assert_eq!(field.value(), b"");
    assert_eq!(output[10..], [0xcc; 6]);
    assert_eq!(
        decoder.decode_next(&mut output),
        Ok(HpackDecodeStep::Complete)
    );
    let _ = decoder;

    assert_eq!(context.next_required_size_update(), None);
    assert_eq!(context.dynamic_table().maximum_size(), 64);
    assert!(context.dynamic_table().is_empty());
    assert_eq!(
        context.decode_block(&[]).decode_next(&mut output),
        Ok(HpackDecodeStep::Complete)
    );
}

#[test]
fn hpack_block_encoder_requires_and_emits_leading_size_updates() {
    let mut bytes = [0x5a; 64];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let before_bytes = bytes;
    let before_entries = entries;
    {
        let table = HpackDynamicTable::new(&mut bytes, &mut entries, 64).unwrap();
        let mut context = HpackEncoderContext::new(table, 32).unwrap();
        let mut encoder = context.begin_block();
        assert!(encoder.requires_size_update());

        let mut short_destination = [0xaa; 1];
        let before_short_destination = short_destination;
        assert_eq!(
            encoder.encode_dynamic_table_size_update(&mut short_destination, 32),
            Err(HpackEncodeError::Representation(
                HpackRepresentationBuildError::BufferTooShort {
                    required: 2,
                    available: 1,
                }
            ))
        );
        assert_eq!(short_destination, before_short_destination);
        assert!(encoder.requires_size_update());
        assert_eq!(context.dynamic_table().maximum_size(), 64);
    }
    assert_eq!(bytes, before_bytes);
    assert_eq!(entries, before_entries);

    {
        let table = HpackDynamicTable::new(&mut bytes, &mut entries, 64).unwrap();
        let mut context = HpackEncoderContext::new(table, 32).unwrap();
        let mut encoder = context.begin_block();
        assert!(encoder.requires_size_update());
        let mut indexed_destination = [0xaa; 4];
        let before_destination = indexed_destination;
        assert_eq!(
            encoder.encode_indexed(&mut indexed_destination, 1),
            Err(HpackEncodeError::DynamicTableSizeUpdateRequired)
        );
        assert_eq!(indexed_destination, before_destination);
        assert!(encoder.requires_size_update());

        let mut destination = [0xaa; 4];
        let update = encoder
            .encode_dynamic_table_size_update(&mut destination, 32)
            .unwrap();
        assert_eq!(update, [0x3f, 0x01]);
        assert!(matches!(
            HpackRepresentation::parse(update),
            Ok(HpackRepresentation::DynamicTableSizeUpdate(field)) if field.size_value() == 32
        ));
        assert!(!encoder.requires_size_update());
        assert_eq!(destination[2..], [0xaa; 2]);

        let repeated = encoder
            .encode_dynamic_table_size_update(&mut destination, 30)
            .unwrap();
        assert_eq!(repeated, [0x3e]);
        assert_eq!(context.dynamic_table().maximum_size(), 30);
    }
    assert_eq!(bytes, before_bytes);
    assert_eq!(entries, before_entries);
}

#[test]
fn hpack_block_encoder_encodes_resolved_indices_and_preserves_output_lifetimes() {
    let mut bytes = [0; 64];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let mut table = HpackDynamicTable::new(&mut bytes, &mut entries, 64).unwrap();
    table.insert(b"n", b"v").unwrap();

    let mut context = HpackEncoderContext::new(table, 64).unwrap();
    {
        let mut encoder = context.begin_block();
        let mut destination = [0xaa; 4];
        let static_output = encoder.encode_indexed(&mut destination, 2).unwrap();
        assert_eq!(static_output, [0x82]);
        assert!(encoder.has_emitted_field());
        assert!(matches!(
            HpackRepresentation::parse(static_output),
            Ok(HpackRepresentation::Indexed(field)) if field.index_value() == 2
        ));
        assert_eq!(destination[1..], [0xaa; 3]);

        let dynamic_output = encoder.encode_indexed(&mut destination, 62).unwrap();
        assert_eq!(dynamic_output, [0xbe]);
        assert!(matches!(
            HpackRepresentation::parse(dynamic_output),
            Ok(HpackRepresentation::Indexed(field)) if field.index_value() == 62
        ));

        let before_destination = destination;
        assert_eq!(
            encoder.encode_indexed(&mut destination, 0),
            Err(HpackEncodeError::UnavailableIndex { index: 0 })
        );
        assert_eq!(
            encoder.encode_indexed(&mut destination, 63),
            Err(HpackEncodeError::UnavailableIndex { index: 63 })
        );
        assert_eq!(destination, before_destination);
        assert_eq!(
            encoder.encode_dynamic_table_size_update(&mut destination, 32),
            Err(HpackEncodeError::DynamicTableSizeUpdateAfterField)
        );
        assert_eq!(destination, before_destination);
        assert_eq!(
            context.dynamic_table().get(1),
            Some(HpackHeaderFieldRef::new(b"n", b"v"))
        );
    }
}

#[test]
fn hpack_block_encoder_rejects_policy_and_capacity_atomically() {
    let mut bytes = [0x5a; 64];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let before_bytes = bytes;
    let before_entries = entries;

    {
        let table = HpackDynamicTable::new(&mut bytes, &mut entries, 64).unwrap();
        let mut context = HpackEncoderContext::new(table, 63).unwrap();
        let mut encoder = context.begin_block();
        let mut destination = [0xaa; 4];
        let before_destination = destination;
        assert_eq!(
            encoder.encode_dynamic_table_size_update(&mut destination, 64),
            Err(HpackEncodeError::DynamicTableSizeUpdateMismatch {
                expected: 63,
                requested: 64,
            })
        );
        assert_eq!(destination, before_destination);
        assert!(encoder.requires_size_update());
        assert_eq!(context.dynamic_table().maximum_size(), 64);
        let table = context.into_dynamic_table();

        assert!(matches!(
            HpackEncoderContext::new(table, 96),
            Err(HpackEncodeError::AllowedMaximumExceedsCapacity {
                allowed: 96,
                capacity: 95,
            })
        ));
    }
    assert_eq!(bytes, before_bytes);
    assert_eq!(entries, before_entries);
}

#[test]
fn hpack_block_encoder_emits_plain_literal_names_in_every_mode() {
    for (mode, first) in [
        (HpackLiteralMode::IncrementalIndexing, 0x40),
        (HpackLiteralMode::WithoutIndexing, 0),
        (HpackLiteralMode::NeverIndexed, 0x10),
    ] {
        let mut bytes = [0; 128];
        let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
        let table = HpackDynamicTable::new(&mut bytes, &mut entries, 95).unwrap();
        let mut context = HpackEncoderContext::new(table, 95).unwrap();
        let mut encoder = context.begin_block();
        let mut destination = [0xaa; 16];
        let output = encoder
            .encode_literal(
                &mut destination,
                mode,
                HpackEncodeLiteralName::Literal(&[0, 0xff]),
                &[0x80, 0],
            )
            .unwrap();
        assert_eq!(output, [first, 2, 0, 0xff, 2, 0x80, 0]);
        let HpackRepresentation::Literal(field) = HpackRepresentation::parse(output).unwrap()
        else {
            panic!("expected literal field");
        };
        assert_eq!(field.mode(), mode);
        assert_eq!(field.name().unwrap().encoded_bytes(), [0, 0xff]);
        assert!(!field.name().unwrap().is_huffman());
        assert_eq!(field.value().encoded_bytes(), [0x80, 0]);
        assert!(!field.value().is_huffman());
        assert_eq!(destination[7..], [0xaa; 9]);
    }
}

#[test]
fn hpack_block_encoder_literal_indexed_names_validate_and_emit_only_indices() {
    let mut bytes = [0; 128];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let mut table = HpackDynamicTable::new(&mut bytes, &mut entries, 95).unwrap();
    table.insert(b"dynamic", b"old").unwrap();
    let mut context = HpackEncoderContext::new(table, 95).unwrap();
    let mut encoder = context.begin_block();
    let mut destination = [0xaa; 16];
    let static_output = encoder
        .encode_literal(
            &mut destination,
            HpackLiteralMode::WithoutIndexing,
            HpackEncodeLiteralName::Indexed {
                index: 2,
                decoded: b":method",
            },
            b"PUT",
        )
        .unwrap();
    assert_eq!(static_output, [2, 3, b'P', b'U', b'T']);
    assert!(
        !static_output
            .windows(b":method".len())
            .any(|bytes| bytes == b":method")
    );
    let dynamic_output = encoder
        .encode_literal(
            &mut destination,
            HpackLiteralMode::WithoutIndexing,
            HpackEncodeLiteralName::Indexed {
                index: 62,
                decoded: b"dynamic",
            },
            b"new",
        )
        .unwrap();
    assert_eq!(dynamic_output, [15, 47, 3, b'n', b'e', b'w']);
    let before = destination;
    assert_eq!(
        encoder.encode_literal(
            &mut destination,
            HpackLiteralMode::WithoutIndexing,
            HpackEncodeLiteralName::Indexed {
                index: 2,
                decoded: b"wrong",
            },
            b"v",
        ),
        Err(HpackEncodeError::IndexedLiteralNameMismatch { index: 2 })
    );
    assert_eq!(destination, before);
    assert_eq!(
        encoder.encode_literal(
            &mut destination,
            HpackLiteralMode::WithoutIndexing,
            HpackEncodeLiteralName::Indexed {
                index: 0,
                decoded: b"",
            },
            b"v",
        ),
        Err(HpackEncodeError::UnavailableIndex { index: 0 })
    );
}

#[test]
fn hpack_block_encoder_literal_insertion_is_independent() {
    let mut bytes = [0; 128];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let table = HpackDynamicTable::new(&mut bytes, &mut entries, 95).unwrap();
    let mut name = *b"name";
    let mut value = *b"value";
    {
        let mut context = HpackEncoderContext::new(table, 95).unwrap();
        let mut encoder = context.begin_block();
        let mut destination = [0xaa; 16];
        let output = encoder
            .encode_literal(
                &mut destination,
                HpackLiteralMode::IncrementalIndexing,
                HpackEncodeLiteralName::Literal(&name),
                &value,
            )
            .unwrap();
        name[0] = b'x';
        value[0] = b'y';
        assert_eq!(name, *b"xame");
        assert_eq!(value, *b"yalue");
        assert_eq!(
            output,
            [
                0x40, 4, b'n', b'a', b'm', b'e', 5, b'v', b'a', b'l', b'u', b'e'
            ]
        );
        assert_eq!(
            encoder.encode_dynamic_table_size_update(&mut destination, 64),
            Err(HpackEncodeError::DynamicTableSizeUpdateAfterField)
        );
        assert_eq!(
            context.dynamic_table().get(1),
            Some(HpackHeaderFieldRef::new(b"name", b"value"))
        );
    }
}

#[test]
fn hpack_block_encoder_non_indexing_literals_preserve_caller_table_stores() {
    let mut bytes = [0x5a; 128];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let before_bytes = bytes;
    let before_entries = entries;
    {
        let table = HpackDynamicTable::new(&mut bytes, &mut entries, 95).unwrap();
        let mut context = HpackEncoderContext::new(table, 95).unwrap();
        let mut encoder = context.begin_block();
        let mut destination = [0xaa; 16];
        for mode in [
            HpackLiteralMode::WithoutIndexing,
            HpackLiteralMode::NeverIndexed,
        ] {
            encoder
                .encode_literal(
                    &mut destination,
                    mode,
                    HpackEncodeLiteralName::Literal(b"other"),
                    b"v",
                )
                .unwrap();
        }
    }
    assert_eq!(bytes, before_bytes);
    assert_eq!(entries, before_entries);
}

#[test]
fn hpack_block_encoder_literal_short_output_is_atomic_and_oversized_clears_table() {
    let mut bytes = [0x5a; 128];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let mut table = HpackDynamicTable::new(&mut bytes, &mut entries, 64).unwrap();
    table.insert(b"a", b"b").unwrap();
    let before = (table.len(), table.size(), table.maximum_size());
    let mut context = HpackEncoderContext::new(table, 64).unwrap();
    {
        let mut encoder = context.begin_block();
        let mut short = [0xaa; 2];
        let short_before = short;
        assert!(matches!(
            encoder.encode_literal(
                &mut short,
                HpackLiteralMode::IncrementalIndexing,
                HpackEncodeLiteralName::Literal(b"n"),
                b"value"
            ),
            Err(HpackEncodeError::Representation(
                HpackRepresentationBuildError::BufferTooShort { .. }
            ))
        ));
        assert_eq!(short, short_before);
        assert!(!encoder.has_emitted_field());
    }
    assert_eq!(
        (
            context.dynamic_table().len(),
            context.dynamic_table().size(),
            context.dynamic_table().maximum_size()
        ),
        before
    );
    assert_eq!(
        context.dynamic_table().get(1),
        Some(HpackHeaderFieldRef::new(b"a", b"b"))
    );
    {
        let mut encoder = context.begin_block();
        let mut destination = [0xaa; 96];
        let output = encoder
            .encode_literal(
                &mut destination,
                HpackLiteralMode::IncrementalIndexing,
                HpackEncodeLiteralName::Literal(b"oversized"),
                b"0123456789012345678901234567890123456789",
            )
            .unwrap();
        assert!(matches!(
            HpackRepresentation::parse(output),
            Ok(HpackRepresentation::Literal(_))
        ));
    }
    assert!(context.dynamic_table().is_empty());
    assert_eq!(context.dynamic_table().size(), 0);
}

#[test]
fn hpack_block_encoder_rejects_literals_while_size_update_is_required() {
    let mut bytes = [0x5a; 64];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let table = HpackDynamicTable::new(&mut bytes, &mut entries, 64).unwrap();
    let mut context = HpackEncoderContext::new(table, 32).unwrap();
    let mut encoder = context.begin_block();
    let mut destination = [0xaa; 16];
    let before = destination;
    assert_eq!(
        encoder.encode_literal(
            &mut destination,
            HpackLiteralMode::IncrementalIndexing,
            HpackEncodeLiteralName::Literal(b"n"),
            b"v"
        ),
        Err(HpackEncodeError::DynamicTableSizeUpdateRequired)
    );
    assert_eq!(destination, before);
    assert!(encoder.requires_size_update());
    assert!(!encoder.has_emitted_field());
}

#[test]
fn hpack_huffman_literal_strategies_match_standalone_payloads_and_decode() {
    let name = [0, 0xff];
    let value = [0x80, 0];

    for strategy in [
        HpackLiteralHuffman::NONE,
        HpackLiteralHuffman::NAME,
        HpackLiteralHuffman::VALUE,
        HpackLiteralHuffman::BOTH,
    ] {
        let mut encoding_bytes = [0; 128];
        let mut encoding_entries = [HpackDynamicTableEntry::EMPTY; 2];
        let encoding_table =
            HpackDynamicTable::new(&mut encoding_bytes, &mut encoding_entries, 95).unwrap();
        let mut destination = [0xaa; 32];
        let mut encoding_context = HpackEncoderContext::new(encoding_table, 95).unwrap();
        let output = encoding_context
            .begin_block()
            .encode_literal_with_huffman(
                &mut destination,
                HpackLiteralMode::WithoutIndexing,
                HpackEncodeLiteralName::Literal(&name),
                &value,
                strategy,
            )
            .unwrap();
        let HpackRepresentation::Literal(field) = HpackRepresentation::parse(output).unwrap()
        else {
            unreachable!();
        };
        let name_literal = field.name().unwrap();
        assert_eq!(name_literal.is_huffman(), strategy.encodes_name());
        assert_eq!(field.value().is_huffman(), strategy.encodes_value());

        let mut expected_name_storage = [0; 8];
        let expected_name = if strategy.encodes_name() {
            HpackHuffmanEncoder::new(&name, &mut expected_name_storage)
                .encode()
                .unwrap()
        } else {
            &name
        };
        let mut expected_value_storage = [0; 8];
        let expected_value = if strategy.encodes_value() {
            HpackHuffmanEncoder::new(&value, &mut expected_value_storage)
                .encode()
                .unwrap()
        } else {
            &value
        };
        assert_eq!(name_literal.encoded_bytes(), expected_name);
        assert_eq!(field.value().encoded_bytes(), expected_value);

        let mut decoding_bytes = [0; 128];
        let mut decoding_entries = [HpackDynamicTableEntry::EMPTY; 2];
        let decoding_table =
            HpackDynamicTable::new(&mut decoding_bytes, &mut decoding_entries, 95).unwrap();
        let mut decoding_context = HpackDecoderContext::new(decoding_table, 95).unwrap();
        let mut decoded_bytes = [0; 8];
        let HpackDecodeStep::Field(decoded) = decoding_context
            .decode_block(output)
            .decode_next(&mut decoded_bytes)
            .unwrap()
        else {
            unreachable!();
        };
        assert_eq!(decoded.name(), name);
        assert_eq!(decoded.value(), value);
    }
}

#[test]
fn hpack_huffman_none_matches_plain_literal_encoding() {
    let mut plain_bytes = [0; 128];
    let mut plain_entries = [HpackDynamicTableEntry::EMPTY; 2];
    let plain_table = HpackDynamicTable::new(&mut plain_bytes, &mut plain_entries, 95).unwrap();
    let mut huffman_bytes = [0; 128];
    let mut huffman_entries = [HpackDynamicTableEntry::EMPTY; 2];
    let huffman_table =
        HpackDynamicTable::new(&mut huffman_bytes, &mut huffman_entries, 95).unwrap();
    let mut plain_destination = [0xaa; 32];
    let mut huffman_destination = [0xaa; 32];
    let mut plain_context = HpackEncoderContext::new(plain_table, 95).unwrap();
    let plain = plain_context
        .begin_block()
        .encode_literal(
            &mut plain_destination,
            HpackLiteralMode::WithoutIndexing,
            HpackEncodeLiteralName::Literal(&[0, 0xff]),
            &[0x80, 0],
        )
        .unwrap();
    let mut huffman_context = HpackEncoderContext::new(huffman_table, 95).unwrap();
    let huffman = huffman_context
        .begin_block()
        .encode_literal_with_huffman(
            &mut huffman_destination,
            HpackLiteralMode::WithoutIndexing,
            HpackEncodeLiteralName::Literal(&[0, 0xff]),
            &[0x80, 0],
            HpackLiteralHuffman::NONE,
        )
        .unwrap();
    assert_eq!(huffman, plain);
}

#[test]
fn hpack_huffman_value_with_static_or_dynamic_indexed_name_omits_name_bytes() {
    let mut static_bytes = [0; 128];
    let mut static_entries = [HpackDynamicTableEntry::EMPTY; 2];
    let static_table = HpackDynamicTable::new(&mut static_bytes, &mut static_entries, 95).unwrap();
    let mut static_destination = [0xaa; 32];
    let mut static_context = HpackEncoderContext::new(static_table, 95).unwrap();
    let static_output = static_context
        .begin_block()
        .encode_literal_with_huffman(
            &mut static_destination,
            HpackLiteralMode::WithoutIndexing,
            HpackEncodeLiteralName::Indexed {
                index: 2,
                decoded: b":method",
            },
            b"PUT",
            HpackLiteralHuffman::VALUE,
        )
        .unwrap();
    let HpackRepresentation::Literal(static_field) =
        HpackRepresentation::parse(static_output).unwrap()
    else {
        unreachable!();
    };
    assert_eq!(static_field.name_index_value(), 2);
    assert!(static_field.name().is_none());
    assert!(static_field.value().is_huffman());
    let mut static_decoding_bytes = [0; 128];
    let mut static_decoding_entries = [HpackDynamicTableEntry::EMPTY; 2];
    let static_decoding_table =
        HpackDynamicTable::new(&mut static_decoding_bytes, &mut static_decoding_entries, 95)
            .unwrap();
    let mut static_decoding_context = HpackDecoderContext::new(static_decoding_table, 95).unwrap();
    let mut static_decoded_bytes = [0; 16];
    let HpackDecodeStep::Field(static_decoded) = static_decoding_context
        .decode_block(static_output)
        .decode_next(&mut static_decoded_bytes)
        .unwrap()
    else {
        unreachable!();
    };
    assert_eq!(static_decoded.name(), b":method");
    assert_eq!(static_decoded.value(), b"PUT");

    let mut dynamic_bytes = [0; 128];
    let mut dynamic_entries = [HpackDynamicTableEntry::EMPTY; 2];
    let mut dynamic_table =
        HpackDynamicTable::new(&mut dynamic_bytes, &mut dynamic_entries, 95).unwrap();
    dynamic_table.insert(b"dynamic-name", b"seed").unwrap();
    let mut dynamic_destination = [0xaa; 32];
    let dynamic_index = (HPACK_STATIC_TABLE_LEN + 1) as u64;
    let mut dynamic_context = HpackEncoderContext::new(dynamic_table, 95).unwrap();
    let dynamic_output = dynamic_context
        .begin_block()
        .encode_literal_with_huffman(
            &mut dynamic_destination,
            HpackLiteralMode::WithoutIndexing,
            HpackEncodeLiteralName::Indexed {
                index: dynamic_index,
                decoded: b"dynamic-name",
            },
            b"PUT",
            HpackLiteralHuffman::VALUE,
        )
        .unwrap();
    let HpackRepresentation::Literal(dynamic_field) =
        HpackRepresentation::parse(dynamic_output).unwrap()
    else {
        unreachable!();
    };
    assert_eq!(dynamic_field.name_index_value(), dynamic_index);
    assert!(dynamic_field.name().is_none());
    assert!(dynamic_field.value().is_huffman());
    let mut dynamic_decoding_bytes = [0; 128];
    let mut dynamic_decoding_entries = [HpackDynamicTableEntry::EMPTY; 2];
    let mut dynamic_decoding_table = HpackDynamicTable::new(
        &mut dynamic_decoding_bytes,
        &mut dynamic_decoding_entries,
        95,
    )
    .unwrap();
    dynamic_decoding_table
        .insert(b"dynamic-name", b"seed")
        .unwrap();
    let mut dynamic_decoding_context =
        HpackDecoderContext::new(dynamic_decoding_table, 95).unwrap();
    let mut dynamic_decoded_bytes = [0; 32];
    let HpackDecodeStep::Field(dynamic_decoded) = dynamic_decoding_context
        .decode_block(dynamic_output)
        .decode_next(&mut dynamic_decoded_bytes)
        .unwrap()
    else {
        unreachable!();
    };
    assert_eq!(dynamic_decoded.name(), b"dynamic-name");
    assert_eq!(dynamic_decoded.value(), b"PUT");
}

#[test]
fn hpack_incremental_huffman_insertion_owns_decoded_bytes_and_preserves_suffix() {
    let mut table_bytes = [0; 128];
    let mut table_entries = [HpackDynamicTableEntry::EMPTY; 2];
    let table = HpackDynamicTable::new(&mut table_bytes, &mut table_entries, 95).unwrap();
    let mut name = *b"name";
    let mut value = *b"value";
    let mut destination = [0xaa; 32];
    let mut context = HpackEncoderContext::new(table, 95).unwrap();
    let output_len = {
        let output = context
            .begin_block()
            .encode_literal_with_huffman(
                &mut destination,
                HpackLiteralMode::IncrementalIndexing,
                HpackEncodeLiteralName::Literal(&name),
                &value,
                HpackLiteralHuffman::BOTH,
            )
            .unwrap();
        let output_before = output.to_vec();
        name[0] = b'x';
        value[0] = b'y';
        assert_eq!(name, *b"xame");
        assert_eq!(value, *b"yalue");
        assert_eq!(output, output_before);
        output.len()
    };
    assert!(output_len < destination.len());
    assert!(destination[output_len..].iter().all(|byte| *byte == 0xaa));
    assert_eq!(
        context.dynamic_table().get(1),
        Some(HpackHeaderFieldRef::new(b"name", b"value"))
    );
}

#[test]
fn hpack_oversized_incremental_huffman_literal_clears_nonempty_table() {
    let mut bytes = [0; 128];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let mut table = HpackDynamicTable::new(&mut bytes, &mut entries, 64).unwrap();
    table.insert(b"seed", b"value").unwrap();
    let mut destination = [0xaa; 128];
    let mut context = HpackEncoderContext::new(table, 64).unwrap();
    let output = context
        .begin_block()
        .encode_literal_with_huffman(
            &mut destination,
            HpackLiteralMode::IncrementalIndexing,
            HpackEncodeLiteralName::Literal(b"oversized"),
            b"0123456789012345678901234567890123456789",
            HpackLiteralHuffman::BOTH,
        )
        .unwrap();
    assert!(matches!(
        HpackRepresentation::parse(output),
        Ok(HpackRepresentation::Literal(_))
    ));
    assert!(context.dynamic_table().is_empty());
    assert_eq!(context.dynamic_table().size(), 0);
}

#[test]
fn hpack_huffman_short_destination_preserves_output_and_empty_table_storage() {
    let mut bytes = [0x5a; 128];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let before_bytes = bytes;
    let before_entries = entries;
    let mut destination = [0xaa; 2];
    let before_destination = destination;
    {
        let table = HpackDynamicTable::new(&mut bytes, &mut entries, 95).unwrap();
        let mut context = HpackEncoderContext::new(table, 95).unwrap();
        let mut encoder = context.begin_block();
        assert!(matches!(
            encoder.encode_literal_with_huffman(
                &mut destination,
                HpackLiteralMode::IncrementalIndexing,
                HpackEncodeLiteralName::Literal(b"name"),
                b"value",
                HpackLiteralHuffman::BOTH,
            ),
            Err(HpackEncodeError::Representation(
                HpackRepresentationBuildError::BufferTooShort { .. }
            ))
        ));
        assert!(!encoder.has_emitted_field());
        assert!(!encoder.requires_size_update());
    }
    assert_eq!(destination, before_destination);
    assert_eq!(bytes, before_bytes);
    assert_eq!(entries, before_entries);
}

#[test]
fn hpack_huffman_size_update_requirement_preserves_encoder_and_destination() {
    let mut bytes = [0x5a; 64];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let table = HpackDynamicTable::new(&mut bytes, &mut entries, 64).unwrap();
    let mut context = HpackEncoderContext::new(table, 32).unwrap();
    let mut encoder = context.begin_block();
    let mut destination = [0xaa; 16];
    let before = destination;
    assert_eq!(
        encoder.encode_literal_with_huffman(
            &mut destination,
            HpackLiteralMode::IncrementalIndexing,
            HpackEncodeLiteralName::Literal(b"name"),
            b"value",
            HpackLiteralHuffman::BOTH,
        ),
        Err(HpackEncodeError::DynamicTableSizeUpdateRequired)
    );
    assert_eq!(destination, before);
    assert!(encoder.requires_size_update());
    assert!(!encoder.has_emitted_field());
}

#[test]
fn hpack_huffman_name_strategy_for_indexed_name_preserves_state() {
    let mut bytes = [0x5a; 128];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let before_bytes = bytes;
    let before_entries = entries;
    let mut destination = [0xaa; 16];
    let before_destination = destination;
    {
        let table = HpackDynamicTable::new(&mut bytes, &mut entries, 95).unwrap();
        let mut context = HpackEncoderContext::new(table, 95).unwrap();
        let mut encoder = context.begin_block();
        assert_eq!(
            encoder.encode_literal_with_huffman(
                &mut destination,
                HpackLiteralMode::WithoutIndexing,
                HpackEncodeLiteralName::Indexed {
                    index: 2,
                    decoded: b":method",
                },
                b"GET",
                HpackLiteralHuffman::NAME,
            ),
            Err(HpackEncodeError::HuffmanNameForIndexedName)
        );
        assert!(!encoder.has_emitted_field());
    }
    assert_eq!(destination, before_destination);
    assert_eq!(bytes, before_bytes);
    assert_eq!(entries, before_entries);
}

#[test]
fn hpack_huffman_unavailable_index_preserves_state() {
    let mut bytes = [0x5a; 128];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let before_bytes = bytes;
    let before_entries = entries;
    let mut destination = [0xaa; 16];
    let before_destination = destination;
    {
        let table = HpackDynamicTable::new(&mut bytes, &mut entries, 95).unwrap();
        let mut context = HpackEncoderContext::new(table, 95).unwrap();
        let mut encoder = context.begin_block();
        assert_eq!(
            encoder.encode_literal_with_huffman(
                &mut destination,
                HpackLiteralMode::WithoutIndexing,
                HpackEncodeLiteralName::Indexed {
                    index: 62,
                    decoded: b"missing",
                },
                b"value",
                HpackLiteralHuffman::VALUE,
            ),
            Err(HpackEncodeError::UnavailableIndex { index: 62 })
        );
        assert!(!encoder.has_emitted_field());
    }
    assert_eq!(destination, before_destination);
    assert_eq!(bytes, before_bytes);
    assert_eq!(entries, before_entries);
}

#[test]
fn hpack_huffman_indexed_name_mismatch_preserves_state() {
    let mut bytes = [0x5a; 128];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let before_bytes = bytes;
    let before_entries = entries;
    let mut destination = [0xaa; 16];
    let before_destination = destination;
    {
        let table = HpackDynamicTable::new(&mut bytes, &mut entries, 95).unwrap();
        let mut context = HpackEncoderContext::new(table, 95).unwrap();
        let mut encoder = context.begin_block();
        assert_eq!(
            encoder.encode_literal_with_huffman(
                &mut destination,
                HpackLiteralMode::WithoutIndexing,
                HpackEncodeLiteralName::Indexed {
                    index: 2,
                    decoded: b":path",
                },
                b"value",
                HpackLiteralHuffman::VALUE,
            ),
            Err(HpackEncodeError::IndexedLiteralNameMismatch { index: 2 })
        );
        assert!(!encoder.has_emitted_field());
    }
    assert_eq!(destination, before_destination);
    assert_eq!(bytes, before_bytes);
    assert_eq!(entries, before_entries);
}
