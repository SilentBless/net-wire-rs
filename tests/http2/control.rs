use net_wire::http2::{
    Http2BuildError, Http2ErrorCode, Http2Frame, Http2FrameType, Http2Goaway, Http2GoawayBuilder,
    Http2ParseError, Http2Ping, Http2PingBuilder, Http2Priority, Http2PriorityFrame,
    Http2PriorityFrameBuilder, Http2RstStream, Http2RstStreamBuilder, Http2StreamId,
    Http2WindowIncrement, Http2WindowUpdate, Http2WindowUpdateBuilder,
};

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
