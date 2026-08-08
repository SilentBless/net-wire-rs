use net_wire::http2::{
    Http2BuildError, Http2Continuation, Http2ContinuationBuilder, Http2Data, Http2FrameType,
    Http2Headers, Http2HeadersBuilder, Http2ParseError, Http2Priority, Http2PushPromise,
    Http2PushPromiseBuilder, Http2StreamId,
};

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
