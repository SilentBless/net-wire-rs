use net_wire::http2::{
    HTTP2_CLIENT_PREFACE, Http2BuildError, Http2ClientPreface, Http2Frame, Http2FrameBuilder,
    Http2FrameMut, Http2FrameType, Http2ParseError, Http2StreamId,
};

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
