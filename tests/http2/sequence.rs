use net_wire::http2::{
    Http2Frame, Http2FrameType, Http2HeaderBlockFragment, Http2HeaderBlockSequence,
    Http2HeaderBlockSequenceError, Http2ParseError,
};

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
