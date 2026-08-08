use net_wire::quic::*;

mod ack;
mod connection_close;
mod connection_id;
mod control;
mod crypto;
mod data_limits;
mod path;
mod stream;
mod stream_limits;
mod token;

#[test]
fn quic_frames_preserve_exact_padding_and_ping_type_encodings() {
    for (bytes, expected_type) in [
        (&[0x00, 0xfe][..], QuicVarIntLen::One),
        (&[0x40, 0x00, 0xfe][..], QuicVarIntLen::Two),
        (&[0x01, 0xfe][..], QuicVarIntLen::One),
        (&[0x40, 0x01, 0xfe][..], QuicVarIntLen::Two),
    ] {
        let (frame, suffix) = QuicFrame::parse(bytes).unwrap();
        assert_eq!(frame.as_bytes(), &bytes[..expected_type.byte_len()]);
        assert_eq!(frame.frame_type().as_bytes(), frame.as_bytes());
        assert_eq!(frame.frame_type().encoded_len(), expected_type);
        assert_eq!(suffix, &bytes[expected_type.byte_len()..]);
    }
}

#[test]
fn quic_frames_keep_adjacent_padding_distinct_and_validate_sequences() {
    let bytes = [0, 0, 0x40, 1, 0];
    let frames = QuicFrames::parse(&bytes).unwrap();
    assert_eq!(frames.as_bytes(), &bytes);

    let mut iter = frames.iter();
    assert!(matches!(iter.next(), Some(Ok(QuicFrame::Padding(_)))));
    assert!(matches!(iter.next(), Some(Ok(QuicFrame::Padding(_)))));
    let ping = iter.next().unwrap().unwrap();
    assert!(matches!(ping, QuicFrame::Ping(_)));
    assert_eq!(ping.as_bytes(), &[0x40, 1]);
    assert!(matches!(iter.next(), Some(Ok(QuicFrame::Padding(_)))));
    assert_eq!(iter.next(), None);
}

#[test]
fn quic_frames_report_empty_and_truncated_frame_types() {
    assert_eq!(
        QuicFrames::parse(&[]),
        Err(QuicFrameParseError::EmptySequence)
    );

    for (input, required) in [
        (&[][..], 1),
        (&[0x40][..], 2),
        (&[0x80, 0, 0][..], 4),
        (&[0xc0, 0, 0, 0, 0, 0, 0][..], 8),
    ] {
        assert_eq!(
            QuicFrame::parse(input),
            Err(QuicFrameParseError::FrameType {
                offset: 0,
                error: QuicVarIntParseError::Incomplete {
                    required,
                    available: input.len(),
                },
            })
        );
    }
}

#[test]
fn quic_frames_fail_closed_with_exact_unknown_type_details() {
    for (input, value, length) in [
        (&[0x1f][..], 0x1f, QuicVarIntLen::One),
        (&[0x40, 0x1f][..], 0x1f, QuicVarIntLen::Two),
    ] {
        assert_eq!(
            QuicFrame::parse(input),
            Err(QuicFrameParseError::UnsupportedFrameType {
                value,
                length,
                offset: 0,
            })
        );
    }

    let bytes = [0, 1, 0x40, 0x1f];
    assert_eq!(
        QuicFrames::parse(&bytes),
        Err(QuicFrameParseError::UnsupportedFrameType {
            value: 0x1f,
            length: QuicVarIntLen::Two,
            offset: 2,
        })
    );
}

#[test]
fn raw_quic_frame_iterator_exposes_prefix_then_one_error_and_is_fused() {
    let mut unknown = QuicFrameIter::new(&[0, 0x40, 0x1f]);
    assert!(matches!(unknown.next(), Some(Ok(QuicFrame::Padding(_)))));
    assert_eq!(
        unknown.next(),
        Some(Err(QuicFrameParseError::UnsupportedFrameType {
            value: 0x1f,
            length: QuicVarIntLen::Two,
            offset: 1,
        }))
    );
    assert_eq!(unknown.next(), None);

    let truncated_bytes = [1, 0x80, 0];
    assert_eq!(
        QuicFrames::parse(&truncated_bytes),
        Err(QuicFrameParseError::FrameType {
            offset: 1,
            error: QuicVarIntParseError::Incomplete {
                required: 4,
                available: 2,
            },
        })
    );

    let mut truncated = QuicFrameIter::new(&truncated_bytes);
    assert!(matches!(truncated.next(), Some(Ok(QuicFrame::Ping(_)))));
    assert_eq!(
        truncated.next(),
        Some(Err(QuicFrameParseError::FrameType {
            offset: 1,
            error: QuicVarIntParseError::Incomplete {
                required: 4,
                available: 2,
            },
        }))
    );
    assert_eq!(truncated.next(), None);
}

#[test]
fn quic_frame_types_parse_ping() {
    let (frame, _) = QuicFrame::parse(&[1]).unwrap();
    assert!(matches!(frame, QuicFrame::Ping(_)));
}
