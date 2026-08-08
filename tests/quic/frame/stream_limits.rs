use net_wire::quic::*;

#[test]
fn stream_count_frames_parse_exact_layouts_directions_and_suffixes() {
    for (bytes, direction, blocked) in [
        (
            &[0x12, 3, 0xfe][..],
            QuicStreamDirection::Bidirectional,
            false,
        ),
        (
            &[0x13, 4, 0xfe][..],
            QuicStreamDirection::Unidirectional,
            false,
        ),
        (
            &[0x16, 5, 0xfe][..],
            QuicStreamDirection::Bidirectional,
            true,
        ),
        (
            &[0x17, 6, 0xfe][..],
            QuicStreamDirection::Unidirectional,
            true,
        ),
    ] {
        let (frame, suffix) = QuicFrame::parse(bytes).unwrap();
        assert_eq!(frame.as_bytes(), &bytes[..2]);
        assert_eq!(frame.frame_type().value(), bytes[0] as u64);
        assert_eq!(suffix, &[0xfe]);
        match (frame, blocked) {
            (QuicFrame::MaxStreams(frame), false) => {
                assert_eq!(frame.direction(), direction);
                assert_eq!(frame.maximum_streams().value(), bytes[1] as u64);
            }
            (QuicFrame::StreamsBlocked(frame), true) => {
                assert_eq!(frame.direction(), direction);
                assert_eq!(frame.maximum_streams().value(), bytes[1] as u64);
            }
            _ => panic!("unexpected stream-count frame variant"),
        }
    }
}

#[test]
fn stream_count_frames_preserve_noncanonical_type_and_field_widths() {
    for (bytes, blocked) in [
        (&[0x40, 0x12, 0x80, 0, 0, 1][..], false),
        (&[0x40, 0x13, 0x40, 2][..], false),
        (&[0x40, 0x16, 0x80, 0, 0, 3][..], true),
        (&[0x40, 0x17, 0xc0, 0, 0, 0, 0, 0, 0, 4][..], true),
    ] {
        let (frame, suffix) = QuicFrame::parse(bytes).unwrap();
        assert!(suffix.is_empty());
        assert_eq!(frame.frame_type().as_bytes(), &bytes[..2]);
        match (frame, blocked) {
            (QuicFrame::MaxStreams(frame), false) => {
                assert_eq!(frame.maximum_streams().as_bytes(), &bytes[2..]);
            }
            (QuicFrame::StreamsBlocked(frame), true) => {
                assert_eq!(frame.maximum_streams().as_bytes(), &bytes[2..]);
            }
            _ => panic!("unexpected stream-count frame variant"),
        }
    }
}

#[test]
fn stream_count_frame_field_truncations_report_exact_offsets() {
    for frame_type in [0x12u8, 0x13, 0x16, 0x17] {
        for (field, required) in [
            (&[][..], 1),
            (&[0x40][..], 2),
            (&[0x80, 0, 0][..], 4),
            (&[0xc0, 0, 0, 0, 0, 0, 0][..], 8),
        ] {
            let mut bytes = [0; 8];
            bytes[0] = frame_type;
            bytes[1..1 + field.len()].copy_from_slice(field);
            let input = &bytes[..1 + field.len()];
            assert_eq!(
                QuicFrame::parse(input),
                Err(QuicFrameParseError::Field {
                    field: QuicFrameField::MaximumStreams,
                    offset: 1,
                    error: QuicVarIntParseError::Incomplete {
                        required,
                        available: field.len(),
                    },
                })
            );
        }
    }
}

#[test]
fn stream_count_frames_accept_the_rfc_maximum_in_both_directions() {
    for frame_type in [0x12u8, 0x13, 0x16, 0x17] {
        let bytes = [frame_type, 0xd0, 0, 0, 0, 0, 0, 0, 0];
        let (frame, suffix) = QuicFrame::parse(&bytes).unwrap();
        assert!(suffix.is_empty());
        match frame {
            QuicFrame::MaxStreams(frame) => {
                assert_eq!(frame.maximum_streams().value(), 1u64 << 60)
            }
            QuicFrame::StreamsBlocked(frame) => {
                assert_eq!(frame.maximum_streams().value(), 1u64 << 60)
            }
            _ => panic!("unexpected stream-count frame variant"),
        }
    }
}

#[test]
fn stream_count_frames_reject_out_of_range_values_at_absolute_offsets() {
    for (value, encoded) in [
        (1u64 << 60 | 1, &[0xd0, 0, 0, 0, 0, 0, 0, 1][..]),
        (
            (1u64 << 62) - 1,
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..],
        ),
    ] {
        for frame_type in [0x12u8, 0x13, 0x16, 0x17] {
            let mut bytes = [0; 9];
            bytes[0] = frame_type;
            bytes[1..].copy_from_slice(encoded);
            assert_eq!(
                QuicFrame::parse(&bytes),
                Err(QuicFrameParseError::FieldValueOutOfRange {
                    field: QuicFrameField::MaximumStreams,
                    offset: 1,
                    value,
                    maximum: 1u64 << 60,
                })
            );
        }
    }

    let bytes = [1, 0x16, 0xd0, 0, 0, 0, 0, 0, 0, 1];
    let expected = QuicFrameParseError::FieldValueOutOfRange {
        field: QuicFrameField::MaximumStreams,
        offset: 2,
        value: 1u64 << 60 | 1,
        maximum: 1u64 << 60,
    };
    assert_eq!(QuicFrames::parse(&bytes), Err(expected));
    let mut iter = QuicFrameIter::new(&bytes);
    assert!(matches!(iter.next(), Some(Ok(QuicFrame::Ping(_)))));
    assert_eq!(iter.next(), Some(Err(expected)));
    assert_eq!(iter.next(), None);
    assert_eq!(iter.next(), None);
}

#[test]
fn stream_count_frames_mix_at_exact_boundaries() {
    let bytes = [0, 0x12, 1, 0x13, 2, 0x16, 3, 0x17, 4, 1];
    let frames = QuicFrames::parse(&bytes).unwrap();
    let mut iter = frames.iter();
    for (length, kind) in [(1usize, 0), (2, 1), (2, 2), (2, 3), (2, 4), (1, 5)] {
        let frame = iter.next().unwrap().unwrap();
        assert_eq!(frame.as_bytes().len(), length);
        match kind {
            0 => assert!(matches!(frame, QuicFrame::Padding(_))),
            1 | 2 => assert!(matches!(frame, QuicFrame::MaxStreams(_))),
            3 | 4 => assert!(matches!(frame, QuicFrame::StreamsBlocked(_))),
            _ => assert!(matches!(frame, QuicFrame::Ping(_))),
        }
    }
    assert_eq!(iter.next(), None);
}
