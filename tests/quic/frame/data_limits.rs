use net_wire::quic::*;

#[test]
fn data_limit_frames_parse_exact_layouts_accessors_and_suffixes() {
    let max_data = [0x10, 0x2a, 0xfe];
    let (frame, suffix) = QuicFrame::parse(&max_data).unwrap();
    let QuicFrame::MaxData(frame) = frame else {
        panic!("expected MAX_DATA")
    };
    assert_eq!(frame.as_bytes(), &max_data[..2]);
    assert_eq!(frame.frame_type().as_bytes(), &[0x10]);
    assert_eq!(frame.maximum_data().value(), 42);
    assert_eq!(suffix, &[0xfe]);

    let max_stream_data = [0x11, 7, 0x40, 0x2a, 0xfe];
    let (frame, suffix) = QuicFrame::parse(&max_stream_data).unwrap();
    let QuicFrame::MaxStreamData(frame) = frame else {
        panic!("expected MAX_STREAM_DATA")
    };
    assert_eq!(frame.as_bytes(), &max_stream_data[..4]);
    assert_eq!(frame.stream_id().value(), 7);
    assert_eq!(frame.maximum_stream_data().value(), 42);
    assert_eq!(suffix, &[0xfe]);

    let data_blocked = [0x14, 0x2a, 0xfe];
    let (frame, suffix) = QuicFrame::parse(&data_blocked).unwrap();
    let QuicFrame::DataBlocked(frame) = frame else {
        panic!("expected DATA_BLOCKED")
    };
    assert_eq!(frame.as_bytes(), &data_blocked[..2]);
    assert_eq!(frame.maximum_data().value(), 42);
    assert_eq!(suffix, &[0xfe]);

    let stream_data_blocked = [0x15, 7, 0x40, 0x2a, 0xfe];
    let (frame, suffix) = QuicFrame::parse(&stream_data_blocked).unwrap();
    let QuicFrame::StreamDataBlocked(frame) = frame else {
        panic!("expected STREAM_DATA_BLOCKED")
    };
    assert_eq!(frame.as_bytes(), &stream_data_blocked[..4]);
    assert_eq!(frame.stream_id().value(), 7);
    assert_eq!(frame.maximum_stream_data().value(), 42);
    assert_eq!(suffix, &[0xfe]);
}

#[test]
fn data_limit_frames_preserve_noncanonical_types_and_each_field_width() {
    let max_data = [0x40, 0x10, 0x40, 1];
    let (QuicFrame::MaxData(frame), suffix) = QuicFrame::parse(&max_data).unwrap() else {
        panic!("expected MAX_DATA")
    };
    assert!(suffix.is_empty());
    assert_eq!(frame.frame_type().as_bytes(), &[0x40, 0x10]);
    assert_eq!(frame.maximum_data().as_bytes(), &[0x40, 1]);

    let max_stream_data = [0x40, 0x11, 0x80, 0, 0, 2, 0xc0, 0, 0, 0, 0, 0, 0, 3];
    let (QuicFrame::MaxStreamData(frame), suffix) = QuicFrame::parse(&max_stream_data).unwrap()
    else {
        panic!("expected MAX_STREAM_DATA")
    };
    assert!(suffix.is_empty());
    assert_eq!(frame.stream_id().as_bytes(), &[0x80, 0, 0, 2]);
    assert_eq!(
        frame.maximum_stream_data().as_bytes(),
        &[0xc0, 0, 0, 0, 0, 0, 0, 3]
    );

    let data_blocked = [0x40, 0x14, 0x80, 0, 0, 4];
    let (QuicFrame::DataBlocked(frame), _) = QuicFrame::parse(&data_blocked).unwrap() else {
        panic!("expected DATA_BLOCKED")
    };
    assert_eq!(frame.maximum_data().as_bytes(), &[0x80, 0, 0, 4]);

    let stream_data_blocked = [0x40, 0x15, 0xc0, 0, 0, 0, 0, 0, 0, 5, 0x40, 6];
    let (QuicFrame::StreamDataBlocked(frame), _) = QuicFrame::parse(&stream_data_blocked).unwrap()
    else {
        panic!("expected STREAM_DATA_BLOCKED")
    };
    assert_eq!(frame.stream_id().as_bytes(), &[0xc0, 0, 0, 0, 0, 0, 0, 5]);
    assert_eq!(frame.maximum_stream_data().as_bytes(), &[0x40, 6]);
}

#[test]
fn data_limit_frame_field_truncations_report_exact_absolute_offsets() {
    let cases = [
        (0x10, 0, QuicFrameField::MaximumData),
        (0x11, 0, QuicFrameField::StreamId),
        (0x11, 1, QuicFrameField::MaximumStreamData),
        (0x14, 0, QuicFrameField::MaximumData),
        (0x15, 0, QuicFrameField::StreamId),
        (0x15, 1, QuicFrameField::MaximumStreamData),
    ];
    for (frame_type, field_index, field) in cases {
        for (prefix, required) in [
            (&[][..], 1),
            (&[0x40][..], 2),
            (&[0x80, 0, 0][..], 4),
            (&[0xc0, 0, 0, 0, 0, 0, 0][..], 8),
        ] {
            let mut bytes = [0; 16];
            bytes[0] = frame_type;
            bytes[1..field_index + 1].fill(0);
            bytes[field_index + 1..field_index + 1 + prefix.len()].copy_from_slice(prefix);
            let input = &bytes[..field_index + 1 + prefix.len()];
            assert_eq!(
                QuicFrame::parse(input),
                Err(QuicFrameParseError::Field {
                    field,
                    offset: field_index + 1,
                    error: QuicVarIntParseError::Incomplete {
                        required,
                        available: prefix.len(),
                    },
                })
            );
        }
    }
}

#[test]
fn data_limit_frames_iterate_among_existing_frames_at_exact_boundaries() {
    let bytes = [0, 0x10, 1, 1, 0x11, 2, 3, 0x14, 5, 0x15, 6, 7, 0];
    let frames = QuicFrames::parse(&bytes).unwrap();
    let mut iter = frames.iter();
    for (length, variant) in [(1, 0), (2, 1), (1, 2), (3, 3), (2, 4), (3, 5), (1, 6)] {
        let frame = iter.next().unwrap().unwrap();
        assert_eq!(frame.as_bytes().len(), length);
        match variant {
            0 | 6 => assert!(matches!(frame, QuicFrame::Padding(_))),
            1 => assert!(matches!(frame, QuicFrame::MaxData(_))),
            2 => assert!(matches!(frame, QuicFrame::Ping(_))),
            3 => assert!(matches!(frame, QuicFrame::MaxStreamData(_))),
            4 => assert!(matches!(frame, QuicFrame::DataBlocked(_))),
            _ => assert!(matches!(frame, QuicFrame::StreamDataBlocked(_))),
        }
    }
    assert_eq!(iter.next(), None);
}

#[test]
fn malformed_later_data_limit_frame_fails_closed_at_absolute_offset() {
    let bytes = [1, 0x15, 9, 0x80, 0];
    let expected = QuicFrameParseError::Field {
        field: QuicFrameField::MaximumStreamData,
        offset: 3,
        error: QuicVarIntParseError::Incomplete {
            required: 4,
            available: 2,
        },
    };
    assert_eq!(QuicFrames::parse(&bytes), Err(expected));
    let mut iter = QuicFrameIter::new(&bytes);
    assert!(matches!(iter.next(), Some(Ok(QuicFrame::Ping(_)))));
    assert_eq!(iter.next(), Some(Err(expected)));
    assert_eq!(iter.next(), None);
    assert_eq!(iter.next(), None);
}

#[test]
fn data_limit_frames_accept_maximum_62_bit_values() {
    let maximum = [0xff; 8];
    let max_data = [0x10, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let (QuicFrame::MaxData(frame), _) = QuicFrame::parse(&max_data).unwrap() else {
        panic!("expected MAX_DATA")
    };
    assert_eq!(frame.maximum_data().as_bytes(), maximum);
    assert_eq!(frame.maximum_data().value(), (1u64 << 62) - 1);

    let max_stream_data = [
        0x11, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ];
    let (QuicFrame::MaxStreamData(frame), _) = QuicFrame::parse(&max_stream_data).unwrap() else {
        panic!("expected MAX_STREAM_DATA")
    };
    assert_eq!(frame.stream_id().value(), (1u64 << 62) - 1);
    assert_eq!(frame.maximum_stream_data().as_bytes(), maximum);

    let data_blocked = [0x14, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let (QuicFrame::DataBlocked(frame), _) = QuicFrame::parse(&data_blocked).unwrap() else {
        panic!("expected DATA_BLOCKED")
    };
    assert_eq!(frame.maximum_data().value(), (1u64 << 62) - 1);

    let stream_data_blocked = [
        0x15, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ];
    let (QuicFrame::StreamDataBlocked(frame), _) = QuicFrame::parse(&stream_data_blocked).unwrap()
    else {
        panic!("expected STREAM_DATA_BLOCKED")
    };
    assert_eq!(frame.stream_id().as_bytes(), maximum);
    assert_eq!(frame.maximum_stream_data().value(), (1u64 << 62) - 1);
}

#[test]
fn data_limit_frame_fields_remain_distinct() {
    assert_ne!(
        QuicFrameField::MaximumData,
        QuicFrameField::MaximumStreamData
    );
}
