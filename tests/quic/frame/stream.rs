use net_wire::quic::*;

#[test]
fn stream_frames_cover_all_flag_layouts_and_terminal_implicit_data() {
    for (frame_type, offset, length, fin, expected_data, suffix) in [
        (0x08, None, None, false, &[0xaa, 1, 0][..], &[][..]),
        (0x09, None, None, true, &[0xaa, 1, 0][..], &[][..]),
        (0x0a, None, Some(2), false, &[0xaa, 0xbb][..], &[1][..]),
        (0x0b, None, Some(2), true, &[0xaa, 0xbb][..], &[1][..]),
        (0x0c, Some(3), None, false, &[0xaa, 1, 0][..], &[][..]),
        (0x0d, Some(3), None, true, &[0xaa, 1, 0][..], &[][..]),
        (0x0e, Some(3), Some(2), false, &[0xaa, 0xbb][..], &[1][..]),
        (0x0f, Some(3), Some(2), true, &[0xaa, 0xbb][..], &[1][..]),
    ] {
        let mut bytes = [0; 8];
        bytes[0] = frame_type;
        bytes[1] = 7;
        let mut end = 2;
        if let Some(value) = offset {
            bytes[end] = value;
            end += 1;
        }
        if let Some(value) = length {
            bytes[end] = value;
            end += 1;
            bytes[end..end + 2].copy_from_slice(&[0xaa, 0xbb]);
            end += 2;
            bytes[end] = 1;
            end += 1;
        } else {
            bytes[end..end + 3].copy_from_slice(&[0xaa, 1, 0]);
            end += 3;
        }
        let (QuicFrame::Stream(frame), actual_suffix) = QuicFrame::parse(&bytes[..end]).unwrap()
        else {
            panic!("expected STREAM")
        };
        assert_eq!(frame.frame_type().value(), frame_type as u64);
        assert_eq!(frame.stream_id().value(), 7);
        assert_eq!(frame.offset().map(QuicVarInt::value), offset.map(u64::from));
        assert_eq!(frame.length().map(QuicVarInt::value), length.map(u64::from));
        assert_eq!(frame.fin(), fin);
        assert_eq!(frame.stream_data(), expected_data);
        assert_eq!(actual_suffix, suffix);
    }

    let terminal = [0x08, 1, 1, 0, 0x1e];
    let frames = QuicFrames::parse(&terminal).unwrap();
    let mut iter = frames.iter();
    assert!(matches!(iter.next(), Some(Ok(QuicFrame::Stream(_)))));
    assert_eq!(iter.next(), None);

    for bytes in [
        &[0x08, 1][..],
        &[0x09, 1][..],
        &[0x0a, 1, 0][..],
        &[0x0b, 1, 0][..],
        &[0x0c, 1, 0][..],
        &[0x0d, 1, 0][..],
        &[0x0e, 1, 0, 0][..],
        &[0x0f, 1, 0, 0][..],
    ] {
        let (QuicFrame::Stream(frame), suffix) = QuicFrame::parse(bytes).unwrap() else {
            panic!("expected STREAM")
        };
        assert!(frame.stream_data().is_empty());
        assert!(suffix.is_empty());
    }

    let explicit = [0x0a, 1, 1, 0xaa, 1, 0];
    let frames = QuicFrames::parse(&explicit).unwrap();
    assert_eq!(
        frames.iter().next().unwrap().unwrap().as_bytes(),
        &explicit[..4]
    );
}

#[test]
fn stream_frames_preserve_noncanonical_encodings_and_explicit_boundaries() {
    for bytes in [
        &[0x40, 0x0e, 0x40, 1, 0x40, 2, 0x40, 1, 0xaa, 1][..],
        &[
            0x80, 0, 0, 0x0e, 0x80, 0, 0, 1, 0x80, 0, 0, 2, 0x80, 0, 0, 1, 0xaa, 1,
        ][..],
        &[
            0xc0, 0, 0, 0, 0, 0, 0, 0x0e, 0xc0, 0, 0, 0, 0, 0, 0, 1, 0xc0, 0, 0, 0, 0, 0, 0, 2,
            0xc0, 0, 0, 0, 0, 0, 0, 1, 0xaa, 1,
        ][..],
    ] {
        let (QuicFrame::Stream(frame), suffix) = QuicFrame::parse(bytes).unwrap() else {
            panic!("expected STREAM")
        };
        assert_eq!(suffix, &[1]);
        assert_eq!(
            frame.frame_type().as_bytes(),
            &bytes[..frame.frame_type().byte_len()]
        );
        assert_eq!(
            frame.stream_id().encoded_len(),
            frame.frame_type().encoded_len()
        );
        assert_eq!(
            frame.offset().unwrap().encoded_len(),
            frame.frame_type().encoded_len()
        );
        assert_eq!(
            frame.length().unwrap().encoded_len(),
            frame.frame_type().encoded_len()
        );
        assert_eq!(frame.stream_data(), &[0xaa]);
    }
}

#[test]
fn stream_frames_report_range_and_truncation_diagnostics_exactly() {
    let maximum = (1u64 << 62) - 1;
    for bytes in [
        &[0x0e, 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0][..],
        &[
            0x0e, 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 1, 0xaa,
        ][..],
    ] {
        assert!(matches!(
            QuicFrame::parse(bytes),
            Ok((QuicFrame::Stream(_), _))
        ));
    }
    for (bytes, start, length, diagnostic_offset) in [
        (
            &[0x0e, 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1][..],
            maximum,
            1,
            2,
        ),
        (
            &[0x0e, 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 2][..],
            maximum - 1,
            2,
            2,
        ),
    ] {
        assert_eq!(
            QuicFrame::parse(bytes),
            Err(QuicFrameParseError::FieldRangeOutOfRange {
                field: QuicFrameField::StreamOffset,
                offset: diagnostic_offset,
                start,
                length,
                maximum,
            })
        );
    }
    for (type_byte, field, field_offset) in [
        (0x08, QuicFrameField::StreamId, 1),
        (0x0c, QuicFrameField::StreamOffset, 2),
        (0x0e, QuicFrameField::StreamLength, 3),
    ] {
        for (prefix, required) in [
            (&[][..], 1),
            (&[0x40][..], 2),
            (&[0x80, 0, 0][..], 4),
            (&[0xc0, 0, 0, 0, 0, 0, 0][..], 8),
        ] {
            let mut bytes = [0; 11];
            bytes[0] = type_byte;
            bytes[1..field_offset].fill(0);
            bytes[field_offset..field_offset + prefix.len()].copy_from_slice(prefix);
            assert_eq!(
                QuicFrame::parse(&bytes[..field_offset + prefix.len()]),
                Err(QuicFrameParseError::Field {
                    field,
                    offset: field_offset,
                    error: QuicVarIntParseError::Incomplete {
                        required,
                        available: prefix.len(),
                    },
                })
            );
        }
    }
    for available in 0..3 {
        let bytes = [0x0a, 1, 3, 0xaa, 0xbb];
        assert_eq!(
            QuicFrame::parse(&bytes[..3 + available]),
            Err(QuicFrameParseError::IncompleteBytes {
                field: QuicFrameField::StreamData,
                offset: 3,
                required: 3,
                available,
            })
        );
    }
}

#[test]
fn stream_frames_fail_closed_later() {
    let bytes = [1, 0x0e, 1, 0, 0x80, 0];
    let expected = QuicFrameParseError::Field {
        field: QuicFrameField::StreamLength,
        offset: 4,
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
}
