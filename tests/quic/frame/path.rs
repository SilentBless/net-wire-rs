use net_wire::quic::*;

#[test]
fn path_frames_parse_exact_canonical_layouts_and_opaque_data() {
    for (bytes, response, data) in [
        (
            &[0x1a, 0, 1, 2, 3, 4, 5, 6, 7, 0xfe][..],
            false,
            &[0, 1, 2, 3, 4, 5, 6, 7],
        ),
        (
            &[0x1b, 0xff, 0, 0x80, 1, 2, 3, 4, 5, 0xfe][..],
            true,
            &[0xff, 0, 0x80, 1, 2, 3, 4, 5],
        ),
    ] {
        let (frame, suffix) = QuicFrame::parse(bytes).unwrap();
        assert_eq!(frame.as_bytes(), &bytes[..9]);
        assert_eq!(frame.frame_type().as_bytes(), &bytes[..1]);
        assert_eq!(suffix, &[0xfe]);
        match (frame, response) {
            (QuicFrame::PathChallenge(frame), false) => assert_eq!(frame.data(), data),
            (QuicFrame::PathResponse(frame), true) => assert_eq!(frame.data(), data),
            _ => panic!("unexpected path frame variant"),
        }
    }
}

#[test]
fn path_frames_preserve_noncanonical_type_widths_and_boundaries() {
    for (type_bytes, response) in [
        (&[0x40, 0x1a][..], false),
        (&[0x80, 0, 0, 0x1a][..], false),
        (&[0xc0, 0, 0, 0, 0, 0, 0, 0x1a][..], false),
        (&[0x40, 0x1b][..], true),
        (&[0x80, 0, 0, 0x1b][..], true),
        (&[0xc0, 0, 0, 0, 0, 0, 0, 0x1b][..], true),
    ] {
        let mut bytes = [0; 17];
        bytes[..type_bytes.len()].copy_from_slice(type_bytes);
        bytes[type_bytes.len()..type_bytes.len() + 8].copy_from_slice(&[9; 8]);
        bytes[type_bytes.len() + 8] = 0xfe;
        let input = &bytes[..type_bytes.len() + 9];
        let (frame, suffix) = QuicFrame::parse(input).unwrap();
        assert_eq!(frame.as_bytes(), &input[..type_bytes.len() + 8]);
        assert_eq!(frame.frame_type().as_bytes(), type_bytes);
        assert_eq!(suffix, &[0xfe]);
        assert!(matches!(frame, QuicFrame::PathResponse(_)) == response);
    }
}

#[test]
fn path_frames_report_every_incomplete_data_length() {
    for frame_type in [0x1a, 0x1b] {
        for available in 0..8 {
            let mut bytes = [0; 9];
            bytes[0] = frame_type;
            assert_eq!(
                QuicFrame::parse(&bytes[..available + 1]),
                Err(QuicFrameParseError::IncompleteBytes {
                    field: QuicFrameField::PathData,
                    offset: 1,
                    required: 8,
                    available,
                })
            );
        }
    }
}

#[test]
fn malformed_later_path_frame_has_absolute_offset_and_fused_iterator() {
    let bytes = [1, 0x1a, 0, 0, 0];
    let expected = QuicFrameParseError::IncompleteBytes {
        field: QuicFrameField::PathData,
        offset: 2,
        required: 8,
        available: 3,
    };
    assert_eq!(QuicFrames::parse(&bytes), Err(expected));
    let mut iter = QuicFrameIter::new(&bytes);
    assert!(matches!(iter.next(), Some(Ok(QuicFrame::Ping(_)))));
    assert_eq!(iter.next(), Some(Err(expected)));
    assert_eq!(iter.next(), None);
    assert_eq!(iter.next(), None);
}

#[test]
fn path_frames_mix_at_exact_boundaries_with_existing_frames() {
    let bytes = [
        0, 0x1a, 0, 1, 2, 3, 4, 5, 6, 7, 1, 0x1b, 8, 9, 10, 11, 12, 13, 14, 15, 0x1e,
    ];
    let frames = QuicFrames::parse(&bytes).unwrap();
    let mut iter = frames.iter();
    for (length, kind) in [(1, 0), (9, 1), (1, 2), (9, 3), (1, 4)] {
        let frame = iter.next().unwrap().unwrap();
        assert_eq!(frame.as_bytes().len(), length);
        match kind {
            0 => assert!(matches!(frame, QuicFrame::Padding(_))),
            1 => assert!(matches!(frame, QuicFrame::PathChallenge(_))),
            2 => assert!(matches!(frame, QuicFrame::Ping(_))),
            3 => assert!(matches!(frame, QuicFrame::PathResponse(_))),
            _ => assert!(matches!(frame, QuicFrame::HandshakeDone(_))),
        }
    }
    assert_eq!(iter.next(), None);
}

#[test]
fn path_frames_accept_arbitrary_opaque_data() {
    for (frame_type, data, response) in [
        (0x1a, [0; 8], false),
        (0x1b, [0xff; 8], true),
        (0x1a, [0, 0xff, 0x80, 0x7f, 1, 2, 3, 4], false),
    ] {
        let mut bytes = [0; 9];
        bytes[0] = frame_type;
        bytes[1..].copy_from_slice(&data);
        let (frame, suffix) = QuicFrame::parse(&bytes).unwrap();
        assert!(suffix.is_empty());
        match (frame, response) {
            (QuicFrame::PathChallenge(frame), false) => assert_eq!(frame.data(), &data),
            (QuicFrame::PathResponse(frame), true) => assert_eq!(frame.data(), &data),
            _ => panic!("unexpected path frame variant"),
        }
    }
}
