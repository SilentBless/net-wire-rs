use net_wire::quic::*;

#[test]
fn reset_stream_and_stop_sending_parse_exact_layouts_and_suffixes() {
    let reset_bytes = [4, 9, 0x40, 0x2a, 63, 0xfe];
    let (frame, suffix) = QuicFrame::parse(&reset_bytes).unwrap();
    let QuicFrame::ResetStream(reset) = frame else {
        panic!("expected RESET_STREAM")
    };
    assert_eq!(reset.as_bytes(), &reset_bytes[..5]);
    assert_eq!(reset.frame_type().value(), 4);
    assert_eq!(reset.stream_id().value(), 9);
    assert_eq!(reset.application_error_code().value(), 42);
    assert_eq!(reset.final_size().value(), 63);
    assert_eq!(suffix, &[0xfe]);

    let stop_bytes = [5, 7, 0x40, 0x2a, 0xfe];
    let (frame, suffix) = QuicFrame::parse(&stop_bytes).unwrap();
    let QuicFrame::StopSending(stop) = frame else {
        panic!("expected STOP_SENDING")
    };
    assert_eq!(stop.as_bytes(), &stop_bytes[..4]);
    assert_eq!(stop.frame_type().value(), 5);
    assert_eq!(stop.stream_id().value(), 7);
    assert_eq!(stop.application_error_code().value(), 42);
    assert_eq!(suffix, &[0xfe]);
}

#[test]
fn control_frames_preserve_each_nested_noncanonical_width() {
    let reset_bytes = [4, 0x40, 1, 0x80, 0, 0, 2, 0xc0, 0, 0, 0, 0, 0, 0, 3];
    let (frame, suffix) = QuicFrame::parse(&reset_bytes).unwrap();
    let QuicFrame::ResetStream(reset) = frame else {
        panic!("expected RESET_STREAM")
    };
    assert!(suffix.is_empty());
    assert_eq!(reset.stream_id().as_bytes(), &[0x40, 1]);
    assert_eq!(reset.application_error_code().as_bytes(), &[0x80, 0, 0, 2]);
    assert_eq!(reset.final_size().as_bytes(), &[0xc0, 0, 0, 0, 0, 0, 0, 3]);
    assert!(!reset.stream_id().is_canonical());
    assert!(!reset.application_error_code().is_canonical());
    assert!(!reset.final_size().is_canonical());

    let stop_bytes = [5, 0x80, 0, 0, 1, 0xc0, 0, 0, 0, 0, 0, 0, 2];
    let (frame, suffix) = QuicFrame::parse(&stop_bytes).unwrap();
    let QuicFrame::StopSending(stop) = frame else {
        panic!("expected STOP_SENDING")
    };
    assert!(suffix.is_empty());
    assert_eq!(stop.stream_id().as_bytes(), &[0x80, 0, 0, 1]);
    assert_eq!(
        stop.application_error_code().as_bytes(),
        &[0xc0, 0, 0, 0, 0, 0, 0, 2]
    );
}

#[test]
fn control_frame_field_truncations_report_semantic_absolute_offsets() {
    for (frame_type, fields) in [(4u8, 3usize), (5u8, 2usize)] {
        for field_index in 0..fields {
            let field = match field_index {
                0 => QuicFrameField::StreamId,
                1 => QuicFrameField::ApplicationErrorCode,
                _ => QuicFrameField::FinalSize,
            };
            for (prefix, required) in [
                (&[][..], 1),
                (&[0x40][..], 2),
                (&[0x80, 0, 0][..], 4),
                (&[0xc0, 0, 0, 0, 0, 0, 0][..], 8),
            ] {
                let mut bytes = [0; 32];
                bytes[0] = frame_type;
                let field_offset = field_index + 1;
                bytes[1..field_offset].fill(0);
                bytes[field_offset..field_offset + prefix.len()].copy_from_slice(prefix);
                let input = &bytes[..field_offset + prefix.len()];
                assert_eq!(
                    QuicFrame::parse(input),
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
    }
}

#[test]
fn control_frames_iterate_with_padding_and_ping_at_exact_boundaries() {
    let bytes = [0, 1, 4, 2, 3, 4, 5, 6, 7, 0];
    let frames = QuicFrames::parse(&bytes).unwrap();
    let mut iter = frames.iter();
    for expected in [1usize, 1, 4, 3, 1] {
        let frame = iter.next().unwrap().unwrap();
        assert_eq!(frame.as_bytes().len(), expected);
    }
    assert!(matches!(
        QuicFrame::parse(&bytes[2..]).unwrap().0,
        QuicFrame::ResetStream(_)
    ));
    assert!(matches!(
        QuicFrame::parse(&bytes[6..]).unwrap().0,
        QuicFrame::StopSending(_)
    ));
    assert_eq!(iter.next(), None);
}

#[test]
fn malformed_control_frame_has_absolute_offset_and_fused_raw_iterator() {
    let bytes = [1, 5, 9, 0x80, 0];
    let expected = QuicFrameParseError::Field {
        field: QuicFrameField::ApplicationErrorCode,
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
fn control_frames_accept_raw_error_codes_and_maximum_varints() {
    let maximum = [0xff; 8];
    let mut reset_bytes = [0; 25];
    reset_bytes[0] = 4;
    reset_bytes[1..9].copy_from_slice(&maximum);
    reset_bytes[9..17].copy_from_slice(&maximum);
    reset_bytes[17..25].copy_from_slice(&maximum);
    let (frame, suffix) = QuicFrame::parse(&reset_bytes).unwrap();
    let QuicFrame::ResetStream(reset) = frame else {
        panic!("expected RESET_STREAM")
    };
    assert!(suffix.is_empty());
    assert_eq!(reset.stream_id().value(), (1u64 << 62) - 1);
    assert_eq!(reset.application_error_code().as_bytes(), &maximum);
    assert_eq!(reset.final_size().value(), (1u64 << 62) - 1);

    let stop_bytes = [5, 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let (frame, _) = QuicFrame::parse(&stop_bytes).unwrap();
    let QuicFrame::StopSending(stop) = frame else {
        panic!("expected STOP_SENDING")
    };
    assert_eq!(stop.application_error_code().value(), (1u64 << 62) - 1);
}

#[test]
fn control_frame_views_are_available_from_the_canonical_namespace() {
    let _: Option<net_wire::quic::QuicResetStreamFrame<'_>> = None;
}
