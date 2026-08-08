use net_wire::quic::*;

#[test]
fn connection_close_frames_preserve_transport_and_application_layouts() {
    let transport = [0x1c, 0x2a, 0x06, 3, 0xff, 0, 0x80, 1];
    let (QuicFrame::ConnectionClose(frame), suffix) = QuicFrame::parse(&transport).unwrap() else {
        panic!("expected CONNECTION_CLOSE")
    };
    assert_eq!(frame.as_bytes(), &transport[..7]);
    assert_eq!(frame.frame_type().as_bytes(), &[0x1c]);
    assert_eq!(frame.error_code().value(), 42);
    assert_eq!(frame.triggering_frame_type().unwrap().value(), 6);
    assert_eq!(frame.reason_phrase_length().as_bytes(), &[3]);
    assert_eq!(frame.reason_phrase(), &[0xff, 0, 0x80]);
    assert_eq!(suffix, &[1]);

    for (application, reason, suffix) in [
        (&[0x1d, 9, 0, 0x1e][..], &[][..], &[0x1e][..]),
        (
            &[0x1d, 9, 2, 0xff, 0x80, 1][..],
            &[0xff, 0x80][..],
            &[1][..],
        ),
    ] {
        let (QuicFrame::ConnectionClose(frame), actual_suffix) =
            QuicFrame::parse(application).unwrap()
        else {
            panic!("expected application CONNECTION_CLOSE")
        };
        assert_eq!(frame.frame_type().value(), 0x1d);
        assert_eq!(frame.error_code().value(), 9);
        assert_eq!(frame.triggering_frame_type(), None);
        assert_eq!(frame.reason_phrase(), reason);
        assert_eq!(actual_suffix, suffix);
    }

    let maximum = [0xff; 8];
    let mut extreme = [0; 18];
    extreme[0] = 0x1c;
    extreme[1..9].copy_from_slice(&maximum);
    extreme[9..17].copy_from_slice(&maximum);
    extreme[17] = 0;
    let (QuicFrame::ConnectionClose(frame), suffix) = QuicFrame::parse(&extreme).unwrap() else {
        panic!("expected maximum CONNECTION_CLOSE")
    };
    assert!(suffix.is_empty());
    assert_eq!(frame.error_code().value(), (1u64 << 62) - 1);
    assert_eq!(
        frame.triggering_frame_type().unwrap().value(),
        (1u64 << 62) - 1
    );
    assert_eq!(frame.reason_phrase_length().value(), 0);
}

#[test]
fn connection_close_frames_preserve_noncanonical_widths_and_exact_boundaries() {
    let transport = [
        0x40, 0x1c, // type
        0x40, 1, // error code
        0x80, 0, 0, 2, // triggering type
        0xc0, 0, 0, 0, 0, 0, 0, 1, // reason length
        0xaa, 1,
    ];
    let (QuicFrame::ConnectionClose(frame), suffix) = QuicFrame::parse(&transport).unwrap() else {
        panic!("expected CONNECTION_CLOSE")
    };
    assert_eq!(suffix, &[1]);
    for (field, bytes, width) in [
        (frame.frame_type(), &[0x40, 0x1c][..], QuicVarIntLen::Two),
        (frame.error_code(), &[0x40, 1][..], QuicVarIntLen::Two),
        (
            frame.triggering_frame_type().unwrap(),
            &[0x80, 0, 0, 2][..],
            QuicVarIntLen::Four,
        ),
        (
            frame.reason_phrase_length(),
            &[0xc0, 0, 0, 0, 0, 0, 0, 1][..],
            QuicVarIntLen::Eight,
        ),
    ] {
        assert_eq!((field.as_bytes(), field.encoded_len()), (bytes, width));
        assert!(!field.is_canonical());
    }
    assert_eq!(frame.reason_phrase(), &[0xaa]);

    let application = [0x80, 0, 0, 0x1d, 0, 1, 0];
    let (QuicFrame::ConnectionClose(frame), suffix) = QuicFrame::parse(&application).unwrap()
    else {
        panic!("expected application CONNECTION_CLOSE")
    };
    assert_eq!(frame.frame_type().encoded_len(), QuicVarIntLen::Four);
    assert_eq!(frame.error_code().value(), 0);
    assert_eq!(frame.reason_phrase_length().value(), 1);
    assert_eq!(frame.reason_phrase(), &[0]);
    assert!(suffix.is_empty());
}

#[test]
fn connection_close_fields_and_reason_bounds_report_exact_errors() {
    for (bytes, field, offset, required, available) in [
        (
            &[0x1c][..],
            QuicFrameField::ConnectionCloseErrorCode,
            1,
            1,
            0,
        ),
        (
            &[0x1c, 0x40][..],
            QuicFrameField::ConnectionCloseErrorCode,
            1,
            2,
            1,
        ),
        (&[0x1c, 0][..], QuicFrameField::TriggeringFrameType, 2, 1, 0),
        (
            &[0x1c, 0, 0x80, 0, 0][..],
            QuicFrameField::TriggeringFrameType,
            2,
            4,
            3,
        ),
        (
            &[0x1c, 0, 0][..],
            QuicFrameField::ReasonPhraseLength,
            3,
            1,
            0,
        ),
        (
            &[0x1c, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0][..],
            QuicFrameField::ReasonPhraseLength,
            3,
            8,
            7,
        ),
        (
            &[0x1d][..],
            QuicFrameField::ConnectionCloseErrorCode,
            1,
            1,
            0,
        ),
        (
            &[0x1d, 0x80, 0, 0][..],
            QuicFrameField::ConnectionCloseErrorCode,
            1,
            4,
            3,
        ),
        (&[0x1d, 0][..], QuicFrameField::ReasonPhraseLength, 2, 1, 0),
        (
            &[0x1d, 0, 0x40][..],
            QuicFrameField::ReasonPhraseLength,
            2,
            2,
            1,
        ),
    ] {
        assert_eq!(
            QuicFrame::parse(bytes),
            Err(QuicFrameParseError::Field {
                field,
                offset,
                error: QuicVarIntParseError::Incomplete {
                    required,
                    available,
                },
            })
        );
    }

    for available in 0..3 {
        let bytes = [0x1c, 0, 0, 3, 0xaa, 0xbb];
        assert_eq!(
            QuicFrame::parse(&bytes[..4 + available]),
            Err(QuicFrameParseError::IncompleteBytes {
                field: QuicFrameField::ReasonPhrase,
                offset: 4,
                required: 3,
                available,
            })
        );
    }
    let (QuicFrame::ConnectionClose(frame), suffix) = QuicFrame::parse(&[0x1d, 0, 0, 1]).unwrap()
    else {
        panic!("expected empty CONNECTION_CLOSE")
    };
    assert!(frame.reason_phrase().is_empty());
    assert_eq!(suffix, &[1]);
}

#[cfg(target_pointer_width = "32")]
#[test]
fn connection_close_rejects_an_unrepresentable_reason_length() {
    let bytes = [0x1d, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert_eq!(
        QuicFrame::parse(&bytes),
        Err(QuicFrameParseError::LengthNotRepresentable {
            field: QuicFrameField::ReasonPhraseLength,
            offset: 2,
            value: (1u64 << 62) - 1,
        })
    );
}

#[cfg(target_pointer_width = "64")]
#[test]
fn connection_close_reports_huge_representable_reason_length_as_incomplete() {
    let bytes = [0x1d, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert_eq!(
        QuicFrame::parse(&bytes),
        Err(QuicFrameParseError::IncompleteBytes {
            field: QuicFrameField::ReasonPhrase,
            offset: 10,
            required: (1usize << 62) - 1,
            available: 0,
        })
    );
}

#[test]
fn connection_close_frames_mix_and_fail_closed_at_absolute_offsets() {
    let bytes = [0, 1, 0x1c, 2, 3, 1, 0xaa, 0x1d, 4, 0, 0];
    let frames = QuicFrames::parse(&bytes).unwrap();
    let mut iter = frames.iter();
    for (length, close) in [
        (1usize, false),
        (1, false),
        (5, true),
        (3, true),
        (1, false),
    ] {
        let frame = iter.next().unwrap().unwrap();
        assert_eq!(frame.as_bytes().len(), length);
        assert_eq!(matches!(frame, QuicFrame::ConnectionClose(_)), close);
    }
    assert_eq!(iter.next(), None);

    let malformed = [1, 0x1d, 0, 3, 0xaa];
    let expected = QuicFrameParseError::IncompleteBytes {
        field: QuicFrameField::ReasonPhrase,
        offset: 4,
        required: 3,
        available: 1,
    };
    assert_eq!(QuicFrames::parse(&malformed), Err(expected));
    let mut raw = QuicFrameIter::new(&malformed);
    assert!(matches!(raw.next(), Some(Ok(QuicFrame::Ping(_)))));
    assert_eq!(raw.next(), Some(Err(expected)));
    assert_eq!(raw.next(), None);
    assert_eq!(raw.next(), None);

    let _close: Option<QuicConnectionCloseFrame<'_>> = None;
    let (frame, _) = QuicFrame::parse(&[0x1c, 0, 0, 0]).unwrap();
    match frame {
        QuicFrame::ConnectionClose(frame) => {
            assert_eq!(frame.error_code().value(), 0);
            assert_eq!(frame.triggering_frame_type().unwrap().value(), 0);
        }
        _ => panic!("expected CONNECTION_CLOSE"),
    }
}
