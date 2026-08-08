use net_wire::quic::*;

#[test]
fn new_token_and_handshake_done_preserve_exact_views_and_suffixes() {
    let new_token = [0x07, 3, 0, 0x80, 0xff, 0xfe];
    let (QuicFrame::NewToken(frame), suffix) = QuicFrame::parse(&new_token).unwrap() else {
        panic!("expected NEW_TOKEN")
    };
    assert_eq!(frame.as_bytes(), &new_token[..5]);
    assert_eq!(frame.frame_type().as_bytes(), &[0x07]);
    assert_eq!(frame.token_length().as_bytes(), &[3]);
    assert_eq!(frame.token(), &[0, 0x80, 0xff]);
    assert_eq!(suffix, &[0xfe]);

    let handshake_done = [0x1e, 0xfe];
    let (QuicFrame::HandshakeDone(frame), suffix) = QuicFrame::parse(&handshake_done).unwrap()
    else {
        panic!("expected HANDSHAKE_DONE")
    };
    assert_eq!(frame.as_bytes(), &[0x1e]);
    assert_eq!(frame.frame_type().as_bytes(), &[0x1e]);
    assert_eq!(suffix, &[0xfe]);
}

#[test]
fn new_token_and_handshake_done_preserve_noncanonical_type_and_length_widths() {
    let new_token = [0x40, 0x07, 0x80, 0, 0, 2, 0xaa, 0xbb];
    let (QuicFrame::NewToken(frame), suffix) = QuicFrame::parse(&new_token).unwrap() else {
        panic!("expected NEW_TOKEN")
    };
    assert!(suffix.is_empty());
    assert_eq!(frame.frame_type().as_bytes(), &[0x40, 0x07]);
    assert_eq!(frame.token_length().as_bytes(), &[0x80, 0, 0, 2]);
    assert_eq!(frame.token(), &[0xaa, 0xbb]);

    for (bytes, encoded_length) in [
        (&[7, 0x40, 1, 0xaa][..], &[0x40, 1][..]),
        (
            &[7, 0xc0, 0, 0, 0, 0, 0, 0, 1, 0xaa][..],
            &[0xc0, 0, 0, 0, 0, 0, 0, 1][..],
        ),
    ] {
        let (QuicFrame::NewToken(frame), suffix) = QuicFrame::parse(bytes).unwrap() else {
            panic!("expected NEW_TOKEN")
        };
        assert!(suffix.is_empty());
        assert_eq!(frame.token_length().as_bytes(), encoded_length);
        assert_eq!(frame.token(), &[0xaa]);
    }

    let (QuicFrame::HandshakeDone(frame), suffix) = QuicFrame::parse(&[0x40, 0x1e, 0]).unwrap()
    else {
        panic!("expected HANDSHAKE_DONE")
    };
    assert_eq!(frame.as_bytes(), &[0x40, 0x1e]);
    assert_eq!(suffix, &[0]);
}

#[test]
fn new_token_reports_token_length_and_bounded_byte_errors() {
    for (prefix, required) in [
        (&[][..], 1),
        (&[0x40][..], 2),
        (&[0x80, 0, 0][..], 4),
        (&[0xc0, 0, 0, 0, 0, 0, 0][..], 8),
    ] {
        let mut bytes = [0; 9];
        bytes[0] = 7;
        bytes[1..1 + prefix.len()].copy_from_slice(prefix);
        assert_eq!(
            QuicFrame::parse(&bytes[..1 + prefix.len()]),
            Err(QuicFrameParseError::Field {
                field: QuicFrameField::TokenLength,
                offset: 1,
                error: QuicVarIntParseError::Incomplete {
                    required,
                    available: prefix.len(),
                },
            })
        );
    }

    for (bytes, offset) in [(&[7, 0][..], 2), (&[0x40, 7, 0x40, 0][..], 4)] {
        assert_eq!(
            QuicFrame::parse(bytes),
            Err(QuicFrameParseError::EmptyField {
                field: QuicFrameField::Token,
                offset,
            })
        );
    }

    for (bytes, required, available) in [(&[7, 1][..], 1, 0), (&[7, 3, 0xaa][..], 3, 1)] {
        assert_eq!(
            QuicFrame::parse(bytes),
            Err(QuicFrameParseError::IncompleteBytes {
                field: QuicFrameField::Token,
                offset: 2,
                required,
                available,
            })
        );
    }
}

#[cfg(target_pointer_width = "32")]
#[test]
fn new_token_rejects_unrepresentable_token_lengths() {
    let bytes = [7, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert_eq!(
        QuicFrame::parse(&bytes),
        Err(QuicFrameParseError::LengthNotRepresentable {
            field: QuicFrameField::TokenLength,
            offset: 1,
            value: (1u64 << 62) - 1,
        })
    );
}

#[test]
fn new_token_fails_closed_at_absolute_offsets_and_mixes_with_other_frames() {
    let malformed = [1, 7, 3, 0xaa];
    let expected = QuicFrameParseError::IncompleteBytes {
        field: QuicFrameField::Token,
        offset: 3,
        required: 3,
        available: 1,
    };
    assert_eq!(QuicFrames::parse(&malformed), Err(expected));
    let mut iter = QuicFrameIter::new(&malformed);
    assert!(matches!(iter.next(), Some(Ok(QuicFrame::Ping(_)))));
    assert_eq!(iter.next(), Some(Err(expected)));
    assert_eq!(iter.next(), None);
    assert_eq!(iter.next(), None);

    let bytes = [0, 7, 1, 0xaa, 0x1e, 1];
    let frames = QuicFrames::parse(&bytes).unwrap();
    let mut iter = frames.iter();
    for expected_len in [1, 3, 1, 1] {
        assert_eq!(iter.next().unwrap().unwrap().as_bytes().len(), expected_len);
    }
    assert_eq!(iter.next(), None);
}

#[test]
fn new_token_and_handshake_done_fields_remain_distinct() {
    assert_ne!(QuicFrameField::Token, QuicFrameField::TokenLength);
}
