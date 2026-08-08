use net_wire::quic::*;

#[test]
fn connection_id_frames_parse_exact_views_and_suffixes() {
    let bytes = [
        0x18, 3, 2, 3, 0xa1, 0xa2, 0xa3, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0xfe,
    ];
    let (QuicFrame::NewConnectionId(frame), suffix) = QuicFrame::parse(&bytes).unwrap() else {
        panic!("expected NEW_CONNECTION_ID")
    };
    assert_eq!(frame.as_bytes(), &bytes[..23]);
    assert_eq!(frame.sequence_number().value(), 3);
    assert_eq!(frame.retire_prior_to().value(), 2);
    assert_eq!(frame.connection_id_length(), 3);
    assert_eq!(frame.connection_id().as_bytes(), &[0xa1, 0xa2, 0xa3]);
    assert_eq!(
        frame.stateless_reset_token(),
        &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    );
    assert_eq!(suffix, &[0xfe]);

    let retire = [0xc0, 0, 0, 0, 0, 0, 0, 0x19, 0x40, 7, 0xfe];
    let (QuicFrame::RetireConnectionId(frame), suffix) = QuicFrame::parse(&retire).unwrap() else {
        panic!("expected RETIRE_CONNECTION_ID")
    };
    assert_eq!(frame.as_bytes(), &retire[..10]);
    assert_eq!(frame.frame_type().as_bytes(), &retire[..8]);
    assert_eq!(frame.sequence_number().as_bytes(), &[0x40, 7]);
    assert_eq!(suffix, &[0xfe]);
}

#[test]
fn connection_id_frames_preserve_widths_and_maximum_values() {
    let bytes = [
        0x80, 0, 0, 0x18, 0x40, 1, 0x80, 0, 0, 1, 1, 0xaa, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    ];
    let (QuicFrame::NewConnectionId(frame), suffix) = QuicFrame::parse(&bytes).unwrap() else {
        panic!("expected NEW_CONNECTION_ID")
    };
    assert!(suffix.is_empty());
    assert_eq!(frame.frame_type().as_bytes(), &[0x80, 0, 0, 0x18]);
    assert_eq!(frame.sequence_number().as_bytes(), &[0x40, 1]);
    assert_eq!(frame.retire_prior_to().as_bytes(), &[0x80, 0, 0, 1]);

    let two_byte_type = [
        0x40, 0x18, 0x80, 0, 0, 1, 0x40, 1, 1, 0xaa, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    ];
    let (QuicFrame::NewConnectionId(frame), suffix) = QuicFrame::parse(&two_byte_type).unwrap()
    else {
        panic!("expected NEW_CONNECTION_ID")
    };
    assert!(suffix.is_empty());
    assert_eq!(frame.frame_type().as_bytes(), &[0x40, 0x18]);
    assert_eq!(frame.sequence_number().as_bytes(), &[0x80, 0, 0, 1]);
    assert_eq!(frame.retire_prior_to().as_bytes(), &[0x40, 1]);

    let maximum = [0xff; 8];
    let mut maximum_new = [0; 42];
    maximum_new[..8].copy_from_slice(&[0xc0, 0, 0, 0, 0, 0, 0, 0x18]);
    maximum_new[8..16].copy_from_slice(&maximum);
    maximum_new[16..24].copy_from_slice(&maximum);
    maximum_new[24] = 1;
    maximum_new[25] = 0xaa;
    maximum_new[26..].fill(0x55);
    let (QuicFrame::NewConnectionId(frame), _) = QuicFrame::parse(&maximum_new).unwrap() else {
        panic!("expected NEW_CONNECTION_ID")
    };
    assert_eq!(frame.frame_type().as_bytes(), &maximum_new[..8]);
    assert_eq!(frame.sequence_number().value(), (1u64 << 62) - 1);
    assert_eq!(frame.retire_prior_to().value(), (1u64 << 62) - 1);
    assert_eq!(frame.stateless_reset_token(), &[0x55; 16]);

    for type_bytes in [
        &[0x40, 0x19][..],
        &[0x80, 0, 0, 0x19][..],
        &[0xc0, 0, 0, 0, 0, 0, 0, 0x19][..],
    ] {
        let mut retire = [0; 9];
        retire[..type_bytes.len()].copy_from_slice(type_bytes);
        let (QuicFrame::RetireConnectionId(frame), suffix) =
            QuicFrame::parse(&retire[..type_bytes.len() + 1]).unwrap()
        else {
            panic!("expected RETIRE_CONNECTION_ID")
        };
        assert!(suffix.is_empty());
        assert_eq!(frame.frame_type().as_bytes(), type_bytes);
    }
}

#[test]
fn connection_id_frames_report_semantic_errors_and_absolute_offsets() {
    for (bytes, field, offset, required, available) in [
        (&[0x18][..], QuicFrameField::SequenceNumber, 1, 1, 0),
        (&[0x18, 0x40][..], QuicFrameField::SequenceNumber, 1, 2, 1),
        (
            &[0x18, 0x80, 0, 0][..],
            QuicFrameField::SequenceNumber,
            1,
            4,
            3,
        ),
        (
            &[0x18, 0xc0, 0, 0, 0, 0, 0, 0][..],
            QuicFrameField::SequenceNumber,
            1,
            8,
            7,
        ),
        (&[0x18, 0][..], QuicFrameField::RetirePriorTo, 2, 1, 0),
        (&[0x18, 0, 0x40][..], QuicFrameField::RetirePriorTo, 2, 2, 1),
        (
            &[0x18, 0, 0x80, 0, 0][..],
            QuicFrameField::RetirePriorTo,
            2,
            4,
            3,
        ),
        (
            &[0x18, 0, 0xc0, 0, 0, 0, 0, 0, 0][..],
            QuicFrameField::RetirePriorTo,
            2,
            8,
            7,
        ),
        (
            &[0x19, 0xc0, 0, 0, 0, 0, 0, 0][..],
            QuicFrameField::SequenceNumber,
            1,
            8,
            7,
        ),
    ] {
        assert_eq!(
            QuicFrame::parse(bytes),
            Err(QuicFrameParseError::Field {
                field,
                offset,
                error: QuicVarIntParseError::Incomplete {
                    required,
                    available
                },
            })
        );
    }
    assert_eq!(
        QuicFrame::parse(&[0x18, 0, 0]),
        Err(QuicFrameParseError::IncompleteBytes {
            field: QuicFrameField::ConnectionIdLength,
            offset: 3,
            required: 1,
            available: 0,
        })
    );
    assert_eq!(
        QuicFrame::parse(&[0x18, 0, 0, 0]),
        Err(QuicFrameParseError::EmptyField {
            field: QuicFrameField::ConnectionId,
            offset: 4,
        })
    );
    assert_eq!(
        QuicFrame::parse(&[0x18, 0, 0, 21]),
        Err(QuicFrameParseError::FieldValueOutOfRange {
            field: QuicFrameField::ConnectionIdLength,
            offset: 3,
            value: 21,
            maximum: 20,
        })
    );
    assert_eq!(
        QuicFrames::parse(&[1, 0x40, 0x18, 0x40, 1, 0x80, 0, 0, 2]),
        Err(QuicFrameParseError::FieldValueExceedsField {
            field: QuicFrameField::RetirePriorTo,
            offset: 5,
            value: 2,
            maximum_field: QuicFrameField::SequenceNumber,
            maximum: 1,
        })
    );
}

#[test]
fn connection_id_frames_bound_cid_token_and_fail_closed() {
    assert_eq!(
        QuicFrame::parse(&[0x18, 0, 0, 3]),
        Err(QuicFrameParseError::IncompleteBytes {
            field: QuicFrameField::ConnectionId,
            offset: 4,
            required: 3,
            available: 0,
        })
    );
    assert_eq!(
        QuicFrame::parse(&[0x18, 0, 0, 3, 0xaa]),
        Err(QuicFrameParseError::IncompleteBytes {
            field: QuicFrameField::ConnectionId,
            offset: 4,
            required: 3,
            available: 1,
        })
    );
    for available in 0..16 {
        let mut bytes = [0; 20];
        bytes[..4].copy_from_slice(&[0x18, 0, 0, 1]);
        bytes[4] = 0xaa;
        assert_eq!(
            QuicFrame::parse(&bytes[..5 + available]),
            Err(QuicFrameParseError::IncompleteBytes {
                field: QuicFrameField::StatelessResetToken,
                offset: 5,
                required: 16,
                available,
            })
        );
    }
    let mut maximum_connection_id = [0; 40];
    maximum_connection_id[..4].copy_from_slice(&[0x18, 0, 0, 20]);
    maximum_connection_id[4..24].fill(0xaa);
    maximum_connection_id[24..].fill(0x55);
    let (QuicFrame::NewConnectionId(frame), suffix) =
        QuicFrame::parse(&maximum_connection_id).unwrap()
    else {
        panic!("expected NEW_CONNECTION_ID")
    };
    assert!(suffix.is_empty());
    assert_eq!(frame.connection_id().len(), 20);
    assert_eq!(frame.connection_id().as_bytes(), &[0xaa; 20]);

    let bytes = [1, 0x19, 2, 0x18, 0, 0, 1, 0xaa];
    let expected = QuicFrameParseError::IncompleteBytes {
        field: QuicFrameField::StatelessResetToken,
        offset: 8,
        required: 16,
        available: 0,
    };
    assert_eq!(QuicFrames::parse(&bytes), Err(expected));
    let mut iter = QuicFrameIter::new(&bytes);
    assert!(matches!(iter.next(), Some(Ok(QuicFrame::Ping(_)))));
    assert!(matches!(
        iter.next(),
        Some(Ok(QuicFrame::RetireConnectionId(_)))
    ));
    assert_eq!(iter.next(), Some(Err(expected)));
    assert_eq!(iter.next(), None);

    let complete = [
        1, 0x19, 2, 0x18, 1, 0, 1, 0xaa, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0x1e,
    ];
    let frames = QuicFrames::parse(&complete).unwrap();
    let mut iter = frames.iter();
    assert!(matches!(iter.next(), Some(Ok(QuicFrame::Ping(_)))));
    assert!(matches!(
        iter.next(),
        Some(Ok(QuicFrame::RetireConnectionId(_)))
    ));
    assert!(matches!(
        iter.next(),
        Some(Ok(QuicFrame::NewConnectionId(_)))
    ));
    assert!(matches!(iter.next(), Some(Ok(QuicFrame::HandshakeDone(_)))));
    assert_eq!(iter.next(), None);
}
