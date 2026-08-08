use net_wire::quic::*;

#[test]
fn ack_zero_ranges_preserves_headers_and_valid_looking_suffix() {
    let bytes = [2, 10, 1, 0, 2, 1];
    let (QuicFrame::Ack(frame), suffix) = QuicFrame::parse(&bytes).unwrap() else {
        panic!("expected ACK");
    };
    assert_eq!(frame.as_bytes(), &bytes[..5]);
    assert_eq!(suffix, &[1]);
    for (field, raw, value) in [
        (frame.frame_type(), &[2][..], 2),
        (frame.largest_acknowledged(), &[10][..], 10),
        (frame.ack_delay(), &[1][..], 1),
        (frame.ack_range_count(), &[0][..], 0),
        (frame.first_ack_range(), &[2][..], 2),
    ] {
        assert_eq!(field.as_bytes(), raw);
        assert_eq!(field.value(), value);
        assert_eq!(field.encoded_len(), QuicVarIntLen::One);
    }
    assert_eq!(frame.first_smallest_acknowledged(), 8);
    assert_eq!(frame.ranges().next(), None);
    assert!(frame.ecn_counts().is_none());
}

#[test]
fn ack_ecn_zero_ranges_preserves_counts_and_suffix() {
    let bytes = [3, 4, 0, 0, 0, 1, 2, 3, 0];
    let (QuicFrame::Ack(frame), suffix) = QuicFrame::parse(&bytes).unwrap() else {
        panic!("expected ACK_ECN");
    };
    assert_eq!(frame.as_bytes(), &bytes[..8]);
    assert_eq!(suffix, &[0]);
    let counts = frame.ecn_counts().unwrap();
    assert_eq!(counts.as_bytes(), &[1, 2, 3]);
    for (field, raw, value) in [
        (counts.ect0_count(), &[1][..], 1),
        (counts.ect1_count(), &[2][..], 2),
        (counts.ecn_ce_count(), &[3][..], 3),
    ] {
        assert_eq!(field.as_bytes(), raw);
        assert_eq!(field.value(), value);
    }
}

#[test]
fn ack_additional_ranges_are_descending_clonable_and_fused() {
    let bytes = [2, 20, 0, 2, 2, 0, 1, 2, 0];
    let (QuicFrame::Ack(frame), suffix) = QuicFrame::parse(&bytes).unwrap() else {
        panic!("expected ACK");
    };
    assert!(suffix.is_empty());
    assert_eq!(frame.ack_range_count().value(), 2);
    assert_eq!(frame.first_smallest_acknowledged(), 18);

    let mut ranges = frame.ranges();
    let mut clone = ranges.clone();
    let first = ranges.next().unwrap();
    let cloned_first = clone.next().unwrap();
    assert_eq!(first, cloned_first);
    assert_eq!(first.as_bytes(), &[0, 1]);
    assert_eq!(first.gap().value(), 0);
    assert_eq!(first.ack_range_length().value(), 1);
    assert_eq!(
        (first.largest_acknowledged(), first.smallest_acknowledged()),
        (16, 15)
    );

    let second = ranges.next().unwrap();
    assert_eq!(second.as_bytes(), &[2, 0]);
    assert_eq!(second.gap().value(), 2);
    assert_eq!(second.ack_range_length().value(), 0);
    assert_eq!(
        (
            second.largest_acknowledged(),
            second.smallest_acknowledged()
        ),
        (11, 11)
    );
    assert_eq!(ranges.next(), None);
    assert_eq!(ranges.next(), None);
    assert_eq!(clone.next().unwrap(), second);
    assert_eq!(clone.next(), None);
}

#[test]
fn ack_noncanonical_widths_preserve_every_accessor() {
    let bytes = [
        0x40, 3, // ACK_ECN type, two-byte encoding
        0x80, 0, 0, 10, // largest acknowledged, four-byte encoding
        0xc0, 0, 0, 0, 0, 0, 0, 1, // ACK delay, eight-byte encoding
        0x40, 1, // range count, two-byte encoding
        0x80, 0, 0, 0, // first range, four-byte encoding
        0x40, 0, // Gap, two-byte encoding
        0xc0, 0, 0, 0, 0, 0, 0, 0, // ACK Range Length, eight-byte encoding
        0x40, 1, // ECT(0), two-byte encoding
        0x80, 0, 0, 2, // ECT(1), four-byte encoding
        0xc0, 0, 0, 0, 0, 0, 0, 3, // ECN-CE, eight-byte encoding
    ];
    let (QuicFrame::Ack(frame), suffix) = QuicFrame::parse(&bytes).unwrap() else {
        panic!("expected ACK_ECN");
    };
    assert!(suffix.is_empty());
    for (field, raw, width, value) in [
        (frame.frame_type(), &[0x40, 3][..], QuicVarIntLen::Two, 3),
        (
            frame.largest_acknowledged(),
            &[0x80, 0, 0, 10][..],
            QuicVarIntLen::Four,
            10,
        ),
        (
            frame.ack_delay(),
            &[0xc0, 0, 0, 0, 0, 0, 0, 1][..],
            QuicVarIntLen::Eight,
            1,
        ),
        (
            frame.ack_range_count(),
            &[0x40, 1][..],
            QuicVarIntLen::Two,
            1,
        ),
        (
            frame.first_ack_range(),
            &[0x80, 0, 0, 0][..],
            QuicVarIntLen::Four,
            0,
        ),
    ] {
        assert_eq!(
            (field.as_bytes(), field.encoded_len(), field.value()),
            (raw, width, value)
        );
    }
    let range = frame.ranges().next().unwrap();
    for (field, raw, width, value) in [
        (range.gap(), &[0x40, 0][..], QuicVarIntLen::Two, 0),
        (
            range.ack_range_length(),
            &[0xc0, 0, 0, 0, 0, 0, 0, 0][..],
            QuicVarIntLen::Eight,
            0,
        ),
    ] {
        assert_eq!(
            (field.as_bytes(), field.encoded_len(), field.value()),
            (raw, width, value)
        );
    }
    let counts = frame.ecn_counts().unwrap();
    for (field, raw, width, value) in [
        (counts.ect0_count(), &[0x40, 1][..], QuicVarIntLen::Two, 1),
        (
            counts.ect1_count(),
            &[0x80, 0, 0, 2][..],
            QuicVarIntLen::Four,
            2,
        ),
        (
            counts.ecn_ce_count(),
            &[0xc0, 0, 0, 0, 0, 0, 0, 3][..],
            QuicVarIntLen::Eight,
            3,
        ),
    ] {
        assert_eq!(
            (field.as_bytes(), field.encoded_len(), field.value()),
            (raw, width, value)
        );
    }
}

#[test]
fn ack_arithmetic_boundaries_and_underflows_are_exact() {
    let maximum = [0xff; 8];
    let mut bytes = [0; 19];
    bytes[0] = 2;
    bytes[1..9].copy_from_slice(&maximum);
    bytes[11..19].copy_from_slice(&maximum);
    let (QuicFrame::Ack(frame), suffix) = QuicFrame::parse(&bytes).unwrap() else {
        panic!("expected ACK");
    };
    assert!(suffix.is_empty());
    assert_eq!(frame.first_smallest_acknowledged(), 0);

    assert_eq!(
        QuicFrame::parse(&[2, 1, 0, 0, 2]),
        Err(QuicFrameParseError::AckRangeUnderflow {
            field: QuicFrameField::FirstAckRange,
            offset: 4,
            base: 1,
            value: 2,
            adjustment: 0,
        })
    );
    let (QuicFrame::Ack(frame), _) = QuicFrame::parse(&[2, 2, 0, 1, 0, 0, 0]).unwrap() else {
        panic!("expected ACK");
    };
    let range = frame.ranges().next().unwrap();
    assert_eq!(
        (range.largest_acknowledged(), range.smallest_acknowledged()),
        (0, 0)
    );
    assert_eq!(
        QuicFrame::parse(&[2, 1, 0, 1, 0, 0, 0]),
        Err(QuicFrameParseError::AckRangeUnderflow {
            field: QuicFrameField::AckGap,
            offset: 5,
            base: 1,
            value: 0,
            adjustment: 2,
        })
    );
    assert_eq!(
        QuicFrame::parse(&[2, 3, 0, 1, 0, 0, 2]),
        Err(QuicFrameParseError::AckRangeUnderflow {
            field: QuicFrameField::AckRangeLength,
            offset: 6,
            base: 1,
            value: 2,
            adjustment: 0,
        })
    );
}

#[test]
fn ack_range_counts_fail_at_the_first_missing_range_field() {
    assert_eq!(
        QuicFrame::parse(&[2, 10, 0, 1, 0]),
        Err(QuicFrameParseError::Field {
            field: QuicFrameField::AckGap,
            offset: 5,
            error: QuicVarIntParseError::Incomplete {
                required: 1,
                available: 0,
            },
        })
    );
    assert_eq!(
        QuicFrame::parse(&[2, 10, 0, 1, 0, 0]),
        Err(QuicFrameParseError::Field {
            field: QuicFrameField::AckRangeLength,
            offset: 6,
            error: QuicVarIntParseError::Incomplete {
                required: 1,
                available: 0,
            },
        })
    );
    assert_eq!(
        QuicFrame::parse(&[2, 10, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]),
        Err(QuicFrameParseError::Field {
            field: QuicFrameField::AckGap,
            offset: 12,
            error: QuicVarIntParseError::Incomplete {
                required: 1,
                available: 0,
            },
        })
    );
}

#[test]
fn ack_varint_truncations_name_each_field_and_absolute_offset() {
    for (bytes, field, offset, required, available) in [
        (&[2][..], QuicFrameField::LargestAcknowledged, 1, 1, 0),
        (&[2, 0, 0x40][..], QuicFrameField::AckDelay, 2, 2, 1),
        (
            &[2, 0, 0, 0x80, 0, 0][..],
            QuicFrameField::AckRangeCount,
            3,
            4,
            3,
        ),
        (
            &[2, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0][..],
            QuicFrameField::FirstAckRange,
            4,
            8,
            7,
        ),
        (&[3, 0, 0, 0, 0][..], QuicFrameField::Ect0Count, 5, 1, 0),
        (
            &[3, 0, 0, 0, 0, 0, 0x40][..],
            QuicFrameField::Ect1Count,
            6,
            2,
            1,
        ),
        (
            &[3, 0, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0][..],
            QuicFrameField::EcnCeCount,
            7,
            8,
            7,
        ),
        (
            &[2, 2, 0, 1, 0, 0x80, 0, 0][..],
            QuicFrameField::AckGap,
            5,
            4,
            3,
        ),
        (
            &[2, 2, 0, 1, 0, 0][..],
            QuicFrameField::AckRangeLength,
            6,
            1,
            0,
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
}

#[test]
fn ack_sequences_preserve_boundaries_and_fail_closed() {
    let bytes = [1, 2, 5, 0, 0, 0, 0];
    let frames = QuicFrames::parse(&bytes).unwrap();
    let mut iter = frames.iter();
    assert_eq!(iter.next().unwrap().unwrap().as_bytes(), &[1]);
    assert_eq!(iter.next().unwrap().unwrap().as_bytes(), &[2, 5, 0, 0, 0]);
    assert_eq!(iter.next().unwrap().unwrap().as_bytes(), &[0]);
    assert_eq!(iter.next(), None);

    let malformed = [1, 2, 5, 0, 1, 0];
    let expected = QuicFrameParseError::Field {
        field: QuicFrameField::AckGap,
        offset: 6,
        error: QuicVarIntParseError::Incomplete {
            required: 1,
            available: 0,
        },
    };
    assert_eq!(QuicFrames::parse(&malformed), Err(expected));
    let mut iter = QuicFrameIter::new(&malformed);
    assert!(matches!(iter.next(), Some(Ok(QuicFrame::Ping(_)))));
    assert_eq!(iter.next(), Some(Err(expected)));
    assert_eq!(iter.next(), None);
    assert_eq!(iter.next(), None);
}
