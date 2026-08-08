use net_wire::quic::*;

#[test]
fn crypto_frames_preserve_exact_boundaries_and_varint_encodings() {
    let bytes = [6, 2, 3, 0xaa, 0xbb, 0xcc, 0xfe];
    let (QuicFrame::Crypto(frame), suffix) = QuicFrame::parse(&bytes).unwrap() else {
        panic!("expected CRYPTO")
    };
    assert_eq!(frame.as_bytes(), &bytes[..6]);
    assert_eq!(frame.frame_type().as_bytes(), &[6]);
    assert_eq!(frame.offset().as_bytes(), &[2]);
    assert_eq!(frame.length().as_bytes(), &[3]);
    assert_eq!(frame.crypto_data(), &[0xaa, 0xbb, 0xcc]);
    assert_eq!(suffix, &[0xfe]);

    let zero = [6, 63, 0, 0xfe];
    let (QuicFrame::Crypto(frame), suffix) = QuicFrame::parse(&zero).unwrap() else {
        panic!("expected CRYPTO")
    };
    assert_eq!(frame.as_bytes(), &zero[..3]);
    assert_eq!(frame.crypto_data(), &[]);
    assert_eq!(suffix, &[0xfe]);

    for (bytes, type_bytes, offset_bytes, length_bytes) in [
        (
            &[0x40, 6, 0x40, 1, 0x40, 1, 0xaa][..],
            &[0x40, 6][..],
            &[0x40, 1][..],
            &[0x40, 1][..],
        ),
        (
            &[0x80, 0, 0, 6, 0x80, 0, 0, 2, 0x80, 0, 0, 1, 0xaa][..],
            &[0x80, 0, 0, 6][..],
            &[0x80, 0, 0, 2][..],
            &[0x80, 0, 0, 1][..],
        ),
        (
            &[
                0xc0, 0, 0, 0, 0, 0, 0, 6, 0xc0, 0, 0, 0, 0, 0, 0, 3, 0xc0, 0, 0, 0, 0, 0, 0, 1,
                0xaa,
            ][..],
            &[0xc0, 0, 0, 0, 0, 0, 0, 6][..],
            &[0xc0, 0, 0, 0, 0, 0, 0, 3][..],
            &[0xc0, 0, 0, 0, 0, 0, 0, 1][..],
        ),
    ] {
        let (QuicFrame::Crypto(frame), suffix) = QuicFrame::parse(bytes).unwrap() else {
            panic!("expected CRYPTO")
        };
        assert!(suffix.is_empty());
        assert_eq!(frame.as_bytes(), bytes);
        assert_eq!(frame.frame_type().as_bytes(), type_bytes);
        assert_eq!(frame.offset().as_bytes(), offset_bytes);
        assert_eq!(frame.length().as_bytes(), length_bytes);
        assert_eq!(frame.crypto_data(), &[0xaa]);
    }
}

#[test]
fn crypto_frames_validate_ranges_and_report_all_bounds() {
    let maximum = (1u64 << 62) - 1;
    for bytes in [
        &[6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0][..],
        &[6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 1, 0xaa][..],
    ] {
        assert!(matches!(
            QuicFrame::parse(bytes),
            Ok((QuicFrame::Crypto(_), _))
        ));
    }
    for (bytes, start, length) in [
        (
            &[6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1][..],
            maximum,
            1,
        ),
        (
            &[6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 2][..],
            maximum - 1,
            2,
        ),
    ] {
        assert_eq!(
            QuicFrame::parse(bytes),
            Err(QuicFrameParseError::FieldRangeOutOfRange {
                field: QuicFrameField::CryptoOffset,
                offset: 1,
                start,
                length,
                maximum,
            })
        );
    }

    for (field, offset) in [
        (QuicFrameField::CryptoOffset, 1),
        (QuicFrameField::CryptoLength, 2),
    ] {
        for (first, required) in [(0, 1), (0x40, 2), (0x80, 4), (0xc0, 8)] {
            for available in 0..required {
                let mut bytes = [0; 10];
                bytes[0] = 6;
                if field == QuicFrameField::CryptoLength {
                    bytes[1] = 0;
                }
                if available != 0 {
                    bytes[offset] = first;
                }
                let expected_required = if available == 0 { 1 } else { required };
                assert_eq!(
                    QuicFrame::parse(&bytes[..offset + available]),
                    Err(QuicFrameParseError::Field {
                        field,
                        offset,
                        error: QuicVarIntParseError::Incomplete {
                            required: expected_required,
                            available,
                        },
                    })
                );
            }
        }
    }

    for (bytes, required, available) in [(&[6, 0, 1][..], 1, 0), (&[6, 0, 3, 0xaa][..], 3, 1)] {
        assert_eq!(
            QuicFrame::parse(bytes),
            Err(QuicFrameParseError::IncompleteBytes {
                field: QuicFrameField::CryptoData,
                offset: 3,
                required,
                available,
            })
        );
    }
}

#[cfg(target_pointer_width = "32")]
#[test]
fn crypto_frames_reject_unrepresentable_lengths() {
    let bytes = [6, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert_eq!(
        QuicFrame::parse(&bytes),
        Err(QuicFrameParseError::LengthNotRepresentable {
            field: QuicFrameField::CryptoLength,
            offset: 2,
            value: (1u64 << 62) - 1,
        })
    );
}

#[test]
fn crypto_frames_mix_at_exact_boundaries() {
    let malformed = [1, 6, 0, 3, 0xaa];
    let expected = QuicFrameParseError::IncompleteBytes {
        field: QuicFrameField::CryptoData,
        offset: 4,
        required: 3,
        available: 1,
    };
    assert_eq!(QuicFrames::parse(&malformed), Err(expected));
    let mut failed = QuicFrameIter::new(&malformed);
    assert!(matches!(failed.next(), Some(Ok(QuicFrame::Ping(_)))));
    assert_eq!(failed.next(), Some(Err(expected)));
    assert_eq!(failed.next(), None);
    assert_eq!(failed.next(), None);

    let bytes = [0, 6, 0, 1, 0xaa, 1, 6, 1, 0, 0x1e];
    let frames = QuicFrames::parse(&bytes).unwrap();
    let mut iter = frames.iter();
    for (length, kind) in [(1, 0), (4, 1), (1, 2), (3, 1), (1, 3)] {
        let frame = iter.next().unwrap().unwrap();
        assert_eq!(frame.as_bytes().len(), length);
        match kind {
            0 => assert!(matches!(frame, QuicFrame::Padding(_))),
            1 => assert!(matches!(frame, QuicFrame::Crypto(_))),
            2 => assert!(matches!(frame, QuicFrame::Ping(_))),
            _ => assert!(matches!(frame, QuicFrame::HandshakeDone(_))),
        }
    }
    assert_eq!(iter.next(), None);
}
