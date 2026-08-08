use net_wire::quic::*;

mod semantic;
mod value;

#[test]
fn transport_parameters_preserve_empty_tuples_boundaries_and_raw_varints() {
    let empty = QuicTransportParameters::parse(&[]).unwrap();
    assert_eq!(empty.as_bytes(), &[]);
    assert_eq!(empty.iter().next(), None);

    let bytes = [
        0x01, 0x00, 0x40, 0x25, 0x40, 0x02, 0xaa, 0xbb, 0x1b, 0x01, 0xcc,
    ];
    let parameters = QuicTransportParameters::parse(&bytes).unwrap();
    assert_eq!(parameters.as_bytes(), &bytes);
    let mut iter = parameters.iter();
    let first = iter.next().unwrap().unwrap();
    assert_eq!(first.as_bytes(), &[0x01, 0x00]);
    assert_eq!(
        first.parameter_id(),
        QuicTransportParameterId::MAX_IDLE_TIMEOUT
    );
    assert_eq!(first.value(), &[]);
    let second = iter.next().unwrap().unwrap();
    assert_eq!(second.as_bytes(), &[0x40, 0x25, 0x40, 0x02, 0xaa, 0xbb]);
    assert_eq!(second.id().as_bytes(), &[0x40, 0x25]);
    assert_eq!(second.id().value(), 37);
    assert_eq!(second.length().as_bytes(), &[0x40, 0x02]);
    assert_eq!(second.value(), &[0xaa, 0xbb]);
    let third = iter.next().unwrap().unwrap();
    assert!(third.parameter_id().is_reserved());
    assert_eq!(third.value(), &[0xcc]);
    assert_eq!(iter.next(), None);
}

#[test]
fn transport_parameter_varint_widths_and_reserved_ids_are_exact() {
    let bytes = [
        0x01, 0x00, 0x40, 0x40, 0x40, 0x00, 0x80, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0xc0,
        0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let parameters = QuicTransportParameters::parse(&bytes).unwrap();
    let mut iter = parameters.iter();
    let one = iter.next().unwrap().unwrap();
    assert_eq!(one.id().as_bytes(), &[0x01]);
    assert_eq!(one.length().as_bytes(), &[0x00]);
    let two = iter.next().unwrap().unwrap();
    assert_eq!(two.id().as_bytes(), &[0x40, 0x40]);
    assert_eq!(two.length().as_bytes(), &[0x40, 0x00]);
    let four = iter.next().unwrap().unwrap();
    assert_eq!(four.id().as_bytes(), &[0x80, 0x00, 0x40, 0x00]);
    assert_eq!(four.length().as_bytes(), &[0x80, 0x00, 0x00, 0x00]);
    let eight = iter.next().unwrap().unwrap();
    assert_eq!(
        eight.id().as_bytes(),
        &[0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        eight.length().as_bytes(),
        &[0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );
    assert_eq!(iter.next(), None);

    for id in [
        QuicTransportParameterId::new(27),
        QuicTransportParameterId::new(58),
        QuicTransportParameterId::new(((1u64 << 62) - 1) - 7),
        QuicTransportParameterId::new(u64::MAX - 19),
    ] {
        assert!(id.is_reserved());
    }
    for id in [26, 28, 57, 59, (1u64 << 62) - 1, u64::MAX] {
        assert!(!QuicTransportParameterId::new(id).is_reserved());
    }
}

#[test]
fn transport_parameter_errors_report_absolute_fields_and_value_boundaries() {
    for (bytes, required) in [
        (&[0x40][..], 2),
        (&[0x80, 0][..], 4),
        (&[0xc0, 0, 0][..], 8),
    ] {
        assert_eq!(
            QuicTransportParameters::parse(bytes),
            Err(QuicTransportParameterParseError::IncompleteVarInt {
                field: QuicTransportParameterField::Id,
                offset: 0,
                error: QuicVarIntParseError::Incomplete {
                    required,
                    available: bytes.len(),
                },
            })
        );
    }
    for (bytes, required) in [
        (&[1, 0x40][..], 2),
        (&[1, 0x80, 0][..], 4),
        (&[1, 0xc0, 0, 0][..], 8),
    ] {
        assert_eq!(
            QuicTransportParameters::parse(bytes),
            Err(QuicTransportParameterParseError::IncompleteVarInt {
                field: QuicTransportParameterField::Length,
                offset: 1,
                error: QuicVarIntParseError::Incomplete {
                    required,
                    available: bytes.len() - 1,
                },
            })
        );
    }
    for (bytes, available) in [(&[1, 2][..], 0), (&[1, 2, 0xaa][..], 1)] {
        assert_eq!(
            QuicTransportParameters::parse(bytes),
            Err(QuicTransportParameterParseError::IncompleteValue {
                offset: 2,
                required: 2,
                available,
            })
        );
    }

    let huge = [1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    match usize::try_from((1u64 << 62) - 1) {
        Ok(required) => assert_eq!(
            QuicTransportParameters::parse(&huge),
            Err(QuicTransportParameterParseError::IncompleteValue {
                offset: 9,
                required,
                available: 0,
            })
        ),
        Err(_) => assert_eq!(
            QuicTransportParameters::parse(&huge),
            Err(QuicTransportParameterParseError::LengthNotRepresentable {
                offset: 1,
                value: (1u64 << 62) - 1,
            })
        ),
    }
}

#[test]
fn transport_parameter_duplicates_and_iteration_are_validated() {
    let duplicate = [1, 0, 2, 0, 1, 0];
    assert_eq!(
        QuicTransportParameters::parse(&duplicate),
        Err(QuicTransportParameterParseError::DuplicateId {
            id: QuicTransportParameterId::new(1),
            first_offset: 0,
            duplicate_offset: 4,
        })
    );
    let noncanonical_duplicate = [1, 0, 37, 0, 0x40, 1, 0];
    assert_eq!(
        QuicTransportParameters::parse(&noncanonical_duplicate),
        Err(QuicTransportParameterParseError::DuplicateId {
            id: QuicTransportParameterId::new(1),
            first_offset: 0,
            duplicate_offset: 4,
        })
    );
    assert_eq!(
        QuicTransportParameters::parse(&[1, 0, 0x40, 1, 2, 0xaa]),
        Err(QuicTransportParameterParseError::IncompleteValue {
            offset: 5,
            required: 2,
            available: 1,
        })
    );

    let validated = QuicTransportParameters::parse(&[1, 0, 2, 1, 0xaa]).unwrap();
    let mut left = validated.iter();
    let mut right = left.clone();
    assert_eq!(left.next().unwrap().unwrap().parameter_id().raw(), 1);
    assert_eq!(right.next().unwrap().unwrap().parameter_id().raw(), 1);
    assert_eq!(left.next().unwrap().unwrap().value(), &[0xaa]);
    assert_eq!(left.next(), None);
    assert_eq!(left.next(), None);
    let _: Option<QuicTransportParameterIter<'_>> = Some(right);
    let _: Option<QuicTransportParameter<'_>> = None;
}
