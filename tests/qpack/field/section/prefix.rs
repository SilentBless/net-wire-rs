use net_wire::qpack::{
    QPACK_INTEGER_MAX, QpackFieldSectionPrefix, QpackFieldSectionPrefixBuildError,
    QpackFieldSectionPrefixBuilder, QpackFieldSectionPrefixParseError, QpackIntegerBuildError,
    QpackIntegerParseError,
};

#[test]
fn qpack_field_section_prefix_rfc_vectors_and_raw_boundaries_are_exact() {
    for (wire, required_insert_count, negative, delta_base) in [
        (&[0x00, 0x00][..], 0, false, 0),
        (&[0x03, 0x81][..], 3, true, 1),
        (&[0x05, 0x00][..], 5, false, 0),
        (&[0x00, 0x80][..], 0, true, 0),
    ] {
        assert_eq!(
            QpackFieldSectionPrefix::parse(wire).map(|prefix| (
                prefix.as_bytes(),
                prefix.encoded_required_insert_count().value(),
                prefix.is_negative(),
                prefix.delta_base().value(),
            )),
            Ok((wire, required_insert_count, negative, delta_base))
        );
    }

    let with_field_line = [0x03, 0x81, 0xd1, 0xaa];
    let prefix = QpackFieldSectionPrefix::parse(&with_field_line).expect("complete prefix");
    assert_eq!(prefix.as_bytes(), &[0x03, 0x81]);
    assert_eq!(prefix.encoded_required_insert_count().as_bytes(), &[0x03]);
    assert_eq!(prefix.delta_base().as_bytes(), &[0x81]);

    let noncanonical = [0xff, 0x80, 0, 0xff, 0x80, 0, 0xd1];
    let prefix = QpackFieldSectionPrefix::parse(&noncanonical).expect("complete prefix");
    assert_eq!(prefix.as_bytes(), &noncanonical[..6]);
    assert_eq!(prefix.encoded_required_insert_count().value(), 255);
    assert_eq!(
        prefix.encoded_required_insert_count().as_bytes(),
        &noncanonical[..3]
    );
    assert!(prefix.is_negative());
    assert_eq!(prefix.delta_base().value(), 127);
    assert_eq!(prefix.delta_base().as_bytes(), &noncanonical[3..6]);

    assert_eq!(
        QpackFieldSectionPrefix::parse(&[]),
        Err(QpackFieldSectionPrefixParseError::RequiredInsertCount(
            QpackIntegerParseError::Incomplete {
                required: 1,
                available: 0,
            }
        ))
    );
    assert_eq!(
        QpackFieldSectionPrefix::parse(&[0xff]),
        Err(QpackFieldSectionPrefixParseError::RequiredInsertCount(
            QpackIntegerParseError::Incomplete {
                required: 2,
                available: 1,
            }
        ))
    );
    assert_eq!(
        QpackFieldSectionPrefix::parse(&[0x00]),
        Err(QpackFieldSectionPrefixParseError::DeltaBase(
            QpackIntegerParseError::Incomplete {
                required: 1,
                available: 0,
            }
        ))
    );
    assert_eq!(
        QpackFieldSectionPrefix::parse(&[0x00, 0xff]),
        Err(QpackFieldSectionPrefixParseError::DeltaBase(
            QpackIntegerParseError::Incomplete {
                required: 2,
                available: 1,
            }
        ))
    );
}

#[test]
fn qpack_field_section_prefix_builder_is_canonical_atomic_and_destination_only() {
    for (required_insert_count, negative, delta_base, expected) in [
        (0, false, 0, &[0x00, 0x00][..]),
        (3, true, 1, &[0x03, 0x81][..]),
        (5, false, 0, &[0x05, 0x00][..]),
        (0, true, 0, &[0x00, 0x80][..]),
        (255, false, 127, &[0xff, 0x00, 0x7f, 0x00][..]),
        (255, true, 127, &[0xff, 0x00, 0xff, 0x00][..]),
    ] {
        let mut destination = [0xaa; 20];
        let prefix = QpackFieldSectionPrefixBuilder::new(
            &mut destination,
            required_insert_count,
            negative,
            delta_base,
        )
        .build()
        .expect("capacity");
        assert_eq!(prefix.as_bytes(), expected);
        assert_eq!(destination[expected.len()], 0xaa);
    }

    let mut exact = [0xaa; 2];
    assert_eq!(
        QpackFieldSectionPrefixBuilder::new(&mut exact, 3, true, 1)
            .build()
            .map(QpackFieldSectionPrefix::as_bytes),
        Ok(&[0x03, 0x81][..])
    );

    let mut short = [0xaa; 2];
    let before = short;
    assert_eq!(
        QpackFieldSectionPrefixBuilder::new(&mut short, 255, true, 127).build(),
        Err(QpackFieldSectionPrefixBuildError::BufferTooShort {
            required: 4,
            available: 2,
        })
    );
    assert_eq!(short, before);

    for (required_insert_count, negative, delta_base, error) in [
        (
            QPACK_INTEGER_MAX + 1,
            false,
            0,
            QpackFieldSectionPrefixBuildError::RequiredInsertCount(
                QpackIntegerBuildError::ValueTooLarge {
                    value: QPACK_INTEGER_MAX + 1,
                },
            ),
        ),
        (
            0,
            true,
            QPACK_INTEGER_MAX + 1,
            QpackFieldSectionPrefixBuildError::DeltaBase(QpackIntegerBuildError::ValueTooLarge {
                value: QPACK_INTEGER_MAX + 1,
            }),
        ),
    ] {
        let mut destination = [0xaa; 20];
        let before = destination;
        assert_eq!(
            QpackFieldSectionPrefixBuilder::new(
                &mut destination,
                required_insert_count,
                negative,
                delta_base,
            )
            .build(),
            Err(error)
        );
        assert_eq!(destination, before);
    }

    let mut maximum = [0xaa; 20];
    let prefix = QpackFieldSectionPrefixBuilder::new(
        &mut maximum,
        QPACK_INTEGER_MAX,
        true,
        QPACK_INTEGER_MAX,
    )
    .build()
    .expect("maximum capacity");
    assert_eq!(
        prefix.encoded_required_insert_count().value(),
        QPACK_INTEGER_MAX
    );
    assert_eq!(prefix.delta_base().value(), QPACK_INTEGER_MAX);
    assert!(prefix.is_negative());
}
