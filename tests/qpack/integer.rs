use net_wire::qpack::{
    QPACK_INTEGER_MAX, QpackInteger, QpackIntegerBuildError, QpackIntegerBuilder,
    QpackIntegerParseError,
};

#[test]
fn rfc_integer_examples_are_exact_and_bounded() {
    let ten = [0x0a, 0xaa];
    assert_eq!(
        QpackInteger::parse(&ten, 5).map(|integer| (integer.value(), integer.as_bytes())),
        Ok((10, &ten[..1]))
    );
    let thirteen_thirty_seven = [0x1f, 0x9a, 0x0a, 0xaa];
    assert_eq!(
        QpackInteger::parse(&thirteen_thirty_seven, 5)
            .map(|integer| (integer.value(), integer.as_bytes())),
        Ok((1337, &thirteen_thirty_seven[..3]))
    );
    let forty_two = [42, 0xaa];
    assert_eq!(
        QpackInteger::parse(&forty_two, 8).map(|integer| (integer.value(), integer.as_bytes())),
        Ok((42, &forty_two[..1]))
    );
    let bytes = [0];
    assert_eq!(
        net_wire::qpack::QpackInteger::parse(&bytes, 8).map(net_wire::qpack::QpackInteger::value),
        Ok(0)
    );
}

#[test]
fn every_prefix_width_preserves_legal_high_bits() {
    for prefix_bits in 1..=8 {
        let mask = if prefix_bits == 8 {
            0xff
        } else {
            (1u8 << prefix_bits) - 1
        };
        let high_bits = !mask;
        let mut destination = [0xaa; 2];
        assert_eq!(
            QpackIntegerBuilder::new(&mut destination, prefix_bits, high_bits, 0)
                .build()
                .map(|integer| {
                    (
                        integer.as_bytes(),
                        integer.high_bits(),
                        integer.prefix_bits(),
                    )
                }),
            Ok((&[high_bits][..], high_bits, prefix_bits))
        );
    }
}

#[test]
fn saturated_prefix_and_continuation_boundaries_are_canonical() {
    for (value, expected) in [
        (31, &[0x1f, 0][..]),
        (158, &[0x1f, 127][..]),
        (159, &[0x1f, 128, 1][..]),
    ] {
        let mut destination = [0xaa; 4];
        assert_eq!(
            QpackIntegerBuilder::new(&mut destination, 5, 0, value)
                .build()
                .map(|integer| integer.as_bytes()),
            Ok(expected)
        );
    }
}

#[test]
fn noncanonical_integer_preserves_its_exact_bytes() {
    let wire = [0x1f, 0x80, 0, 0xaa];
    assert_eq!(
        QpackInteger::parse(&wire, 5).map(|integer| (integer.value(), integer.as_bytes())),
        Ok((31, &wire[..3]))
    );
}

#[test]
fn incomplete_integer_reports_exact_boundaries() {
    assert_eq!(
        QpackInteger::parse(&[], 5),
        Err(QpackIntegerParseError::Incomplete {
            required: 1,
            available: 0,
        })
    );
    assert_eq!(
        QpackInteger::parse(&[0x1f], 5),
        Err(QpackIntegerParseError::Incomplete {
            required: 2,
            available: 1,
        })
    );
    assert_eq!(
        QpackInteger::parse(&[0x1f, 0x80], 5),
        Err(QpackIntegerParseError::Incomplete {
            required: 3,
            available: 2,
        })
    );
    assert_eq!(
        QpackInteger::parse(&[0x1f, 0x80, 0x80], 5),
        Err(QpackIntegerParseError::Incomplete {
            required: 4,
            available: 3,
        })
    );
}

#[test]
fn parse_distinguishes_overflow_from_qpack_value_limit() {
    let over_limit = [0xff, 0x81, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f];
    let overflow = [
        0xff, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0,
    ];
    assert!(matches!(
        QpackInteger::parse(&over_limit, 8),
        Err(QpackIntegerParseError::ValueTooLarge { .. })
    ));
    assert_eq!(
        QpackInteger::parse(&overflow, 8),
        Err(QpackIntegerParseError::Overflow)
    );
}

#[test]
fn qpack_integer_limit_roundtrips_and_rejects_the_next_value() {
    let mut destination = [0xaa; 16];
    assert_eq!(
        QpackIntegerBuilder::new(&mut destination, 8, 0, QPACK_INTEGER_MAX)
            .build()
            .map(|integer| integer.value()),
        Ok(QPACK_INTEGER_MAX)
    );
    assert_eq!(
        QpackInteger::parse(&destination, 8).map(|integer| integer.value()),
        Ok(QPACK_INTEGER_MAX)
    );
    let mut too_large_destination = [0xaa; 16];
    assert_eq!(
        QpackIntegerBuilder::new(&mut too_large_destination, 8, 0, QPACK_INTEGER_MAX + 1).build(),
        Err(QpackIntegerBuildError::ValueTooLarge {
            value: QPACK_INTEGER_MAX + 1,
        })
    );
    let over_limit = [0xff, 0x81, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f];
    assert!(matches!(
        QpackInteger::parse(&over_limit, 8),
        Err(QpackIntegerParseError::ValueTooLarge { .. })
    ));
}

#[test]
fn canonical_builder_uses_exact_capacity_and_preserves_suffix() {
    let mut exact = [0xaa; 3];
    assert_eq!(
        QpackIntegerBuilder::new(&mut exact, 5, 0, 1337)
            .build()
            .map(|integer| integer.as_bytes()),
        Ok(&[0x1f, 0x9a, 0x0a][..])
    );
    let mut destination = [0xaa; 4];
    assert_eq!(
        QpackIntegerBuilder::new(&mut destination, 5, 0, 1337)
            .build()
            .map(|integer| integer.as_bytes()),
        Ok(&[0x1f, 0x9a, 0x0a][..])
    );
    assert_eq!(destination[3], 0xaa);
}

#[test]
fn builder_errors_leave_the_whole_destination_unchanged() {
    let cases = [
        (
            0,
            0,
            0,
            QpackIntegerBuildError::InvalidPrefixBits { prefix_bits: 0 },
        ),
        (
            5,
            1,
            0,
            QpackIntegerBuildError::HighBitsOverlap {
                high_bits: 1,
                prefix_bits: 5,
            },
        ),
        (
            5,
            0,
            QPACK_INTEGER_MAX + 1,
            QpackIntegerBuildError::ValueTooLarge {
                value: QPACK_INTEGER_MAX + 1,
            },
        ),
    ];
    for (prefix_bits, high_bits, value, error) in cases {
        let mut destination = [0xaa; 2];
        assert_eq!(
            QpackIntegerBuilder::new(&mut destination, prefix_bits, high_bits, value).build(),
            Err(error)
        );
        assert_eq!(destination, [0xaa; 2]);
    }
    let mut destination = [0xaa; 2];
    assert_eq!(
        QpackIntegerBuilder::new(&mut destination, 5, 0, 1337).build(),
        Err(QpackIntegerBuildError::BufferTooShort {
            required: 3,
            available: 2,
        })
    );
    assert_eq!(destination, [0xaa; 2]);
}
