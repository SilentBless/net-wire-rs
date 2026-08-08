use net_wire::qpack;
use net_wire::qpack::{
    QPACK_INTEGER_MAX, QpackFieldLine, QpackFieldLineBuildError, QpackFieldLineIter,
    QpackFieldLineParseError, QpackFieldLines, QpackIndexedFieldLineBuilder,
    QpackIndexedPostBaseFieldLineBuilder, QpackIntegerBuildError, QpackLiteralNameFieldLineBuilder,
    QpackLiteralNameReferenceFieldLineBuilder, QpackLiteralPostBaseNameReferenceFieldLineBuilder,
};

#[test]
fn qpack_field_line_all_five_forms_flags_and_boundaries_are_exact() {
    let literal_ref = [
        0x51, 0x0b, b'/', b'i', b'n', b'd', b'e', b'x', b'.', b'h', b't', b'm', b'l', 0xaa,
    ];
    let line = QpackFieldLine::parse(&literal_ref).expect("literal name reference");
    assert_eq!(line.as_bytes(), &literal_ref[..13]);
    match line {
        QpackFieldLine::LiteralNameReference(field) => {
            assert!(!field.is_never_indexed());
            assert!(field.is_static());
            assert_eq!(field.name_index().value(), 1);
            assert_eq!(field.value().encoded_payload(), b"/index.html");
        }
        _ => panic!("wrong field-line form"),
    }

    for (wire, index) in [([0x10, 0xaa], 0), ([0x11, 0xaa], 1)] {
        let line = QpackFieldLine::parse(&wire).expect("indexed post-base");
        assert_eq!(line.as_bytes(), &wire[..1]);
        match line {
            QpackFieldLine::IndexedPostBase(field) => assert_eq!(field.index().value(), index),
            _ => panic!("wrong field-line form"),
        }
    }

    for (wire, is_static, index) in [
        ([0x80, 0xaa], false, 0),
        ([0xc1, 0xaa], true, 1),
        ([0x81, 0xaa], false, 1),
    ] {
        let line = QpackFieldLine::parse(&wire).expect("indexed");
        assert_eq!(line.as_bytes(), &wire[..1]);
        match line {
            QpackFieldLine::Indexed(field) => {
                assert_eq!(field.is_static(), is_static);
                assert_eq!(field.index().value(), index);
            }
            _ => panic!("wrong field-line form"),
        }
    }

    for (wire, never_indexed, value) in [
        ([0x00, 1, b'x', 0xaa], false, b"x".as_slice()),
        ([0x08, 1, b'y', 0xaa], true, b"y".as_slice()),
    ] {
        let line = QpackFieldLine::parse(&wire).expect("literal post-base name reference");
        assert_eq!(line.as_bytes(), &wire[..3]);
        match line {
            QpackFieldLine::LiteralPostBaseNameReference(field) => {
                assert_eq!(field.is_never_indexed(), never_indexed);
                assert_eq!(field.name_index().value(), 0);
                assert_eq!(field.value().encoded_payload(), value);
            }
            _ => panic!("wrong field-line form"),
        }
    }

    for (wire, never_indexed, huffman, name, value) in [
        (
            [0x21, b'n', 1, b'v', 0xaa],
            false,
            false,
            b"n".as_slice(),
            b"v".as_slice(),
        ),
        (
            [0x39, b'h', 1, b'w', 0xaa],
            true,
            true,
            b"h".as_slice(),
            b"w".as_slice(),
        ),
    ] {
        let line = QpackFieldLine::parse(&wire).expect("literal name");
        assert_eq!(line.as_bytes(), &wire[..4]);
        match line {
            QpackFieldLine::LiteralName(field) => {
                assert_eq!(field.is_never_indexed(), never_indexed);
                assert_eq!(field.name().is_huffman(), huffman);
                assert_eq!(field.name().encoded_payload(), name);
                assert_eq!(field.value().encoded_payload(), value);
            }
            _ => panic!("wrong field-line form"),
        }
    }

    for (first, never_indexed, is_static) in [
        (0x40, false, false),
        (0x50, false, true),
        (0x60, true, false),
        (0x70, true, true),
    ] {
        let wire = [first, 1, b'v', 0xaa];
        let line = QpackFieldLine::parse(&wire).expect("literal name reference");
        assert_eq!(line.as_bytes(), &wire[..3]);
        match line {
            QpackFieldLine::LiteralNameReference(field) => {
                assert_eq!(field.is_never_indexed(), never_indexed);
                assert_eq!(field.is_static(), is_static);
                assert_eq!(field.name_index().value(), 0);
                assert_eq!(field.value().encoded_payload(), b"v");
            }
            _ => panic!("wrong field-line form"),
        }
    }
}

#[test]
fn qpack_field_line_noncanonical_components_and_nested_errors_are_exact() {
    let indexed = [0xbf, 0x80, 0, 0xaa];
    let line = QpackFieldLine::parse(&indexed).expect("noncanonical indexed integer");
    assert_eq!(line.as_bytes(), &indexed[..3]);
    match line {
        QpackFieldLine::Indexed(field) => {
            assert_eq!(field.index().as_bytes(), &indexed[..3]);
            assert_eq!(field.index().value(), 63);
        }
        _ => panic!("wrong field-line form"),
    }

    let literal_ref = [0x4f, 0x80, 0, 1, b'v', 0xaa];
    let line = QpackFieldLine::parse(&literal_ref).expect("noncanonical literal reference integer");
    assert_eq!(line.as_bytes(), &literal_ref[..5]);
    match line {
        QpackFieldLine::LiteralNameReference(field) => {
            assert_eq!(field.name_index().as_bytes(), &literal_ref[..3]);
            assert_eq!(field.name_index().value(), 15);
        }
        _ => panic!("wrong field-line form"),
    }

    let literal_name = [
        0x27, 0x80, 0, b'a', b'b', b'c', b'd', b'e', b'f', b'g', 0, 0xaa,
    ];
    let line = QpackFieldLine::parse(&literal_name).expect("noncanonical literal name length");
    assert_eq!(line.as_bytes(), &literal_name[..11]);
    match line {
        QpackFieldLine::LiteralName(field) => {
            assert_eq!(field.name().as_bytes(), &literal_name[..10]);
            assert!(!field.name().is_huffman());
            assert_eq!(field.name().encoded_payload(), b"abcdefg");
            assert_eq!(field.value().as_bytes(), &[0]);
        }
        _ => panic!("wrong field-line form"),
    }

    assert_eq!(
        QpackFieldLine::parse(&[]),
        Err(QpackFieldLineParseError::DispatchIncomplete)
    );
    assert_eq!(
        QpackFieldLine::parse(&[0xbf]),
        Err(QpackFieldLineParseError::IndexedIndex(
            qpack::QpackIntegerParseError::Incomplete {
                required: 2,
                available: 1
            }
        ))
    );
    assert_eq!(
        QpackFieldLine::parse(&[0x40]),
        Err(QpackFieldLineParseError::LiteralNameReferenceValue(
            qpack::QpackStringLiteralParseError::Length(
                qpack::QpackIntegerParseError::Incomplete {
                    required: 1,
                    available: 0
                }
            )
        ))
    );
    assert_eq!(
        QpackFieldLine::parse(&[0x40, 2, b'a']),
        Err(QpackFieldLineParseError::LiteralNameReferenceValue(
            qpack::QpackStringLiteralParseError::Incomplete {
                required: 3,
                available: 2
            }
        ))
    );
    assert_eq!(
        QpackFieldLine::parse(&[0x22, b'a']),
        Err(QpackFieldLineParseError::LiteralNameName(
            qpack::QpackStringLiteralParseError::Incomplete {
                required: 3,
                available: 2
            }
        ))
    );
    assert_eq!(
        QpackFieldLine::parse(&[0x21, b'n']),
        Err(QpackFieldLineParseError::LiteralNameValue(
            qpack::QpackStringLiteralParseError::Length(
                qpack::QpackIntegerParseError::Incomplete {
                    required: 1,
                    available: 0
                }
            )
        ))
    );
    assert_eq!(
        QpackFieldLine::parse(&[0x00]),
        Err(QpackFieldLineParseError::LiteralPostBaseNameReferenceValue(
            qpack::QpackStringLiteralParseError::Length(
                qpack::QpackIntegerParseError::Incomplete {
                    required: 1,
                    available: 0
                }
            )
        ))
    );
}

#[test]
fn qpack_field_line_builders_are_canonical_exact_and_destination_only() {
    let mut indexed_static = [0xaa; 2];
    let indexed = QpackIndexedFieldLineBuilder::new(&mut indexed_static, true, 0)
        .build()
        .expect("capacity");
    assert!(indexed.is_static());
    assert_eq!(indexed.index().value(), 0);
    assert_eq!(indexed.as_bytes(), &[0xc0]);
    assert!(matches!(
        QpackFieldLine::parse(indexed.as_bytes()),
        Ok(QpackFieldLine::Indexed(field))
            if field.is_static() && field.index().value() == 0 && field.as_bytes() == [0xc0]
    ));
    assert_eq!(indexed_static[1], 0xaa);

    let mut indexed_dynamic = [0xaa; 3];
    let indexed = QpackIndexedFieldLineBuilder::new(&mut indexed_dynamic, false, 63)
        .build()
        .expect("capacity");
    assert!(!indexed.is_static());
    assert_eq!(indexed.index().value(), 63);
    assert_eq!(indexed.as_bytes(), &[0xbf, 0x00]);
    assert_eq!(indexed_dynamic[2], 0xaa);

    let mut indexed_post_base = [0xaa; 3];
    let indexed = QpackIndexedPostBaseFieldLineBuilder::new(&mut indexed_post_base, 15)
        .build()
        .expect("capacity");
    assert_eq!(indexed.index().value(), 15);
    assert_eq!(indexed.as_bytes(), &[0x1f, 0x00]);
    assert_eq!(indexed_post_base[2], 0xaa);

    let mut literal_reference = [0xaa; 6];
    let field = QpackLiteralNameReferenceFieldLineBuilder::new(
        &mut literal_reference,
        true,
        true,
        15,
        true,
        &[0xab, 0xcd],
    )
    .build()
    .expect("capacity");
    assert!(field.is_never_indexed());
    assert!(field.is_static());
    assert_eq!(field.name_index().value(), 15);
    assert!(field.value().is_huffman());
    assert_eq!(field.value().encoded_payload(), &[0xab, 0xcd]);
    assert_eq!(field.as_bytes(), &[0x7f, 0x00, 0x82, 0xab, 0xcd]);
    assert!(matches!(
        QpackFieldLine::parse(field.as_bytes()),
        Ok(QpackFieldLine::LiteralNameReference(parsed))
            if parsed.is_never_indexed()
                && parsed.is_static()
                && parsed.name_index().value() == 15
                && parsed.value().is_huffman()
                && parsed.value().encoded_payload() == [0xab, 0xcd]
    ));
    assert_eq!(literal_reference[5], 0xaa);

    let mut literal_reference_plain = [0xaa; 4];
    let field = QpackLiteralNameReferenceFieldLineBuilder::new(
        &mut literal_reference_plain,
        false,
        false,
        1,
        false,
        b"x",
    )
    .build()
    .expect("capacity");
    assert!(!field.is_never_indexed());
    assert!(!field.is_static());
    assert_eq!(field.name_index().value(), 1);
    assert!(!field.value().is_huffman());
    assert_eq!(field.value().encoded_payload(), b"x");
    assert_eq!(field.as_bytes(), &[0x41, 0x01, b'x']);
    assert_eq!(literal_reference_plain[3], 0xaa);

    let mut post_base_literal = [0xaa; 5];
    let field = QpackLiteralPostBaseNameReferenceFieldLineBuilder::new(
        &mut post_base_literal,
        true,
        7,
        false,
        b"x",
    )
    .build()
    .expect("capacity");
    assert!(field.is_never_indexed());
    assert_eq!(field.name_index().value(), 7);
    assert!(!field.value().is_huffman());
    assert_eq!(field.value().encoded_payload(), b"x");
    assert_eq!(field.as_bytes(), &[0x0f, 0x00, 0x01, b'x']);
    assert_eq!(post_base_literal[4], 0xaa);

    let mut literal_name = [0xaa; 5];
    let field =
        QpackLiteralNameFieldLineBuilder::new(&mut literal_name, true, true, b"n", false, b"v")
            .build()
            .expect("capacity");
    assert!(field.is_never_indexed());
    assert!(field.name().is_huffman());
    assert_eq!(field.name().encoded_payload(), b"n");
    assert!(!field.value().is_huffman());
    assert_eq!(field.value().encoded_payload(), b"v");
    assert_eq!(field.as_bytes(), &[0x39, b'n', 0x01, b'v']);
    assert_eq!(literal_name[4], 0xaa);

    let mut destination = [0xaa; 5];
    let field = {
        let name = *b"n";
        let value = *b"v";
        QpackLiteralNameFieldLineBuilder::new(&mut destination, false, false, &name, true, &value)
            .build()
            .expect("capacity")
    };
    assert_eq!(field.name().encoded_payload(), b"n");
    assert!(field.value().is_huffman());
    assert_eq!(field.value().encoded_payload(), b"v");
    assert_eq!(field.as_bytes(), &[0x21, b'n', 0x81, b'v']);
    assert_eq!(destination[4], 0xaa);
}

#[test]
fn qpack_field_line_builder_failures_are_atomic() {
    let mut short = [0xaa; 4];
    let before = short;
    assert_eq!(
        QpackLiteralNameReferenceFieldLineBuilder::new(
            &mut short,
            true,
            true,
            15,
            true,
            &[0xab, 0xcd],
        )
        .build(),
        Err(QpackFieldLineBuildError::BufferTooShort {
            required: 5,
            available: 4,
        })
    );
    assert_eq!(short, before);

    let too_large = QPACK_INTEGER_MAX + 1;
    let mut indexed = [0xaa; 16];
    let before = indexed;
    assert_eq!(
        QpackIndexedFieldLineBuilder::new(&mut indexed, false, too_large).build(),
        Err(QpackFieldLineBuildError::IndexedIndex(
            QpackIntegerBuildError::ValueTooLarge { value: too_large },
        ))
    );
    assert_eq!(indexed, before);

    let mut post_base = [0xaa; 16];
    let before = post_base;
    assert_eq!(
        QpackLiteralPostBaseNameReferenceFieldLineBuilder::new(
            &mut post_base,
            false,
            too_large,
            false,
            b"",
        )
        .build(),
        Err(
            QpackFieldLineBuildError::LiteralPostBaseNameReferenceNameIndex(
                QpackIntegerBuildError::ValueTooLarge { value: too_large },
            )
        )
    );
    assert_eq!(post_base, before);
}

#[test]
fn qpack_field_lines_sequence_iteration_is_exact() {
    let bytes = [0x80, 0x10, 0x00, 1, b'x', 0x21, b'n', 1, b'v'];
    let lines = QpackFieldLines::parse(&bytes).expect("field-line sequence");
    assert_eq!(lines.as_bytes(), &bytes);
    let mut iter = lines.iter();
    assert_eq!(
        iter.next().expect("first").expect("indexed").as_bytes(),
        &[0x80]
    );
    assert_eq!(
        iter.next().expect("second").expect("post-base").as_bytes(),
        &[0x10]
    );
    assert_eq!(
        iter.next()
            .expect("third")
            .expect("post-base literal")
            .as_bytes(),
        &[0x00, 1, b'x']
    );
    assert_eq!(
        iter.next()
            .expect("fourth")
            .expect("literal name")
            .as_bytes(),
        &[0x21, b'n', 1, b'v']
    );
    assert_eq!(iter.next(), None);
    assert_eq!(iter.next(), None);

    let empty = QpackFieldLines::parse(&[]).expect("empty sequence");
    assert_eq!(empty.as_bytes(), &[]);
    assert_eq!(empty.iter().next(), None);

    let malformed = [0x80, 0x40];
    let expected = QpackFieldLineParseError::LiteralNameReferenceValue(
        qpack::QpackStringLiteralParseError::Length(qpack::QpackIntegerParseError::Incomplete {
            required: 1,
            available: 0,
        }),
    );
    let error = QpackFieldLines::parse(&malformed).expect_err("malformed sequence");
    assert_eq!(error.offset(), 1);
    assert_eq!(error.error(), expected);
    let mut iter = QpackFieldLineIter::new(&malformed);
    assert_eq!(
        iter.next().expect("first").expect("indexed").as_bytes(),
        &[0x80]
    );
    assert_eq!(iter.next(), Some(Err(expected)));
    assert_eq!(iter.next(), None);
    assert_eq!(iter.next(), None);
}
