use net_wire::qpack;
use net_wire::qpack::{
    QPACK_INTEGER_MAX, QpackDuplicateBuilder, QpackEncoderInstruction,
    QpackEncoderInstructionBuildError, QpackEncoderInstructionParseError, QpackEncoderInstructions,
    QpackEncoderInstructionsParseError, QpackInsertWithLiteralNameBuilder,
    QpackInsertWithNameReferenceBuilder, QpackIntegerBuildError, QpackIntegerParseError,
    QpackSetDynamicTableCapacityBuilder, QpackStringLiteralParseError,
};

#[test]
fn qpack_encoder_instruction_rfc9204_appendix_b_vectors_are_exact() {
    let capacity = [0x3f, 0xbd, 0x01];
    let static_authority = [
        0xc0, 0x0f, b'w', b'w', b'w', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
        b'o', b'm',
    ];
    let static_path = [
        0xc1, 0x0c, b'/', b's', b'a', b'm', b'p', b'l', b'e', b'/', b'p', b'a', b't', b'h',
    ];
    let literal = [
        0x4a, b'c', b'u', b's', b't', b'o', b'm', b'-', b'k', b'e', b'y', 0x0c, b'c', b'u', b's',
        b't', b'o', b'm', b'-', b'v', b'a', b'l', b'u', b'e',
    ];
    let duplicate = [0x02];
    let dynamic = [
        0x81, 0x0d, b'c', b'u', b's', b't', b'o', b'm', b'-', b'v', b'a', b'l', b'u', b'e', b'2',
    ];

    assert!(matches!(
        QpackEncoderInstruction::parse(&capacity),
        Ok(QpackEncoderInstruction::SetDynamicTableCapacity(instruction))
            if instruction.capacity().value() == 220 && instruction.as_bytes() == capacity
    ));
    assert!(matches!(
        QpackEncoderInstruction::parse(&static_authority),
        Ok(QpackEncoderInstruction::InsertWithNameReference(instruction))
            if instruction.is_static() && instruction.name_index().value() == 0
                && instruction.value().encoded_payload() == b"www.example.com"
    ));
    assert!(matches!(
        QpackEncoderInstruction::parse(&static_path),
        Ok(QpackEncoderInstruction::InsertWithNameReference(instruction))
            if instruction.is_static() && instruction.name_index().value() == 1
                && instruction.value().encoded_payload() == b"/sample/path"
    ));
    assert!(matches!(
        QpackEncoderInstruction::parse(&literal),
        Ok(QpackEncoderInstruction::InsertWithLiteralName(instruction))
            if instruction.name().encoded_payload() == b"custom-key"
                && instruction.value().encoded_payload() == b"custom-value"
    ));
    assert!(matches!(
        QpackEncoderInstruction::parse(&duplicate),
        Ok(QpackEncoderInstruction::Duplicate(instruction)) if instruction.index().value() == 2
    ));
    assert!(matches!(
        QpackEncoderInstruction::parse(&dynamic),
        Ok(QpackEncoderInstruction::InsertWithNameReference(instruction))
            if !instruction.is_static() && instruction.name_index().value() == 1
                && instruction.value().encoded_payload() == b"custom-value2"
    ));

    let mut sequence = [0; 74];
    let mut offset = 0;
    for vector in [
        &capacity[..],
        &static_authority,
        &static_path,
        &literal,
        &duplicate,
        &dynamic,
    ] {
        sequence[offset..offset + vector.len()].copy_from_slice(vector);
        offset += vector.len();
    }
    let sequence = &sequence[..offset];
    let parsed = QpackEncoderInstructions::parse(sequence).expect("RFC sequence");
    assert_eq!(parsed.as_bytes(), sequence);
    assert_eq!(parsed.iter().count(), 6);
    assert_eq!(
        QpackEncoderInstructions::parse(&[]).map(|instructions| instructions.iter().count()),
        Ok(0)
    );
}

#[test]
fn qpack_encoder_instruction_dispatch_suffix_and_nested_errors_are_exact() {
    let cases = [
        (&[0x20, 0xaa][..], 1),
        (&[0x80, 0x00, 0xaa][..], 2),
        (&[0x40, 0x00, 0x00, 0xaa][..], 2),
        (&[0x00, 0xaa][..], 1),
    ];
    for (wire, length) in cases {
        assert_eq!(
            QpackEncoderInstruction::parse(wire).map(|instruction| instruction.as_bytes()),
            Ok(&wire[..length])
        );
    }
    assert_eq!(
        QpackEncoderInstruction::parse(&[]),
        Err(QpackEncoderInstructionParseError::DispatchIncomplete)
    );
    assert_eq!(
        QpackEncoderInstruction::parse(&[0x80]),
        Err(
            QpackEncoderInstructionParseError::InsertWithNameReferenceValue(
                QpackStringLiteralParseError::Length(QpackIntegerParseError::Incomplete {
                    required: 1,
                    available: 0,
                })
            )
        )
    );
    assert_eq!(
        QpackEncoderInstruction::parse(&[0x40]),
        Err(
            QpackEncoderInstructionParseError::InsertWithLiteralNameValue(
                QpackStringLiteralParseError::Length(QpackIntegerParseError::Incomplete {
                    required: 1,
                    available: 0,
                })
            )
        )
    );
    assert_eq!(
        QpackEncoderInstruction::parse(&[0x1f]),
        Err(QpackEncoderInstructionParseError::DuplicateIndex(
            QpackIntegerParseError::Incomplete {
                required: 2,
                available: 1,
            }
        ))
    );

    let invalid = [0x02, 0x80];
    assert_eq!(
        QpackEncoderInstructions::parse(&invalid),
        Err(QpackEncoderInstructionsParseError {
            offset: 1,
            error: QpackEncoderInstructionParseError::InsertWithNameReferenceValue(
                QpackStringLiteralParseError::Length(QpackIntegerParseError::Incomplete {
                    required: 1,
                    available: 0,
                })
            ),
        })
    );
}

#[test]
fn qpack_encoder_instruction_wire_families_preserve_noncanonical_fields_and_flags() {
    let capacity = [0x3f, 0x80, 0, 0xaa];
    let duplicate = [0x1f, 0x80, 0, 0xaa];
    let static_name_reference = [0xff, 0x80, 0, 0x00, 0xaa];
    let dynamic_name_reference = [0xbf, 0x80, 0, 0x00, 0xaa];
    let literal_name_huffman = [0x61, 0x11, 0x01, 0x22, 0xaa];
    let literal_value_huffman = [0x41, 0x11, 0x81, 0x22, 0xaa];
    let literal_name_and_value_huffman = [0x61, 0x11, 0x81, 0x22, 0xaa];

    assert!(matches!(
        QpackEncoderInstruction::parse(&capacity),
        Ok(QpackEncoderInstruction::SetDynamicTableCapacity(instruction))
            if instruction.capacity().value() == 31
                && instruction.capacity().as_bytes() == &capacity[..3]
                && instruction.as_bytes() == &capacity[..3]
    ));
    assert!(matches!(
        QpackEncoderInstruction::parse(&duplicate),
        Ok(QpackEncoderInstruction::Duplicate(instruction))
            if instruction.index().value() == 31
                && instruction.index().as_bytes() == &duplicate[..3]
                && instruction.as_bytes() == &duplicate[..3]
    ));
    assert!(matches!(
        QpackEncoderInstruction::parse(&static_name_reference),
        Ok(QpackEncoderInstruction::InsertWithNameReference(instruction))
            if instruction.is_static()
                && instruction.name_index().value() == 63
                && instruction.name_index().as_bytes() == &static_name_reference[..3]
                && !instruction.value().is_huffman()
                && instruction.value().encoded_payload().is_empty()
                && instruction.as_bytes() == &static_name_reference[..4]
    ));
    assert!(matches!(
        QpackEncoderInstruction::parse(&dynamic_name_reference),
        Ok(QpackEncoderInstruction::InsertWithNameReference(instruction))
            if !instruction.is_static()
                && instruction.name_index().value() == 63
                && instruction.name_index().as_bytes() == &dynamic_name_reference[..3]
                && instruction.value().encoded_payload().is_empty()
                && instruction.as_bytes() == &dynamic_name_reference[..4]
    ));
    for (wire, name_huffman, value_huffman) in [
        (&literal_name_huffman[..], true, false),
        (&literal_value_huffman[..], false, true),
        (&literal_name_and_value_huffman[..], true, true),
    ] {
        assert!(matches!(
            QpackEncoderInstruction::parse(wire),
            Ok(QpackEncoderInstruction::InsertWithLiteralName(instruction))
                if instruction.name().is_huffman() == name_huffman
                    && instruction.name().encoded_payload() == b"\x11"
                    && instruction.value().is_huffman() == value_huffman
                    && instruction.value().encoded_payload() == b"\x22"
                    && instruction.as_bytes() == &wire[..4]
        ));
    }

    let mut name_length_noncanonical = [0; 36];
    name_length_noncanonical[..3].copy_from_slice(&[0x5f, 0x80, 0]);
    name_length_noncanonical[3..34].fill(b'n');
    name_length_noncanonical[34] = 0;
    name_length_noncanonical[35] = 0xaa;
    assert!(matches!(
        QpackEncoderInstruction::parse(&name_length_noncanonical),
        Ok(QpackEncoderInstruction::InsertWithLiteralName(instruction))
            if instruction.name().length().value() == 31
                && instruction.name().length().as_bytes() == &name_length_noncanonical[..3]
                && instruction.name().encoded_payload() == [b'n'; 31]
                && instruction.value().encoded_payload().is_empty()
                && instruction.as_bytes() == &name_length_noncanonical[..35]
    ));

    let mut value_length_noncanonical = [0; 131];
    value_length_noncanonical[..4].copy_from_slice(&[0x80, 0xff, 0x80, 0]);
    value_length_noncanonical[4..131].fill(b'v');
    assert!(matches!(
        QpackEncoderInstruction::parse(&value_length_noncanonical),
        Ok(QpackEncoderInstruction::InsertWithNameReference(instruction))
            if !instruction.is_static()
                && instruction.name_index().value() == 0
                && instruction.value().length().value() == 127
                && instruction.value().length().as_bytes() == &value_length_noncanonical[1..4]
                && instruction.value().encoded_payload() == [b'v'; 127]
                && instruction.as_bytes() == value_length_noncanonical
    ));
}

#[test]
fn qpack_encoder_instruction_truncation_errors_are_nested_and_exact() {
    let cases = [
        (
            &[0x3f][..],
            QpackEncoderInstructionParseError::SetDynamicTableCapacity(
                QpackIntegerParseError::Incomplete {
                    required: 2,
                    available: 1,
                },
            ),
        ),
        (
            &[0x3f, 0x80][..],
            QpackEncoderInstructionParseError::SetDynamicTableCapacity(
                QpackIntegerParseError::Incomplete {
                    required: 3,
                    available: 2,
                },
            ),
        ),
        (
            &[0x1f][..],
            QpackEncoderInstructionParseError::DuplicateIndex(QpackIntegerParseError::Incomplete {
                required: 2,
                available: 1,
            }),
        ),
        (
            &[0x1f, 0x80][..],
            QpackEncoderInstructionParseError::DuplicateIndex(QpackIntegerParseError::Incomplete {
                required: 3,
                available: 2,
            }),
        ),
        (
            &[0xff][..],
            QpackEncoderInstructionParseError::InsertWithNameReferenceNameIndex(
                QpackIntegerParseError::Incomplete {
                    required: 2,
                    available: 1,
                },
            ),
        ),
        (
            &[0x80][..],
            QpackEncoderInstructionParseError::InsertWithNameReferenceValue(
                QpackStringLiteralParseError::Length(QpackIntegerParseError::Incomplete {
                    required: 1,
                    available: 0,
                }),
            ),
        ),
        (
            &[0x80, 0x02, b'x'][..],
            QpackEncoderInstructionParseError::InsertWithNameReferenceValue(
                QpackStringLiteralParseError::Incomplete {
                    required: 3,
                    available: 2,
                },
            ),
        ),
        (
            &[0x5f][..],
            QpackEncoderInstructionParseError::InsertWithLiteralNameName(
                QpackStringLiteralParseError::Length(QpackIntegerParseError::Incomplete {
                    required: 2,
                    available: 1,
                }),
            ),
        ),
        (
            &[0x42, b'x'][..],
            QpackEncoderInstructionParseError::InsertWithLiteralNameName(
                QpackStringLiteralParseError::Incomplete {
                    required: 3,
                    available: 2,
                },
            ),
        ),
        (
            &[0x40, 0xff][..],
            QpackEncoderInstructionParseError::InsertWithLiteralNameValue(
                QpackStringLiteralParseError::Length(QpackIntegerParseError::Incomplete {
                    required: 2,
                    available: 1,
                }),
            ),
        ),
        (
            &[0x40, 0x02, b'x'][..],
            QpackEncoderInstructionParseError::InsertWithLiteralNameValue(
                QpackStringLiteralParseError::Incomplete {
                    required: 3,
                    available: 2,
                },
            ),
        ),
    ];
    for (wire, expected) in cases {
        assert_eq!(QpackEncoderInstruction::parse(wire), Err(expected));
    }

    let sequence = [0x02, 0x40, 0xff];
    assert_eq!(
        QpackEncoderInstructions::parse(&sequence),
        Err(QpackEncoderInstructionsParseError {
            offset: 1,
            error: QpackEncoderInstructionParseError::InsertWithLiteralNameValue(
                QpackStringLiteralParseError::Length(QpackIntegerParseError::Incomplete {
                    required: 2,
                    available: 1,
                }),
            ),
        })
    );

    let empty_wire = [];
    let mut empty = QpackEncoderInstructions::parse(&empty_wire)
        .expect("empty sequence")
        .iter();
    assert_eq!(empty.next(), None);
    assert_eq!(empty.next(), None);
    let complete_wire = [0x02];
    let mut complete = QpackEncoderInstructions::parse(&complete_wire)
        .expect("complete sequence")
        .iter();
    assert!(matches!(
        complete.next(),
        Some(Ok(QpackEncoderInstruction::Duplicate(_)))
    ));
    assert_eq!(complete.next(), None);
    assert_eq!(complete.next(), None);
}

#[test]
fn qpack_encoder_instruction_public_namespace_compiles() {
    let _: Option<qpack::QpackEncoderInstruction<'static>> = None;
    let _: Option<qpack::QpackSetDynamicTableCapacity<'static>> = None;
    let _: Option<qpack::QpackInsertWithNameReference<'static>> = None;
    let _: Option<qpack::QpackInsertWithLiteralName<'static>> = None;
    let _: Option<qpack::QpackDuplicate<'static>> = None;
    let _: Option<qpack::QpackEncoderInstructions<'static>> = None;
    let _: Option<qpack::QpackEncoderInstructionIter<'static>> = None;
    let _: Option<qpack::QpackEncoderInstructionParseError> = None;
    let _: Option<qpack::QpackEncoderInstructionsParseError> = None;
    let _: Option<qpack::QpackEncoderInstructionBuildError> = None;
    let _: Option<qpack::QpackSetDynamicTableCapacityBuilder<'static>> = None;
    let _: Option<qpack::QpackInsertWithNameReferenceBuilder<'static, 'static>> = None;
    let _: Option<qpack::QpackInsertWithLiteralNameBuilder<'static, 'static, 'static>> = None;
    let _: Option<qpack::QpackDuplicateBuilder<'static>> = None;
}

#[test]
fn qpack_encoder_instruction_builders_emit_rfc_vectors_and_are_atomic() {
    let mut capacity = [0xaa; 4];
    assert_eq!(
        QpackSetDynamicTableCapacityBuilder::new(&mut capacity, 220)
            .build()
            .map(|instruction| instruction.as_bytes()),
        Ok(&[0x3f, 0xbd, 0x01][..])
    );
    assert_eq!(capacity[3], 0xaa);

    let mut static_name = [0xaa; 18];
    assert_eq!(
        QpackInsertWithNameReferenceBuilder::new(
            &mut static_name,
            true,
            0,
            false,
            b"www.example.com"
        )
        .build()
        .map(|instruction| instruction.as_bytes()),
        Ok(&[
            0xc0, 0x0f, b'w', b'w', b'w', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.',
            b'c', b'o', b'm',
        ][..])
    );
    assert_eq!(static_name[17], 0xaa);

    let mut literal = [0xaa; 25];
    assert_eq!(
        QpackInsertWithLiteralNameBuilder::new(
            &mut literal,
            false,
            b"custom-key",
            false,
            b"custom-value",
        )
        .build()
        .map(|instruction| instruction.as_bytes()),
        Ok(&[
            0x4a, b'c', b'u', b's', b't', b'o', b'm', b'-', b'k', b'e', b'y', 0x0c, b'c', b'u',
            b's', b't', b'o', b'm', b'-', b'v', b'a', b'l', b'u', b'e',
        ][..])
    );
    assert_eq!(literal[24], 0xaa);

    let mut duplicate = [0xaa; 2];
    assert_eq!(
        QpackDuplicateBuilder::new(&mut duplicate, 2)
            .build()
            .map(|instruction| instruction.as_bytes()),
        Ok(&[0x02][..])
    );
    assert_eq!(duplicate[1], 0xaa);

    let mut short = [0xaa; 2];
    let before = short;
    assert_eq!(
        QpackInsertWithNameReferenceBuilder::new(&mut short, false, 1, false, b"x").build(),
        Err(QpackEncoderInstructionBuildError::BufferTooShort {
            required: 3,
            available: 2,
        })
    );
    assert_eq!(short, before);
    let mut too_large = [0xaa; 16];
    let before = too_large;
    assert_eq!(
        QpackDuplicateBuilder::new(&mut too_large, QPACK_INTEGER_MAX + 1).build(),
        Err(QpackEncoderInstructionBuildError::DuplicateIndex(
            QpackIntegerBuildError::ValueTooLarge {
                value: QPACK_INTEGER_MAX + 1,
            }
        ))
    );
    assert_eq!(too_large, before);
}

#[test]
fn qpack_encoder_instruction_builders_cover_boundaries_flags_atomicity_and_lifetimes() {
    let mut static_index_one = [0xaa; 15];
    assert_eq!(
        QpackInsertWithNameReferenceBuilder::new(
            &mut static_index_one,
            true,
            1,
            false,
            b"/sample/path"
        )
        .build()
        .map(|instruction| instruction.as_bytes()),
        Ok(&[
            0xc1, 0x0c, b'/', b's', b'a', b'm', b'p', b'l', b'e', b'/', b'p', b'a', b't', b'h'
        ][..])
    );
    assert_eq!(static_index_one[14], 0xaa);

    let mut dynamic = [0xaa; 15];
    assert_eq!(
        QpackInsertWithNameReferenceBuilder::new(&mut dynamic, false, 1, false, b"custom-value2")
            .build()
            .map(|instruction| instruction.as_bytes()),
        Ok(&[
            0x81, 0x0d, b'c', b'u', b's', b't', b'o', b'm', b'-', b'v', b'a', b'l', b'u', b'e',
            b'2'
        ][..])
    );

    for (name_huffman, value_huffman, expected) in [
        (false, false, &[0x40, 0][..]),
        (true, false, &[0x60, 0][..]),
        (false, true, &[0x40, 0x80][..]),
        (true, true, &[0x60, 0x80][..]),
    ] {
        let mut destination = [0xaa; 4];
        assert_eq!(
            QpackInsertWithLiteralNameBuilder::new(
                &mut destination,
                name_huffman,
                b"",
                value_huffman,
                b"",
            )
            .build()
            .map(|instruction| instruction.as_bytes()),
            Ok(expected)
        );
        assert_eq!(&destination[2..], &[0xaa; 2]);
    }
    let mut name_reference_huffman = [0xaa; 3];
    assert_eq!(
        QpackInsertWithNameReferenceBuilder::new(&mut name_reference_huffman, false, 0, true, b"")
            .build()
            .map(|instruction| instruction.as_bytes()),
        Ok(&[0x80, 0x80][..])
    );
    assert_eq!(name_reference_huffman[2], 0xaa);

    let mut short_capacity = [0xaa; 2];
    let before = short_capacity;
    assert_eq!(
        QpackSetDynamicTableCapacityBuilder::new(&mut short_capacity, 220).build(),
        Err(QpackEncoderInstructionBuildError::BufferTooShort {
            required: 3,
            available: 2,
        })
    );
    assert_eq!(short_capacity, before);

    let mut short_name_reference = [0xaa; 1];
    let before = short_name_reference;
    assert_eq!(
        QpackInsertWithNameReferenceBuilder::new(&mut short_name_reference, false, 0, false, b"",)
            .build(),
        Err(QpackEncoderInstructionBuildError::BufferTooShort {
            required: 2,
            available: 1,
        })
    );
    assert_eq!(short_name_reference, before);

    let mut short_literal = [0xaa; 1];
    let before = short_literal;
    assert_eq!(
        QpackInsertWithLiteralNameBuilder::new(&mut short_literal, false, b"", false, b"").build(),
        Err(QpackEncoderInstructionBuildError::BufferTooShort {
            required: 2,
            available: 1,
        })
    );
    assert_eq!(short_literal, before);

    let mut short_duplicate = [];
    let before = short_duplicate;
    assert_eq!(
        QpackDuplicateBuilder::new(&mut short_duplicate, 0).build(),
        Err(QpackEncoderInstructionBuildError::BufferTooShort {
            required: 1,
            available: 0,
        })
    );
    assert_eq!(short_duplicate, before);

    let mut too_large_capacity = [0xaa; 16];
    let before = too_large_capacity;
    assert_eq!(
        QpackSetDynamicTableCapacityBuilder::new(&mut too_large_capacity, QPACK_INTEGER_MAX + 1)
            .build(),
        Err(QpackEncoderInstructionBuildError::SetDynamicTableCapacity(
            QpackIntegerBuildError::ValueTooLarge {
                value: QPACK_INTEGER_MAX + 1,
            }
        ))
    );
    assert_eq!(too_large_capacity, before);

    let mut too_large_name_index = [0xaa; 16];
    let before = too_large_name_index;
    assert_eq!(
        QpackInsertWithNameReferenceBuilder::new(
            &mut too_large_name_index,
            false,
            QPACK_INTEGER_MAX + 1,
            false,
            b"",
        )
        .build(),
        Err(
            QpackEncoderInstructionBuildError::InsertWithNameReferenceNameIndex(
                QpackIntegerBuildError::ValueTooLarge {
                    value: QPACK_INTEGER_MAX + 1,
                }
            )
        )
    );
    assert_eq!(too_large_name_index, before);

    let mut too_large_duplicate = [0xaa; 16];
    let before = too_large_duplicate;
    assert_eq!(
        QpackDuplicateBuilder::new(&mut too_large_duplicate, QPACK_INTEGER_MAX + 1).build(),
        Err(QpackEncoderInstructionBuildError::DuplicateIndex(
            QpackIntegerBuildError::ValueTooLarge {
                value: QPACK_INTEGER_MAX + 1,
            }
        ))
    );
    assert_eq!(too_large_duplicate, before);

    let mut name = *b"name";
    let mut value = *b"value";
    let mut destination = [0xaa; 16];
    let view =
        QpackInsertWithLiteralNameBuilder::new(&mut destination, false, &name, false, &value)
            .build()
            .expect("capacity");
    name.fill(b'x');
    value.fill(b'y');
    assert_eq!(view.name().encoded_payload(), b"name");
    assert_eq!(view.value().encoded_payload(), b"value");
    assert_eq!(view.as_bytes(), b"Dname\x05value");
}
