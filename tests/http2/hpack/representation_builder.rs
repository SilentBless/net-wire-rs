use net_wire::http2::hpack::{
    HpackDynamicTableSizeUpdateBuilder, HpackIndexedFieldBuilder, HpackLiteralFieldBuilder,
    HpackLiteralMode, HpackLiteralName, HpackLiteralValue, HpackRepresentation,
    HpackRepresentationBuildError,
};

#[test]
fn hpack_representation_builders_emit_all_forms_and_round_trip() {
    let mut indexed_destination = [0xaa; 4];
    let indexed = HpackIndexedFieldBuilder::new(&mut indexed_destination, 2)
        .build()
        .unwrap();
    assert_eq!(indexed, [0x82]);
    let indexed = indexed.to_vec();
    assert_eq!(indexed_destination, [0x82, 0xaa, 0xaa, 0xaa]);
    assert!(matches!(
        HpackRepresentation::parse(&indexed),
        Ok(HpackRepresentation::Indexed(field)) if field.index_value() == 2
    ));

    let mut update_destination = [0xaa; 4];
    let update = HpackDynamicTableSizeUpdateBuilder::new(&mut update_destination, 31)
        .build()
        .unwrap();
    assert_eq!(update, [0x3f, 0x00]);
    assert!(matches!(
        HpackRepresentation::parse(update),
        Ok(HpackRepresentation::DynamicTableSizeUpdate(field)) if field.size_value() == 31
    ));

    for (mode, prefix) in [
        (HpackLiteralMode::IncrementalIndexing, 0x40),
        (HpackLiteralMode::WithoutIndexing, 0x00),
        (HpackLiteralMode::NeverIndexed, 0x10),
    ] {
        let mut destination = [0xaa; 8];
        let wire = HpackLiteralFieldBuilder::new(
            &mut destination,
            mode,
            HpackLiteralName::Literal {
                encoded_bytes: &[0, 0xff],
                huffman: true,
            },
            HpackLiteralValue::new_encoded(&[0x80], false),
        )
        .build()
        .unwrap();
        assert_eq!(wire, [prefix, 0x82, 0, 0xff, 0x01, 0x80]);
        let HpackRepresentation::Literal(field) = HpackRepresentation::parse(wire).unwrap() else {
            panic!("expected literal field");
        };
        assert_eq!(field.mode(), mode);
        assert_eq!(field.name().unwrap().encoded_bytes(), [0, 0xff]);
        assert!(field.name().unwrap().is_huffman());
        assert_eq!(field.value().encoded_bytes(), [0x80]);
        assert!(!field.value().is_huffman());
        assert_eq!(destination[6..], [0xaa; 2]);
    }
}

#[test]
fn hpack_literal_builders_cover_indices_string_boundaries_and_atomicity() {
    for (mode, index, expected) in [
        (
            HpackLiteralMode::IncrementalIndexing,
            63,
            vec![0x7f, 0x00, 0x00],
        ),
        (
            HpackLiteralMode::IncrementalIndexing,
            64,
            vec![0x7f, 0x01, 0x00],
        ),
        (
            HpackLiteralMode::WithoutIndexing,
            15,
            vec![0x0f, 0x00, 0x00],
        ),
        (
            HpackLiteralMode::WithoutIndexing,
            16,
            vec![0x0f, 0x01, 0x00],
        ),
        (HpackLiteralMode::NeverIndexed, 15, vec![0x1f, 0x00, 0x00]),
        (HpackLiteralMode::NeverIndexed, 16, vec![0x1f, 0x01, 0x00]),
    ] {
        let mut destination = [0xaa; 8];
        let wire = HpackLiteralFieldBuilder::new(
            &mut destination,
            mode,
            HpackLiteralName::Indexed(index),
            HpackLiteralValue::new_encoded(&[], false),
        )
        .build()
        .unwrap();
        assert_eq!(wire, expected);
        let HpackRepresentation::Literal(field) = HpackRepresentation::parse(wire).unwrap() else {
            panic!("expected literal field");
        };
        assert_eq!(field.name_index_value(), index);
        assert_eq!(field.name(), None);
    }
    for (index, expected) in [(127, vec![0xff, 0]), (128, vec![0xff, 1])] {
        let mut destination = [0xaa; 3];
        assert_eq!(
            HpackIndexedFieldBuilder::new(&mut destination, index)
                .build()
                .unwrap(),
            expected
        );
    }
    for (size, expected) in [(31, vec![0x3f, 0]), (32, vec![0x3f, 1])] {
        let mut destination = [0xaa; 3];
        assert_eq!(
            HpackDynamicTableSizeUpdateBuilder::new(&mut destination, size)
                .build()
                .unwrap(),
            expected
        );
    }
    let mut maximum_destination = [0xaa; 16];
    let maximum_index = HpackIndexedFieldBuilder::new(&mut maximum_destination, u64::MAX)
        .build()
        .unwrap();
    let HpackRepresentation::Indexed(maximum_index) =
        HpackRepresentation::parse(maximum_index).unwrap()
    else {
        panic!("expected indexed field");
    };
    assert_eq!(maximum_index.index_value(), u64::MAX);

    let maximum_update =
        HpackDynamicTableSizeUpdateBuilder::new(&mut maximum_destination, u64::MAX)
            .build()
            .unwrap();
    let HpackRepresentation::DynamicTableSizeUpdate(maximum_update) =
        HpackRepresentation::parse(maximum_update).unwrap()
    else {
        panic!("expected dynamic table size update");
    };
    assert_eq!(maximum_update.size_value(), u64::MAX);

    let maximum_literal = HpackLiteralFieldBuilder::new(
        &mut maximum_destination,
        HpackLiteralMode::IncrementalIndexing,
        HpackLiteralName::Indexed(u64::MAX),
        HpackLiteralValue::new_encoded(&[], false),
    )
    .build()
    .unwrap();
    let HpackRepresentation::Literal(maximum_literal) =
        HpackRepresentation::parse(maximum_literal).unwrap()
    else {
        panic!("expected literal field");
    };
    assert_eq!(maximum_literal.name_index_value(), u64::MAX);

    for length in [127, 128] {
        let value = vec![0x5a; length];
        let mut destination = vec![0xaa; length + 4];
        let wire = HpackLiteralFieldBuilder::new(
            &mut destination,
            HpackLiteralMode::WithoutIndexing,
            HpackLiteralName::Indexed(1),
            HpackLiteralValue::new_encoded(&value, true),
        )
        .build()
        .unwrap();
        assert_eq!(wire[1], 0xff);
        assert_eq!(wire[2], if length == 127 { 0 } else { 1 });
        assert!(
            matches!(HpackRepresentation::parse(wire), Ok(HpackRepresentation::Literal(field)) if field.value().is_huffman())
        );
    }

    let name = [0x80, 0xff];
    let value = [0, 0xfe];
    let mut full_destination = [0xaa; 16];
    let full = HpackLiteralFieldBuilder::new(
        &mut full_destination,
        HpackLiteralMode::IncrementalIndexing,
        HpackLiteralName::Literal {
            encoded_bytes: &name,
            huffman: true,
        },
        HpackLiteralValue::new_encoded(&value, false),
    )
    .build()
    .unwrap()
    .to_vec();
    for available in 0..full.len() {
        let mut destination = vec![0xaa; available];
        let before = destination.clone();
        assert_eq!(
            HpackLiteralFieldBuilder::new(
                &mut destination,
                HpackLiteralMode::IncrementalIndexing,
                HpackLiteralName::Literal {
                    encoded_bytes: &name,
                    huffman: true
                },
                HpackLiteralValue::new_encoded(&value, false),
            )
            .build(),
            Err(HpackRepresentationBuildError::BufferTooShort {
                required: full.len(),
                available
            })
        );
        assert_eq!(destination, before);
    }
    let mut zero_destination = [0xaa; 4];
    let before = zero_destination;
    assert_eq!(
        HpackIndexedFieldBuilder::new(&mut zero_destination, 0).build(),
        Err(HpackRepresentationBuildError::IndexedFieldZero)
    );
    assert_eq!(zero_destination, before);

    for mode in [
        HpackLiteralMode::IncrementalIndexing,
        HpackLiteralMode::WithoutIndexing,
        HpackLiteralMode::NeverIndexed,
    ] {
        let mut destination = [0xaa; 4];
        let before = destination;
        assert_eq!(
            HpackLiteralFieldBuilder::new(
                &mut destination,
                mode,
                HpackLiteralName::Indexed(0),
                HpackLiteralValue::new_encoded(&[], false),
            )
            .build(),
            Err(HpackRepresentationBuildError::LiteralNameIndexZero)
        );
        assert_eq!(destination, before);
    }
}

#[test]
fn hpack_representation_builder_output_does_not_borrow_inputs() {
    let mut source_name = *b"n";
    let mut source_value = *b"v";
    let mut destination = [0xaa; 8];
    let output = HpackLiteralFieldBuilder::new(
        &mut destination,
        HpackLiteralMode::WithoutIndexing,
        HpackLiteralName::Literal {
            encoded_bytes: &source_name,
            huffman: false,
        },
        HpackLiteralValue::new_encoded(&source_value, false),
    )
    .build()
    .unwrap();
    source_name[0] = b'x';
    source_value[0] = b'y';
    assert_eq!(source_name, *b"x");
    assert_eq!(source_value, *b"y");
    let HpackRepresentation::Literal(field) = HpackRepresentation::parse(output).unwrap() else {
        panic!("expected literal field");
    };
    assert_eq!(field.name().unwrap().encoded_bytes(), b"n");
    assert_eq!(field.value().encoded_bytes(), b"v");
}
