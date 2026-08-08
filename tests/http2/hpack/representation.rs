use net_wire::http2::hpack::{
    HpackIntegerParseError, HpackLiteralMode, HpackRepresentation, HpackRepresentationParseError,
    HpackStringLiteralParseError,
};

#[test]
fn hpack_representations_parse_all_wire_forms_and_exact_boundaries() {
    let indexed = HpackRepresentation::parse(&[0x82, 0xaa]).unwrap();
    let HpackRepresentation::Indexed(indexed) = indexed else {
        panic!("expected indexed field");
    };
    assert_eq!(indexed.as_bytes(), [0x82]);
    assert_eq!(indexed.index().as_bytes(), [0x82]);
    assert_eq!(indexed.index_value(), 2);

    let wire = [0x42, 0x81, 0xfe, 0xaa];
    let literal = HpackRepresentation::parse(&wire).unwrap();
    let HpackRepresentation::Literal(literal) = literal else {
        panic!("expected literal field");
    };
    assert_eq!(literal.as_bytes(), &wire[..3]);
    assert_eq!(literal.mode(), HpackLiteralMode::IncrementalIndexing);
    assert_eq!(literal.name_index_value(), 2);
    assert_eq!(literal.name(), None);
    assert!(literal.value().is_huffman());
    assert_eq!(literal.value().encoded_bytes(), [0xfe]);

    let wire = [0x3f, 0x80, 0x00, 0xaa];
    let update = HpackRepresentation::parse(&wire).unwrap();
    let HpackRepresentation::DynamicTableSizeUpdate(update) = update else {
        panic!("expected table size update");
    };
    assert_eq!(update.as_bytes(), &wire[..3]);
    assert_eq!(update.size().as_bytes(), [0x3f, 0x80, 0x00]);
    assert_eq!(update.size_value(), 31);

    for (wire, mode) in [
        (
            &[0x10, 0x01, b'n', 0x81, 0xff, 0xaa][..],
            HpackLiteralMode::NeverIndexed,
        ),
        (
            &[0x00, 0x81, 0x00, 0x81, 0xfe, 0xaa][..],
            HpackLiteralMode::WithoutIndexing,
        ),
    ] {
        let literal = HpackRepresentation::parse(wire).unwrap();
        let HpackRepresentation::Literal(literal) = literal else {
            panic!("expected literal field");
        };
        assert_eq!(literal.as_bytes(), &wire[..wire.len() - 1]);
        assert_eq!(literal.mode(), mode);
        assert_eq!(literal.name_index_value(), 0);
        let name = literal.name().unwrap();
        assert!(literal.value().is_huffman());
        if mode == HpackLiteralMode::NeverIndexed {
            assert_eq!(name.as_bytes(), [0x01, b'n']);
            assert!(!name.is_huffman());
        } else {
            assert_eq!(name.as_bytes(), [0x81, 0x00]);
            assert!(name.is_huffman());
        }
    }

    for (wire, mode, has_name) in [
        (
            &[0x41, 0x00][..],
            HpackLiteralMode::IncrementalIndexing,
            false,
        ),
        (
            &[0x40, 0x00, 0x00][..],
            HpackLiteralMode::IncrementalIndexing,
            true,
        ),
        (&[0x11, 0x00][..], HpackLiteralMode::NeverIndexed, false),
        (
            &[0x10, 0x00, 0x00][..],
            HpackLiteralMode::NeverIndexed,
            true,
        ),
        (&[0x01, 0x00][..], HpackLiteralMode::WithoutIndexing, false),
        (
            &[0x00, 0x00, 0x00][..],
            HpackLiteralMode::WithoutIndexing,
            true,
        ),
    ] {
        let HpackRepresentation::Literal(literal) = HpackRepresentation::parse(wire).unwrap()
        else {
            panic!("expected literal field");
        };
        assert_eq!(literal.mode(), mode);
        assert_eq!(literal.name().is_some(), has_name);
        assert_eq!(literal.name_index_value() == 0, has_name);
    }
}

#[test]
fn hpack_representations_preserve_overlong_encodings_and_dispatch_boundaries() {
    for (wire, kind) in [
        (&[0x81][..], 0),
        (&[0x40, 0x00, 0x00][..], 1),
        (&[0x20][..], 2),
        (&[0x10, 0x00, 0x00][..], 3),
        (&[0x00, 0x00, 0x00][..], 4),
    ] {
        match (kind, HpackRepresentation::parse(wire).unwrap()) {
            (0, HpackRepresentation::Indexed(_))
            | (1 | 3 | 4, HpackRepresentation::Literal(_))
            | (2, HpackRepresentation::DynamicTableSizeUpdate(_)) => {}
            _ => panic!("wrong representation dispatch"),
        }
    }

    let wire = [0x7f, 0x80, 0x00, 0x00, 0xaa];
    let literal = HpackRepresentation::parse(&wire).unwrap();
    let HpackRepresentation::Literal(literal) = literal else {
        panic!("expected literal field");
    };
    assert_eq!(literal.as_bytes(), &wire[..4]);
    assert_eq!(literal.name_index().as_bytes(), [0x7f, 0x80, 0x00]);
    assert_eq!(literal.name_index_value(), 63);
    assert_eq!(literal.value().length().as_bytes(), [0x00]);
    assert_eq!(literal.value().encoded_bytes(), []);
}

#[test]
fn hpack_representations_distinguish_malformed_components() {
    assert_eq!(
        HpackRepresentation::parse(&[0xff]),
        Err(HpackRepresentationParseError::IndexedIndex(
            HpackIntegerParseError::Incomplete {
                required: 2,
                available: 1,
            }
        ))
    );
    assert_eq!(
        HpackRepresentation::parse(&[0x80, 0x00]),
        Err(HpackRepresentationParseError::IndexedFieldZero)
    );
    assert_eq!(
        HpackRepresentation::parse(&[0x7f]),
        Err(HpackRepresentationParseError::LiteralNameIndex(
            HpackIntegerParseError::Incomplete {
                required: 2,
                available: 1,
            }
        ))
    );
    assert!(matches!(
        HpackRepresentation::parse(&[0x00, 0x02, b'n']),
        Err(HpackRepresentationParseError::LiteralName(
            HpackStringLiteralParseError::IncompleteEncodedPayload { .. }
        ))
    ));
    assert!(matches!(
        HpackRepresentation::parse(&[0x42, 0x02, b'v']),
        Err(HpackRepresentationParseError::LiteralValue(
            HpackStringLiteralParseError::IncompleteEncodedPayload { .. }
        ))
    ));
}
