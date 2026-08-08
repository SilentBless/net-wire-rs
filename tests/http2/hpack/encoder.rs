// This suite keeps the HPACK encoder context, block emission, Huffman, and atomic state-output contracts together.
use net_wire::http2::hpack::{
    HPACK_STATIC_TABLE_LEN, HpackDecodeStep, HpackDecoderContext, HpackDynamicTable,
    HpackDynamicTableEntry, HpackEncodeError, HpackEncodeLiteralName, HpackEncoderContext,
    HpackHeaderFieldRef, HpackHuffmanEncoder, HpackLiteralHuffman, HpackLiteralMode,
    HpackRepresentation, HpackRepresentationBuildError,
};

#[test]
fn hpack_encoder_two_pending_size_updates_are_atomic_and_complete() {
    let mut bytes = [0; 128];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 4];
    let mut table = HpackDynamicTable::new(&mut bytes, &mut entries, 64).unwrap();
    table.insert(b"a", b"b").unwrap();
    let mut context = HpackEncoderContext::new(table, 64).unwrap();
    context.set_allowed_maximum_size(32).unwrap();
    context.set_allowed_maximum_size(64).unwrap();
    assert_eq!(context.next_required_size_update(), Some(32));

    assert_eq!(
        context.begin_block().finish(),
        Err(HpackEncodeError::DynamicTableSizeUpdateRequired)
    );
    assert_eq!(context.next_required_size_update(), Some(32));
    assert_eq!(context.dynamic_table().maximum_size(), 64);
    assert_eq!(
        context.dynamic_table().get(1),
        Some(HpackHeaderFieldRef::new(b"a", b"b"))
    );

    {
        let mut block = context.begin_block();
        let mut wrong = [0xaa; 4];
        let before_wrong = wrong;
        assert_eq!(
            block.encode_dynamic_table_size_update(&mut wrong, 64),
            Err(HpackEncodeError::DynamicTableSizeUpdateMismatch {
                expected: 32,
                requested: 64,
            })
        );
        assert_eq!(wrong, before_wrong);

        let mut short = [0xaa; 1];
        let before_short = short;
        assert!(matches!(
            block.encode_dynamic_table_size_update(&mut short, 32),
            Err(HpackEncodeError::Representation(
                HpackRepresentationBuildError::BufferTooShort {
                    required: 2,
                    available: 1,
                }
            ))
        ));
        assert_eq!(short, before_short);
    }
    assert_eq!(context.next_required_size_update(), Some(32));
    assert_eq!(context.dynamic_table().maximum_size(), 64);
    assert_eq!(
        context.dynamic_table().get(1),
        Some(HpackHeaderFieldRef::new(b"a", b"b"))
    );

    {
        let mut block = context.begin_block();
        let mut first_destination = [0xaa; 4];
        assert_eq!(
            block
                .encode_dynamic_table_size_update(&mut first_destination, 32)
                .unwrap(),
            [0x3f, 0x01]
        );
        assert_eq!(first_destination[2..], [0xaa; 2]);

        let mut second_destination = [0xaa; 4];
        assert_eq!(
            block
                .encode_dynamic_table_size_update(&mut second_destination, 64)
                .unwrap(),
            [0x3f, 0x21]
        );
        assert_eq!(second_destination[2..], [0xaa; 2]);
        block.finish().unwrap();
    }
    assert_eq!(context.next_required_size_update(), None);
    assert_eq!(context.dynamic_table().maximum_size(), 64);
    assert!(context.dynamic_table().is_empty());
    context.begin_block().finish().unwrap();
}

#[test]
fn hpack_block_encoder_requires_and_emits_leading_size_updates() {
    let mut bytes = [0x5a; 64];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let before_bytes = bytes;
    let before_entries = entries;
    {
        let table = HpackDynamicTable::new(&mut bytes, &mut entries, 64).unwrap();
        let mut context = HpackEncoderContext::new(table, 32).unwrap();
        let mut encoder = context.begin_block();
        assert!(encoder.requires_size_update());

        let mut short_destination = [0xaa; 1];
        let before_short_destination = short_destination;
        assert_eq!(
            encoder.encode_dynamic_table_size_update(&mut short_destination, 32),
            Err(HpackEncodeError::Representation(
                HpackRepresentationBuildError::BufferTooShort {
                    required: 2,
                    available: 1,
                }
            ))
        );
        assert_eq!(short_destination, before_short_destination);
        assert!(encoder.requires_size_update());
        assert_eq!(context.dynamic_table().maximum_size(), 64);
    }
    assert_eq!(bytes, before_bytes);
    assert_eq!(entries, before_entries);

    {
        let table = HpackDynamicTable::new(&mut bytes, &mut entries, 64).unwrap();
        let mut context = HpackEncoderContext::new(table, 32).unwrap();
        let mut encoder = context.begin_block();
        assert!(encoder.requires_size_update());
        let mut indexed_destination = [0xaa; 4];
        let before_destination = indexed_destination;
        assert_eq!(
            encoder.encode_indexed(&mut indexed_destination, 1),
            Err(HpackEncodeError::DynamicTableSizeUpdateRequired)
        );
        assert_eq!(indexed_destination, before_destination);
        assert!(encoder.requires_size_update());

        let mut destination = [0xaa; 4];
        let update = encoder
            .encode_dynamic_table_size_update(&mut destination, 32)
            .unwrap();
        assert_eq!(update, [0x3f, 0x01]);
        assert!(matches!(
            HpackRepresentation::parse(update),
            Ok(HpackRepresentation::DynamicTableSizeUpdate(field)) if field.size_value() == 32
        ));
        assert!(!encoder.requires_size_update());
        assert_eq!(destination[2..], [0xaa; 2]);

        let repeated = encoder
            .encode_dynamic_table_size_update(&mut destination, 30)
            .unwrap();
        assert_eq!(repeated, [0x3e]);
        assert_eq!(context.dynamic_table().maximum_size(), 30);
    }
    assert_eq!(bytes, before_bytes);
    assert_eq!(entries, before_entries);
}

#[test]
fn hpack_block_encoder_encodes_resolved_indices_and_preserves_output_lifetimes() {
    let mut bytes = [0; 64];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let mut table = HpackDynamicTable::new(&mut bytes, &mut entries, 64).unwrap();
    table.insert(b"n", b"v").unwrap();

    let mut context = HpackEncoderContext::new(table, 64).unwrap();
    {
        let mut encoder = context.begin_block();
        let mut destination = [0xaa; 4];
        let static_output = encoder.encode_indexed(&mut destination, 2).unwrap();
        assert_eq!(static_output, [0x82]);
        assert!(encoder.has_emitted_field());
        assert!(matches!(
            HpackRepresentation::parse(static_output),
            Ok(HpackRepresentation::Indexed(field)) if field.index_value() == 2
        ));
        assert_eq!(destination[1..], [0xaa; 3]);

        let dynamic_output = encoder.encode_indexed(&mut destination, 62).unwrap();
        assert_eq!(dynamic_output, [0xbe]);
        assert!(matches!(
            HpackRepresentation::parse(dynamic_output),
            Ok(HpackRepresentation::Indexed(field)) if field.index_value() == 62
        ));

        let before_destination = destination;
        assert_eq!(
            encoder.encode_indexed(&mut destination, 0),
            Err(HpackEncodeError::UnavailableIndex { index: 0 })
        );
        assert_eq!(
            encoder.encode_indexed(&mut destination, 63),
            Err(HpackEncodeError::UnavailableIndex { index: 63 })
        );
        assert_eq!(destination, before_destination);
        assert_eq!(
            encoder.encode_dynamic_table_size_update(&mut destination, 32),
            Err(HpackEncodeError::DynamicTableSizeUpdateAfterField)
        );
        assert_eq!(destination, before_destination);
        assert_eq!(
            context.dynamic_table().get(1),
            Some(HpackHeaderFieldRef::new(b"n", b"v"))
        );
    }
}

#[test]
fn hpack_block_encoder_rejects_policy_and_capacity_atomically() {
    let mut bytes = [0x5a; 64];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let before_bytes = bytes;
    let before_entries = entries;

    {
        let table = HpackDynamicTable::new(&mut bytes, &mut entries, 64).unwrap();
        let mut context = HpackEncoderContext::new(table, 63).unwrap();
        let mut encoder = context.begin_block();
        let mut destination = [0xaa; 4];
        let before_destination = destination;
        assert_eq!(
            encoder.encode_dynamic_table_size_update(&mut destination, 64),
            Err(HpackEncodeError::DynamicTableSizeUpdateMismatch {
                expected: 63,
                requested: 64,
            })
        );
        assert_eq!(destination, before_destination);
        assert!(encoder.requires_size_update());
        assert_eq!(context.dynamic_table().maximum_size(), 64);
        let table = context.into_dynamic_table();

        assert!(matches!(
            HpackEncoderContext::new(table, 96),
            Err(HpackEncodeError::AllowedMaximumExceedsCapacity {
                allowed: 96,
                capacity: 95,
            })
        ));
    }
    assert_eq!(bytes, before_bytes);
    assert_eq!(entries, before_entries);
}

#[test]
fn hpack_block_encoder_emits_plain_literal_names_in_every_mode() {
    for (mode, first) in [
        (HpackLiteralMode::IncrementalIndexing, 0x40),
        (HpackLiteralMode::WithoutIndexing, 0),
        (HpackLiteralMode::NeverIndexed, 0x10),
    ] {
        let mut bytes = [0; 128];
        let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
        let table = HpackDynamicTable::new(&mut bytes, &mut entries, 95).unwrap();
        let mut context = HpackEncoderContext::new(table, 95).unwrap();
        let mut encoder = context.begin_block();
        let mut destination = [0xaa; 16];
        let output = encoder
            .encode_literal(
                &mut destination,
                mode,
                HpackEncodeLiteralName::Literal(&[0, 0xff]),
                &[0x80, 0],
            )
            .unwrap();
        assert_eq!(output, [first, 2, 0, 0xff, 2, 0x80, 0]);
        let HpackRepresentation::Literal(field) = HpackRepresentation::parse(output).unwrap()
        else {
            panic!("expected literal field");
        };
        assert_eq!(field.mode(), mode);
        assert_eq!(field.name().unwrap().encoded_bytes(), [0, 0xff]);
        assert!(!field.name().unwrap().is_huffman());
        assert_eq!(field.value().encoded_bytes(), [0x80, 0]);
        assert!(!field.value().is_huffman());
        assert_eq!(destination[7..], [0xaa; 9]);
    }
}

#[test]
fn hpack_block_encoder_literal_indexed_names_validate_and_emit_only_indices() {
    let mut bytes = [0; 128];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let mut table = HpackDynamicTable::new(&mut bytes, &mut entries, 95).unwrap();
    table.insert(b"dynamic", b"old").unwrap();
    let mut context = HpackEncoderContext::new(table, 95).unwrap();
    let mut encoder = context.begin_block();
    let mut destination = [0xaa; 16];
    let static_output = encoder
        .encode_literal(
            &mut destination,
            HpackLiteralMode::WithoutIndexing,
            HpackEncodeLiteralName::Indexed {
                index: 2,
                decoded: b":method",
            },
            b"PUT",
        )
        .unwrap();
    assert_eq!(static_output, [2, 3, b'P', b'U', b'T']);
    assert!(
        !static_output
            .windows(b":method".len())
            .any(|bytes| bytes == b":method")
    );
    let dynamic_output = encoder
        .encode_literal(
            &mut destination,
            HpackLiteralMode::WithoutIndexing,
            HpackEncodeLiteralName::Indexed {
                index: 62,
                decoded: b"dynamic",
            },
            b"new",
        )
        .unwrap();
    assert_eq!(dynamic_output, [15, 47, 3, b'n', b'e', b'w']);
    let before = destination;
    assert_eq!(
        encoder.encode_literal(
            &mut destination,
            HpackLiteralMode::WithoutIndexing,
            HpackEncodeLiteralName::Indexed {
                index: 2,
                decoded: b"wrong",
            },
            b"v",
        ),
        Err(HpackEncodeError::IndexedLiteralNameMismatch { index: 2 })
    );
    assert_eq!(destination, before);
    assert_eq!(
        encoder.encode_literal(
            &mut destination,
            HpackLiteralMode::WithoutIndexing,
            HpackEncodeLiteralName::Indexed {
                index: 0,
                decoded: b"",
            },
            b"v",
        ),
        Err(HpackEncodeError::UnavailableIndex { index: 0 })
    );
}

#[test]
fn hpack_block_encoder_literal_insertion_is_independent() {
    let mut bytes = [0; 128];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let table = HpackDynamicTable::new(&mut bytes, &mut entries, 95).unwrap();
    let mut name = *b"name";
    let mut value = *b"value";
    {
        let mut context = HpackEncoderContext::new(table, 95).unwrap();
        let mut encoder = context.begin_block();
        let mut destination = [0xaa; 16];
        let output = encoder
            .encode_literal(
                &mut destination,
                HpackLiteralMode::IncrementalIndexing,
                HpackEncodeLiteralName::Literal(&name),
                &value,
            )
            .unwrap();
        name[0] = b'x';
        value[0] = b'y';
        assert_eq!(name, *b"xame");
        assert_eq!(value, *b"yalue");
        assert_eq!(
            output,
            [
                0x40, 4, b'n', b'a', b'm', b'e', 5, b'v', b'a', b'l', b'u', b'e'
            ]
        );
        assert_eq!(
            encoder.encode_dynamic_table_size_update(&mut destination, 64),
            Err(HpackEncodeError::DynamicTableSizeUpdateAfterField)
        );
        assert_eq!(
            context.dynamic_table().get(1),
            Some(HpackHeaderFieldRef::new(b"name", b"value"))
        );
    }
}

#[test]
fn hpack_block_encoder_non_indexing_literals_preserve_caller_table_stores() {
    let mut bytes = [0x5a; 128];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let before_bytes = bytes;
    let before_entries = entries;
    {
        let table = HpackDynamicTable::new(&mut bytes, &mut entries, 95).unwrap();
        let mut context = HpackEncoderContext::new(table, 95).unwrap();
        let mut encoder = context.begin_block();
        let mut destination = [0xaa; 16];
        for mode in [
            HpackLiteralMode::WithoutIndexing,
            HpackLiteralMode::NeverIndexed,
        ] {
            encoder
                .encode_literal(
                    &mut destination,
                    mode,
                    HpackEncodeLiteralName::Literal(b"other"),
                    b"v",
                )
                .unwrap();
        }
    }
    assert_eq!(bytes, before_bytes);
    assert_eq!(entries, before_entries);
}

#[test]
fn hpack_block_encoder_literal_short_output_is_atomic_and_oversized_clears_table() {
    let mut bytes = [0x5a; 128];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let mut table = HpackDynamicTable::new(&mut bytes, &mut entries, 64).unwrap();
    table.insert(b"a", b"b").unwrap();
    let before = (table.len(), table.size(), table.maximum_size());
    let mut context = HpackEncoderContext::new(table, 64).unwrap();
    {
        let mut encoder = context.begin_block();
        let mut short = [0xaa; 2];
        let short_before = short;
        assert!(matches!(
            encoder.encode_literal(
                &mut short,
                HpackLiteralMode::IncrementalIndexing,
                HpackEncodeLiteralName::Literal(b"n"),
                b"value"
            ),
            Err(HpackEncodeError::Representation(
                HpackRepresentationBuildError::BufferTooShort { .. }
            ))
        ));
        assert_eq!(short, short_before);
        assert!(!encoder.has_emitted_field());
    }
    assert_eq!(
        (
            context.dynamic_table().len(),
            context.dynamic_table().size(),
            context.dynamic_table().maximum_size()
        ),
        before
    );
    assert_eq!(
        context.dynamic_table().get(1),
        Some(HpackHeaderFieldRef::new(b"a", b"b"))
    );
    {
        let mut encoder = context.begin_block();
        let mut destination = [0xaa; 96];
        let output = encoder
            .encode_literal(
                &mut destination,
                HpackLiteralMode::IncrementalIndexing,
                HpackEncodeLiteralName::Literal(b"oversized"),
                b"0123456789012345678901234567890123456789",
            )
            .unwrap();
        assert!(matches!(
            HpackRepresentation::parse(output),
            Ok(HpackRepresentation::Literal(_))
        ));
    }
    assert!(context.dynamic_table().is_empty());
    assert_eq!(context.dynamic_table().size(), 0);
}

#[test]
fn hpack_block_encoder_rejects_literals_while_size_update_is_required() {
    let mut bytes = [0x5a; 64];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let table = HpackDynamicTable::new(&mut bytes, &mut entries, 64).unwrap();
    let mut context = HpackEncoderContext::new(table, 32).unwrap();
    let mut encoder = context.begin_block();
    let mut destination = [0xaa; 16];
    let before = destination;
    assert_eq!(
        encoder.encode_literal(
            &mut destination,
            HpackLiteralMode::IncrementalIndexing,
            HpackEncodeLiteralName::Literal(b"n"),
            b"v"
        ),
        Err(HpackEncodeError::DynamicTableSizeUpdateRequired)
    );
    assert_eq!(destination, before);
    assert!(encoder.requires_size_update());
    assert!(!encoder.has_emitted_field());
}

#[test]
fn hpack_huffman_literal_strategies_match_standalone_payloads_and_decode() {
    let name = [0, 0xff];
    let value = [0x80, 0];

    for strategy in [
        HpackLiteralHuffman::NONE,
        HpackLiteralHuffman::NAME,
        HpackLiteralHuffman::VALUE,
        HpackLiteralHuffman::BOTH,
    ] {
        let mut encoding_bytes = [0; 128];
        let mut encoding_entries = [HpackDynamicTableEntry::EMPTY; 2];
        let encoding_table =
            HpackDynamicTable::new(&mut encoding_bytes, &mut encoding_entries, 95).unwrap();
        let mut destination = [0xaa; 32];
        let mut encoding_context = HpackEncoderContext::new(encoding_table, 95).unwrap();
        let output = encoding_context
            .begin_block()
            .encode_literal_with_huffman(
                &mut destination,
                HpackLiteralMode::WithoutIndexing,
                HpackEncodeLiteralName::Literal(&name),
                &value,
                strategy,
            )
            .unwrap();
        let HpackRepresentation::Literal(field) = HpackRepresentation::parse(output).unwrap()
        else {
            unreachable!();
        };
        let name_literal = field.name().unwrap();
        assert_eq!(name_literal.is_huffman(), strategy.encodes_name());
        assert_eq!(field.value().is_huffman(), strategy.encodes_value());

        let mut expected_name_storage = [0; 8];
        let expected_name = if strategy.encodes_name() {
            HpackHuffmanEncoder::new(&name, &mut expected_name_storage)
                .encode()
                .unwrap()
        } else {
            &name
        };
        let mut expected_value_storage = [0; 8];
        let expected_value = if strategy.encodes_value() {
            HpackHuffmanEncoder::new(&value, &mut expected_value_storage)
                .encode()
                .unwrap()
        } else {
            &value
        };
        assert_eq!(name_literal.encoded_bytes(), expected_name);
        assert_eq!(field.value().encoded_bytes(), expected_value);

        let mut decoding_bytes = [0; 128];
        let mut decoding_entries = [HpackDynamicTableEntry::EMPTY; 2];
        let decoding_table =
            HpackDynamicTable::new(&mut decoding_bytes, &mut decoding_entries, 95).unwrap();
        let mut decoding_context = HpackDecoderContext::new(decoding_table, 95).unwrap();
        let mut decoded_bytes = [0; 8];
        let HpackDecodeStep::Field(decoded) = decoding_context
            .decode_block(output)
            .decode_next(&mut decoded_bytes)
            .unwrap()
        else {
            unreachable!();
        };
        assert_eq!(decoded.name(), name);
        assert_eq!(decoded.value(), value);
    }
}

#[test]
fn hpack_huffman_none_matches_plain_literal_encoding() {
    let mut plain_bytes = [0; 128];
    let mut plain_entries = [HpackDynamicTableEntry::EMPTY; 2];
    let plain_table = HpackDynamicTable::new(&mut plain_bytes, &mut plain_entries, 95).unwrap();
    let mut huffman_bytes = [0; 128];
    let mut huffman_entries = [HpackDynamicTableEntry::EMPTY; 2];
    let huffman_table =
        HpackDynamicTable::new(&mut huffman_bytes, &mut huffman_entries, 95).unwrap();
    let mut plain_destination = [0xaa; 32];
    let mut huffman_destination = [0xaa; 32];
    let mut plain_context = HpackEncoderContext::new(plain_table, 95).unwrap();
    let plain = plain_context
        .begin_block()
        .encode_literal(
            &mut plain_destination,
            HpackLiteralMode::WithoutIndexing,
            HpackEncodeLiteralName::Literal(&[0, 0xff]),
            &[0x80, 0],
        )
        .unwrap();
    let mut huffman_context = HpackEncoderContext::new(huffman_table, 95).unwrap();
    let huffman = huffman_context
        .begin_block()
        .encode_literal_with_huffman(
            &mut huffman_destination,
            HpackLiteralMode::WithoutIndexing,
            HpackEncodeLiteralName::Literal(&[0, 0xff]),
            &[0x80, 0],
            HpackLiteralHuffman::NONE,
        )
        .unwrap();
    assert_eq!(huffman, plain);
}

#[test]
fn hpack_huffman_value_with_static_or_dynamic_indexed_name_omits_name_bytes() {
    let mut static_bytes = [0; 128];
    let mut static_entries = [HpackDynamicTableEntry::EMPTY; 2];
    let static_table = HpackDynamicTable::new(&mut static_bytes, &mut static_entries, 95).unwrap();
    let mut static_destination = [0xaa; 32];
    let mut static_context = HpackEncoderContext::new(static_table, 95).unwrap();
    let static_output = static_context
        .begin_block()
        .encode_literal_with_huffman(
            &mut static_destination,
            HpackLiteralMode::WithoutIndexing,
            HpackEncodeLiteralName::Indexed {
                index: 2,
                decoded: b":method",
            },
            b"PUT",
            HpackLiteralHuffman::VALUE,
        )
        .unwrap();
    let HpackRepresentation::Literal(static_field) =
        HpackRepresentation::parse(static_output).unwrap()
    else {
        unreachable!();
    };
    assert_eq!(static_field.name_index_value(), 2);
    assert!(static_field.name().is_none());
    assert!(static_field.value().is_huffman());
    let mut static_decoding_bytes = [0; 128];
    let mut static_decoding_entries = [HpackDynamicTableEntry::EMPTY; 2];
    let static_decoding_table =
        HpackDynamicTable::new(&mut static_decoding_bytes, &mut static_decoding_entries, 95)
            .unwrap();
    let mut static_decoding_context = HpackDecoderContext::new(static_decoding_table, 95).unwrap();
    let mut static_decoded_bytes = [0; 16];
    let HpackDecodeStep::Field(static_decoded) = static_decoding_context
        .decode_block(static_output)
        .decode_next(&mut static_decoded_bytes)
        .unwrap()
    else {
        unreachable!();
    };
    assert_eq!(static_decoded.name(), b":method");
    assert_eq!(static_decoded.value(), b"PUT");

    let mut dynamic_bytes = [0; 128];
    let mut dynamic_entries = [HpackDynamicTableEntry::EMPTY; 2];
    let mut dynamic_table =
        HpackDynamicTable::new(&mut dynamic_bytes, &mut dynamic_entries, 95).unwrap();
    dynamic_table.insert(b"dynamic-name", b"seed").unwrap();
    let mut dynamic_destination = [0xaa; 32];
    let dynamic_index = (HPACK_STATIC_TABLE_LEN + 1) as u64;
    let mut dynamic_context = HpackEncoderContext::new(dynamic_table, 95).unwrap();
    let dynamic_output = dynamic_context
        .begin_block()
        .encode_literal_with_huffman(
            &mut dynamic_destination,
            HpackLiteralMode::WithoutIndexing,
            HpackEncodeLiteralName::Indexed {
                index: dynamic_index,
                decoded: b"dynamic-name",
            },
            b"PUT",
            HpackLiteralHuffman::VALUE,
        )
        .unwrap();
    let HpackRepresentation::Literal(dynamic_field) =
        HpackRepresentation::parse(dynamic_output).unwrap()
    else {
        unreachable!();
    };
    assert_eq!(dynamic_field.name_index_value(), dynamic_index);
    assert!(dynamic_field.name().is_none());
    assert!(dynamic_field.value().is_huffman());
    let mut dynamic_decoding_bytes = [0; 128];
    let mut dynamic_decoding_entries = [HpackDynamicTableEntry::EMPTY; 2];
    let mut dynamic_decoding_table = HpackDynamicTable::new(
        &mut dynamic_decoding_bytes,
        &mut dynamic_decoding_entries,
        95,
    )
    .unwrap();
    dynamic_decoding_table
        .insert(b"dynamic-name", b"seed")
        .unwrap();
    let mut dynamic_decoding_context =
        HpackDecoderContext::new(dynamic_decoding_table, 95).unwrap();
    let mut dynamic_decoded_bytes = [0; 32];
    let HpackDecodeStep::Field(dynamic_decoded) = dynamic_decoding_context
        .decode_block(dynamic_output)
        .decode_next(&mut dynamic_decoded_bytes)
        .unwrap()
    else {
        unreachable!();
    };
    assert_eq!(dynamic_decoded.name(), b"dynamic-name");
    assert_eq!(dynamic_decoded.value(), b"PUT");
}

#[test]
fn hpack_incremental_huffman_insertion_owns_decoded_bytes_and_preserves_suffix() {
    let mut table_bytes = [0; 128];
    let mut table_entries = [HpackDynamicTableEntry::EMPTY; 2];
    let table = HpackDynamicTable::new(&mut table_bytes, &mut table_entries, 95).unwrap();
    let mut name = *b"name";
    let mut value = *b"value";
    let mut destination = [0xaa; 32];
    let mut context = HpackEncoderContext::new(table, 95).unwrap();
    let output_len = {
        let output = context
            .begin_block()
            .encode_literal_with_huffman(
                &mut destination,
                HpackLiteralMode::IncrementalIndexing,
                HpackEncodeLiteralName::Literal(&name),
                &value,
                HpackLiteralHuffman::BOTH,
            )
            .unwrap();
        let output_before = output.to_vec();
        name[0] = b'x';
        value[0] = b'y';
        assert_eq!(name, *b"xame");
        assert_eq!(value, *b"yalue");
        assert_eq!(output, output_before);
        output.len()
    };
    assert!(output_len < destination.len());
    assert!(destination[output_len..].iter().all(|byte| *byte == 0xaa));
    assert_eq!(
        context.dynamic_table().get(1),
        Some(HpackHeaderFieldRef::new(b"name", b"value"))
    );
}

#[test]
fn hpack_oversized_incremental_huffman_literal_clears_nonempty_table() {
    let mut bytes = [0; 128];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let mut table = HpackDynamicTable::new(&mut bytes, &mut entries, 64).unwrap();
    table.insert(b"seed", b"value").unwrap();
    let mut destination = [0xaa; 128];
    let mut context = HpackEncoderContext::new(table, 64).unwrap();
    let output = context
        .begin_block()
        .encode_literal_with_huffman(
            &mut destination,
            HpackLiteralMode::IncrementalIndexing,
            HpackEncodeLiteralName::Literal(b"oversized"),
            b"0123456789012345678901234567890123456789",
            HpackLiteralHuffman::BOTH,
        )
        .unwrap();
    assert!(matches!(
        HpackRepresentation::parse(output),
        Ok(HpackRepresentation::Literal(_))
    ));
    assert!(context.dynamic_table().is_empty());
    assert_eq!(context.dynamic_table().size(), 0);
}

#[test]
fn hpack_huffman_short_destination_preserves_output_and_empty_table_storage() {
    let mut bytes = [0x5a; 128];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let before_bytes = bytes;
    let before_entries = entries;
    let mut destination = [0xaa; 2];
    let before_destination = destination;
    {
        let table = HpackDynamicTable::new(&mut bytes, &mut entries, 95).unwrap();
        let mut context = HpackEncoderContext::new(table, 95).unwrap();
        let mut encoder = context.begin_block();
        assert!(matches!(
            encoder.encode_literal_with_huffman(
                &mut destination,
                HpackLiteralMode::IncrementalIndexing,
                HpackEncodeLiteralName::Literal(b"name"),
                b"value",
                HpackLiteralHuffman::BOTH,
            ),
            Err(HpackEncodeError::Representation(
                HpackRepresentationBuildError::BufferTooShort { .. }
            ))
        ));
        assert!(!encoder.has_emitted_field());
        assert!(!encoder.requires_size_update());
    }
    assert_eq!(destination, before_destination);
    assert_eq!(bytes, before_bytes);
    assert_eq!(entries, before_entries);
}

#[test]
fn hpack_huffman_size_update_requirement_preserves_encoder_and_destination() {
    let mut bytes = [0x5a; 64];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let table = HpackDynamicTable::new(&mut bytes, &mut entries, 64).unwrap();
    let mut context = HpackEncoderContext::new(table, 32).unwrap();
    let mut encoder = context.begin_block();
    let mut destination = [0xaa; 16];
    let before = destination;
    assert_eq!(
        encoder.encode_literal_with_huffman(
            &mut destination,
            HpackLiteralMode::IncrementalIndexing,
            HpackEncodeLiteralName::Literal(b"name"),
            b"value",
            HpackLiteralHuffman::BOTH,
        ),
        Err(HpackEncodeError::DynamicTableSizeUpdateRequired)
    );
    assert_eq!(destination, before);
    assert!(encoder.requires_size_update());
    assert!(!encoder.has_emitted_field());
}

#[test]
fn hpack_huffman_name_strategy_for_indexed_name_preserves_state() {
    let mut bytes = [0x5a; 128];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let before_bytes = bytes;
    let before_entries = entries;
    let mut destination = [0xaa; 16];
    let before_destination = destination;
    {
        let table = HpackDynamicTable::new(&mut bytes, &mut entries, 95).unwrap();
        let mut context = HpackEncoderContext::new(table, 95).unwrap();
        let mut encoder = context.begin_block();
        assert_eq!(
            encoder.encode_literal_with_huffman(
                &mut destination,
                HpackLiteralMode::WithoutIndexing,
                HpackEncodeLiteralName::Indexed {
                    index: 2,
                    decoded: b":method",
                },
                b"GET",
                HpackLiteralHuffman::NAME,
            ),
            Err(HpackEncodeError::HuffmanNameForIndexedName)
        );
        assert!(!encoder.has_emitted_field());
    }
    assert_eq!(destination, before_destination);
    assert_eq!(bytes, before_bytes);
    assert_eq!(entries, before_entries);
}

#[test]
fn hpack_huffman_unavailable_index_preserves_state() {
    let mut bytes = [0x5a; 128];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let before_bytes = bytes;
    let before_entries = entries;
    let mut destination = [0xaa; 16];
    let before_destination = destination;
    {
        let table = HpackDynamicTable::new(&mut bytes, &mut entries, 95).unwrap();
        let mut context = HpackEncoderContext::new(table, 95).unwrap();
        let mut encoder = context.begin_block();
        assert_eq!(
            encoder.encode_literal_with_huffman(
                &mut destination,
                HpackLiteralMode::WithoutIndexing,
                HpackEncodeLiteralName::Indexed {
                    index: 62,
                    decoded: b"missing",
                },
                b"value",
                HpackLiteralHuffman::VALUE,
            ),
            Err(HpackEncodeError::UnavailableIndex { index: 62 })
        );
        assert!(!encoder.has_emitted_field());
    }
    assert_eq!(destination, before_destination);
    assert_eq!(bytes, before_bytes);
    assert_eq!(entries, before_entries);
}

#[test]
fn hpack_huffman_indexed_name_mismatch_preserves_state() {
    let mut bytes = [0x5a; 128];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let before_bytes = bytes;
    let before_entries = entries;
    let mut destination = [0xaa; 16];
    let before_destination = destination;
    {
        let table = HpackDynamicTable::new(&mut bytes, &mut entries, 95).unwrap();
        let mut context = HpackEncoderContext::new(table, 95).unwrap();
        let mut encoder = context.begin_block();
        assert_eq!(
            encoder.encode_literal_with_huffman(
                &mut destination,
                HpackLiteralMode::WithoutIndexing,
                HpackEncodeLiteralName::Indexed {
                    index: 2,
                    decoded: b":path",
                },
                b"value",
                HpackLiteralHuffman::VALUE,
            ),
            Err(HpackEncodeError::IndexedLiteralNameMismatch { index: 2 })
        );
        assert!(!encoder.has_emitted_field());
    }
    assert_eq!(destination, before_destination);
    assert_eq!(bytes, before_bytes);
    assert_eq!(entries, before_entries);
}
