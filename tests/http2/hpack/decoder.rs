use net_wire::http2::hpack::{
    HpackDecodeError, HpackDecodeStep, HpackDecodedFieldMode, HpackDecoderContext,
    HpackDynamicTable, HpackDynamicTableEntry, HpackHeaderFieldRef, HpackHuffmanDecodeError,
    HpackIntegerParseError, HpackRepresentationParseError,
};

#[test]
fn hpack_block_decoder_completes_and_resolves_static_indices() {
    let mut bytes = [0xaa; 64];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let table = HpackDynamicTable::new(&mut bytes, &mut entries, 64).unwrap();
    let mut context = HpackDecoderContext::new(table, 64).unwrap();

    let mut empty = context.decode_block(&[]);
    let mut output = [0xcc; 32];
    assert_eq!(
        empty.decode_next(&mut output),
        Ok(HpackDecodeStep::Complete)
    );
    assert_eq!(empty.remaining(), []);

    let block = [0x81, 0xbd];
    let mut decoder = context.decode_block(&block);
    let HpackDecodeStep::Field(first) = decoder.decode_next(&mut output).unwrap() else {
        panic!("expected indexed field");
    };
    assert_eq!(first.name(), b":authority");
    assert_eq!(first.value(), b"");
    assert!(output[10..].iter().all(|byte| *byte == 0xcc));
    let HpackDecodeStep::Field(last) = decoder.decode_next(&mut output).unwrap() else {
        panic!("expected indexed field");
    };
    assert_eq!(last.name(), b"www-authenticate");
    assert_eq!(last.value(), b"");
    assert_eq!(decoder.remaining(), []);
    let _ = decoder;

    let mut unavailable = context.decode_block(&[0xbe]);
    let before = output;
    assert_eq!(
        unavailable.decode_next(&mut output),
        Err(HpackDecodeError::UnavailableIndex { index: 62 })
    );
    assert_eq!(output, before);
    assert_eq!(unavailable.remaining(), [0xbe]);
}

#[test]
fn hpack_block_decoder_decodes_literals_and_dynamic_indices() {
    let mut bytes = [0; 80];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let table = HpackDynamicTable::new(&mut bytes, &mut entries, 70).unwrap();
    let block = [
        0x42, 0x01, b'a', 0x40, 0x01, b'b', 0x01, b'c', 0x00, 0x88, 0x25, 0xa8, 0x49, 0xe9, 0x5b,
        0xa9, 0x7d, 0x7f, 0x89, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf,
    ];
    let mut context = HpackDecoderContext::new(table, 70).unwrap();
    let mut decoder = context.decode_block(&block);
    let mut output = [0xcc; 32];
    for (name, value, mode) in [
        (
            b":method" as &[u8],
            b"a" as &[u8],
            HpackDecodedFieldMode::IncrementalIndexing,
        ),
        (
            b"b" as &[u8],
            b"c" as &[u8],
            HpackDecodedFieldMode::IncrementalIndexing,
        ),
        (
            b"custom-key" as &[u8],
            b"custom-value" as &[u8],
            HpackDecodedFieldMode::WithoutIndexing,
        ),
    ] {
        let HpackDecodeStep::Field(field) = decoder.decode_next(&mut output).unwrap() else {
            panic!("expected literal field");
        };
        assert_eq!(field.name(), name);
        assert_eq!(field.value(), value);
        assert_eq!(field.mode(), mode);
    }
    let _ = decoder;
    assert_eq!(
        context.dynamic_table().get(1),
        Some(HpackHeaderFieldRef::new(b"b", b"c"))
    );
    assert_eq!(context.dynamic_table().get(2), None);

    let mut indexed = context.decode_block(&[0xbe]);
    let HpackDecodeStep::Field(field) = indexed.decode_next(&mut output).unwrap() else {
        panic!("expected dynamic indexed field");
    };
    assert_eq!(field.name(), b"b");
    assert_eq!(field.value(), b"c");
    let _ = indexed;

    let mut never = context.decode_block(&[0x10, 0x01, b'n', 0x01, b'v']);
    assert!(matches!(
        never.decode_next(&mut output),
        Ok(HpackDecodeStep::Field(_))
    ));
    let _ = never;
    assert_eq!(context.dynamic_table().len(), 1);
}

#[test]
fn hpack_block_decoder_applies_only_leading_size_updates() {
    let mut bytes = [0; 64];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let table = HpackDynamicTable::new(&mut bytes, &mut entries, 33).unwrap();
    let mut context = HpackDecoderContext::new(table, 33).unwrap();
    let mut decoder = context.decode_block(&[0x3f, 0x01, 0x3f, 0x02]);
    let mut output = [];
    assert_eq!(
        decoder.decode_next(&mut output),
        Ok(HpackDecodeStep::DynamicTableSizeUpdate { maximum_size: 32 })
    );
    assert_eq!(
        decoder.decode_next(&mut output),
        Ok(HpackDecodeStep::DynamicTableSizeUpdate { maximum_size: 33 })
    );
    let _ = decoder;
    assert_eq!(context.dynamic_table().maximum_size(), 33);

    let mut after_field = context.decode_block(&[0x00, 0x00, 0x00, 0x20]);
    let mut field_output = [0; 1];
    assert!(matches!(
        after_field.decode_next(&mut field_output),
        Ok(HpackDecodeStep::Field(_))
    ));
    assert_eq!(
        after_field.decode_next(&mut field_output),
        Err(HpackDecodeError::DynamicTableSizeUpdateAfterField)
    );
    assert_eq!(after_field.remaining(), [0x20]);
    let _ = after_field;
    assert_eq!(context.dynamic_table().maximum_size(), 33);
    let mut table = context.into_dynamic_table();
    table.set_maximum_size(32).unwrap();
    let mut context = HpackDecoderContext::new(table, 32).unwrap();

    let mut above = context.decode_block(&[0x3f, 0x02]);
    assert_eq!(
        above.decode_next(&mut output),
        Err(HpackDecodeError::DynamicTableSizeUpdateExceedsAllowed {
            requested: 33,
            allowed: 32,
        })
    );
    assert_eq!(above.remaining(), [0x3f, 0x02]);
}

#[test]
fn hpack_block_decoder_requires_leading_size_update_after_policy_reduction() {
    let mut bytes = [0xaa; 64];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let table = HpackDynamicTable::new(&mut bytes, &mut entries, 64).unwrap();
    let mut context = HpackDecoderContext::new(table, 63).unwrap();
    let mut output = [0xcc; 32];

    let mut field_first = context.decode_block(&[0x81]);
    let before_output = output;
    assert_eq!(
        field_first.decode_next(&mut output),
        Err(HpackDecodeError::DynamicTableSizeUpdateRequired)
    );
    assert_eq!(field_first.remaining(), [0x81]);
    assert_eq!(output, before_output);
    let _ = field_first;
    assert_eq!(context.dynamic_table().maximum_size(), 64);

    let mut empty = context.decode_block(&[]);
    assert_eq!(
        empty.decode_next(&mut output),
        Err(HpackDecodeError::DynamicTableSizeUpdateRequired)
    );
    assert!(empty.is_complete());
    let _ = empty;

    let mut above = context.decode_block(&[0x3f, 0x21]);
    assert_eq!(
        above.decode_next(&mut output),
        Err(HpackDecodeError::DynamicTableSizeUpdateMismatch {
            expected: 63,
            requested: 64,
        })
    );
    assert_eq!(above.remaining(), [0x3f, 0x21]);
    assert_eq!(output, before_output);
    let _ = above;
    assert_eq!(context.dynamic_table().maximum_size(), 64);

    let mut decoder = context.decode_block(&[0x3f, 0x20, 0x81]);
    assert_eq!(
        decoder.decode_next(&mut output),
        Ok(HpackDecodeStep::DynamicTableSizeUpdate { maximum_size: 63 })
    );
    let HpackDecodeStep::Field(field) = decoder.decode_next(&mut output).unwrap() else {
        panic!("expected indexed field");
    };
    assert_eq!(field.name(), b":authority");
    assert_eq!(context.dynamic_table().maximum_size(), 63);
}

#[test]
fn hpack_block_decoder_failures_preserve_caller_stores_and_output() {
    let mut bytes = [0x5a; 80];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let mut table = HpackDynamicTable::new(&mut bytes, &mut entries, 70).unwrap();
    table.insert(b"old", b"entry").unwrap();
    let mut context = HpackDecoderContext::new(table, 70).unwrap();

    for (block, expected) in [
        (
            &[0xff][..],
            HpackDecodeError::Representation(HpackRepresentationParseError::IndexedIndex(
                HpackIntegerParseError::Incomplete {
                    required: 2,
                    available: 1,
                },
            )),
        ),
        (
            &[0x00, 0x81, 0x00, 0x00][..],
            HpackDecodeError::HuffmanName(HpackHuffmanDecodeError::InvalidPadding),
        ),
        (
            &[0x00, 0x01, b'n', 0x81, 0x00][..],
            HpackDecodeError::HuffmanValue(HpackHuffmanDecodeError::InvalidPadding),
        ),
        (
            &[0x0f, 0x30, 0x00][..],
            HpackDecodeError::UnavailableIndex { index: 63 },
        ),
    ] {
        let mut decoder = context.decode_block(block);
        let mut output = [0xcc; 8];
        let before_output = output;
        assert_eq!(decoder.decode_next(&mut output), Err(expected));
        assert_eq!(output, before_output);
        assert_eq!(decoder.remaining(), block);
        let _ = decoder;
        assert_eq!(
            context.dynamic_table().get(1),
            Some(HpackHeaderFieldRef::new(b"old", b"entry"))
        );
    }
    let mut short = context.decode_block(&[0x40, 0x01, b'n', 0x01, b'v']);
    let mut output = [0xcc; 1];
    assert_eq!(
        short.decode_next(&mut output),
        Err(HpackDecodeError::OutputTooShort {
            required: 2,
            available: 1,
        })
    );
    let _ = short;
    assert_eq!(
        context.dynamic_table().get(1),
        Some(HpackHeaderFieldRef::new(b"old", b"entry"))
    );

    let table = context.into_dynamic_table();
    assert!(matches!(
        HpackDecoderContext::new(table, 96),
        Err(HpackDecodeError::AllowedMaximumExceedsCapacity { .. })
    ));
    let _ = table;

    let mut empty_bytes = [0x3c; 64];
    let mut empty_entries = [HpackDynamicTableEntry::EMPTY; 2];
    let before_bytes = empty_bytes;
    let before_entries = empty_entries;
    {
        let empty_table = HpackDynamicTable::new(&mut empty_bytes, &mut empty_entries, 64).unwrap();
        let mut context = HpackDecoderContext::new(empty_table, 64).unwrap();
        let mut decoder = context.decode_block(&[0x40, 0x01, b'n', 0x01, b'v']);
        let mut short_output = [0xcc; 1];
        assert!(matches!(
            decoder.decode_next(&mut short_output),
            Err(HpackDecodeError::OutputTooShort { .. })
        ));
    }
    assert_eq!(empty_bytes, before_bytes);
    assert_eq!(empty_entries, before_entries);
}

#[test]
fn hpack_block_decoder_oversized_incremental_field_clears_and_emits() {
    let mut bytes = [0; 64];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let mut table = HpackDynamicTable::new(&mut bytes, &mut entries, 34).unwrap();
    table.insert(b"a", b"b").unwrap();
    let mut context = HpackDecoderContext::new(table, 34).unwrap();
    let mut decoder = context.decode_block(&[0x40, 0x03, b'n', b'a', b'm', 0x00]);
    let mut output = [0xcc; 8];
    let HpackDecodeStep::Field(field) = decoder.decode_next(&mut output).unwrap() else {
        panic!("expected oversized literal field");
    };
    assert_eq!(field.name(), b"nam");
    assert_eq!(field.value(), b"");
    let _ = decoder;
    assert!(context.dynamic_table().is_empty());
}

#[test]
fn hpack_decoder_two_pending_size_updates_are_atomic_and_complete() {
    let mut bytes = [0; 128];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 4];
    let mut table = HpackDynamicTable::new(&mut bytes, &mut entries, 64).unwrap();
    table.insert(b"a", b"b").unwrap();
    let mut context = HpackDecoderContext::new(table, 64).unwrap();
    context.set_allowed_maximum_size(32).unwrap();
    context.set_allowed_maximum_size(64).unwrap();
    let mut output = [0xcc; 16];
    let before_output = output;

    {
        let mut empty = context.decode_block(&[]);
        assert_eq!(
            empty.decode_next(&mut output),
            Err(HpackDecodeError::DynamicTableSizeUpdateRequired)
        );
    }
    {
        let mut field_first = context.decode_block(&[0x81]);
        assert_eq!(
            field_first.decode_next(&mut output),
            Err(HpackDecodeError::DynamicTableSizeUpdateRequired)
        );
        assert_eq!(field_first.remaining(), [0x81]);
    }
    {
        let mut wrong = context.decode_block(&[0x3f, 0x21]);
        assert_eq!(
            wrong.decode_next(&mut output),
            Err(HpackDecodeError::DynamicTableSizeUpdateMismatch {
                expected: 32,
                requested: 64,
            })
        );
        assert_eq!(wrong.remaining(), [0x3f, 0x21]);
    }
    assert_eq!(output, before_output);
    assert_eq!(context.next_required_size_update(), Some(32));
    assert_eq!(context.dynamic_table().maximum_size(), 64);
    assert_eq!(
        context.dynamic_table().get(1),
        Some(HpackHeaderFieldRef::new(b"a", b"b"))
    );

    let mut decoder = context.decode_block(&[0x3f, 0x01, 0x3f, 0x21, 0x81]);
    assert_eq!(
        decoder.decode_next(&mut output),
        Ok(HpackDecodeStep::DynamicTableSizeUpdate { maximum_size: 32 })
    );
    assert_eq!(
        decoder.decode_next(&mut output),
        Ok(HpackDecodeStep::DynamicTableSizeUpdate { maximum_size: 64 })
    );
    let HpackDecodeStep::Field(field) = decoder.decode_next(&mut output).unwrap() else {
        panic!("expected static indexed field");
    };
    assert_eq!(field.name(), b":authority");
    assert_eq!(field.value(), b"");
    assert_eq!(output[10..], [0xcc; 6]);
    assert_eq!(
        decoder.decode_next(&mut output),
        Ok(HpackDecodeStep::Complete)
    );
    let _ = decoder;

    assert_eq!(context.next_required_size_update(), None);
    assert_eq!(context.dynamic_table().maximum_size(), 64);
    assert!(context.dynamic_table().is_empty());
    assert_eq!(
        context.decode_block(&[]).decode_next(&mut output),
        Ok(HpackDecodeStep::Complete)
    );
}
