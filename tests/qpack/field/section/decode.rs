use net_wire::qpack::{
    QpackDecodedFieldEntry, QpackDecodedFieldRef, QpackDynamicTable, QpackDynamicTableEntry,
    QpackDynamicTableError, QpackEncoderInstruction, QpackEncoderInstructionApplier,
    QpackEncoderInstructionApplyOutcome, QpackFieldLineParseError, QpackFieldSectionContext,
    QpackFieldSectionDecodeError, QpackFieldSectionDecodeOutcome, QpackFieldSectionDecoder,
    QpackFieldSectionOutput, QpackFieldSectionPrefixBuilder, QpackFieldSectionPrefixParseError,
    QpackHuffmanDecodeError, QpackIndexedFieldLineBuilder, QpackIndexedPostBaseFieldLineBuilder,
    QpackIntegerParseError, QpackLiteralNameFieldLineBuilder,
    QpackLiteralNameReferenceFieldLineBuilder, QpackLiteralPostBaseNameReferenceFieldLineBuilder,
};

#[test]
fn qpack_field_section_decoder_all_forms_order_and_flags_are_exact() {
    let mut storage = [0; 104];
    let mut table_entries = [QpackDynamicTableEntry::EMPTY; 4];
    let mut table = QpackDynamicTable::new(&mut storage, &mut table_entries);
    assert_eq!(table.set_capacity(136, |_| true), Ok(()));
    for (name, value, absolute) in [
        (b"a" as &[u8], b"0" as &[u8], 0),
        (b"b", b"1", 1),
        (b"c", b"2", 2),
        (b"d", b"3", 3),
    ] {
        assert_eq!(table.insert(name, value, |_| true), Ok(absolute));
    }
    let maximum = 160;
    let encoded_ric =
        QpackFieldSectionContext::encode_required_insert_count(4, maximum).expect("RIC");
    let mut prefix = [0xaa; 4];
    let mut indexed_static = [0xaa; 2];
    let mut indexed_pre_base = [0xaa; 2];
    let mut literal_static = [0xaa; 4];
    let mut literal_post_base = [0xaa; 4];
    let mut literal_name = [0xaa; 5];
    let mut indexed_post_base = [0xaa; 2];
    let mut section = [0xaa; 32];
    let mut offset = 0;
    for bytes in [
        QpackFieldSectionPrefixBuilder::new(&mut prefix, encoded_ric, true, 1)
            .build()
            .expect("prefix")
            .as_bytes(),
        QpackIndexedFieldLineBuilder::new(&mut indexed_static, true, 17)
            .build()
            .expect("static")
            .as_bytes(),
        QpackIndexedFieldLineBuilder::new(&mut indexed_pre_base, false, 0)
            .build()
            .expect("pre-base")
            .as_bytes(),
        QpackLiteralNameReferenceFieldLineBuilder::new(
            &mut literal_static,
            true,
            true,
            0,
            false,
            b"x",
        )
        .build()
        .expect("static name")
        .as_bytes(),
        QpackLiteralPostBaseNameReferenceFieldLineBuilder::new(
            &mut literal_post_base,
            true,
            0,
            false,
            b"y",
        )
        .build()
        .expect("post-base name")
        .as_bytes(),
        QpackLiteralNameFieldLineBuilder::new(&mut literal_name, true, false, b"n", false, b"v")
            .build()
            .expect("literal")
            .as_bytes(),
        QpackIndexedPostBaseFieldLineBuilder::new(&mut indexed_post_base, 1)
            .build()
            .expect("post-base")
            .as_bytes(),
    ] {
        section[offset..offset + bytes.len()].copy_from_slice(bytes);
        offset += bytes.len();
    }
    let mut output_bytes = [0xaa; 30];
    let mut output_entries = [QpackDecodedFieldEntry::EMPTY; 7];
    {
        let mut output = QpackFieldSectionOutput::new(&mut output_bytes, &mut output_entries);
        let decoded = match QpackFieldSectionDecoder::new(maximum)
            .decode(&section[..offset], &table, &mut output)
            .expect("decode")
        {
            QpackFieldSectionDecodeOutcome::Decoded(decoded) => decoded,
            QpackFieldSectionDecodeOutcome::Blocked(_) => panic!("complete table"),
        };
        assert_eq!(
            (
                decoded.required_insert_count(),
                decoded.base(),
                decoded.len()
            ),
            (4, 2, 6)
        );
        assert!(decoded.contains_dynamic_references());
        for (index, name, value, never_indexed) in [
            (0, b":method" as &[u8], b"GET" as &[u8], false),
            (1, b"b", b"1", false),
            (2, b":authority", b"x", true),
            (3, b"c", b"y", true),
            (4, b"n", b"v", true),
            (5, b"d", b"3", false),
        ] {
            let field = decoded.get(index).expect("field");
            assert_eq!(
                (field.name(), field.value(), field.never_indexed()),
                (name, value, never_indexed)
            );
        }
        assert_eq!(decoded.get(6), None);
        let mut iter = decoded.iter();
        assert_eq!((iter.len(), iter.size_hint()), (6, (6, Some(6))));
        assert_eq!(
            iter.next().map(QpackDecodedFieldRef::name),
            Some(b":method" as &[u8])
        );
        assert_eq!(iter.by_ref().count(), 5);
        assert_eq!(iter.next(), None);
        assert_eq!(output.len(), 6);
    }
    assert_eq!(output_bytes[29], 0xaa);
    assert_eq!(output_entries[6], QpackDecodedFieldEntry::EMPTY);
}

#[test]
fn qpack_field_section_decoder_huffman_empty_and_output_capacity_are_atomic() {
    let key = [0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f];
    let value = [0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf];
    let mut line = [0xaa; 20];
    let line = QpackLiteralNameFieldLineBuilder::new(&mut line, true, true, &key, true, &value)
        .build()
        .expect("Huffman")
        .as_bytes();
    let mut section = [0; 22];
    section[..2].copy_from_slice(&[0, 0]);
    section[2..].copy_from_slice(line);
    let mut storage = [];
    let mut table_entries = [];
    let table = QpackDynamicTable::new(&mut storage, &mut table_entries);
    let decoder = QpackFieldSectionDecoder::new(128);
    let mut exact_bytes = [0xaa; 22];
    let mut exact_entries = [QpackDecodedFieldEntry::EMPTY; 1];
    {
        let mut output = QpackFieldSectionOutput::new(&mut exact_bytes, &mut exact_entries);
        let decoded = match decoder
            .decode(&section, &table, &mut output)
            .expect("exact")
        {
            QpackFieldSectionDecodeOutcome::Decoded(decoded) => decoded,
            _ => panic!("RIC zero"),
        };
        let field = decoded.get(0).expect("field");
        assert_eq!(
            (
                decoded.required_insert_count(),
                decoded.base(),
                field.name(),
                field.value(),
                field.never_indexed()
            ),
            (0, 0, b"custom-key" as &[u8], b"custom-value" as &[u8], true)
        );
    }
    for (byte_len, field_len, expected) in [
        (
            21,
            1,
            QpackFieldSectionDecodeError::OutputBytesTooShort {
                required: 22,
                available: 21,
            },
        ),
        (
            22,
            0,
            QpackFieldSectionDecodeError::OutputFieldsTooShort {
                required: 1,
                available: 0,
            },
        ),
    ] {
        let mut bytes = [0xaa; 22];
        let mut fields = [QpackDecodedFieldEntry::EMPTY; 1];
        let before_bytes = bytes;
        let before_fields = fields;
        let error = {
            let mut output =
                QpackFieldSectionOutput::new(&mut bytes[..byte_len], &mut fields[..field_len]);
            decoder
                .decode(&section, &table, &mut output)
                .expect_err("short")
        };
        assert_eq!(error, expected);
        assert!(error.is_output_provisioning_error());
        assert!(!error.is_decompression_failed());
        assert_eq!((bytes, fields), (before_bytes, before_fields));
    }
    let mut empty_bytes = [];
    let mut empty_fields = [];
    let mut empty = QpackFieldSectionOutput::new(&mut empty_bytes, &mut empty_fields);
    assert!(
        matches!(decoder.decode(&[0, 0], &table, &mut empty), Ok(QpackFieldSectionDecodeOutcome::Decoded(decoded)) if decoded.is_empty() && decoded.required_insert_count() == 0 && decoded.base() == 0)
    );
    assert_eq!(empty.len(), 0);
}

#[test]
fn qpack_field_section_decoder_errors_are_exact_and_transactional() {
    let mut storage = [0; 36];
    let mut table_entries = [QpackDynamicTableEntry::EMPTY; 2];
    let mut table = QpackDynamicTable::new(&mut storage, &mut table_entries);
    assert_eq!(table.set_capacity(68, |_| true), Ok(()));
    assert_eq!(table.insert(b"a", b"0", |_| true), Ok(0));
    assert_eq!(table.insert(b"b", b"1", |_| true), Ok(1));
    assert_eq!(table.set_capacity(34, |_| true), Ok(()));
    let decoder = QpackFieldSectionDecoder::new(128);
    let mut bytes = [0xaa; 16];
    let mut fields = [QpackDecodedFieldEntry::EMPTY; 2];
    let before_bytes = bytes;
    let before_fields = fields;
    {
        let mut output = QpackFieldSectionOutput::new(&mut bytes, &mut fields);
        for encoded in [
            &[0][..],
            &[0, 0, 0x40],
            &[0, 0, 0xff, 0x24],
            &[2, 0x80, 0x80],
            &[3, 0, 0x10],
            &[3, 0, 0x81],
            &[0, 0, 0x2c, 0xff, 0xff, 0xff, 0xff, 0],
            &[0, 0, 0x21, b'n', 0x84, 0xff, 0xff, 0xff, 0xff],
        ] {
            let error = decoder
                .decode(encoded, &table, &mut output)
                .expect_err("semantic error");
            assert!(error.is_decompression_failed());
            assert!(!error.is_output_provisioning_error());
        }
        assert_eq!(
            decoder.decode(&[0], &table, &mut output),
            Err(QpackFieldSectionDecodeError::Prefix(
                QpackFieldSectionPrefixParseError::DeltaBase(QpackIntegerParseError::Incomplete {
                    required: 1,
                    available: 0
                })
            ))
        );
        assert!(
            matches!(decoder.decode(&[0, 0, 0x40], &table, &mut output), Err(QpackFieldSectionDecodeError::FieldLines(error)) if error.offset() == 0 && matches!(error.error(), QpackFieldLineParseError::LiteralNameReferenceValue(_)))
        );
        assert_eq!(
            decoder.decode(&[0, 0, 0xff, 0x24], &table, &mut output),
            Err(QpackFieldSectionDecodeError::StaticIndexOutOfRange { index: 99 })
        );
        assert_eq!(
            decoder.decode(&[2, 0x80, 0x80], &table, &mut output),
            Err(QpackFieldSectionDecodeError::DynamicReference(
                QpackDynamicTableError::FieldRelativeIndexUnderflow { base: 0, index: 0 }
            ))
        );
        assert_eq!(
            decoder.decode(&[3, 0, 0x10], &table, &mut output),
            Err(QpackFieldSectionDecodeError::DynamicReference(
                QpackDynamicTableError::ReferenceAtOrAfterRequiredInsertCount {
                    requested: 2,
                    required_insert_count: 2
                }
            ))
        );
        assert_eq!(
            decoder.decode(&[3, 0, 0x81], &table, &mut output),
            Err(QpackFieldSectionDecodeError::DynamicReference(
                QpackDynamicTableError::EvictedAbsoluteIndex {
                    requested: 0,
                    oldest_available: 1
                }
            ))
        );
        assert_eq!(
            decoder.decode(
                &[0, 0, 0x2c, 0xff, 0xff, 0xff, 0xff, 0],
                &table,
                &mut output
            ),
            Err(QpackFieldSectionDecodeError::LiteralNameHuffman(
                QpackHuffmanDecodeError::EosSymbol
            ))
        );
        assert_eq!(
            decoder.decode(
                &[0, 0, 0x21, b'n', 0x84, 0xff, 0xff, 0xff, 0xff],
                &table,
                &mut output
            ),
            Err(QpackFieldSectionDecodeError::ValueHuffman(
                QpackHuffmanDecodeError::EosSymbol
            ))
        );
        assert_eq!(output.len(), 0);
    }
    assert_eq!((bytes, fields), (before_bytes, before_fields));
}

#[test]
fn qpack_field_section_decoder_blocked_retry_is_exact_and_non_mutating() {
    let mut storage = [0; 36];
    let mut table_entries = [QpackDynamicTableEntry::EMPTY; 2];
    let mut table = QpackDynamicTable::new(&mut storage, &mut table_entries);
    assert_eq!(table.set_capacity(68, |_| true), Ok(()));
    let decoder = QpackFieldSectionDecoder::new(128);
    let section = [2, 0, 0x80];
    let mut bytes = [0xaa; 16];
    let mut fields = [QpackDecodedFieldEntry::EMPTY; 2];
    let mut output = QpackFieldSectionOutput::new(&mut bytes, &mut fields);
    assert!(
        matches!(decoder.decode(&section, &table, &mut output), Ok(QpackFieldSectionDecodeOutcome::Blocked(blocked)) if blocked.required_insert_count() == 1 && blocked.base() == 1)
    );
    assert_eq!(output.len(), 0);
    let instruction = QpackEncoderInstruction::parse(&[0xc0, 1, b'x']).expect("insert");
    let mut scratch = [0xaa; 1];
    assert_eq!(
        QpackEncoderInstructionApplier::new(128).apply(
            &mut table,
            instruction,
            &mut scratch,
            |_| true
        ),
        Ok(QpackEncoderInstructionApplyOutcome::Inserted { absolute_index: 0 })
    );
    match decoder
        .decode(&section, &table, &mut output)
        .expect("retry")
    {
        QpackFieldSectionDecodeOutcome::Decoded(decoded) => {
            let field = decoded.get(0).expect("field");
            assert_eq!(
                (
                    decoded.required_insert_count(),
                    decoded.base(),
                    field.name(),
                    field.value()
                ),
                (1, 1, b":authority" as &[u8], b"x" as &[u8])
            );
        }
        QpackFieldSectionDecodeOutcome::Blocked(_) => panic!("unblocked"),
    }
}
