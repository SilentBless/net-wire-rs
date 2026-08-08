use net_wire::qpack;
use net_wire::qpack::{
    QpackDynamicTable, QpackDynamicTableEntry, QpackDynamicTableError, QpackEncoderInstruction,
    QpackEncoderInstructionApplier, QpackEncoderInstructionApplyError,
    QpackEncoderInstructionApplyOutcome, QpackEncoderInstructionParseError,
    QpackEncoderInstructionsApplyError, QpackEncoderInstructionsParseError,
    QpackHuffmanDecodeError, QpackInsertWithLiteralNameBuilder,
    QpackInsertWithNameReferenceBuilder, QpackIntegerParseError, QpackStringLiteralParseError,
};

#[test]
fn qpack_encoder_stream_applies_rfc9204_appendix_b_exactly() {
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
    let mut storage = [0; 256];
    let mut entries = [QpackDynamicTableEntry::EMPTY; 8];
    let mut table = QpackDynamicTable::new(&mut storage, &mut entries);
    let applier = QpackEncoderInstructionApplier::new(220);
    let mut scratch = [0xaa; 64];

    for (wire, expected) in [
        (
            &capacity[..],
            QpackEncoderInstructionApplyOutcome::CapacityUpdated { capacity: 220 },
        ),
        (
            &static_authority[..],
            QpackEncoderInstructionApplyOutcome::Inserted { absolute_index: 0 },
        ),
        (
            &static_path[..],
            QpackEncoderInstructionApplyOutcome::Inserted { absolute_index: 1 },
        ),
        (
            &literal[..],
            QpackEncoderInstructionApplyOutcome::Inserted { absolute_index: 2 },
        ),
        (
            &duplicate[..],
            QpackEncoderInstructionApplyOutcome::Inserted { absolute_index: 3 },
        ),
        (
            &dynamic[..],
            QpackEncoderInstructionApplyOutcome::Inserted { absolute_index: 4 },
        ),
    ] {
        let instruction = QpackEncoderInstruction::parse(wire).expect("RFC Appendix B instruction");
        assert_eq!(
            applier.apply(&mut table, instruction, &mut scratch, |_| true),
            Ok(expected)
        );
    }

    assert_eq!(
        (
            table.insert_count(),
            table.size(),
            table.len(),
            table.capacity()
        ),
        (5, 215, 4, 220)
    );
    assert_eq!(
        table.get_absolute(0),
        Err(QpackDynamicTableError::EvictedAbsoluteIndex {
            requested: 0,
            oldest_available: 1,
        })
    );
    for (absolute, name, value) in [
        (1, b":path" as &[u8], b"/sample/path" as &[u8]),
        (2, b"custom-key" as &[u8], b"custom-value" as &[u8]),
        (3, b":authority" as &[u8], b"www.example.com" as &[u8]),
        (4, b"custom-key" as &[u8], b"custom-value2" as &[u8]),
    ] {
        assert_eq!(
            table
                .get_absolute(absolute)
                .map(|field| (field.name(), field.value())),
            Ok((name, value))
        );
    }
}

#[test]
fn qpack_encoder_stream_huffman_staging_is_decoded_and_exact() {
    let custom_key = [0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f];
    let custom_value = [0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf];
    let mut wire = [0; 19];
    let instruction = {
        let view = QpackInsertWithLiteralNameBuilder::new(
            &mut wire,
            true,
            &custom_key,
            true,
            &custom_value,
        )
        .build()
        .expect("literal instruction capacity");
        QpackEncoderInstruction::parse(view.as_bytes()).expect("literal instruction")
    };
    let mut storage = [0; 68];
    let mut entries = [QpackDynamicTableEntry::EMPTY; 3];
    let mut table = QpackDynamicTable::new(&mut storage, &mut entries);
    assert_eq!(table.set_capacity(100, |_| true), Ok(()));
    let applier = QpackEncoderInstructionApplier::new(100);
    let mut scratch = [0xaa; 23];

    assert_eq!(
        applier.apply(&mut table, instruction, &mut scratch, |_| true),
        Ok(QpackEncoderInstructionApplyOutcome::Inserted { absolute_index: 0 })
    );
    assert_eq!(
        table
            .get_absolute(0)
            .map(|field| (field.name(), field.value())),
        Ok((b"custom-key" as &[u8], b"custom-value" as &[u8]))
    );
    assert_eq!(table.size(), 54);
    assert_eq!(&scratch[..22], b"custom-keycustom-value");
    assert_eq!(scratch[22], 0xaa);
}

#[test]
fn qpack_encoder_stream_dynamic_sources_survive_self_eviction() {
    let mut name_storage = [0; 7];
    let mut name_entries = [QpackDynamicTableEntry::EMPTY; 1];
    let mut name_table = QpackDynamicTable::new(&mut name_storage, &mut name_entries);
    assert_eq!(name_table.set_capacity(39, |_| true), Ok(()));
    assert_eq!(name_table.insert(b"name", b"old", |_| true), Ok(0));
    let mut name_wire = [0; 5];
    let name_instruction = {
        let view =
            QpackInsertWithNameReferenceBuilder::new(&mut name_wire, false, 0, false, b"new")
                .build()
                .expect("dynamic name instruction capacity");
        QpackEncoderInstruction::parse(view.as_bytes()).expect("dynamic name instruction")
    };
    let mut name_scratch = [0xaa; 4];
    let applier = QpackEncoderInstructionApplier::new(39);
    assert_eq!(
        applier.apply(&mut name_table, name_instruction, &mut name_scratch, |_| {
            true
        }),
        Ok(QpackEncoderInstructionApplyOutcome::Inserted { absolute_index: 1 })
    );
    assert_eq!(
        name_table.get_absolute(0),
        Err(QpackDynamicTableError::EvictedAbsoluteIndex {
            requested: 0,
            oldest_available: 1,
        })
    );
    assert_eq!(
        name_table
            .get_absolute(1)
            .map(|field| (field.name(), field.value())),
        Ok((b"name" as &[u8], b"new" as &[u8]))
    );

    let mut duplicate_storage = [0; 2];
    let mut duplicate_entries = [QpackDynamicTableEntry::EMPTY; 1];
    let mut duplicate_table =
        QpackDynamicTable::new(&mut duplicate_storage, &mut duplicate_entries);
    assert_eq!(duplicate_table.set_capacity(34, |_| true), Ok(()));
    assert_eq!(duplicate_table.insert(b"a", b"b", |_| true), Ok(0));
    let duplicate = QpackEncoderInstruction::parse(&[0]).expect("Duplicate instruction");
    let mut duplicate_scratch = [0xaa; 2];
    let before = (
        duplicate_table.capacity(),
        duplicate_table.size(),
        duplicate_table.len(),
        duplicate_table.insert_count(),
    );
    assert_eq!(
        applier.apply(
            &mut duplicate_table,
            duplicate,
            &mut duplicate_scratch,
            |_| false
        ),
        Err(QpackEncoderInstructionApplyError::Insert(
            QpackDynamicTableError::EvictionBlocked { absolute_index: 0 }
        ))
    );
    assert!(
        QpackEncoderInstructionApplyError::Insert(QpackDynamicTableError::EvictionBlocked {
            absolute_index: 0
        })
        .is_encoder_stream_error()
    );
    assert_eq!(
        (
            duplicate_table.capacity(),
            duplicate_table.size(),
            duplicate_table.len(),
            duplicate_table.insert_count(),
        ),
        before
    );
    assert_eq!(&duplicate_scratch, b"ab");
    assert_eq!(
        applier.apply(
            &mut duplicate_table,
            duplicate,
            &mut duplicate_scratch,
            |_| true
        ),
        Ok(QpackEncoderInstructionApplyOutcome::Inserted { absolute_index: 1 })
    );
    assert_eq!(
        duplicate_table.get_absolute(0),
        Err(QpackDynamicTableError::EvictedAbsoluteIndex {
            requested: 0,
            oldest_available: 1,
        })
    );
    assert_eq!(
        duplicate_table
            .get_absolute(1)
            .map(|field| (field.name(), field.value())),
        Ok((b"a" as &[u8], b"b" as &[u8]))
    );
}

#[test]
fn qpack_encoder_stream_failures_classification_and_atomicity_are_exact() {
    assert_eq!(
        QpackEncoderInstructionApplier::new(100).maximum_dynamic_table_capacity(),
        100
    );

    let mut capacity_storage = [];
    let mut capacity_entries = [QpackDynamicTableEntry::EMPTY; 1];
    let mut capacity_table = QpackDynamicTable::new(&mut capacity_storage, &mut capacity_entries);
    let mut capacity_scratch = [0xaa; 2];
    let capacity_instruction =
        QpackEncoderInstruction::parse(&[0x3f, 0x46]).expect("capacity instruction");
    assert_eq!(
        QpackEncoderInstructionApplier::new(100).apply(
            &mut capacity_table,
            capacity_instruction,
            &mut capacity_scratch,
            |_| true,
        ),
        Err(QpackEncoderInstructionApplyError::CapacityExceedsMaximum {
            requested: 101,
            maximum: 100,
        })
    );
    assert!(
        QpackEncoderInstructionApplyError::CapacityExceedsMaximum {
            requested: 101,
            maximum: 100,
        }
        .is_encoder_stream_error()
    );
    assert_eq!(
        (
            capacity_table.capacity(),
            capacity_table.size(),
            capacity_table.len(),
            capacity_table.insert_count(),
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(capacity_scratch, [0xaa; 2]);

    let mut physical_storage = [];
    let mut physical_entries = [QpackDynamicTableEntry::EMPTY; 1];
    let mut physical_table = QpackDynamicTable::new(&mut physical_storage, &mut physical_entries);
    let physical_capacity = physical_table.storage_capacity();
    let mut physical_scratch = [0xaa; 2];
    let capacity_220 =
        QpackEncoderInstruction::parse(&[0x3f, 0xbd, 0x01]).expect("capacity instruction");
    assert_eq!(
        QpackEncoderInstructionApplier::new(220).apply(
            &mut physical_table,
            capacity_220,
            &mut physical_scratch,
            |_| true,
        ),
        Err(QpackEncoderInstructionApplyError::CapacityChange(
            QpackDynamicTableError::CapacityExceedsStorage {
                requested: 220,
                capacity: physical_capacity,
            }
        ))
    );
    assert!(
        !QpackEncoderInstructionApplyError::CapacityChange(
            QpackDynamicTableError::CapacityExceedsStorage {
                requested: 220,
                capacity: physical_capacity,
            }
        )
        .is_encoder_stream_error()
    );
    assert_eq!(
        (
            physical_table.capacity(),
            physical_table.size(),
            physical_table.len(),
            physical_table.insert_count(),
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(physical_scratch, [0xaa; 2]);

    let mut small_storage = [];
    let mut small_entries = [QpackDynamicTableEntry::EMPTY; 1];
    let mut small_table = QpackDynamicTable::new(&mut small_storage, &mut small_entries);
    assert_eq!(small_table.set_capacity(32, |_| true), Ok(()));
    let mut small_scratch = [0xaa; 2];
    let empty_authority =
        QpackEncoderInstruction::parse(&[0xc0, 0]).expect("authority instruction");
    assert_eq!(
        QpackEncoderInstructionApplier::new(100).apply(
            &mut small_table,
            empty_authority,
            &mut small_scratch,
            |_| true,
        ),
        Err(QpackEncoderInstructionApplyError::Insert(
            QpackDynamicTableError::EntryLargerThanCapacity {
                entry_size: 42,
                capacity: 32,
            }
        ))
    );
    assert!(
        QpackEncoderInstructionApplyError::Insert(
            QpackDynamicTableError::EntryLargerThanCapacity {
                entry_size: 42,
                capacity: 32,
            }
        )
        .is_encoder_stream_error()
    );
    assert_eq!(
        (
            small_table.size(),
            small_table.len(),
            small_table.insert_count()
        ),
        (0, 0, 0)
    );
    assert_eq!(small_scratch, [0xaa; 2]);

    let mut error_storage = [0; 68];
    let mut error_entries = [QpackDynamicTableEntry::EMPTY; 3];
    let mut error_table = QpackDynamicTable::new(&mut error_storage, &mut error_entries);
    assert_eq!(error_table.set_capacity(100, |_| true), Ok(()));
    let applier = QpackEncoderInstructionApplier::new(100);
    let mut error_scratch = [0xaa; 16];
    for (instruction, error) in [
        (
            QpackEncoderInstruction::parse(&[0xff, 0x24, 0]).expect("static index instruction"),
            QpackEncoderInstructionApplyError::StaticNameIndexOutOfRange { index: 99 },
        ),
        (
            QpackEncoderInstruction::parse(&[0x80, 0]).expect("dynamic index instruction"),
            QpackEncoderInstructionApplyError::DynamicNameReference(
                QpackDynamicTableError::EncoderRelativeIndexUnderflow {
                    insert_count: 0,
                    index: 0,
                },
            ),
        ),
        (
            QpackEncoderInstruction::parse(&[0xc0, 0x84, 0xff, 0xff, 0xff, 0xff])
                .expect("malformed Huffman instruction"),
            QpackEncoderInstructionApplyError::ValueHuffman(QpackHuffmanDecodeError::EosSymbol),
        ),
    ] {
        assert_eq!(
            applier.apply(&mut error_table, instruction, &mut error_scratch, |_| true),
            Err(error)
        );
        assert!(error.is_encoder_stream_error());
        assert_eq!(
            (
                error_table.capacity(),
                error_table.size(),
                error_table.len(),
                error_table.insert_count(),
            ),
            (100, 0, 0, 0)
        );
        assert_eq!(error_scratch, [0xaa; 16]);
    }

    let www = [
        0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
    ];
    let mut short_wire = [0; 14];
    let short_instruction = {
        let view = QpackInsertWithNameReferenceBuilder::new(&mut short_wire, true, 0, true, &www)
            .build()
            .expect("Huffman instruction capacity");
        QpackEncoderInstruction::parse(view.as_bytes()).expect("Huffman instruction")
    };
    let mut short_scratch = [0xaa; 14];
    assert_eq!(
        applier.apply(
            &mut error_table,
            short_instruction,
            &mut short_scratch,
            |_| true
        ),
        Err(QpackEncoderInstructionApplyError::ScratchTooShort {
            required: 15,
            available: 14,
        })
    );
    assert!(
        !QpackEncoderInstructionApplyError::ScratchTooShort {
            required: 15,
            available: 14,
        }
        .is_encoder_stream_error()
    );
    assert_eq!(
        (
            error_table.capacity(),
            error_table.size(),
            error_table.len(),
            error_table.insert_count(),
        ),
        (100, 0, 0, 0)
    );
    assert_eq!(short_scratch, [0xaa; 14]);
}

#[test]
fn qpack_encoder_stream_sequence_applies_appendix_b_and_empty_input_exactly() {
    let _: Option<qpack::QpackEncoderInstructionsApplyError> = None;

    let applier = QpackEncoderInstructionApplier::new(220);
    let mut empty_storage = [0; 68];
    let mut empty_entries = [QpackDynamicTableEntry::EMPTY; 2];
    let mut empty_table = QpackDynamicTable::new(&mut empty_storage, &mut empty_entries);
    let mut empty_scratch = [0xaa; 4];
    let mut empty_calls = 0;
    assert_eq!(
        applier.apply_sequence(&mut empty_table, &[], &mut empty_scratch, |_| {
            empty_calls += 1;
            true
        }),
        Ok(())
    );
    assert_eq!(empty_calls, 0);
    assert_eq!(empty_scratch, [0xaa; 4]);
    assert_eq!(
        (
            empty_table.capacity(),
            empty_table.size(),
            empty_table.len(),
            empty_table.insert_count(),
        ),
        (0, 0, 0, 0)
    );

    let sequence = b"\x3f\xbd\x01\xc0\x0fwww.example.com\xc1\x0c/sample/path\x4acustom-key\x0ccustom-value\x02\x81\x0dcustom-value2";
    let mut storage = [0; 256];
    let mut entries = [QpackDynamicTableEntry::EMPTY; 8];
    let mut table = QpackDynamicTable::new(&mut storage, &mut entries);
    let mut scratch = [0xaa; 64];
    let mut evicted = [0; 1];
    let mut eviction_count = 0;
    assert_eq!(
        applier.apply_sequence(&mut table, sequence, &mut scratch, |absolute| {
            evicted[eviction_count] = absolute;
            eviction_count += 1;
            true
        }),
        Ok(())
    );
    assert_eq!(eviction_count, 1);
    assert_eq!(evicted, [0]);
    assert_eq!(
        (
            table.capacity(),
            table.insert_count(),
            table.size(),
            table.len()
        ),
        (220, 5, 215, 4)
    );
    assert_eq!(
        table.get_absolute(0),
        Err(QpackDynamicTableError::EvictedAbsoluteIndex {
            requested: 0,
            oldest_available: 1,
        })
    );
    for (absolute, name, value) in [
        (1, b":path" as &[u8], b"/sample/path" as &[u8]),
        (2, b"custom-key" as &[u8], b"custom-value" as &[u8]),
        (3, b":authority" as &[u8], b"www.example.com" as &[u8]),
        (4, b"custom-key" as &[u8], b"custom-value2" as &[u8]),
    ] {
        assert_eq!(
            table
                .get_absolute(absolute)
                .map(|field| (field.name(), field.value())),
            Ok((name, value))
        );
    }
}

#[test]
fn qpack_encoder_stream_sequence_prevalidation_is_atomic_and_reports_parse_context() {
    let applier = QpackEncoderInstructionApplier::new(100);
    let mut storage = [0; 128];
    let mut entries = [QpackDynamicTableEntry::EMPTY; 3];
    let mut table = QpackDynamicTable::new(&mut storage, &mut entries);
    let before = (
        table.capacity(),
        table.size(),
        table.len(),
        table.insert_count(),
    );
    let mut scratch = [0xaa; 8];
    let mut calls = 0;
    let error = applier
        .apply_sequence(&mut table, &[0x3f, 0x45, 0x80], &mut scratch, |_| {
            calls += 1;
            true
        })
        .expect_err("truncated suffix must reject the entire sequence before application");
    assert_eq!(
        error,
        QpackEncoderInstructionsApplyError::Parse(QpackEncoderInstructionsParseError {
            offset: 2,
            error: QpackEncoderInstructionParseError::InsertWithNameReferenceValue(
                QpackStringLiteralParseError::Length(QpackIntegerParseError::Incomplete {
                    required: 1,
                    available: 0,
                })
            ),
        })
    );
    assert!(error.is_encoder_stream_error());
    assert!(error.to_string().contains("byte 2"));
    assert!(error.to_string().contains("Insert With Name Reference"));
    assert_eq!(calls, 0);
    assert_eq!(scratch, [0xaa; 8]);
    assert_eq!(
        (
            table.capacity(),
            table.size(),
            table.len(),
            table.insert_count()
        ),
        before
    );
}

#[test]
fn qpack_encoder_stream_sequence_commits_prefix_and_reports_exact_offsets() {
    let applier = QpackEncoderInstructionApplier::new(100);
    let mut storage = [0; 128];
    let mut entries = [QpackDynamicTableEntry::EMPTY; 3];
    let mut table = QpackDynamicTable::new(&mut storage, &mut entries);
    let mut scratch = [0xaa; 16];
    let sequence = [0x3f, 0xc5, 0, 0xff, 0x24, 0, 0xc0, 0];
    let error = applier
        .apply_sequence(&mut table, &sequence, &mut scratch, |_| true)
        .expect_err("invalid static index must stop before the suffix");
    assert_eq!(
        error,
        QpackEncoderInstructionsApplyError::Apply {
            offset: 3,
            error: QpackEncoderInstructionApplyError::StaticNameIndexOutOfRange { index: 99 },
        }
    );
    assert!(error.is_encoder_stream_error());
    assert!(error.to_string().contains("at byte 3"));
    assert!(
        error
            .to_string()
            .contains("static name index is out of range: 99")
    );
    assert_eq!(
        (
            table.capacity(),
            table.size(),
            table.len(),
            table.insert_count()
        ),
        (100, 0, 0, 0)
    );
    assert_eq!(scratch, [0xaa; 16]);

    let mut local_storage = [0; 128];
    let mut local_entries = [QpackDynamicTableEntry::EMPTY; 3];
    let mut local_table = QpackDynamicTable::new(&mut local_storage, &mut local_entries);
    let mut local_scratch = [0xaa; 14];
    let local_sequence = [
        0x3f, 0xc5, 0, 0xc0, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90,
        0xf4, 0xff,
    ];
    let local_error = applier
        .apply_sequence(
            &mut local_table,
            &local_sequence,
            &mut local_scratch,
            |_| true,
        )
        .expect_err("caller-provided scratch must remain distinguishable from protocol failures");
    assert_eq!(
        local_error,
        QpackEncoderInstructionsApplyError::Apply {
            offset: 3,
            error: QpackEncoderInstructionApplyError::ScratchTooShort {
                required: 15,
                available: 14,
            },
        }
    );
    assert!(!local_error.is_encoder_stream_error());
    assert!(local_error.to_string().contains("at byte 3"));
    assert!(local_error.to_string().contains("scratch is too short"));
    assert_eq!(
        (
            local_table.capacity(),
            local_table.size(),
            local_table.len(),
            local_table.insert_count(),
        ),
        (100, 0, 0, 0)
    );
    assert_eq!(local_scratch, [0xaa; 14]);
}
