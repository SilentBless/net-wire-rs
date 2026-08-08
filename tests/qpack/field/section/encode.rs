use net_wire::qpack::{
    QPACK_STATIC_TABLE_LEN, QpackDecodedFieldEntry, QpackDynamicTable, QpackDynamicTableEntry,
    QpackDynamicTableError, QpackEncoderOutstandingSection, QpackEncoderState,
    QpackEncoderStateError, QpackFieldPlan, QpackFieldSectionBase, QpackFieldSectionContextError,
    QpackFieldSectionDecodeOutcome, QpackFieldSectionDecoder, QpackFieldSectionEncodeBuffers,
    QpackFieldSectionEncodeError, QpackFieldSectionEncoder, QpackFieldSectionOutput,
    QpackFieldSectionPlanError, QpackFieldSectionPlanSlot,
};

#[test]
fn qpack_field_section_encoder_static_forms_are_exact_and_unregistered() {
    let mut table_bytes = [];
    let mut table_entries = [];
    let table = QpackDynamicTable::new(&mut table_bytes, &mut table_entries);
    let mut sections = [QpackEncoderOutstandingSection::EMPTY; 1];
    let mut retained_references = [0; 1];
    let mut state = QpackEncoderState::new(&mut sections, &mut retained_references, 0);
    let mut references = [];
    let mut slots = [QpackFieldSectionPlanSlot::EMPTY; 3];
    let mut destination = [0xaa; 16];
    let plans = [
        QpackFieldPlan::IndexedStatic { index: 17 },
        QpackFieldPlan::LiteralStaticNameReference {
            never_indexed: true,
            name_index: 0,
            value_huffman: true,
            encoded_value: &[0x1f],
        },
        QpackFieldPlan::LiteralName {
            never_indexed: true,
            name_huffman: true,
            encoded_name: &[0x1f],
            value_huffman: true,
            encoded_value: &[0x8f],
        },
    ];
    let encoded = QpackFieldSectionEncoder::new(128)
        .encode(
            7,
            &plans,
            QpackFieldSectionBase::RequiredInsertCount,
            &table,
            &mut state,
            QpackFieldSectionEncodeBuffers::new(&mut references, &mut slots, &mut destination),
        )
        .expect("static section");
    assert_eq!(
        encoded.as_bytes(),
        &[0, 0, 0xd1, 0x70, 0x81, 0x1f, 0x39, 0x1f, 0x81, 0x8f]
    );
    assert_eq!(
        (
            encoded.required_insert_count(),
            encoded.base(),
            encoded.len()
        ),
        (0, 0, 10)
    );
    assert!(!encoded.is_empty());
    assert_eq!((state.len(), state.reference_len()), (0, 0));
    assert_eq!(destination[10], 0xaa);

    let mut empty_slots = [];
    let mut empty_destination = [0xaa; 3];
    let empty = QpackFieldSectionEncoder::new(128)
        .encode(
            8,
            &[],
            QpackFieldSectionBase::RequiredInsertCount,
            &table,
            &mut state,
            QpackFieldSectionEncodeBuffers::new(
                &mut references,
                &mut empty_slots,
                &mut empty_destination,
            ),
        )
        .expect("empty section");
    assert_eq!(empty.as_bytes(), &[0, 0]);
    assert_eq!(
        (
            empty.required_insert_count(),
            empty.base(),
            empty.len(),
            empty.is_empty()
        ),
        (0, 0, 2, false)
    );
    assert_eq!((state.len(), state.reference_len()), (0, 0));
    assert_eq!(empty_destination[2], 0xaa);
}

#[test]
fn qpack_field_section_encoder_dynamic_default_base_roundtrips_and_retains_duplicates() {
    let mut storage = [0; 70];
    let mut entries = [QpackDynamicTableEntry::EMPTY; 3];
    let mut table = QpackDynamicTable::new(&mut storage, &mut entries);
    assert_eq!(table.set_capacity(102, |_| true), Ok(()));
    for (name, value, absolute) in [
        (b"a" as &[u8], b"0" as &[u8], 0),
        (b"b", b"1", 1),
        (b"c", b"2", 2),
    ] {
        assert_eq!(table.insert(name, value, |_| true), Ok(absolute));
    }
    let mut sections = [QpackEncoderOutstandingSection::EMPTY; 1];
    let mut retained_references = [0; 3];
    {
        let mut state = QpackEncoderState::new(&mut sections, &mut retained_references, 1);
        let mut references = [9; 3];
        let mut slots = [QpackFieldSectionPlanSlot::EMPTY; 3];
        let mut destination = [0xaa; 10];
        let plans = [
            QpackFieldPlan::IndexedDynamic { absolute_index: 2 },
            QpackFieldPlan::LiteralDynamicNameReference {
                never_indexed: true,
                name_absolute_index: 1,
                value_huffman: false,
                encoded_value: b"x",
            },
            QpackFieldPlan::IndexedDynamic { absolute_index: 2 },
        ];
        let encoded = QpackFieldSectionEncoder::new(128)
            .encode(
                7,
                &plans,
                QpackFieldSectionBase::RequiredInsertCount,
                &table,
                &mut state,
                QpackFieldSectionEncodeBuffers::new(&mut references, &mut slots, &mut destination),
            )
            .expect("dynamic section");
        assert_eq!(encoded.as_bytes(), &[4, 0, 0x80, 0x61, 1, b'x', 0x80]);
        assert_eq!((encoded.required_insert_count(), encoded.base()), (3, 3));
        assert_eq!((state.len(), state.reference_len()), (1, 3));

        let mut output_bytes = [0xaa; 8];
        let mut output_entries = [QpackDecodedFieldEntry::EMPTY; 3];
        let mut output = QpackFieldSectionOutput::new(&mut output_bytes, &mut output_entries);
        let decoded = match QpackFieldSectionDecoder::new(128)
            .decode(encoded.as_bytes(), &table, &mut output)
            .expect("round trip")
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
            (3, 3, 3)
        );
        for (index, name, value, never_indexed) in [
            (0, b"c" as &[u8], b"2" as &[u8], false),
            (1, b"b", b"x", true),
            (2, b"c", b"2", false),
        ] {
            let field = decoded.get(index).expect("field");
            assert_eq!(
                (field.name(), field.value(), field.never_indexed()),
                (name, value, never_indexed)
            );
        }
    }
    assert_eq!(retained_references, [2, 1, 2]);
}

#[test]
fn qpack_field_section_encoder_explicit_base_uses_pre_and_post_base_forms() {
    let mut storage = [0; 70];
    let mut entries = [QpackDynamicTableEntry::EMPTY; 3];
    let mut table = QpackDynamicTable::new(&mut storage, &mut entries);
    assert_eq!(table.set_capacity(102, |_| true), Ok(()));
    for (name, value) in [(b"a" as &[u8], b"0" as &[u8]), (b"b", b"1"), (b"c", b"2")] {
        assert!(table.insert(name, value, |_| true).is_ok());
    }
    let mut sections = [QpackEncoderOutstandingSection::EMPTY; 1];

    let mut retained = [0; 3];
    let mut state = QpackEncoderState::new(&mut sections, &mut retained, 1);
    let mut references = [0; 3];
    let mut slots = [QpackFieldSectionPlanSlot::EMPTY; 3];
    let mut destination = [0xaa; 8];
    let plans = [
        QpackFieldPlan::IndexedDynamic { absolute_index: 0 },
        QpackFieldPlan::IndexedDynamic { absolute_index: 2 },
        QpackFieldPlan::LiteralDynamicNameReference {
            never_indexed: true,
            name_absolute_index: 2,
            value_huffman: false,
            encoded_value: b"x",
        },
    ];
    let encoded = QpackFieldSectionEncoder::new(64)
        .encode(
            7,
            &plans,
            QpackFieldSectionBase::Explicit(1),
            &table,
            &mut state,
            QpackFieldSectionEncodeBuffers::new(&mut references, &mut slots, &mut destination),
        )
        .expect("explicit base");
    assert_eq!(encoded.as_bytes(), &[4, 0x81, 0x80, 0x11, 0x09, 1, b'x']);
    assert_eq!((encoded.required_insert_count(), encoded.base()), (3, 1));
    let mut bytes = [0xaa; 8];
    let mut fields = [QpackDecodedFieldEntry::EMPTY; 3];
    let mut output = QpackFieldSectionOutput::new(&mut bytes, &mut fields);
    let decoded = match QpackFieldSectionDecoder::new(64)
        .decode(encoded.as_bytes(), &table, &mut output)
        .expect("round trip")
    {
        QpackFieldSectionDecodeOutcome::Decoded(decoded) => decoded,
        QpackFieldSectionDecodeOutcome::Blocked(_) => panic!("complete table"),
    };
    assert_eq!((decoded.required_insert_count(), decoded.base()), (3, 1));
    assert!(
        matches!(decoded.get(2), Some(field) if field.name() == b"c" && field.value() == b"x" && field.never_indexed())
    );
}

#[test]
fn qpack_field_section_encoder_provisioning_and_reservation_failures_are_atomic() {
    let mut storage = [0; 70];
    let mut entries = [QpackDynamicTableEntry::EMPTY; 3];
    let mut table = QpackDynamicTable::new(&mut storage, &mut entries);
    assert_eq!(table.set_capacity(102, |_| true), Ok(()));
    for (name, value) in [(b"a" as &[u8], b"0" as &[u8]), (b"b", b"1"), (b"c", b"2")] {
        assert!(table.insert(name, value, |_| true).is_ok());
    }
    let plans = [
        QpackFieldPlan::IndexedDynamic { absolute_index: 1 },
        QpackFieldPlan::IndexedDynamic { absolute_index: 2 },
    ];
    let mut sections = [QpackEncoderOutstandingSection::EMPTY; 1];
    let mut retained = [0; 2];
    let mut state = QpackEncoderState::new(&mut sections, &mut retained, 0);
    let mut references = [9; 1];
    let mut slots = [QpackFieldSectionPlanSlot::EMPTY; 2];
    let mut destination = [0xaa; 4];
    let before = (references, destination);
    let error = QpackFieldSectionEncoder::new(128)
        .encode(
            1,
            &plans,
            QpackFieldSectionBase::RequiredInsertCount,
            &table,
            &mut state,
            QpackFieldSectionEncodeBuffers::new(&mut references, &mut slots, &mut destination),
        )
        .expect_err("reference scratch");
    assert_eq!(
        error,
        QpackFieldSectionEncodeError::ReferenceScratchTooShort {
            required: 2,
            available: 1
        }
    );
    assert!(error.is_provisioning_error());
    assert_eq!(
        (references, destination, state.len(), state.reference_len()),
        (before.0, before.1, 0, 0)
    );
    let mut references = [0; 2];
    let mut short_slots = [QpackFieldSectionPlanSlot::EMPTY; 1];
    let error = QpackFieldSectionEncoder::new(128)
        .encode(
            1,
            &plans,
            QpackFieldSectionBase::RequiredInsertCount,
            &table,
            &mut state,
            QpackFieldSectionEncodeBuffers::new(
                &mut references,
                &mut short_slots,
                &mut destination,
            ),
        )
        .expect_err("plan scratch");
    assert_eq!(
        error,
        QpackFieldSectionEncodeError::FieldPlanScratchTooShort {
            required: 2,
            available: 1
        }
    );
    assert!(error.is_provisioning_error());
    assert_eq!(
        (destination, state.len(), state.reference_len()),
        (before.1, 0, 0)
    );
    let mut exact_slots = [QpackFieldSectionPlanSlot::EMPTY; 2];
    let mut short_destination = [0xaa; 3];
    let error = QpackFieldSectionEncoder::new(128)
        .encode(
            1,
            &plans,
            QpackFieldSectionBase::RequiredInsertCount,
            &table,
            &mut state,
            QpackFieldSectionEncodeBuffers::new(
                &mut references,
                &mut exact_slots,
                &mut short_destination,
            ),
        )
        .expect_err("destination");
    assert_eq!(
        error,
        QpackFieldSectionEncodeError::DestinationTooShort {
            required: 4,
            available: 3
        }
    );
    assert!(error.is_provisioning_error());
    assert_eq!(
        (short_destination, state.len(), state.reference_len()),
        ([0xaa; 3], 0, 0)
    );
    let mut slots = [QpackFieldSectionPlanSlot::EMPTY; 2];
    let mut destination = [0xaa; 8];
    let error = QpackFieldSectionEncoder::new(128)
        .encode(
            1,
            &plans,
            QpackFieldSectionBase::RequiredInsertCount,
            &table,
            &mut state,
            QpackFieldSectionEncodeBuffers::new(&mut references, &mut slots, &mut destination),
        )
        .expect_err("blocked streams");
    assert_eq!(
        error,
        QpackFieldSectionEncodeError::EncoderStateReservation(
            QpackEncoderStateError::BlockedStreamsLimitExceeded { maximum: 0 }
        )
    );
    assert!(!error.is_provisioning_error());
    assert_eq!(
        (destination, state.len(), state.reference_len()),
        ([0xaa; 8], 0, 0)
    );
}

#[test]
fn qpack_field_section_encoder_rejects_invalid_table_references_atomically() {
    let mut storage = [0; 2];
    let mut entries = [QpackDynamicTableEntry::EMPTY; 1];
    let mut table = QpackDynamicTable::new(&mut storage, &mut entries);
    assert_eq!(table.set_capacity(34, |_| true), Ok(()));
    assert_eq!(table.insert(b"a", b"b", |_| true), Ok(0));

    let mut sections = [QpackEncoderOutstandingSection::EMPTY; 1];
    let mut retained = [0; 1];
    let mut state = QpackEncoderState::new(&mut sections, &mut retained, 1);
    let static_plans = [
        QpackFieldPlan::IndexedStatic { index: 0 },
        QpackFieldPlan::IndexedStatic {
            index: QPACK_STATIC_TABLE_LEN as u64,
        },
    ];
    let mut references = [];
    let mut slots = [QpackFieldSectionPlanSlot::EMPTY; 2];
    let mut destination = [0xaa; 4];
    let error = QpackFieldSectionEncoder::new(34)
        .encode(
            1,
            &static_plans,
            QpackFieldSectionBase::RequiredInsertCount,
            &table,
            &mut state,
            QpackFieldSectionEncodeBuffers::new(&mut references, &mut slots, &mut destination),
        )
        .expect_err("static index");
    assert_eq!(
        error,
        QpackFieldSectionEncodeError::Plan(QpackFieldSectionPlanError::StaticIndexOutOfRange {
            field_index: 1,
            index: QPACK_STATIC_TABLE_LEN as u64,
        })
    );
    assert!(!error.is_provisioning_error());
    assert_eq!(
        (destination, state.len(), state.reference_len()),
        ([0xaa; 4], 0, 0)
    );

    let future_plans = [QpackFieldPlan::IndexedDynamic { absolute_index: 1 }];
    let mut references = [0; 1];
    let mut slots = [QpackFieldSectionPlanSlot::EMPTY; 1];
    let mut destination = [0xaa; 4];
    let error = QpackFieldSectionEncoder::new(34)
        .encode(
            1,
            &future_plans,
            QpackFieldSectionBase::RequiredInsertCount,
            &table,
            &mut state,
            QpackFieldSectionEncodeBuffers::new(&mut references, &mut slots, &mut destination),
        )
        .expect_err("future dynamic index");
    assert_eq!(
        error,
        QpackFieldSectionEncodeError::Plan(QpackFieldSectionPlanError::DynamicReference {
            field_index: 0,
            error: QpackDynamicTableError::FutureAbsoluteIndex {
                requested: 1,
                insert_count: 1,
            },
        })
    );
    assert!(!error.is_provisioning_error());
    assert_eq!(
        (destination, state.len(), state.reference_len()),
        ([0xaa; 4], 0, 0)
    );

    assert_eq!(table.insert(b"c", b"d", |_| true), Ok(1));
    let evicted_plans = [QpackFieldPlan::IndexedDynamic { absolute_index: 0 }];
    let mut references = [0; 1];
    let mut slots = [QpackFieldSectionPlanSlot::EMPTY; 1];
    let mut destination = [0xaa; 4];
    let error = QpackFieldSectionEncoder::new(34)
        .encode(
            1,
            &evicted_plans,
            QpackFieldSectionBase::RequiredInsertCount,
            &table,
            &mut state,
            QpackFieldSectionEncodeBuffers::new(&mut references, &mut slots, &mut destination),
        )
        .expect_err("evicted dynamic index");
    assert_eq!(
        error,
        QpackFieldSectionEncodeError::Plan(QpackFieldSectionPlanError::DynamicReference {
            field_index: 0,
            error: QpackDynamicTableError::EvictedAbsoluteIndex {
                requested: 0,
                oldest_available: 1,
            },
        })
    );
    assert!(!error.is_provisioning_error());
    assert_eq!(
        (destination, state.len(), state.reference_len()),
        ([0xaa; 4], 0, 0)
    );
}

#[test]
fn qpack_field_section_encoder_rejects_invalid_context_atomically() {
    let mut storage = [0; 2];
    let mut entries = [QpackDynamicTableEntry::EMPTY; 1];
    let mut table = QpackDynamicTable::new(&mut storage, &mut entries);
    assert_eq!(table.set_capacity(34, |_| true), Ok(()));
    assert_eq!(table.insert(b"a", b"b", |_| true), Ok(0));

    let mut sections = [QpackEncoderOutstandingSection::EMPTY; 1];
    let mut retained = [0; 1];
    let mut state = QpackEncoderState::new(&mut sections, &mut retained, 1);
    let static_plans = [QpackFieldPlan::IndexedStatic { index: 0 }];
    let mut references = [];
    let mut slots = [QpackFieldSectionPlanSlot::EMPTY; 1];
    let mut destination = [0xaa; 4];
    let error = QpackFieldSectionEncoder::new(34)
        .encode(
            1,
            &static_plans,
            QpackFieldSectionBase::Explicit(table.insert_count() + 1),
            &table,
            &mut state,
            QpackFieldSectionEncodeBuffers::new(&mut references, &mut slots, &mut destination),
        )
        .expect_err("base beyond insert count");
    assert_eq!(
        error,
        QpackFieldSectionEncodeError::BaseExceedsInsertCount {
            base: 2,
            insert_count: 1,
        }
    );
    assert!(!error.is_provisioning_error());
    assert_eq!(
        (destination, state.len(), state.reference_len()),
        ([0xaa; 4], 0, 0)
    );

    let dynamic_plans = [QpackFieldPlan::IndexedDynamic { absolute_index: 0 }];
    let mut references = [0; 1];
    let mut slots = [QpackFieldSectionPlanSlot::EMPTY; 1];
    let mut destination = [0xaa; 4];
    let error = QpackFieldSectionEncoder::new(0)
        .encode(
            1,
            &dynamic_plans,
            QpackFieldSectionBase::RequiredInsertCount,
            &table,
            &mut state,
            QpackFieldSectionEncodeBuffers::new(&mut references, &mut slots, &mut destination),
        )
        .expect_err("zero maximum entries");
    assert_eq!(
        error,
        QpackFieldSectionEncodeError::RequiredInsertCountEncoding(
            QpackFieldSectionContextError::ZeroMaximumEntries {
                encoded_required_insert_count: 1,
            }
        )
    );
    assert!(!error.is_provisioning_error());
    assert_eq!(
        (destination, state.len(), state.reference_len()),
        ([0xaa; 4], 0, 0)
    );
}
