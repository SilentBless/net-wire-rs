use net_wire::qpack::{
    QPACK_INTEGER_MAX, QpackDecodedFieldEntry, QpackDecoderFeedbackError, QpackDecoderInstruction,
    QpackDecoderInstructionBuildError, QpackDecoderState, QpackDynamicTable,
    QpackDynamicTableEntry, QpackFieldSectionContext, QpackFieldSectionDecodeOutcome,
    QpackFieldSectionDecoder, QpackFieldSectionOutput, QpackFieldSectionPrefixBuilder,
    QpackIndexedFieldLineBuilder, QpackIntegerBuildError,
};

#[test]
fn qpack_decoder_feedback_state_starts_empty() {
    assert_eq!(QpackDecoderState::default().known_received_count(), 0);
}

#[test]
fn qpack_decoder_feedback_acknowledges_decoded_sections_and_is_atomic() {
    let mut storage = [0; 36];
    let mut table_entries = [QpackDynamicTableEntry::EMPTY; 2];
    let mut table = QpackDynamicTable::new(&mut storage, &mut table_entries);
    assert_eq!(table.set_capacity(68, |_| true), Ok(()));
    assert_eq!(table.insert(b"a", b"0", |_| true), Ok(0));
    assert_eq!(table.insert(b"b", b"1", |_| true), Ok(1));
    let decoder = QpackFieldSectionDecoder::new(128);
    let mut state = QpackDecoderState::new();

    let mut zero_bytes = [0xaa; 16];
    let mut zero_fields = [QpackDecodedFieldEntry::EMPTY; 1];
    let mut zero_output = QpackFieldSectionOutput::new(&mut zero_bytes, &mut zero_fields);
    let zero = match decoder
        .decode(&[0, 0, 0xc0], &table, &mut zero_output)
        .expect("static section")
    {
        QpackFieldSectionDecodeOutcome::Decoded(decoded) => decoded,
        QpackFieldSectionDecodeOutcome::Blocked(_) => panic!("static section is ready"),
    };
    assert!(!zero.contains_dynamic_references());
    let mut no_acknowledgment = [0xaa; 2];
    assert_eq!(
        state.acknowledge_field_section(&mut no_acknowledgment, 4, zero),
        Ok(None)
    );
    assert_eq!(no_acknowledgment, [0xaa; 2]);
    assert_eq!(state.known_received_count(), 0);

    let encoded_ric = QpackFieldSectionContext::encode_required_insert_count(2, 128).expect("RIC");
    let mut prefix = [0xaa; 2];
    let mut indexed_static = [0xaa; 2];
    let mut static_only_section = [0xaa; 4];
    let prefix = QpackFieldSectionPrefixBuilder::new(&mut prefix, encoded_ric, false, 0)
        .build()
        .expect("prefix");
    static_only_section[..prefix.as_bytes().len()].copy_from_slice(prefix.as_bytes());
    let static_only_len = prefix.as_bytes().len();
    let indexed_static = QpackIndexedFieldLineBuilder::new(&mut indexed_static, true, 17)
        .build()
        .expect("static field");
    static_only_section[static_only_len..static_only_len + indexed_static.as_bytes().len()]
        .copy_from_slice(indexed_static.as_bytes());
    let static_only_len = static_only_len + indexed_static.as_bytes().len();
    let mut static_only_bytes = [0xaa; 16];
    let mut static_only_fields = [QpackDecodedFieldEntry::EMPTY; 1];
    let mut static_only_output =
        QpackFieldSectionOutput::new(&mut static_only_bytes, &mut static_only_fields);
    let static_only = match decoder
        .decode(
            &static_only_section[..static_only_len],
            &table,
            &mut static_only_output,
        )
        .expect("static-only section with nonzero RIC")
    {
        QpackFieldSectionDecodeOutcome::Decoded(decoded) => decoded,
        QpackFieldSectionDecodeOutcome::Blocked(_) => panic!("complete table"),
    };
    assert_eq!(static_only.required_insert_count(), 2);
    assert!(!static_only.contains_dynamic_references());
    assert_eq!(
        static_only
            .get(0)
            .map(|field| (field.name(), field.value())),
        Some((b":method" as &[u8], b"GET" as &[u8]))
    );
    let mut static_only_state = QpackDecoderState::new();
    let mut static_only_acknowledgment = [0x5a; 2];
    assert_eq!(
        static_only_state.acknowledge_field_section(
            &mut static_only_acknowledgment,
            4,
            static_only,
        ),
        Ok(None)
    );
    assert_eq!(static_only_acknowledgment, [0x5a; 2]);
    assert_eq!(static_only_state.known_received_count(), 0);

    let mut dynamic_bytes = [0xaa; 4];
    let mut dynamic_fields = [QpackDecodedFieldEntry::EMPTY; 1];
    let mut dynamic_output = QpackFieldSectionOutput::new(&mut dynamic_bytes, &mut dynamic_fields);
    let dynamic = match decoder
        .decode(&[3, 0, 0x80], &table, &mut dynamic_output)
        .expect("dynamic section")
    {
        QpackFieldSectionDecodeOutcome::Decoded(decoded) => decoded,
        QpackFieldSectionDecodeOutcome::Blocked(_) => panic!("complete table"),
    };
    assert_eq!(dynamic.required_insert_count(), 2);

    assert!(dynamic.contains_dynamic_references());
    let mut acknowledgment = [0xaa; 2];
    {
        let acknowledgment = state
            .acknowledge_field_section(&mut acknowledgment, 4, dynamic)
            .expect("acknowledgment")
            .expect("dynamic section needs acknowledgment");
        assert_eq!(acknowledgment.as_bytes(), &[0x84]);
        assert_eq!(acknowledgment.stream_id().value(), 4);
        assert_eq!(state.known_received_count(), 2);
    }
    assert_eq!(acknowledgment[1], 0xaa);

    let mut lower_bytes = [0xaa; 4];
    let mut lower_fields = [QpackDecodedFieldEntry::EMPTY; 1];
    let mut lower_output = QpackFieldSectionOutput::new(&mut lower_bytes, &mut lower_fields);
    let lower = match decoder
        .decode(&[2, 0, 0x80], &table, &mut lower_output)
        .expect("lower dynamic section")
    {
        QpackFieldSectionDecodeOutcome::Decoded(decoded) => decoded,
        QpackFieldSectionDecodeOutcome::Blocked(_) => panic!("complete table"),
    };
    assert_eq!(lower.required_insert_count(), 1);
    let mut lower_acknowledgment = [0xaa; 2];
    assert_eq!(
        state
            .acknowledge_field_section(&mut lower_acknowledgment, 4, lower)
            .map(|acknowledgment| acknowledgment.map(|acknowledgment| acknowledgment.as_bytes())),
        Ok(Some(&[0x84][..]))
    );
    assert_eq!(state.known_received_count(), 2);

    let mut equal_acknowledgment = [0xaa; 2];
    {
        let acknowledgment = state
            .acknowledge_field_section(&mut equal_acknowledgment, 4, dynamic)
            .expect("equal acknowledgment")
            .expect("dynamic section needs acknowledgment");
        assert_eq!(acknowledgment.as_bytes(), &[0x84]);
        assert_eq!(acknowledgment.stream_id().value(), 4);
    }
    assert_eq!(equal_acknowledgment[1], 0xaa);
    assert_eq!(state.known_received_count(), 2);

    let mut short = [0xaa; 1];
    let before_short = short;
    let short_error = state
        .acknowledge_field_section(&mut short[..0], 4, dynamic)
        .expect_err("short destination");
    assert_eq!(
        short_error,
        QpackDecoderFeedbackError::InstructionBuild(
            QpackDecoderInstructionBuildError::BufferTooShort {
                required: 1,
                available: 0,
            }
        )
    );
    assert!(short_error.is_provisioning_error());
    assert_eq!(
        short_error.to_string(),
        "QPACK decoder feedback instruction cannot be built: QPACK decoder instruction buffer is too short: need 1 bytes, have 0"
    );
    assert_eq!(short, before_short);
    assert_eq!(state.known_received_count(), 2);

    let mut too_large = [0xaa; 16];
    let before_too_large = too_large;
    let too_large_error = state
        .acknowledge_field_section(&mut too_large, QPACK_INTEGER_MAX + 1, dynamic)
        .expect_err("stream ID exceeds QPACK integer limit");
    assert_eq!(
        too_large_error,
        QpackDecoderFeedbackError::InstructionBuild(
            QpackDecoderInstructionBuildError::SectionAcknowledgment(
                QpackIntegerBuildError::ValueTooLarge {
                    value: QPACK_INTEGER_MAX + 1,
                }
            )
        )
    );
    assert!(!too_large_error.is_provisioning_error());
    assert_eq!(too_large, before_too_large);
    assert_eq!(state.known_received_count(), 2);
}

#[test]
fn qpack_decoder_feedback_cancellation_is_exact_and_atomic() {
    let mut state = QpackDecoderState::new();
    let mut cancellation = [0xaa; 2];
    {
        let cancellation = state
            .cancel_stream(&mut cancellation, 8)
            .expect("cancellation");
        assert_eq!(cancellation.as_bytes(), &[0x48]);
        assert_eq!(cancellation.stream_id().value(), 8);
        assert_eq!(state.known_received_count(), 0);
    }
    assert_eq!(cancellation[1], 0xaa);

    let mut short = [0xaa; 1];
    let before_short = short;
    let error = state
        .cancel_stream(&mut short[..0], 8)
        .expect_err("short destination");
    assert_eq!(
        error,
        QpackDecoderFeedbackError::InstructionBuild(
            QpackDecoderInstructionBuildError::BufferTooShort {
                required: 1,
                available: 0,
            }
        )
    );
    assert!(error.is_provisioning_error());
    assert_eq!(short, before_short);
    assert_eq!(state.known_received_count(), 0);
}

#[test]
fn qpack_decoder_feedback_insert_count_increments_are_coalesced_atomic_and_bounded() {
    let mut state = QpackDecoderState::new();
    let mut equal = [0xaa; 2];
    assert_eq!(state.emit_insert_count_increment(&mut equal, 0), Ok(None));
    assert_eq!(equal, [0xaa; 2]);

    let mut normal = [0xaa; 2];
    {
        let increment = state
            .emit_insert_count_increment(&mut normal, 4)
            .expect("increment")
            .expect("new inserts");
        assert_eq!(increment.as_bytes(), &[0x04]);
        assert_eq!(increment.increment().value(), 4);
        assert_eq!(state.known_received_count(), 4);
    }
    assert_eq!(normal[1], 0xaa);

    let mut short = [0xaa; 1];
    let before_short = short;
    let short_error = state
        .emit_insert_count_increment(&mut short, 67)
        .expect_err("two-byte increment needs capacity");
    assert_eq!(
        short_error,
        QpackDecoderFeedbackError::InstructionBuild(
            QpackDecoderInstructionBuildError::BufferTooShort {
                required: 2,
                available: 1,
            }
        )
    );
    assert!(short_error.is_provisioning_error());
    assert_eq!(short, before_short);
    assert_eq!(state.known_received_count(), 4);

    let before_regression = normal;
    let regression = state
        .emit_insert_count_increment(&mut normal, 3)
        .expect_err("insert count regressed");
    assert_eq!(
        regression,
        QpackDecoderFeedbackError::InsertCountRegression {
            known_received_count: 4,
            decoder_insert_count: 3,
        }
    );
    assert!(!regression.is_provisioning_error());
    assert_eq!(
        regression.to_string(),
        "decoder insert count 3 regresses below Known Received Count 4"
    );
    assert_eq!(state.known_received_count(), 4);
    assert_eq!(normal, before_regression);

    let mut chunked = QpackDecoderState::new();
    let mut maximum = [0xaa; 10];
    {
        let increment = chunked
            .emit_insert_count_increment(&mut maximum, QPACK_INTEGER_MAX + 5)
            .expect("maximum chunk")
            .expect("pending inserts");
        assert_eq!(
            increment.as_bytes(),
            &[0x3f, 0xc0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f]
        );
        assert_eq!(increment.increment().value(), QPACK_INTEGER_MAX);
        assert!(matches!(
            QpackDecoderInstruction::parse(increment.as_bytes()),
            Ok(QpackDecoderInstruction::InsertCountIncrement(parsed))
                if parsed.increment().value() == QPACK_INTEGER_MAX
                    && parsed.as_bytes() == increment.as_bytes()
        ));
        assert_eq!(chunked.known_received_count(), QPACK_INTEGER_MAX);
    }
    let mut remainder = [0xaa; 2];
    {
        let increment = chunked
            .emit_insert_count_increment(&mut remainder, QPACK_INTEGER_MAX + 5)
            .expect("remainder chunk")
            .expect("remaining inserts");
        assert_eq!(increment.as_bytes(), &[0x05]);
        assert_eq!(increment.increment().value(), 5);
        assert!(matches!(
            QpackDecoderInstruction::parse(increment.as_bytes()),
            Ok(QpackDecoderInstruction::InsertCountIncrement(parsed))
                if parsed.increment().value() == 5 && parsed.as_bytes() == increment.as_bytes()
        ));
        assert_eq!(chunked.known_received_count(), QPACK_INTEGER_MAX + 5);
    }
    assert_eq!(remainder[1], 0xaa);
}
