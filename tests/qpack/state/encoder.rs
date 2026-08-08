// This suite keeps encoder feedback, outstanding sections, reference storage, and atomicity together.
use net_wire::qpack::{
    QPACK_INTEGER_MAX, QpackDecoderInstruction, QpackDecoderInstructionApplyError,
    QpackDecoderInstructionParseError, QpackDecoderInstructionsApplyError,
    QpackDecoderInstructionsParseError, QpackEncoderOutstandingSection, QpackEncoderState,
    QpackEncoderStateError, QpackInsertCountIncrementBuilder, QpackIntegerParseError,
};

#[test]
fn qpack_encoder_state_initialization_and_zero_reference_are_exact() {
    let mut sections = [QpackEncoderOutstandingSection::EMPTY; 2];
    let mut references = [9; 3];
    {
        let mut seeded = QpackEncoderState::new(&mut sections, &mut references, 1);
        assert_eq!(seeded.register(7, 2, &[1], 2), Ok(()));
    }
    assert_ne!(sections, [QpackEncoderOutstandingSection::EMPTY; 2]);
    assert_ne!(references, [0; 3]);
    {
        let mut state = QpackEncoderState::new(&mut sections, &mut references, u64::MAX);
        assert_eq!(
            (
                state.known_received_count(),
                state.maximum_blocked_streams(),
                state.len(),
                state.reference_len(),
                state.is_empty(),
                state.section_storage_capacity(),
                state.reference_storage_capacity(),
                state.blocked_stream_count(),
            ),
            (0, u64::MAX, 0, 0, true, 2, 3, 0)
        );
        assert_eq!(state.register(0, 0, &[], 0), Ok(()));
        assert_eq!(
            (
                state.len(),
                state.reference_len(),
                state.blocked_stream_count()
            ),
            (0, 0, 0)
        );
        assert!(!state.is_evictable(0));
        assert!(!state.is_evictable(u64::MAX));
    }
    assert_eq!(sections, [QpackEncoderOutstandingSection::EMPTY; 2]);
    assert_eq!(references, [0; 3]);

    let mut no_sections = [];
    let mut no_references = [];
    let mut empty = QpackEncoderState::new(&mut no_sections, &mut no_references, 0);
    assert_eq!(empty.register(u64::MAX, 0, &[], 0), Ok(()));
    assert_eq!(
        (
            empty.len(),
            empty.reference_len(),
            empty.blocked_stream_count(),
            empty.is_empty()
        ),
        (0, 0, 0, true)
    );
}

#[test]
fn qpack_encoder_state_registration_limits_and_distinct_streams_are_exact() {
    let mut sections = [QpackEncoderOutstandingSection::EMPTY; 5];
    let mut references = [0; 7];
    {
        let mut state = QpackEncoderState::new(&mut sections, &mut references, 2);
        assert_eq!(state.register(0, 4, &[3, 1, 3], 4), Ok(()));
        assert_eq!(
            (
                state.len(),
                state.reference_len(),
                state.blocked_stream_count(),
                state.is_empty()
            ),
            (1, 3, 1, false)
        );
        assert_eq!(state.register(0, 1, &[0], 4), Ok(()));
        assert_eq!(
            (
                state.len(),
                state.reference_len(),
                state.blocked_stream_count()
            ),
            (2, 4, 1)
        );
        assert_eq!(state.register(u64::MAX, 2, &[1], 4), Ok(()));
        assert_eq!(
            (
                state.len(),
                state.reference_len(),
                state.blocked_stream_count()
            ),
            (3, 5, 2)
        );
        assert_eq!(state.register(u64::MAX, 1, &[0], 4), Ok(()));
        assert_eq!(
            (
                state.len(),
                state.reference_len(),
                state.blocked_stream_count()
            ),
            (4, 6, 2)
        );
        let before = (
            state.len(),
            state.reference_len(),
            state.blocked_stream_count(),
            state.is_empty(),
        );
        let error = state
            .register(1, 1, &[0], 4)
            .expect_err("a third stream exceeds the limit");
        assert_eq!(
            error,
            QpackEncoderStateError::BlockedStreamsLimitExceeded { maximum: 2 }
        );
        assert!(!error.is_provisioning_error());
        assert!(error.is_blocked_streams_limit_error());
        assert_eq!(error.to_string(), "blocked streams exceed maximum 2");
        assert_eq!(
            (
                state.len(),
                state.reference_len(),
                state.blocked_stream_count(),
                state.is_empty()
            ),
            before
        );
    }
    assert_eq!(references, [3, 1, 3, 0, 1, 0, 0]);
    assert_eq!(
        (
            sections[0].stream_id(),
            sections[0].required_insert_count(),
            sections[0].reference_len(),
        ),
        (0, 4, 3)
    );
    assert_eq!(
        (
            sections[1].stream_id(),
            sections[1].required_insert_count(),
            sections[1].reference_len(),
        ),
        (0, 1, 1)
    );
    assert_eq!(
        (
            sections[2].stream_id(),
            sections[2].required_insert_count(),
            sections[2].reference_len(),
        ),
        (u64::MAX, 2, 1)
    );
    assert_eq!(
        (
            sections[3].stream_id(),
            sections[3].required_insert_count(),
            sections[3].reference_len(),
        ),
        (u64::MAX, 1, 1)
    );
    assert_eq!(sections[4], QpackEncoderOutstandingSection::EMPTY);

    let mut no_sections = [QpackEncoderOutstandingSection::EMPTY; 1];
    let mut no_references = [0; 1];
    let mut none = QpackEncoderState::new(&mut no_sections, &mut no_references, 0);
    let before = (
        none.len(),
        none.reference_len(),
        none.blocked_stream_count(),
        none.is_empty(),
    );
    assert_eq!(
        none.register(0, 1, &[0], 1),
        Err(QpackEncoderStateError::BlockedStreamsLimitExceeded { maximum: 0 })
    );
    assert_eq!(
        (
            none.len(),
            none.reference_len(),
            none.blocked_stream_count(),
            none.is_empty()
        ),
        before
    );
}

#[test]
fn qpack_encoder_state_registration_errors_are_exact_and_atomic() {
    let mut sections = [QpackEncoderOutstandingSection::EMPTY; 2];
    let mut references = [0; 6];
    {
        let mut state = QpackEncoderState::new(&mut sections, &mut references, 1);
        assert_eq!(state.register(7, 8, &[2, 7, 2, 5], 8), Ok(()));
        let before = (
            state.len(),
            state.reference_len(),
            state.blocked_stream_count(),
            state.is_empty(),
        );

        for error in [
            state.register(8, 1, &[], 8),
            state.register(8, 0, &[0], 8),
            state.register(8, 6, &[2, 7, 2, 5], 8),
            state.register(8, 0, &[u64::MAX], u64::MAX),
            state.register(8, 2, &[1], 1),
        ] {
            let error = error.expect_err("invalid registration");
            assert!(!error.is_provisioning_error());
            assert!(!error.is_blocked_streams_limit_error());
            assert_eq!(
                (
                    state.len(),
                    state.reference_len(),
                    state.blocked_stream_count(),
                    state.is_empty()
                ),
                before
            );
        }
        assert_eq!(
            state.register(8, 1, &[], 8),
            Err(QpackEncoderStateError::RequiredInsertCountMismatch {
                required_insert_count: 1,
                expected_required_insert_count: 0,
            })
        );
        assert_eq!(
            state.register(8, 0, &[0], 8),
            Err(QpackEncoderStateError::RequiredInsertCountMismatch {
                required_insert_count: 0,
                expected_required_insert_count: 1,
            })
        );
        assert_eq!(
            state.register(8, 6, &[2, 7, 2, 5], 8),
            Err(QpackEncoderStateError::RequiredInsertCountMismatch {
                required_insert_count: 6,
                expected_required_insert_count: 8,
            })
        );
        assert_eq!(
            state.register(8, 0, &[u64::MAX], u64::MAX),
            Err(QpackEncoderStateError::RequiredInsertCountOverflow {
                absolute_index: u64::MAX,
            })
        );

        assert_eq!(
            state.register(8, 2, &[1], 1),
            Err(
                QpackEncoderStateError::RequiredInsertCountExceedsInsertCount {
                    required_insert_count: 2,
                    encoder_insert_count: 1,
                }
            )
        );
        let short = state
            .register(8, 3, &[0, 1, 2], 8)
            .expect_err("short references");
        assert_eq!(
            short,
            QpackEncoderStateError::ReferenceStorageTooShort {
                required: 3,
                available: 2,
            }
        );
        assert!(short.is_provisioning_error());
        assert!(!short.is_blocked_streams_limit_error());
        assert_eq!(
            (
                state.len(),
                state.reference_len(),
                state.blocked_stream_count(),
                state.is_empty()
            ),
            before
        );
        let blocked = state.register(8, 1, &[0], 8).expect_err("blocked limit");
        assert_eq!(
            blocked,
            QpackEncoderStateError::BlockedStreamsLimitExceeded { maximum: 1 }
        );
        assert!(!blocked.is_provisioning_error());
        assert!(blocked.is_blocked_streams_limit_error());
        assert_eq!(
            (
                state.len(),
                state.reference_len(),
                state.blocked_stream_count(),
                state.is_empty()
            ),
            before
        );
    }
    assert_eq!(references, [2, 7, 2, 5, 0, 0]);
    assert_eq!(
        (
            sections[0].stream_id(),
            sections[0].required_insert_count(),
            sections[0].reference_len(),
            sections[1],
        ),
        (7, 8, 4, QpackEncoderOutstandingSection::EMPTY)
    );

    let mut full_sections = [QpackEncoderOutstandingSection::EMPTY; 1];
    let mut full_references = [0; 2];
    {
        let mut full = QpackEncoderState::new(&mut full_sections, &mut full_references, u64::MAX);
        assert_eq!(full.register(0, 1, &[0], 1), Ok(()));
        let before = (
            full.len(),
            full.reference_len(),
            full.blocked_stream_count(),
            full.is_empty(),
        );
        let exhausted = full
            .register(u64::MAX, 1, &[0], 1)
            .expect_err("section storage");
        assert_eq!(
            exhausted,
            QpackEncoderStateError::SectionStorageExhausted { capacity: 1 }
        );
        assert!(exhausted.is_provisioning_error());
        assert!(!exhausted.is_blocked_streams_limit_error());
        assert_eq!(
            (
                full.len(),
                full.reference_len(),
                full.blocked_stream_count(),
                full.is_empty()
            ),
            before
        );
    }
    assert_eq!(full_references, [0, 0]);
    assert_eq!(
        (
            full_sections[0].stream_id(),
            full_sections[0].required_insert_count(),
            full_sections[0].reference_len(),
        ),
        (0, 1, 1)
    );
}

#[test]
fn qpack_encoder_state_section_acknowledgment_compacts_and_is_atomic() {
    let mut sections = [QpackEncoderOutstandingSection::EMPTY; 5];
    let mut references = [0; 10];
    {
        let mut state = QpackEncoderState::new(&mut sections, &mut references, 3);
        assert_eq!(state.register(7, 3, &[0, 2], 5), Ok(()));
        assert_eq!(state.register(8, 2, &[1], 5), Ok(()));
        assert_eq!(state.register(7, 5, &[4, 2], 5), Ok(()));
        assert_eq!(state.register(9, 4, &[3], 5), Ok(()));

        let acknowledgment = QpackDecoderInstruction::parse(&[0x87]).expect("acknowledgment");
        assert_eq!(state.apply(acknowledgment, 5), Ok(()));
        assert_eq!(
            (
                state.known_received_count(),
                state.len(),
                state.reference_len(),
                state.blocked_stream_count(),
            ),
            (3, 3, 4, 2)
        );
        assert!(state.is_evictable(0));
        assert!(!state.is_evictable(1));
        assert!(!state.is_evictable(2));
        assert!(!state.is_evictable(3));

        let acknowledgment =
            QpackDecoderInstruction::parse(&[0x87]).expect("second acknowledgment");
        assert_eq!(state.apply(acknowledgment, 5), Ok(()));
        assert_eq!(
            (
                state.known_received_count(),
                state.len(),
                state.reference_len(),
                state.blocked_stream_count(),
            ),
            (5, 2, 2, 0)
        );

        let before = (
            state.known_received_count(),
            state.len(),
            state.reference_len(),
            state.blocked_stream_count(),
        );
        let error = state
            .apply(
                QpackDecoderInstruction::parse(&[0x87]).expect("exhausted acknowledgment"),
                5,
            )
            .expect_err("no matching outstanding section");
        assert_eq!(
            error,
            QpackDecoderInstructionApplyError::SectionAcknowledgmentWithoutOutstandingReferences {
                stream_id: 7,
            }
        );
        assert!(error.is_decoder_stream_error());
        assert!(error.to_string().contains("7"));
        assert!(error.to_string().contains("outstanding"));
        assert_eq!(
            (
                state.known_received_count(),
                state.len(),
                state.reference_len(),
                state.blocked_stream_count(),
            ),
            before
        );
        assert_eq!(
            state.apply(
                QpackDecoderInstruction::parse(&[0xe3]).expect("unknown acknowledgment"),
                5,
            ),
            Err(QpackDecoderInstructionApplyError::SectionAcknowledgmentWithoutOutstandingReferences {
                stream_id: 99,
            })
        );
        assert_eq!(
            (
                state.known_received_count(),
                state.len(),
                state.reference_len(),
                state.blocked_stream_count(),
            ),
            before
        );
    }
    assert_eq!(references, [1, 3, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        (
            sections[0].stream_id(),
            sections[0].required_insert_count(),
            sections[0].reference_len(),
            sections[1].stream_id(),
            sections[1].required_insert_count(),
            sections[1].reference_len(),
        ),
        (8, 2, 1, 9, 4, 1)
    );
    assert_eq!(sections[2..], [QpackEncoderOutstandingSection::EMPTY; 3]);
}

#[test]
fn qpack_encoder_state_cancellation_removes_all_matching_sections() {
    let mut sections = [QpackEncoderOutstandingSection::EMPTY; 5];
    let mut references = [0; 8];
    {
        let mut state = QpackEncoderState::new(&mut sections, &mut references, 3);
        assert_eq!(state.register(1, 2, &[1], 5), Ok(()));
        assert_eq!(state.register(2, 5, &[4, 0], 5), Ok(()));
        assert_eq!(state.register(2, 3, &[2], 5), Ok(()));
        assert_eq!(state.register(3, 4, &[3], 5), Ok(()));
        assert_eq!(
            state.apply(
                QpackDecoderInstruction::parse(&[0x42]).expect("cancellation"),
                5
            ),
            Ok(())
        );
        assert_eq!(
            (
                state.known_received_count(),
                state.len(),
                state.reference_len(),
                state.blocked_stream_count(),
            ),
            (0, 2, 2, 2)
        );

        let before = (
            state.known_received_count(),
            state.len(),
            state.reference_len(),
            state.blocked_stream_count(),
        );
        assert_eq!(
            state.apply(
                QpackDecoderInstruction::parse(&[0x49]).expect("unknown cancellation"),
                5
            ),
            Ok(())
        );
        assert_eq!(
            (
                state.known_received_count(),
                state.len(),
                state.reference_len(),
                state.blocked_stream_count(),
            ),
            before
        );
    }
    assert_eq!(references, [1, 3, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        (
            sections[0].stream_id(),
            sections[0].required_insert_count(),
            sections[0].reference_len(),
            sections[1].stream_id(),
            sections[1].required_insert_count(),
            sections[1].reference_len(),
        ),
        (1, 2, 1, 3, 4, 1)
    );
    assert_eq!(sections[2..], [QpackEncoderOutstandingSection::EMPTY; 3]);
}

#[test]
fn qpack_encoder_state_insert_count_increment_errors_and_overflow_are_exact() {
    let mut sections = [QpackEncoderOutstandingSection::EMPTY; 2];
    let mut references = [0; 2];
    {
        let mut state = QpackEncoderState::new(&mut sections, &mut references, 2);
        assert_eq!(state.register(1, 2, &[1], 4), Ok(()));
        assert_eq!(state.register(2, 4, &[3], 4), Ok(()));
        let before = (
            state.known_received_count(),
            state.len(),
            state.reference_len(),
            state.blocked_stream_count(),
        );
        assert_eq!(
            state.apply(
                QpackDecoderInstruction::parse(&[0]).expect("zero increment"),
                4
            ),
            Err(QpackDecoderInstructionApplyError::InsertCountIncrementZero)
        );
        assert_eq!(
            (
                state.known_received_count(),
                state.len(),
                state.reference_len(),
                state.blocked_stream_count(),
            ),
            before
        );

        assert_eq!(
            state.apply(QpackDecoderInstruction::parse(&[2]).expect("increment"), 4),
            Ok(())
        );
        assert_eq!(
            (
                state.known_received_count(),
                state.len(),
                state.reference_len(),
                state.blocked_stream_count(),
            ),
            (2, 2, 2, 1)
        );
        assert!(state.is_evictable(0));
        assert!(!state.is_evictable(1));
        assert!(!state.is_evictable(2));

        let before = (
            state.known_received_count(),
            state.len(),
            state.reference_len(),
            state.blocked_stream_count(),
        );
        assert_eq!(
            state.apply(
                QpackDecoderInstruction::parse(&[3]).expect("excess increment"),
                4
            ),
            Err(
                QpackDecoderInstructionApplyError::InsertCountIncrementExceedsInsertCount {
                    known_received_count: 2,
                    increment: 3,
                    encoder_insert_count: 4,
                }
            )
        );
        assert_eq!(
            (
                state.known_received_count(),
                state.len(),
                state.reference_len(),
                state.blocked_stream_count(),
            ),
            before
        );
    }

    let mut no_sections = [];
    let mut no_references = [];
    let mut overflow = QpackEncoderState::new(&mut no_sections, &mut no_references, 0);
    let mut maximum_wire = [0; 16];
    let maximum_increment = {
        let built = QpackInsertCountIncrementBuilder::new(&mut maximum_wire, QPACK_INTEGER_MAX)
            .build()
            .expect("maximum legal increment");
        QpackDecoderInstruction::parse(built.as_bytes()).expect("parsed maximum legal increment")
    };
    for _ in 0..4 {
        assert_eq!(overflow.apply(maximum_increment, u64::MAX), Ok(()));
    }
    assert_eq!(overflow.known_received_count(), u64::MAX - 3);
    assert_eq!(
        overflow.apply(
            QpackDecoderInstruction::parse(&[4]).expect("overflow increment"),
            u64::MAX
        ),
        Err(
            QpackDecoderInstructionApplyError::InsertCountIncrementExceedsInsertCount {
                known_received_count: u64::MAX - 3,
                increment: 4,
                encoder_insert_count: u64::MAX,
            }
        )
    );
    assert_eq!(overflow.known_received_count(), u64::MAX - 3);
    assert_eq!(
        overflow.apply(
            QpackDecoderInstruction::parse(&[3]).expect("final increment"),
            u64::MAX
        ),
        Ok(())
    );
    assert_eq!(overflow.known_received_count(), u64::MAX);
    assert_eq!(
        overflow.apply(
            QpackDecoderInstruction::parse(&[1]).expect("overflow increment"),
            u64::MAX
        ),
        Err(
            QpackDecoderInstructionApplyError::InsertCountIncrementExceedsInsertCount {
                known_received_count: u64::MAX,
                increment: 1,

                encoder_insert_count: u64::MAX,
            }
        )
    );
    assert_eq!(overflow.known_received_count(), u64::MAX);
}

#[test]
fn qpack_encoder_state_apply_sequence_mixes_instructions_and_preserves_packed_storage() {
    let _: Option<net_wire::qpack::QpackDecoderInstructionsApplyError> = None;

    let mut no_sections = [];
    let mut no_references = [];
    let mut empty = QpackEncoderState::new(&mut no_sections, &mut no_references, 0);
    assert_eq!(empty.apply_sequence(&[], 0), Ok(()));
    assert_eq!(
        (
            empty.known_received_count(),
            empty.len(),
            empty.reference_len(),
            empty.blocked_stream_count(),
            empty.is_empty(),
        ),
        (0, 0, 0, 0, true)
    );

    let mut sections = [QpackEncoderOutstandingSection::EMPTY; 5];
    let mut references = [0; 8];
    {
        let mut state = QpackEncoderState::new(&mut sections, &mut references, 3);
        assert_eq!(state.register(7, 3, &[0, 2], 5), Ok(()));
        assert_eq!(state.register(8, 2, &[1], 5), Ok(()));
        assert_eq!(state.register(7, 5, &[4, 2], 5), Ok(()));
        assert_eq!(state.register(9, 4, &[3], 5), Ok(()));

        // Section Acknowledgment(7), Stream Cancellation(9), Insert Count Increment(2).
        let sequence = [0x87, 0x49, 0x02];
        assert_eq!(state.apply_sequence(&sequence, 5), Ok(()));
        assert_eq!(
            (
                state.known_received_count(),
                state.len(),
                state.reference_len(),
                state.blocked_stream_count(),
            ),
            (5, 2, 3, 0)
        );
        assert!(state.is_evictable(0));
        assert!(!state.is_evictable(1));
        assert!(!state.is_evictable(2));
        assert!(state.is_evictable(3));
        assert!(!state.is_evictable(4));
        assert!(!state.is_evictable(5));
    }
    assert_eq!(references, [1, 4, 2, 0, 0, 0, 0, 0]);
    assert_eq!(
        (
            sections[0].stream_id(),
            sections[0].required_insert_count(),
            sections[0].reference_len(),
            sections[1].stream_id(),
            sections[1].required_insert_count(),
            sections[1].reference_len(),
        ),
        (8, 2, 1, 7, 5, 2)
    );
    assert_eq!(sections[2..], [QpackEncoderOutstandingSection::EMPTY; 3]);
}

#[test]
fn qpack_encoder_state_apply_sequence_parse_prevalidation_is_atomic() {
    let mut sections = [QpackEncoderOutstandingSection::EMPTY; 3];
    let mut references = [0; 5];
    {
        let mut state = QpackEncoderState::new(&mut sections, &mut references, 2);
        assert_eq!(state.register(1, 2, &[1], 4), Ok(()));
        assert_eq!(state.register(2, 4, &[3, 2], 4), Ok(()));

        // Insert Count Increment(1) is valid, but the following Section Acknowledgment is truncated.
        let error = state
            .apply_sequence(&[0x01, 0xff], 4)
            .expect_err("a malformed complete sequence must not apply its valid prefix");
        assert_eq!(
            error,
            QpackDecoderInstructionsApplyError::Parse(QpackDecoderInstructionsParseError {
                offset: 1,
                error: QpackDecoderInstructionParseError::SectionAcknowledgment(
                    QpackIntegerParseError::Incomplete {
                        required: 2,
                        available: 1,
                    },
                ),
            })
        );
        assert!(error.is_decoder_stream_error());
        assert!(error.to_string().contains("invalid"));
        assert!(error.to_string().contains("byte 1"));
        assert_eq!(
            (
                state.known_received_count(),
                state.len(),
                state.reference_len(),
                state.blocked_stream_count(),
            ),
            (0, 2, 3, 2)
        );
    }
    assert_eq!(references, [1, 3, 2, 0, 0]);
    assert_eq!(
        (
            sections[0].stream_id(),
            sections[0].required_insert_count(),
            sections[0].reference_len(),
            sections[1].stream_id(),
            sections[1].required_insert_count(),
            sections[1].reference_len(),
        ),
        (1, 2, 1, 2, 4, 2)
    );
    assert_eq!(sections[2], QpackEncoderOutstandingSection::EMPTY);
}

#[test]
fn qpack_encoder_state_apply_sequence_commits_prefix_at_exact_failure_offset() {
    let mut sections = [QpackEncoderOutstandingSection::EMPTY; 3];
    let mut references = [0; 5];
    {
        let mut state = QpackEncoderState::new(&mut sections, &mut references, 2);
        assert_eq!(state.register(2, 4, &[3, 1], 100), Ok(()));
        assert_eq!(state.register(5, 5, &[4], 100), Ok(()));

        // A noncanonical Insert Count Increment(63), then unknown acknowledgment, then cancellation.
        let sequence = [0x3f, 0x80, 0x00, 0xe3, 0x42];
        let error = state
            .apply_sequence(&sequence, 100)
            .expect_err("unknown acknowledgment stops the sequence");
        assert_eq!(
            error,
            QpackDecoderInstructionsApplyError::Apply {
                offset: 3,
                error: QpackDecoderInstructionApplyError::SectionAcknowledgmentWithoutOutstandingReferences {
                    stream_id: 99,
                },
            }
        );
        assert!(error.is_decoder_stream_error());
        assert!(error.to_string().contains("byte 3"));
        assert!(error.to_string().contains("99"));
        assert_eq!(
            (
                state.known_received_count(),
                state.len(),
                state.reference_len(),
                state.blocked_stream_count(),
            ),
            (63, 2, 3, 0)
        );
        assert!(state.is_evictable(0));
        assert!(!state.is_evictable(1));
        assert!(!state.is_evictable(3));
        assert!(!state.is_evictable(4));
    }
    assert_eq!(references, [3, 1, 4, 0, 0]);
    assert_eq!(
        (
            sections[0].stream_id(),
            sections[0].required_insert_count(),
            sections[0].reference_len(),
            sections[1].stream_id(),
            sections[1].required_insert_count(),
            sections[1].reference_len(),
        ),
        (2, 4, 2, 5, 5, 1)
    );
    assert_eq!(sections[2], QpackEncoderOutstandingSection::EMPTY);
}
