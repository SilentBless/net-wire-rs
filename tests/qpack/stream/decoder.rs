use net_wire::qpack;
use net_wire::qpack::{
    QPACK_INTEGER_MAX, QpackDecoderInstruction, QpackDecoderInstructionBuildError,
    QpackDecoderInstructionParseError, QpackDecoderInstructions,
    QpackDecoderInstructionsParseError, QpackIntegerBuildError, QpackIntegerParseError,
};

#[test]
fn qpack_decoder_instruction_rfc9204_appendix_b_vectors_are_exact() {
    let acknowledgment = [0x84];
    let cancellation = [0x48];
    let increment = [0x01];

    assert!(matches!(
        QpackDecoderInstruction::parse(&acknowledgment),
        Ok(QpackDecoderInstruction::SectionAcknowledgment(instruction))
            if instruction.stream_id().value() == 4 && instruction.as_bytes() == acknowledgment
    ));
    assert!(matches!(
        QpackDecoderInstruction::parse(&cancellation),
        Ok(QpackDecoderInstruction::StreamCancellation(instruction))
            if instruction.stream_id().value() == 8 && instruction.as_bytes() == cancellation
    ));
    assert!(matches!(
        QpackDecoderInstruction::parse(&increment),
        Ok(QpackDecoderInstruction::InsertCountIncrement(instruction))
            if instruction.increment().value() == 1 && instruction.as_bytes() == increment
    ));
}

#[test]
fn qpack_decoder_instruction_dispatch_suffix_and_noncanonical_integers_are_exact() {
    for (wire, expected) in [
        (&[0x80, 0xaa][..], &[0x80][..]),
        (&[0xff, 0x80, 0, 0xaa][..], &[0xff, 0x80, 0][..]),
        (&[0x40, 0xaa][..], &[0x40][..]),
        (&[0x7f, 0x80, 0, 0xaa][..], &[0x7f, 0x80, 0][..]),
        (&[0, 0xaa][..], &[0][..]),
        (&[0x3f, 0x80, 0, 0xaa][..], &[0x3f, 0x80, 0][..]),
    ] {
        assert_eq!(
            QpackDecoderInstruction::parse(wire).map(QpackDecoderInstruction::as_bytes),
            Ok(expected)
        );
    }
    assert!(matches!(
        QpackDecoderInstruction::parse(&[0, 0xaa]),
        Ok(QpackDecoderInstruction::InsertCountIncrement(instruction))
            if instruction.increment().value() == 0 && instruction.as_bytes() == [0]
    ));
    assert!(matches!(
        QpackDecoderInstruction::parse(&[0xff, 0x80, 0]),
        Ok(QpackDecoderInstruction::SectionAcknowledgment(instruction))
            if instruction.stream_id().value() == 127
                && instruction.stream_id().as_bytes() == [0xff, 0x80, 0]
    ));
    assert!(matches!(
        QpackDecoderInstruction::parse(&[0x7f, 0x80, 0]),
        Ok(QpackDecoderInstruction::StreamCancellation(instruction))
            if instruction.stream_id().value() == 63
                && instruction.stream_id().as_bytes() == [0x7f, 0x80, 0]
    ));
    assert!(matches!(
        QpackDecoderInstruction::parse(&[0x3f, 0x80, 0]),
        Ok(QpackDecoderInstruction::InsertCountIncrement(instruction))
            if instruction.increment().value() == 63
                && instruction.increment().as_bytes() == [0x3f, 0x80, 0]
    ));
}

#[test]
fn qpack_decoder_instruction_truncation_sequence_and_iteration_are_exact() {
    assert_eq!(
        QpackDecoderInstruction::parse(&[]),
        Err(QpackDecoderInstructionParseError::DispatchIncomplete)
    );
    for (wire, expected) in [
        (
            &[0xff][..],
            QpackDecoderInstructionParseError::SectionAcknowledgment(
                QpackIntegerParseError::Incomplete {
                    required: 2,
                    available: 1,
                },
            ),
        ),
        (
            &[0xff, 0x80][..],
            QpackDecoderInstructionParseError::SectionAcknowledgment(
                QpackIntegerParseError::Incomplete {
                    required: 3,
                    available: 2,
                },
            ),
        ),
        (
            &[0x7f][..],
            QpackDecoderInstructionParseError::StreamCancellation(
                QpackIntegerParseError::Incomplete {
                    required: 2,
                    available: 1,
                },
            ),
        ),
        (
            &[0x7f, 0x80][..],
            QpackDecoderInstructionParseError::StreamCancellation(
                QpackIntegerParseError::Incomplete {
                    required: 3,
                    available: 2,
                },
            ),
        ),
        (
            &[0x3f][..],
            QpackDecoderInstructionParseError::InsertCountIncrement(
                QpackIntegerParseError::Incomplete {
                    required: 2,
                    available: 1,
                },
            ),
        ),
        (
            &[0x3f, 0x80][..],
            QpackDecoderInstructionParseError::InsertCountIncrement(
                QpackIntegerParseError::Incomplete {
                    required: 3,
                    available: 2,
                },
            ),
        ),
    ] {
        assert_eq!(QpackDecoderInstruction::parse(wire), Err(expected));
    }

    let sequence = [0x84, 0x48, 0x00];
    let parsed = QpackDecoderInstructions::parse(&sequence).expect("complete sequence");
    assert_eq!(parsed.as_bytes(), sequence);
    assert_eq!(parsed.iter().count(), 3);
    assert_eq!(
        QpackDecoderInstructions::parse(&[]).map(|instructions| instructions.iter().count()),
        Ok(0)
    );
    assert_eq!(
        QpackDecoderInstructions::parse(&[0x84, 0xff]),
        Err(QpackDecoderInstructionsParseError {
            offset: 1,
            error: QpackDecoderInstructionParseError::SectionAcknowledgment(
                QpackIntegerParseError::Incomplete {
                    required: 2,
                    available: 1
                },
            ),
        })
    );
    let mut iterator = parsed.iter();
    assert!(iterator.next().is_some());
    assert!(iterator.next().is_some());
    assert!(iterator.next().is_some());
    assert_eq!(iterator.next(), None);
    assert_eq!(iterator.next(), None);
}

#[test]
fn qpack_decoder_instruction_builders_are_canonical_and_atomic() {
    let mut acknowledgment = [0xaa; 2];
    assert_eq!(
        net_wire::qpack::QpackSectionAcknowledgmentBuilder::new(&mut acknowledgment, 4)
            .build()
            .map(|instruction| instruction.as_bytes()),
        Ok(&[0x84][..])
    );
    assert_eq!(acknowledgment[1], 0xaa);
    let mut cancellation = [0xaa; 2];
    assert_eq!(
        net_wire::qpack::QpackStreamCancellationBuilder::new(&mut cancellation, 8)
            .build()
            .map(|instruction| instruction.as_bytes()),
        Ok(&[0x48][..])
    );
    assert_eq!(cancellation[1], 0xaa);
    let mut increment = [0xaa; 2];
    assert_eq!(
        net_wire::qpack::QpackInsertCountIncrementBuilder::new(&mut increment, 1)
            .build()
            .map(|instruction| instruction.as_bytes()),
        Ok(&[0x01][..])
    );
    assert_eq!(increment[1], 0xaa);
    let mut zero = [0xaa; 1];
    assert_eq!(
        net_wire::qpack::QpackInsertCountIncrementBuilder::new(&mut zero, 0)
            .build()
            .map(|instruction| (instruction.increment().value(), instruction.as_bytes())),
        Ok((0, &[0][..]))
    );

    let mut acknowledgment_boundary = [0xaa; 2];
    assert_eq!(
        net_wire::qpack::QpackSectionAcknowledgmentBuilder::new(&mut acknowledgment_boundary, 127)
            .build()
            .map(|instruction| instruction.as_bytes()),
        Ok(&[0xff, 0][..])
    );
    let mut cancellation_boundary = [0xaa; 2];
    assert_eq!(
        net_wire::qpack::QpackStreamCancellationBuilder::new(&mut cancellation_boundary, 63)
            .build()
            .map(|instruction| instruction.as_bytes()),
        Ok(&[0x7f, 0][..])
    );
    let mut increment_boundary = [0xaa; 2];
    assert_eq!(
        net_wire::qpack::QpackInsertCountIncrementBuilder::new(&mut increment_boundary, 63)
            .build()
            .map(|instruction| instruction.as_bytes()),
        Ok(&[0x3f, 0][..])
    );

    let error = QpackDecoderInstructionBuildError::BufferTooShort {
        required: 1,
        available: 0,
    };
    let mut section = [0xaa; 1];
    let before = section;
    assert_eq!(
        net_wire::qpack::QpackSectionAcknowledgmentBuilder::new(&mut section[..0], 4).build(),
        Err(error)
    );
    assert_eq!(section, before);
    let mut cancel = [0xaa; 1];
    let before = cancel;
    assert_eq!(
        net_wire::qpack::QpackStreamCancellationBuilder::new(&mut cancel[..0], 8).build(),
        Err(error)
    );
    assert_eq!(cancel, before);
    let mut count = [0xaa; 1];
    let before = count;
    assert_eq!(
        net_wire::qpack::QpackInsertCountIncrementBuilder::new(&mut count[..0], 0).build(),
        Err(error)
    );
    assert_eq!(count, before);

    let too_large = QPACK_INTEGER_MAX + 1;
    let mut section = [0xaa; 16];
    let before = section;
    assert_eq!(
        net_wire::qpack::QpackSectionAcknowledgmentBuilder::new(&mut section, too_large).build(),
        Err(QpackDecoderInstructionBuildError::SectionAcknowledgment(
            QpackIntegerBuildError::ValueTooLarge { value: too_large },
        ))
    );
    assert_eq!(section, before);
    let mut cancel = [0xaa; 16];
    let before = cancel;
    assert_eq!(
        net_wire::qpack::QpackStreamCancellationBuilder::new(&mut cancel, too_large).build(),
        Err(QpackDecoderInstructionBuildError::StreamCancellation(
            QpackIntegerBuildError::ValueTooLarge { value: too_large },
        ))
    );
    assert_eq!(cancel, before);
    let mut count = [0xaa; 16];
    let before = count;
    assert_eq!(
        net_wire::qpack::QpackInsertCountIncrementBuilder::new(&mut count, too_large).build(),
        Err(QpackDecoderInstructionBuildError::InsertCountIncrement(
            QpackIntegerBuildError::ValueTooLarge { value: too_large },
        ))
    );
    assert_eq!(count, before);
}

#[test]
fn qpack_decoder_instruction_public_namespace_compiles() {
    let _: Option<qpack::QpackDecoderInstruction<'static>> = None;
    let _: Option<qpack::QpackSectionAcknowledgment<'static>> = None;
    let _: Option<qpack::QpackStreamCancellation<'static>> = None;
    let _: Option<qpack::QpackInsertCountIncrement<'static>> = None;
    let _: Option<qpack::QpackDecoderInstructions<'static>> = None;
    let _: Option<qpack::QpackDecoderInstructionIter<'static>> = None;
    let _: Option<qpack::QpackDecoderInstructionParseError> = None;
    let _: Option<qpack::QpackDecoderInstructionsParseError> = None;
    let _: Option<qpack::QpackDecoderInstructionBuildError> = None;
    let _: Option<qpack::QpackSectionAcknowledgmentBuilder<'static>> = None;
    let _: Option<qpack::QpackStreamCancellationBuilder<'static>> = None;
    let _: Option<qpack::QpackInsertCountIncrementBuilder<'static>> = None;
}
