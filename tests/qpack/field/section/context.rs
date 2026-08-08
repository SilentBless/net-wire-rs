use net_wire::qpack;
use net_wire::qpack::{
    QpackFieldSectionContext, QpackFieldSectionContextError, QpackFieldSectionPrefix,
};

#[test]
fn qpack_field_section_context_rfc_reconstruction_and_base_are_exact() {
    assert_eq!(
        QpackFieldSectionContext::reconstruct_required_insert_count(4, 10, 100),
        Ok(9)
    );
    assert_eq!(
        QpackFieldSectionContext::encode_required_insert_count(9, 100),
        Ok(4)
    );
    assert_eq!(
        QpackFieldSectionContext::reconstruct_required_insert_count(1, 10, 100),
        Ok(12)
    );
    assert_eq!(
        QpackFieldSectionContext::encode_required_insert_count(12, 100),
        Ok(1)
    );
    assert_eq!(
        QpackFieldSectionContext::reconstruct_required_insert_count(0, 10, 0),
        Ok(0)
    );
    assert_eq!(
        QpackFieldSectionContext::encode_required_insert_count(0, 0),
        Ok(0)
    );
    assert_eq!(QpackFieldSectionContext::resolve_base(9, false, 2), Ok(11));
    assert_eq!(QpackFieldSectionContext::resolve_base(9, true, 2), Ok(6));

    let negative_prefix = match QpackFieldSectionPrefix::parse(&[0x04, 0x82]) {
        Ok(prefix) => prefix,
        Err(error) => panic!("{error}"),
    };
    assert_eq!(
        QpackFieldSectionContext::decode(negative_prefix, 10, 100)
            .map(|context| (context.required_insert_count(), context.base())),
        Ok((9, 6))
    );
    let positive_prefix = match QpackFieldSectionPrefix::parse(&[0x04, 0x02]) {
        Ok(prefix) => prefix,
        Err(error) => panic!("{error}"),
    };
    assert_eq!(
        QpackFieldSectionContext::decode(positive_prefix, 10, 100)
            .map(|context| (context.required_insert_count(), context.base())),
        Ok((9, 11))
    );
}

#[test]
fn qpack_field_section_context_invalid_counts_and_arithmetic_are_exact() {
    assert_eq!(
        QpackFieldSectionContext::reconstruct_required_insert_count(1, 0, 31),
        Err(QpackFieldSectionContextError::ZeroMaximumEntries {
            encoded_required_insert_count: 1,
        })
    );
    assert_eq!(
        QpackFieldSectionContext::encode_required_insert_count(1, 31),
        Err(QpackFieldSectionContextError::ZeroMaximumEntries {
            encoded_required_insert_count: 1,
        })
    );
    assert_eq!(
        QpackFieldSectionContext::reconstruct_required_insert_count(7, 10, 100),
        Err(
            QpackFieldSectionContextError::EncodedRequiredInsertCountOutOfRange {
                encoded_required_insert_count: 7,
                full_range: 6,
            }
        )
    );
    assert_eq!(
        QpackFieldSectionContext::reconstruct_required_insert_count(5, 0, 100),
        Err(QpackFieldSectionContextError::RequiredInsertCountTooOld {
            reconstructed: 4,
            maximum_value: 3,
            full_range: 6,
        })
    );
    assert_eq!(
        QpackFieldSectionContext::reconstruct_required_insert_count(1, 0, 100),
        Err(QpackFieldSectionContextError::RequiredInsertCountZero)
    );
    assert_eq!(
        QpackFieldSectionContext::reconstruct_required_insert_count(1, u64::MAX, 32),
        Err(QpackFieldSectionContextError::MaximumValueOverflow {
            total_insert_count: u64::MAX,
            max_entries: 1,
        })
    );
    assert_eq!(
        QpackFieldSectionContext::reconstruct_required_insert_count(
            1_152_921_504_606_846_974,
            17_870_283_321_406_128_128,
            u64::MAX,
        ),
        Err(QpackFieldSectionContextError::RequiredInsertCountOverflow {
            max_wrapped: 18_446_744_073_709_551_584,
            encoded_required_insert_count: 1_152_921_504_606_846_974,
        })
    );
    assert_eq!(
        QpackFieldSectionContext::resolve_base(u64::MAX, false, 1),
        Err(QpackFieldSectionContextError::BaseOverflow {
            required_insert_count: u64::MAX,
            delta_base: 1,
        })
    );
    for (required_insert_count, delta_base) in [(9, 9), (0, 0)] {
        assert_eq!(
            QpackFieldSectionContext::resolve_base(required_insert_count, true, delta_base),
            Err(QpackFieldSectionContextError::BaseUnderflow {
                required_insert_count,
                delta_base,
            })
        );
    }
    let prefix = match QpackFieldSectionPrefix::parse(&[0x07, 0x80]) {
        Ok(prefix) => prefix,
        Err(error) => panic!("{error}"),
    };
    assert_eq!(
        QpackFieldSectionContext::decode(prefix, 10, 100),
        Err(
            QpackFieldSectionContextError::EncodedRequiredInsertCountOutOfRange {
                encoded_required_insert_count: 7,
                full_range: 6,
            }
        )
    );
}

#[test]
fn qpack_field_section_context_public_namespace_is_complete() {
    let _: Option<qpack::QpackFieldSectionContext> = None;
    let _: Option<qpack::QpackFieldSectionContextError> = None;

    let module: Result<qpack::QpackFieldSectionContext, qpack::QpackFieldSectionContextError> =
        match qpack::QpackFieldSectionPrefix::parse(&[0x04, 0x82]) {
            Ok(prefix) => qpack::QpackFieldSectionContext::decode(prefix, 10, 100),
            Err(error) => panic!("{error}"),
        };
    assert_eq!(
        module.map(|context| (context.required_insert_count(), context.base())),
        Ok((9, 6))
    );
}
