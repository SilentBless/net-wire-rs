use net_wire::{
    QPACK_INTEGER_MAX, QPACK_STATIC_TABLE_LEN, QpackBlockedStream, QpackBlockedStreams,
    QpackBlockedStreamsError, QpackDecodedFieldEntry, QpackDecodedFieldIter, QpackDecodedFieldRef,
    QpackDecodedFieldSection, QpackDecoderFeedbackError, QpackDecoderInstruction,
    QpackDecoderInstructionApplyError, QpackDecoderInstructionBuildError,
    QpackDecoderInstructionParseError, QpackDecoderInstructions,
    QpackDecoderInstructionsApplyError, QpackDecoderInstructionsParseError, QpackDecoderState,
    QpackDuplicate, QpackDuplicateBuilder, QpackDynamicTable, QpackDynamicTableEntry,
    QpackDynamicTableError, QpackEncoderInstruction, QpackEncoderInstructionApplier,
    QpackEncoderInstructionApplyError, QpackEncoderInstructionApplyOutcome,
    QpackEncoderInstructionBuildError, QpackEncoderInstructionParseError, QpackEncoderInstructions,
    QpackEncoderInstructionsApplyError, QpackEncoderInstructionsParseError,
    QpackEncoderOutstandingSection, QpackEncoderState, QpackEncoderStateError, QpackFieldLine,
    QpackFieldLineBuildError, QpackFieldLineIter, QpackFieldLineParseError, QpackFieldLines,
    QpackFieldPlan, QpackFieldSectionBase, QpackFieldSectionBlocked, QpackFieldSectionContext,
    QpackFieldSectionContextError, QpackFieldSectionDecodeError, QpackFieldSectionDecodeOutcome,
    QpackFieldSectionDecoder, QpackFieldSectionEncodeBuffers, QpackFieldSectionEncodeError,
    QpackFieldSectionEncoder, QpackFieldSectionOutput, QpackFieldSectionPlanError,
    QpackFieldSectionPlanSlot, QpackFieldSectionPrefix, QpackFieldSectionPrefixBuildError,
    QpackFieldSectionPrefixBuilder, QpackFieldSectionPrefixParseError, QpackHeaderFieldRef,
    QpackHuffmanDecodeError, QpackHuffmanDecoder, QpackHuffmanEncodeError, QpackHuffmanEncoder,
    QpackIndexedFieldLineBuilder, QpackIndexedPostBaseFieldLineBuilder,
    QpackInsertCountIncrementBuilder, QpackInsertWithLiteralNameBuilder,
    QpackInsertWithNameReferenceBuilder, QpackInteger, QpackIntegerBuildError, QpackIntegerBuilder,
    QpackIntegerParseError, QpackLiteralNameFieldLineBuilder,
    QpackLiteralNameReferenceFieldLineBuilder, QpackLiteralPostBaseNameReferenceFieldLineBuilder,
    QpackReadyBlockedStreamIter, QpackSetDynamicTableCapacityBuilder, QpackStaticTable,
    QpackStringLiteral, QpackStringLiteralBuildError, QpackStringLiteralBuilder,
    QpackStringLiteralParseError, qpack,
};

#[test]
fn rfc_integer_examples_are_exact_and_bounded() {
    let ten = [0x0a, 0xaa];
    assert_eq!(
        QpackInteger::parse(&ten, 5).map(|integer| (integer.value(), integer.as_bytes())),
        Ok((10, &ten[..1]))
    );
    let thirteen_thirty_seven = [0x1f, 0x9a, 0x0a, 0xaa];
    assert_eq!(
        QpackInteger::parse(&thirteen_thirty_seven, 5)
            .map(|integer| (integer.value(), integer.as_bytes())),
        Ok((1337, &thirteen_thirty_seven[..3]))
    );
    let forty_two = [42, 0xaa];
    assert_eq!(
        QpackInteger::parse(&forty_two, 8).map(|integer| (integer.value(), integer.as_bytes())),
        Ok((42, &forty_two[..1]))
    );
}

#[test]
fn every_prefix_width_preserves_legal_high_bits() {
    for prefix_bits in 1..=8 {
        let mask = if prefix_bits == 8 {
            0xff
        } else {
            (1u8 << prefix_bits) - 1
        };
        let high_bits = !mask;
        let mut destination = [0xaa; 2];
        assert_eq!(
            QpackIntegerBuilder::new(&mut destination, prefix_bits, high_bits, 0)
                .build()
                .map(|integer| {
                    (
                        integer.as_bytes(),
                        integer.high_bits(),
                        integer.prefix_bits(),
                    )
                }),
            Ok((&[high_bits][..], high_bits, prefix_bits))
        );
    }
}

#[test]
fn saturated_prefix_and_continuation_boundaries_are_canonical() {
    for (value, expected) in [
        (31, &[0x1f, 0][..]),
        (158, &[0x1f, 127][..]),
        (159, &[0x1f, 128, 1][..]),
    ] {
        let mut destination = [0xaa; 4];
        assert_eq!(
            QpackIntegerBuilder::new(&mut destination, 5, 0, value)
                .build()
                .map(|integer| integer.as_bytes()),
            Ok(expected)
        );
    }
}

#[test]
fn noncanonical_integer_preserves_its_exact_bytes() {
    let wire = [0x1f, 0x80, 0, 0xaa];
    assert_eq!(
        QpackInteger::parse(&wire, 5).map(|integer| (integer.value(), integer.as_bytes())),
        Ok((31, &wire[..3]))
    );
}

#[test]
fn incomplete_integer_reports_exact_boundaries() {
    assert_eq!(
        QpackInteger::parse(&[], 5),
        Err(QpackIntegerParseError::Incomplete {
            required: 1,
            available: 0,
        })
    );
    assert_eq!(
        QpackInteger::parse(&[0x1f], 5),
        Err(QpackIntegerParseError::Incomplete {
            required: 2,
            available: 1,
        })
    );
    assert_eq!(
        QpackInteger::parse(&[0x1f, 0x80], 5),
        Err(QpackIntegerParseError::Incomplete {
            required: 3,
            available: 2,
        })
    );
    assert_eq!(
        QpackInteger::parse(&[0x1f, 0x80, 0x80], 5),
        Err(QpackIntegerParseError::Incomplete {
            required: 4,
            available: 3,
        })
    );
}

#[test]
fn parse_distinguishes_overflow_from_qpack_value_limit() {
    let over_limit = [0xff, 0x81, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f];
    let overflow = [
        0xff, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0,
    ];
    assert!(matches!(
        QpackInteger::parse(&over_limit, 8),
        Err(QpackIntegerParseError::ValueTooLarge { .. })
    ));
    assert_eq!(
        QpackInteger::parse(&overflow, 8),
        Err(QpackIntegerParseError::Overflow)
    );
}

#[test]
fn qpack_integer_limit_roundtrips_and_rejects_the_next_value() {
    let mut destination = [0xaa; 16];
    assert_eq!(
        QpackIntegerBuilder::new(&mut destination, 8, 0, QPACK_INTEGER_MAX)
            .build()
            .map(|integer| integer.value()),
        Ok(QPACK_INTEGER_MAX)
    );
    assert_eq!(
        QpackInteger::parse(&destination, 8).map(|integer| integer.value()),
        Ok(QPACK_INTEGER_MAX)
    );
    let mut too_large_destination = [0xaa; 16];
    assert_eq!(
        QpackIntegerBuilder::new(&mut too_large_destination, 8, 0, QPACK_INTEGER_MAX + 1).build(),
        Err(QpackIntegerBuildError::ValueTooLarge {
            value: QPACK_INTEGER_MAX + 1,
        })
    );
    let over_limit = [0xff, 0x81, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f];
    assert!(matches!(
        QpackInteger::parse(&over_limit, 8),
        Err(QpackIntegerParseError::ValueTooLarge { .. })
    ));
}

#[test]
fn canonical_builder_uses_exact_capacity_and_preserves_suffix() {
    let mut exact = [0xaa; 3];
    assert_eq!(
        QpackIntegerBuilder::new(&mut exact, 5, 0, 1337)
            .build()
            .map(|integer| integer.as_bytes()),
        Ok(&[0x1f, 0x9a, 0x0a][..])
    );
    let mut destination = [0xaa; 4];
    assert_eq!(
        QpackIntegerBuilder::new(&mut destination, 5, 0, 1337)
            .build()
            .map(|integer| integer.as_bytes()),
        Ok(&[0x1f, 0x9a, 0x0a][..])
    );
    assert_eq!(destination[3], 0xaa);
}

#[test]
fn builder_errors_leave_the_whole_destination_unchanged() {
    let cases = [
        (
            0,
            0,
            0,
            QpackIntegerBuildError::InvalidPrefixBits { prefix_bits: 0 },
        ),
        (
            5,
            1,
            0,
            QpackIntegerBuildError::HighBitsOverlap {
                high_bits: 1,
                prefix_bits: 5,
            },
        ),
        (
            5,
            0,
            QPACK_INTEGER_MAX + 1,
            QpackIntegerBuildError::ValueTooLarge {
                value: QPACK_INTEGER_MAX + 1,
            },
        ),
    ];
    for (prefix_bits, high_bits, value, error) in cases {
        let mut destination = [0xaa; 2];
        assert_eq!(
            QpackIntegerBuilder::new(&mut destination, prefix_bits, high_bits, value).build(),
            Err(error)
        );
        assert_eq!(destination, [0xaa; 2]);
    }
    let mut destination = [0xaa; 2];
    assert_eq!(
        QpackIntegerBuilder::new(&mut destination, 5, 0, 1337).build(),
        Err(QpackIntegerBuildError::BufferTooShort {
            required: 3,
            available: 2,
        })
    );
    assert_eq!(destination, [0xaa; 2]);
}

const RFC9204_STATIC_TABLE: [(&[u8], &[u8]); 99] = [
    (b":authority", b""),
    (b":path", b"/"),
    (b"age", b"0"),
    (b"content-disposition", b""),
    (b"content-length", b"0"),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"referer", b""),
    (b"set-cookie", b""),
    (b":method", b"CONNECT"),
    (b":method", b"DELETE"),
    (b":method", b"GET"),
    (b":method", b"HEAD"),
    (b":method", b"OPTIONS"),
    (b":method", b"POST"),
    (b":method", b"PUT"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"103"),
    (b":status", b"200"),
    (b":status", b"304"),
    (b":status", b"404"),
    (b":status", b"503"),
    (b"accept", b"*/*"),
    (b"accept", b"application/dns-message"),
    (b"accept-encoding", b"gzip, deflate, br"),
    (b"accept-ranges", b"bytes"),
    (b"access-control-allow-headers", b"cache-control"),
    (b"access-control-allow-headers", b"content-type"),
    (b"access-control-allow-origin", b"*"),
    (b"cache-control", b"max-age=0"),
    (b"cache-control", b"max-age=2592000"),
    (b"cache-control", b"max-age=604800"),
    (b"cache-control", b"no-cache"),
    (b"cache-control", b"no-store"),
    (b"cache-control", b"public, max-age=31536000"),
    (b"content-encoding", b"br"),
    (b"content-encoding", b"gzip"),
    (b"content-type", b"application/dns-message"),
    (b"content-type", b"application/javascript"),
    (b"content-type", b"application/json"),
    (b"content-type", b"application/x-www-form-urlencoded"),
    (b"content-type", b"image/gif"),
    (b"content-type", b"image/jpeg"),
    (b"content-type", b"image/png"),
    (b"content-type", b"text/css"),
    (b"content-type", b"text/html; charset=utf-8"),
    (b"content-type", b"text/plain"),
    (b"content-type", b"text/plain;charset=utf-8"),
    (b"range", b"bytes=0-"),
    (b"strict-transport-security", b"max-age=31536000"),
    (
        b"strict-transport-security",
        b"max-age=31536000; includesubdomains",
    ),
    (
        b"strict-transport-security",
        b"max-age=31536000; includesubdomains; preload",
    ),
    (b"vary", b"accept-encoding"),
    (b"vary", b"origin"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-xss-protection", b"1; mode=block"),
    (b":status", b"100"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"302"),
    (b":status", b"400"),
    (b":status", b"403"),
    (b":status", b"421"),
    (b":status", b"425"),
    (b":status", b"500"),
    (b"accept-language", b""),
    (b"access-control-allow-credentials", b"FALSE"),
    (b"access-control-allow-credentials", b"TRUE"),
    (b"access-control-allow-headers", b"*"),
    (b"access-control-allow-methods", b"get"),
    (b"access-control-allow-methods", b"get, post, options"),
    (b"access-control-allow-methods", b"options"),
    (b"access-control-expose-headers", b"content-length"),
    (b"access-control-request-headers", b"content-type"),
    (b"access-control-request-method", b"get"),
    (b"access-control-request-method", b"post"),
    (b"alt-svc", b"clear"),
    (b"authorization", b""),
    (
        b"content-security-policy",
        b"script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    (b"early-data", b"1"),
    (b"expect-ct", b""),
    (b"forwarded", b""),
    (b"if-range", b""),
    (b"origin", b""),
    (b"purpose", b"prefetch"),
    (b"server", b""),
    (b"timing-allow-origin", b"*"),
    (b"upgrade-insecure-requests", b"1"),
    (b"user-agent", b""),
    (b"x-forwarded-for", b""),
    (b"x-frame-options", b"deny"),
    (b"x-frame-options", b"sameorigin"),
];

#[test]
fn static_table_matches_rfc9204_appendix_a() {
    assert_eq!(QPACK_STATIC_TABLE_LEN, 99);
    assert_eq!(QpackStaticTable::len(), 99);
    assert!(!QpackStaticTable::is_empty());
    for (index, (name, value)) in RFC9204_STATIC_TABLE.iter().copied().enumerate() {
        assert_eq!(
            QpackStaticTable::get(index).map(|field| (field.name(), field.value())),
            Some((name, value))
        );
    }
    assert_eq!(
        QpackStaticTable::get(0).map(|field| (field.name(), field.value())),
        Some((b":authority" as &[u8], b"" as &[u8]))
    );
    assert_eq!(
        QpackStaticTable::get(98).map(|field| (field.name(), field.value())),
        Some((b"x-frame-options" as &[u8], b"sameorigin" as &[u8]))
    );
    assert_eq!(QpackStaticTable::get(99), None);
    assert_eq!(QpackStaticTable::get(100), None);
}

#[test]
fn header_fields_are_byte_opaque_and_both_facades_are_available() {
    let field = QpackHeaderFieldRef::new(&[0xff, 0][..], &[0x80, 0][..]);
    assert_eq!(field.name(), &[0xff, 0]);
    assert_eq!(field.value(), &[0x80, 0]);
    let root_bytes = [0];
    let root: Result<QpackInteger<'_>, QpackIntegerParseError> =
        QpackInteger::parse(&root_bytes, 8);
    assert_eq!(root.map(QpackInteger::value), Ok(0));
    let module_bytes = [0];
    let module: Result<qpack::QpackInteger<'_>, qpack::QpackIntegerParseError> =
        qpack::QpackInteger::parse(&module_bytes, 8);
    assert_eq!(module.map(qpack::QpackInteger::value), Ok(0));
    let _: usize = qpack::QPACK_STATIC_TABLE_LEN;
    let _: Option<qpack::QpackHeaderFieldRef<'static>> = qpack::QpackStaticTable::get(0);
    let _: Option<QpackStringLiteral<'static>> = None;
    let _: Option<qpack::QpackStringLiteral<'static>> = None;
    let _: Option<QpackHuffmanDecodeError> = None;
    let _: Option<qpack::QpackHuffmanDecodeError> = None;
    let _: Option<QpackHuffmanEncodeError> = None;
    let _: Option<qpack::QpackHuffmanEncodeError> = None;
    let mut root_huffman_output = [];
    let _: QpackHuffmanEncoder<'_, '_> = QpackHuffmanEncoder::new(b"", &mut root_huffman_output);
    let mut module_huffman_output = [];
    let _: qpack::QpackHuffmanDecoder<'_, '_> =
        qpack::QpackHuffmanDecoder::new(b"", &mut module_huffman_output);
}

#[test]
fn qpack_dynamic_table_capacity_and_empty_storage_boundaries_are_exact() {
    let mut storage = [0; 68];
    let mut entries = [QpackDynamicTableEntry::EMPTY; 2];
    let mut table = QpackDynamicTable::new(&mut storage, &mut entries);
    assert_eq!(table.storage_capacity(), 95);
    assert_eq!(
        (
            table.capacity(),
            table.size(),
            table.len(),
            table.insert_count()
        ),
        (0, 0, 0, 0)
    );
    assert!(table.is_empty());
    assert_eq!(table.oldest_active_absolute(), None);
    assert_eq!(
        table.set_capacity(96, |_| true),
        Err(QpackDynamicTableError::CapacityExceedsStorage {
            requested: 96,
            capacity: 95
        })
    );
    assert_eq!(table.storage_capacity(), 95);
    assert_eq!(
        (
            table.capacity(),
            table.size(),
            table.len(),
            table.insert_count()
        ),
        (0, 0, 0, 0)
    );
    assert!(table.is_empty());
    assert_eq!(table.oldest_active_absolute(), None);
    assert_eq!(table.set_capacity(95, |_| true), Ok(()));
    assert_eq!(table.insert_count(), 0);

    let mut empty_storage = [];
    let mut empty_entries = [QpackDynamicTableEntry::EMPTY; 1];
    let mut empty_table = QpackDynamicTable::new(&mut empty_storage, &mut empty_entries);
    assert_eq!(empty_table.storage_capacity(), 32);
    assert_eq!(empty_table.set_capacity(32, |_| true), Ok(()));
    assert_eq!(empty_table.insert(b"", b"", |_| true), Ok(0));
    assert_eq!(
        empty_table
            .get_absolute(0)
            .map(|field| (field.name(), field.value())),
        Ok((b"" as &[u8], b"" as &[u8]))
    );

    let mut no_storage = [];
    let mut no_entries = [];
    let mut no_table = QpackDynamicTable::new(&mut no_storage, &mut no_entries);
    assert_eq!(no_table.storage_capacity(), 31);
    assert_eq!(no_table.set_capacity(31, |_| true), Ok(()));
    assert_eq!(
        no_table.set_capacity(32, |_| true),
        Err(QpackDynamicTableError::CapacityExceedsStorage {
            requested: 32,
            capacity: 31
        })
    );
}

#[test]
fn qpack_dynamic_table_insertion_eviction_and_absolute_ids_are_exact() {
    let mut storage = [0; 70];
    let mut entries = [QpackDynamicTableEntry::EMPTY; 4];
    let mut table = QpackDynamicTable::new(&mut storage, &mut entries);
    assert_eq!(table.set_capacity(102, |_| true), Ok(()));
    assert_eq!(table.insert(b"a", b"1", |_| true), Ok(0));
    assert_eq!(table.insert(b"b", b"2", |_| true), Ok(1));
    assert_eq!(table.insert(b"c", b"3", |_| true), Ok(2));
    assert_eq!(
        (table.size(), table.len(), table.insert_count()),
        (102, 3, 3)
    );
    assert_eq!(
        table
            .get_absolute(0)
            .map(|field| (field.name(), field.value())),
        Ok((b"a" as &[u8], b"1" as &[u8]))
    );
    assert_eq!(
        table
            .get_absolute(1)
            .map(|field| (field.name(), field.value())),
        Ok((b"b" as &[u8], b"2" as &[u8]))
    );
    assert_eq!(
        table
            .get_absolute(2)
            .map(|field| (field.name(), field.value())),
        Ok((b"c" as &[u8], b"3" as &[u8]))
    );
    assert_eq!(
        table
            .get_encoder_relative(0)
            .map(|field| (field.name(), field.value())),
        Ok((b"c" as &[u8], b"3" as &[u8]))
    );
    assert_eq!(
        table
            .get_encoder_relative(1)
            .map(|field| (field.name(), field.value())),
        Ok((b"b" as &[u8], b"2" as &[u8]))
    );
    assert_eq!(
        table
            .get_encoder_relative(2)
            .map(|field| (field.name(), field.value())),
        Ok((b"a" as &[u8], b"1" as &[u8]))
    );
    let mut evicted = [0; 3];
    let mut evicted_len = 0;
    assert_eq!(
        table.set_capacity(34, |absolute| {
            evicted[evicted_len] = absolute;
            evicted_len += 1;
            true
        }),
        Ok(())
    );
    assert_eq!(evicted_len, 2);
    assert_eq!(&evicted[..evicted_len], &[0, 1]);
    assert_eq!(
        (table.size(), table.len(), table.insert_count()),
        (34, 1, 3)
    );
    assert_eq!(
        table
            .get_absolute(2)
            .map(|field| (field.name(), field.value())),
        Ok((b"c" as &[u8], b"3" as &[u8]))
    );
    for requested in [0, 1] {
        assert_eq!(
            table.get_absolute(requested),
            Err(QpackDynamicTableError::EvictedAbsoluteIndex {
                requested,
                oldest_available: 2
            })
        );
    }
    assert_eq!(table.set_capacity(0, |_| true), Ok(()));
    assert!(table.is_empty());
    assert_eq!(table.oldest_active_absolute(), None);
    assert_eq!(table.insert_count(), 3);
    assert_eq!(table.set_capacity(34, |_| true), Ok(()));
    assert_eq!(table.insert(b"d", b"4", |_| true), Ok(3));
}

#[test]
fn qpack_dynamic_table_mutation_failures_are_atomic() {
    let mut storage = [0; 36];
    let mut entries = [QpackDynamicTableEntry::EMPTY; 2];
    let mut table = QpackDynamicTable::new(&mut storage, &mut entries);
    assert_eq!(table.set_capacity(68, |_| true), Ok(()));
    assert_eq!(table.insert(b"a", b"1", |_| true), Ok(0));
    assert_eq!(table.insert(b"b", b"2", |_| true), Ok(1));
    let before = (
        table.capacity(),
        table.size(),
        table.len(),
        table.insert_count(),
    );
    let mut insert_calls = 0;
    assert_eq!(
        table.insert(&[0; 37], b"", |_| {
            insert_calls += 1;
            true
        }),
        Err(QpackDynamicTableError::EntryLargerThanCapacity {
            entry_size: 69,
            capacity: 68
        })
    );
    assert_eq!(insert_calls, 0);
    assert_eq!(
        (
            table.capacity(),
            table.size(),
            table.len(),
            table.insert_count()
        ),
        before
    );
    assert_eq!(
        table
            .get_absolute(0)
            .map(|field| (field.name(), field.value())),
        Ok((b"a" as &[u8], b"1" as &[u8]))
    );
    assert_eq!(
        table
            .get_absolute(1)
            .map(|field| (field.name(), field.value())),
        Ok((b"b" as &[u8], b"2" as &[u8]))
    );
    assert_eq!(
        table.insert(b"c", b"3", |_| false),
        Err(QpackDynamicTableError::EvictionBlocked { absolute_index: 0 })
    );
    assert_eq!(
        (
            table.capacity(),
            table.size(),
            table.len(),
            table.insert_count()
        ),
        before
    );
    let mut evicted = [0; 2];
    let mut evicted_len = 0;
    assert_eq!(
        table.set_capacity(0, |absolute| {
            evicted[evicted_len] = absolute;
            evicted_len += 1;
            absolute == 0
        }),
        Err(QpackDynamicTableError::EvictionBlocked { absolute_index: 1 })
    );
    assert_eq!(evicted_len, 2);
    assert_eq!(&evicted[..evicted_len], &[0, 1]);
    assert_eq!(
        (
            table.capacity(),
            table.size(),
            table.len(),
            table.insert_count()
        ),
        before
    );
    assert_eq!(
        table
            .get_absolute(0)
            .map(|field| (field.name(), field.value())),
        Ok((b"a" as &[u8], b"1" as &[u8]))
    );
    assert_eq!(
        table
            .get_absolute(1)
            .map(|field| (field.name(), field.value())),
        Ok((b"b" as &[u8], b"2" as &[u8]))
    );
}

#[test]
fn qpack_dynamic_table_relative_post_base_errors_and_facades_are_exact() {
    let mut storage = [0; 70];
    let mut entries = [QpackDynamicTableEntry::EMPTY; 3];
    let mut table = QpackDynamicTable::new(&mut storage, &mut entries);
    assert_eq!(table.set_capacity(102, |_| true), Ok(()));
    assert_eq!(table.insert(b"a", b"1", |_| true), Ok(0));
    assert_eq!(table.insert(b"b", b"2", |_| true), Ok(1));
    assert_eq!(table.insert(b"c", b"3", |_| true), Ok(2));
    assert_eq!(
        table
            .get_encoder_relative(0)
            .map(|field| (field.name(), field.value())),
        Ok((b"c" as &[u8], b"3" as &[u8]))
    );
    assert_eq!(
        table
            .get_encoder_relative(2)
            .map(|field| (field.name(), field.value())),
        Ok((b"a" as &[u8], b"1" as &[u8]))
    );
    assert_eq!(
        table.get_encoder_relative(3),
        Err(QpackDynamicTableError::EncoderRelativeIndexUnderflow {
            insert_count: 3,
            index: 3
        })
    );
    assert_eq!(
        table
            .get_field_relative(3, 2, 0)
            .map(|field| (field.name(), field.value())),
        Ok((b"b" as &[u8], b"2" as &[u8]))
    );
    assert_eq!(
        table
            .get_field_relative(3, 2, 1)
            .map(|field| (field.name(), field.value())),
        Ok((b"a" as &[u8], b"1" as &[u8]))
    );
    assert_eq!(
        table.get_field_relative(3, 0, 0),
        Err(QpackDynamicTableError::FieldRelativeIndexUnderflow { base: 0, index: 0 })
    );
    assert_eq!(
        table.get_field_relative(3, 4, 0),
        Err(
            QpackDynamicTableError::ReferenceAtOrAfterRequiredInsertCount {
                requested: 3,
                required_insert_count: 3
            }
        )
    );
    assert_eq!(
        table
            .get_post_base(3, 1, 0)
            .map(|field| (field.name(), field.value())),
        Ok((b"b" as &[u8], b"2" as &[u8]))
    );
    assert_eq!(
        table
            .get_post_base(3, 1, 1)
            .map(|field| (field.name(), field.value())),
        Ok((b"c" as &[u8], b"3" as &[u8]))
    );
    assert_eq!(
        table.get_post_base(3, 1, 2),
        Err(
            QpackDynamicTableError::ReferenceAtOrAfterRequiredInsertCount {
                requested: 3,
                required_insert_count: 3
            }
        )
    );
    assert_eq!(
        table.get_post_base(3, u64::MAX, 1),
        Err(QpackDynamicTableError::PostBaseIndexOverflow {
            base: u64::MAX,
            index: 1
        })
    );
    assert_eq!(
        table.get_absolute(3),
        Err(QpackDynamicTableError::FutureAbsoluteIndex {
            requested: 3,
            insert_count: 3
        })
    );
    let _: Option<QpackDynamicTable<'static, 'static>> = None;
    let _: Option<QpackDynamicTableEntry> = None;
    let _: Option<QpackDynamicTableError> = None;
    let _: Option<qpack::QpackDynamicTable<'static, 'static>> = None;
    let _: Option<qpack::QpackDynamicTableEntry> = None;
    let _: Option<qpack::QpackDynamicTableError> = None;
}

#[test]
fn qpack_huffman_rfc_vectors_and_atomic_boundaries() {
    let www = [
        0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
    ];
    let no_cache = [0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf];
    let custom_key = [0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f];
    let custom_value = [0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf];
    for (decoded, encoded) in [
        (b"www.example.com" as &[u8], &www[..]),
        (b"no-cache" as &[u8], &no_cache[..]),
        (b"custom-key" as &[u8], &custom_key[..]),
        (b"custom-value" as &[u8], &custom_value[..]),
    ] {
        assert_eq!(
            QpackHuffmanEncoder::required_encoded_len(decoded),
            Ok(encoded.len())
        );
        let mut output = [0xaa; 32];
        {
            let written = QpackHuffmanEncoder::new(decoded, &mut output)
                .encode()
                .expect("capacity");
            assert_eq!(written, encoded);
        }
        assert_eq!(output[encoded.len()], 0xaa);
        let mut decoded_output = [0xaa; 32];
        assert_eq!(
            QpackHuffmanDecoder::required_decoded_len(encoded),
            Ok(decoded.len())
        );
        assert_eq!(
            QpackHuffmanDecoder::new(encoded, &mut decoded_output).decode(),
            Ok(decoded)
        );
        assert_eq!(decoded_output[decoded.len()], 0xaa);

        let mut short = [0xaa; 31];
        let before = short;
        if !encoded.is_empty() {
            assert_eq!(
                QpackHuffmanEncoder::new(decoded, &mut short[..encoded.len() - 1]).encode(),
                Err(QpackHuffmanEncodeError::DestinationTooShort {
                    required: encoded.len(),
                    available: encoded.len() - 1,
                })
            );
            assert_eq!(short, before);
        }
        let mut short_decoded = [0xaa; 31];
        let before = short_decoded;
        assert_eq!(
            QpackHuffmanDecoder::new(encoded, &mut short_decoded[..decoded.len() - 1]).decode(),
            Err(QpackHuffmanDecodeError::OutputTooShort {
                required: decoded.len(),
                available: decoded.len() - 1,
            })
        );
        assert_eq!(short_decoded, before);
    }

    for (encoded, error) in [
        (
            &[0xff, 0xff, 0xff, 0xff][..],
            QpackHuffmanDecodeError::EosSymbol,
        ),
        (&[0x00][..], QpackHuffmanDecodeError::InvalidPadding),
        (&[0xff][..], QpackHuffmanDecodeError::InvalidPadding),
    ] {
        let mut destination = [0xaa; 8];
        let before = destination;
        assert_eq!(
            QpackHuffmanDecoder::required_decoded_len(encoded),
            Err(error)
        );
        assert_eq!(
            QpackHuffmanDecoder::new(encoded, &mut destination).decode(),
            Err(error)
        );
        assert_eq!(destination, before);
    }
}

#[test]
fn qpack_string_prefix_widths_preserve_flags_and_payload_opacity() {
    for prefix_bits in [2, 3, 4, 6, 8] {
        let previous_high_bits = if prefix_bits == 8 {
            0
        } else {
            !controlled_mask(prefix_bits)
        };
        for huffman in [false, true] {
            let payload = b"abc";
            let mut destination = [0xaa; 8];
            let literal_len;
            let length_len;
            {
                let literal = QpackStringLiteralBuilder::new(
                    &mut destination,
                    prefix_bits,
                    previous_high_bits,
                    huffman,
                    payload,
                )
                .build()
                .expect("valid literal");
                assert_eq!(literal.prefix_bits(), prefix_bits);
                assert_eq!(literal.previous_high_bits(), previous_high_bits);
                assert_eq!(literal.is_huffman(), huffman);
                assert_eq!(literal.encoded_payload(), payload);
                assert_eq!(literal.length().value(), 3);
                length_len = literal.length().as_bytes().len();
                literal_len = literal.as_bytes().len();
                assert_eq!(
                    QpackStringLiteral::parse(literal.as_bytes(), prefix_bits),
                    Ok(literal)
                );
            }
            assert_eq!(literal_len, length_len + payload.len());
            assert_eq!(destination[literal_len], 0xaa);
        }
    }

    let huffman_payload = [
        0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
    ];
    let wire = [
        0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
    ];
    let parsed = QpackStringLiteral::parse(&wire, 8).expect("opaque literal");
    assert!(parsed.is_huffman());
    assert_eq!(parsed.encoded_payload(), huffman_payload);
    let mut decoded = [0; 16];
    assert_eq!(
        QpackHuffmanDecoder::new(parsed.encoded_payload(), &mut decoded).decode(),
        Ok(b"www.example.com" as &[u8])
    );
}

#[test]
fn qpack_string_boundaries_noncanonical_and_errors_are_atomic() {
    for (payload, expected_length_len) in [
        (&[][..], 1),
        (&[1][..], 1),
        (&[0; 3][..], 2),
        (&[0; 130][..], 2),
    ] {
        let required = expected_length_len + payload.len();
        let mut exact = [0xaa; 133];
        let literal =
            QpackStringLiteralBuilder::new(&mut exact[..required], 3, 0xe0, false, payload)
                .build()
                .expect("exact capacity");
        assert_eq!(literal.as_bytes().len(), required);
        let mut short = [0xaa; 133];
        let before = short;
        assert_eq!(
            QpackStringLiteralBuilder::new(&mut short[..required - 1], 3, 0xe0, false, payload)
                .build(),
            Err(QpackStringLiteralBuildError::BufferTooShort {
                required,
                available: required - 1,
            })
        );
        assert_eq!(short, before);
    }

    let noncanonical = [0xe3, 0x80, 0, b'x', b'y', b'z', 0xaa];
    let parsed = QpackStringLiteral::parse(&noncanonical, 3).expect("noncanonical length");
    assert_eq!(parsed.length().as_bytes(), &[0xe3, 0x80, 0]);
    assert_eq!(parsed.encoded_payload(), b"xyz");
    assert_eq!(parsed.as_bytes(), &noncanonical[..6]);

    for prefix_bits in [0, 1, 9] {
        assert_eq!(
            QpackStringLiteral::parse(&[], prefix_bits),
            Err(QpackStringLiteralParseError::InvalidPrefixBits { prefix_bits })
        );
    }
    let mut destination = [0xaa; 4];
    let before = destination;
    assert_eq!(
        QpackStringLiteralBuilder::new(&mut destination, 8, 0x01, false, b"").build(),
        Err(QpackStringLiteralBuildError::HighBitsOverlap {
            high_bits: 1,
            prefix_bits: 8,
        })
    );
    assert_eq!(destination, before);

    assert_eq!(
        QpackStringLiteral::parse(&[0xe3], 3),
        Err(QpackStringLiteralParseError::Length(
            QpackIntegerParseError::Incomplete {
                required: 2,
                available: 1,
            }
        ))
    );
    assert_eq!(
        QpackStringLiteral::parse(&[0xe3, 0x80], 3),
        Err(QpackStringLiteralParseError::Length(
            QpackIntegerParseError::Incomplete {
                required: 3,
                available: 2,
            }
        ))
    );
    assert_eq!(
        QpackStringLiteral::parse(&[0xe1], 3),
        Err(QpackStringLiteralParseError::Incomplete {
            required: 2,
            available: 1,
        })
    );

    let mut long_wire = [0xaa; 133];
    let long = QpackStringLiteralBuilder::new(&mut long_wire, 3, 0xe0, false, &[0; 130])
        .build()
        .expect("long literal");
    assert_eq!(&long.as_bytes()[..2], &[0xe3, 0x7f]);
    let required = long.as_bytes().len();
    for available in 2..required {
        assert_eq!(
            QpackStringLiteral::parse(&long.as_bytes()[..available], 3),
            Err(QpackStringLiteralParseError::Incomplete {
                required,
                available,
            })
        );
    }
}

#[test]
fn qpack_encoder_instruction_rfc9204_appendix_b_vectors_are_exact() {
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

    assert!(matches!(
        QpackEncoderInstruction::parse(&capacity),
        Ok(QpackEncoderInstruction::SetDynamicTableCapacity(instruction))
            if instruction.capacity().value() == 220 && instruction.as_bytes() == capacity
    ));
    assert!(matches!(
        QpackEncoderInstruction::parse(&static_authority),
        Ok(QpackEncoderInstruction::InsertWithNameReference(instruction))
            if instruction.is_static() && instruction.name_index().value() == 0
                && instruction.value().encoded_payload() == b"www.example.com"
    ));
    assert!(matches!(
        QpackEncoderInstruction::parse(&static_path),
        Ok(QpackEncoderInstruction::InsertWithNameReference(instruction))
            if instruction.is_static() && instruction.name_index().value() == 1
                && instruction.value().encoded_payload() == b"/sample/path"
    ));
    assert!(matches!(
        QpackEncoderInstruction::parse(&literal),
        Ok(QpackEncoderInstruction::InsertWithLiteralName(instruction))
            if instruction.name().encoded_payload() == b"custom-key"
                && instruction.value().encoded_payload() == b"custom-value"
    ));
    assert!(matches!(
        QpackEncoderInstruction::parse(&duplicate),
        Ok(QpackEncoderInstruction::Duplicate(instruction)) if instruction.index().value() == 2
    ));
    assert!(matches!(
        QpackEncoderInstruction::parse(&dynamic),
        Ok(QpackEncoderInstruction::InsertWithNameReference(instruction))
            if !instruction.is_static() && instruction.name_index().value() == 1
                && instruction.value().encoded_payload() == b"custom-value2"
    ));

    let mut sequence = [0; 74];
    let mut offset = 0;
    for vector in [
        &capacity[..],
        &static_authority,
        &static_path,
        &literal,
        &duplicate,
        &dynamic,
    ] {
        sequence[offset..offset + vector.len()].copy_from_slice(vector);
        offset += vector.len();
    }
    let sequence = &sequence[..offset];
    let parsed = QpackEncoderInstructions::parse(sequence).expect("RFC sequence");
    assert_eq!(parsed.as_bytes(), sequence);
    assert_eq!(parsed.iter().count(), 6);
    assert_eq!(
        QpackEncoderInstructions::parse(&[]).map(|instructions| instructions.iter().count()),
        Ok(0)
    );
}

#[test]
fn qpack_encoder_instruction_dispatch_suffix_and_nested_errors_are_exact() {
    let cases = [
        (&[0x20, 0xaa][..], 1),
        (&[0x80, 0x00, 0xaa][..], 2),
        (&[0x40, 0x00, 0x00, 0xaa][..], 2),
        (&[0x00, 0xaa][..], 1),
    ];
    for (wire, length) in cases {
        assert_eq!(
            QpackEncoderInstruction::parse(wire).map(|instruction| instruction.as_bytes()),
            Ok(&wire[..length])
        );
    }
    assert_eq!(
        QpackEncoderInstruction::parse(&[]),
        Err(QpackEncoderInstructionParseError::DispatchIncomplete)
    );
    assert_eq!(
        QpackEncoderInstruction::parse(&[0x80]),
        Err(
            QpackEncoderInstructionParseError::InsertWithNameReferenceValue(
                QpackStringLiteralParseError::Length(QpackIntegerParseError::Incomplete {
                    required: 1,
                    available: 0,
                })
            )
        )
    );
    assert_eq!(
        QpackEncoderInstruction::parse(&[0x40]),
        Err(
            QpackEncoderInstructionParseError::InsertWithLiteralNameValue(
                QpackStringLiteralParseError::Length(QpackIntegerParseError::Incomplete {
                    required: 1,
                    available: 0,
                })
            )
        )
    );
    assert_eq!(
        QpackEncoderInstruction::parse(&[0x1f]),
        Err(QpackEncoderInstructionParseError::DuplicateIndex(
            QpackIntegerParseError::Incomplete {
                required: 2,
                available: 1,
            }
        ))
    );

    let invalid = [0x02, 0x80];
    assert_eq!(
        QpackEncoderInstructions::parse(&invalid),
        Err(QpackEncoderInstructionsParseError {
            offset: 1,
            error: QpackEncoderInstructionParseError::InsertWithNameReferenceValue(
                QpackStringLiteralParseError::Length(QpackIntegerParseError::Incomplete {
                    required: 1,
                    available: 0,
                })
            ),
        })
    );
}

#[test]
fn qpack_encoder_instruction_builders_emit_rfc_vectors_and_are_atomic() {
    let mut capacity = [0xaa; 4];
    assert_eq!(
        QpackSetDynamicTableCapacityBuilder::new(&mut capacity, 220)
            .build()
            .map(|instruction| instruction.as_bytes()),
        Ok(&[0x3f, 0xbd, 0x01][..])
    );
    assert_eq!(capacity[3], 0xaa);

    let mut static_name = [0xaa; 18];
    assert_eq!(
        QpackInsertWithNameReferenceBuilder::new(
            &mut static_name,
            true,
            0,
            false,
            b"www.example.com"
        )
        .build()
        .map(|instruction| instruction.as_bytes()),
        Ok(&[
            0xc0, 0x0f, b'w', b'w', b'w', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.',
            b'c', b'o', b'm',
        ][..])
    );
    assert_eq!(static_name[17], 0xaa);

    let mut literal = [0xaa; 25];
    assert_eq!(
        QpackInsertWithLiteralNameBuilder::new(
            &mut literal,
            false,
            b"custom-key",
            false,
            b"custom-value",
        )
        .build()
        .map(|instruction| instruction.as_bytes()),
        Ok(&[
            0x4a, b'c', b'u', b's', b't', b'o', b'm', b'-', b'k', b'e', b'y', 0x0c, b'c', b'u',
            b's', b't', b'o', b'm', b'-', b'v', b'a', b'l', b'u', b'e',
        ][..])
    );
    assert_eq!(literal[24], 0xaa);

    let mut duplicate = [0xaa; 2];
    assert_eq!(
        QpackDuplicateBuilder::new(&mut duplicate, 2)
            .build()
            .map(|instruction| instruction.as_bytes()),
        Ok(&[0x02][..])
    );
    assert_eq!(duplicate[1], 0xaa);

    let mut short = [0xaa; 2];
    let before = short;
    assert_eq!(
        QpackInsertWithNameReferenceBuilder::new(&mut short, false, 1, false, b"x").build(),
        Err(QpackEncoderInstructionBuildError::BufferTooShort {
            required: 3,
            available: 2,
        })
    );
    assert_eq!(short, before);
    let mut too_large = [0xaa; 16];
    let before = too_large;
    assert_eq!(
        QpackDuplicateBuilder::new(&mut too_large, QPACK_INTEGER_MAX + 1).build(),
        Err(QpackEncoderInstructionBuildError::DuplicateIndex(
            QpackIntegerBuildError::ValueTooLarge {
                value: QPACK_INTEGER_MAX + 1,
            }
        ))
    );
    assert_eq!(too_large, before);
}

#[test]
fn qpack_encoder_instruction_facades_expose_new_types() {
    let _: Option<QpackDuplicate<'static>> = None;
    let _: Option<qpack::QpackDuplicate<'static>> = None;
    let _: Option<qpack::QpackEncoderInstructionIter<'static>> = None;
    let _: Option<qpack::QpackEncoderInstructions<'static>> = None;
    let _: Option<qpack::QpackInsertWithNameReference<'static>> = None;
    let _: Option<qpack::QpackInsertWithLiteralName<'static>> = None;
    let _: Option<qpack::QpackSetDynamicTableCapacity<'static>> = None;
}

#[test]
fn qpack_encoder_instruction_wire_families_preserve_noncanonical_fields_and_flags() {
    let capacity = [0x3f, 0x80, 0, 0xaa];
    let duplicate = [0x1f, 0x80, 0, 0xaa];
    let static_name_reference = [0xff, 0x80, 0, 0x00, 0xaa];
    let dynamic_name_reference = [0xbf, 0x80, 0, 0x00, 0xaa];
    let literal_name_huffman = [0x61, 0x11, 0x01, 0x22, 0xaa];
    let literal_value_huffman = [0x41, 0x11, 0x81, 0x22, 0xaa];
    let literal_name_and_value_huffman = [0x61, 0x11, 0x81, 0x22, 0xaa];

    assert!(matches!(
        QpackEncoderInstruction::parse(&capacity),
        Ok(QpackEncoderInstruction::SetDynamicTableCapacity(instruction))
            if instruction.capacity().value() == 31
                && instruction.capacity().as_bytes() == &capacity[..3]
                && instruction.as_bytes() == &capacity[..3]
    ));
    assert!(matches!(
        QpackEncoderInstruction::parse(&duplicate),
        Ok(QpackEncoderInstruction::Duplicate(instruction))
            if instruction.index().value() == 31
                && instruction.index().as_bytes() == &duplicate[..3]
                && instruction.as_bytes() == &duplicate[..3]
    ));
    assert!(matches!(
        QpackEncoderInstruction::parse(&static_name_reference),
        Ok(QpackEncoderInstruction::InsertWithNameReference(instruction))
            if instruction.is_static()
                && instruction.name_index().value() == 63
                && instruction.name_index().as_bytes() == &static_name_reference[..3]
                && !instruction.value().is_huffman()
                && instruction.value().encoded_payload().is_empty()
                && instruction.as_bytes() == &static_name_reference[..4]
    ));
    assert!(matches!(
        QpackEncoderInstruction::parse(&dynamic_name_reference),
        Ok(QpackEncoderInstruction::InsertWithNameReference(instruction))
            if !instruction.is_static()
                && instruction.name_index().value() == 63
                && instruction.name_index().as_bytes() == &dynamic_name_reference[..3]
                && instruction.value().encoded_payload().is_empty()
                && instruction.as_bytes() == &dynamic_name_reference[..4]
    ));
    for (wire, name_huffman, value_huffman) in [
        (&literal_name_huffman[..], true, false),
        (&literal_value_huffman[..], false, true),
        (&literal_name_and_value_huffman[..], true, true),
    ] {
        assert!(matches!(
            QpackEncoderInstruction::parse(wire),
            Ok(QpackEncoderInstruction::InsertWithLiteralName(instruction))
                if instruction.name().is_huffman() == name_huffman
                    && instruction.name().encoded_payload() == b"\x11"
                    && instruction.value().is_huffman() == value_huffman
                    && instruction.value().encoded_payload() == b"\x22"
                    && instruction.as_bytes() == &wire[..4]
        ));
    }

    let mut name_length_noncanonical = [0; 36];
    name_length_noncanonical[..3].copy_from_slice(&[0x5f, 0x80, 0]);
    name_length_noncanonical[3..34].fill(b'n');
    name_length_noncanonical[34] = 0;
    name_length_noncanonical[35] = 0xaa;
    assert!(matches!(
        QpackEncoderInstruction::parse(&name_length_noncanonical),
        Ok(QpackEncoderInstruction::InsertWithLiteralName(instruction))
            if instruction.name().length().value() == 31
                && instruction.name().length().as_bytes() == &name_length_noncanonical[..3]
                && instruction.name().encoded_payload() == [b'n'; 31]
                && instruction.value().encoded_payload().is_empty()
                && instruction.as_bytes() == &name_length_noncanonical[..35]
    ));

    let mut value_length_noncanonical = [0; 131];
    value_length_noncanonical[..4].copy_from_slice(&[0x80, 0xff, 0x80, 0]);
    value_length_noncanonical[4..131].fill(b'v');
    assert!(matches!(
        QpackEncoderInstruction::parse(&value_length_noncanonical),
        Ok(QpackEncoderInstruction::InsertWithNameReference(instruction))
            if !instruction.is_static()
                && instruction.name_index().value() == 0
                && instruction.value().length().value() == 127
                && instruction.value().length().as_bytes() == &value_length_noncanonical[1..4]
                && instruction.value().encoded_payload() == [b'v'; 127]
                && instruction.as_bytes() == value_length_noncanonical
    ));
}

#[test]
fn qpack_encoder_instruction_truncation_errors_are_nested_and_exact() {
    let cases = [
        (
            &[0x3f][..],
            QpackEncoderInstructionParseError::SetDynamicTableCapacity(
                QpackIntegerParseError::Incomplete {
                    required: 2,
                    available: 1,
                },
            ),
        ),
        (
            &[0x3f, 0x80][..],
            QpackEncoderInstructionParseError::SetDynamicTableCapacity(
                QpackIntegerParseError::Incomplete {
                    required: 3,
                    available: 2,
                },
            ),
        ),
        (
            &[0x1f][..],
            QpackEncoderInstructionParseError::DuplicateIndex(QpackIntegerParseError::Incomplete {
                required: 2,
                available: 1,
            }),
        ),
        (
            &[0x1f, 0x80][..],
            QpackEncoderInstructionParseError::DuplicateIndex(QpackIntegerParseError::Incomplete {
                required: 3,
                available: 2,
            }),
        ),
        (
            &[0xff][..],
            QpackEncoderInstructionParseError::InsertWithNameReferenceNameIndex(
                QpackIntegerParseError::Incomplete {
                    required: 2,
                    available: 1,
                },
            ),
        ),
        (
            &[0x80][..],
            QpackEncoderInstructionParseError::InsertWithNameReferenceValue(
                QpackStringLiteralParseError::Length(QpackIntegerParseError::Incomplete {
                    required: 1,
                    available: 0,
                }),
            ),
        ),
        (
            &[0x80, 0x02, b'x'][..],
            QpackEncoderInstructionParseError::InsertWithNameReferenceValue(
                QpackStringLiteralParseError::Incomplete {
                    required: 3,
                    available: 2,
                },
            ),
        ),
        (
            &[0x5f][..],
            QpackEncoderInstructionParseError::InsertWithLiteralNameName(
                QpackStringLiteralParseError::Length(QpackIntegerParseError::Incomplete {
                    required: 2,
                    available: 1,
                }),
            ),
        ),
        (
            &[0x42, b'x'][..],
            QpackEncoderInstructionParseError::InsertWithLiteralNameName(
                QpackStringLiteralParseError::Incomplete {
                    required: 3,
                    available: 2,
                },
            ),
        ),
        (
            &[0x40, 0xff][..],
            QpackEncoderInstructionParseError::InsertWithLiteralNameValue(
                QpackStringLiteralParseError::Length(QpackIntegerParseError::Incomplete {
                    required: 2,
                    available: 1,
                }),
            ),
        ),
        (
            &[0x40, 0x02, b'x'][..],
            QpackEncoderInstructionParseError::InsertWithLiteralNameValue(
                QpackStringLiteralParseError::Incomplete {
                    required: 3,
                    available: 2,
                },
            ),
        ),
    ];
    for (wire, expected) in cases {
        assert_eq!(QpackEncoderInstruction::parse(wire), Err(expected));
    }

    let sequence = [0x02, 0x40, 0xff];
    assert_eq!(
        QpackEncoderInstructions::parse(&sequence),
        Err(QpackEncoderInstructionsParseError {
            offset: 1,
            error: QpackEncoderInstructionParseError::InsertWithLiteralNameValue(
                QpackStringLiteralParseError::Length(QpackIntegerParseError::Incomplete {
                    required: 2,
                    available: 1,
                }),
            ),
        })
    );

    let empty_wire = [];
    let mut empty = QpackEncoderInstructions::parse(&empty_wire)
        .expect("empty sequence")
        .iter();
    assert_eq!(empty.next(), None);
    assert_eq!(empty.next(), None);
    let complete_wire = [0x02];
    let mut complete = QpackEncoderInstructions::parse(&complete_wire)
        .expect("complete sequence")
        .iter();
    assert!(matches!(
        complete.next(),
        Some(Ok(QpackEncoderInstruction::Duplicate(_)))
    ));
    assert_eq!(complete.next(), None);
    assert_eq!(complete.next(), None);
}

#[test]
fn qpack_encoder_instruction_builders_cover_boundaries_flags_atomicity_and_lifetimes() {
    let mut static_index_one = [0xaa; 15];
    assert_eq!(
        QpackInsertWithNameReferenceBuilder::new(
            &mut static_index_one,
            true,
            1,
            false,
            b"/sample/path"
        )
        .build()
        .map(|instruction| instruction.as_bytes()),
        Ok(&[
            0xc1, 0x0c, b'/', b's', b'a', b'm', b'p', b'l', b'e', b'/', b'p', b'a', b't', b'h'
        ][..])
    );
    assert_eq!(static_index_one[14], 0xaa);

    let mut dynamic = [0xaa; 15];
    assert_eq!(
        QpackInsertWithNameReferenceBuilder::new(&mut dynamic, false, 1, false, b"custom-value2")
            .build()
            .map(|instruction| instruction.as_bytes()),
        Ok(&[
            0x81, 0x0d, b'c', b'u', b's', b't', b'o', b'm', b'-', b'v', b'a', b'l', b'u', b'e',
            b'2'
        ][..])
    );

    for (name_huffman, value_huffman, expected) in [
        (false, false, &[0x40, 0][..]),
        (true, false, &[0x60, 0][..]),
        (false, true, &[0x40, 0x80][..]),
        (true, true, &[0x60, 0x80][..]),
    ] {
        let mut destination = [0xaa; 4];
        assert_eq!(
            QpackInsertWithLiteralNameBuilder::new(
                &mut destination,
                name_huffman,
                b"",
                value_huffman,
                b"",
            )
            .build()
            .map(|instruction| instruction.as_bytes()),
            Ok(expected)
        );
        assert_eq!(&destination[2..], &[0xaa; 2]);
    }
    let mut name_reference_huffman = [0xaa; 3];
    assert_eq!(
        QpackInsertWithNameReferenceBuilder::new(&mut name_reference_huffman, false, 0, true, b"")
            .build()
            .map(|instruction| instruction.as_bytes()),
        Ok(&[0x80, 0x80][..])
    );
    assert_eq!(name_reference_huffman[2], 0xaa);

    let mut short_capacity = [0xaa; 2];
    let before = short_capacity;
    assert_eq!(
        QpackSetDynamicTableCapacityBuilder::new(&mut short_capacity, 220).build(),
        Err(QpackEncoderInstructionBuildError::BufferTooShort {
            required: 3,
            available: 2,
        })
    );
    assert_eq!(short_capacity, before);

    let mut short_name_reference = [0xaa; 1];
    let before = short_name_reference;
    assert_eq!(
        QpackInsertWithNameReferenceBuilder::new(&mut short_name_reference, false, 0, false, b"",)
            .build(),
        Err(QpackEncoderInstructionBuildError::BufferTooShort {
            required: 2,
            available: 1,
        })
    );
    assert_eq!(short_name_reference, before);

    let mut short_literal = [0xaa; 1];
    let before = short_literal;
    assert_eq!(
        QpackInsertWithLiteralNameBuilder::new(&mut short_literal, false, b"", false, b"").build(),
        Err(QpackEncoderInstructionBuildError::BufferTooShort {
            required: 2,
            available: 1,
        })
    );
    assert_eq!(short_literal, before);

    let mut short_duplicate = [];
    let before = short_duplicate;
    assert_eq!(
        QpackDuplicateBuilder::new(&mut short_duplicate, 0).build(),
        Err(QpackEncoderInstructionBuildError::BufferTooShort {
            required: 1,
            available: 0,
        })
    );
    assert_eq!(short_duplicate, before);

    let mut too_large_capacity = [0xaa; 16];
    let before = too_large_capacity;
    assert_eq!(
        QpackSetDynamicTableCapacityBuilder::new(&mut too_large_capacity, QPACK_INTEGER_MAX + 1)
            .build(),
        Err(QpackEncoderInstructionBuildError::SetDynamicTableCapacity(
            QpackIntegerBuildError::ValueTooLarge {
                value: QPACK_INTEGER_MAX + 1,
            }
        ))
    );
    assert_eq!(too_large_capacity, before);

    let mut too_large_name_index = [0xaa; 16];
    let before = too_large_name_index;
    assert_eq!(
        QpackInsertWithNameReferenceBuilder::new(
            &mut too_large_name_index,
            false,
            QPACK_INTEGER_MAX + 1,
            false,
            b"",
        )
        .build(),
        Err(
            QpackEncoderInstructionBuildError::InsertWithNameReferenceNameIndex(
                QpackIntegerBuildError::ValueTooLarge {
                    value: QPACK_INTEGER_MAX + 1,
                }
            )
        )
    );
    assert_eq!(too_large_name_index, before);

    let mut too_large_duplicate = [0xaa; 16];
    let before = too_large_duplicate;
    assert_eq!(
        QpackDuplicateBuilder::new(&mut too_large_duplicate, QPACK_INTEGER_MAX + 1).build(),
        Err(QpackEncoderInstructionBuildError::DuplicateIndex(
            QpackIntegerBuildError::ValueTooLarge {
                value: QPACK_INTEGER_MAX + 1,
            }
        ))
    );
    assert_eq!(too_large_duplicate, before);

    let mut name = *b"name";
    let mut value = *b"value";
    let mut destination = [0xaa; 16];
    let view =
        QpackInsertWithLiteralNameBuilder::new(&mut destination, false, &name, false, &value)
            .build()
            .expect("capacity");
    name.fill(b'x');
    value.fill(b'y');
    assert_eq!(view.name().encoded_payload(), b"name");
    assert_eq!(view.value().encoded_payload(), b"value");
    assert_eq!(view.as_bytes(), b"Dname\x05value");
}

#[test]
fn qpack_encoder_instruction_all_public_facades_compile() {
    let _: Option<net_wire::QpackEncoderInstruction<'static>> = None;
    let _: Option<net_wire::QpackSetDynamicTableCapacity<'static>> = None;
    let _: Option<net_wire::QpackInsertWithNameReference<'static>> = None;
    let _: Option<net_wire::QpackInsertWithLiteralName<'static>> = None;
    let _: Option<net_wire::QpackDuplicate<'static>> = None;
    let _: Option<net_wire::QpackEncoderInstructions<'static>> = None;
    let _: Option<net_wire::QpackEncoderInstructionIter<'static>> = None;
    let _: Option<net_wire::QpackEncoderInstructionParseError> = None;
    let _: Option<net_wire::QpackEncoderInstructionsParseError> = None;
    let _: Option<net_wire::QpackEncoderInstructionBuildError> = None;
    let _: Option<net_wire::QpackSetDynamicTableCapacityBuilder<'static>> = None;
    let _: Option<net_wire::QpackInsertWithNameReferenceBuilder<'static, 'static>> = None;
    let _: Option<net_wire::QpackInsertWithLiteralNameBuilder<'static, 'static, 'static>> = None;
    let _: Option<net_wire::QpackDuplicateBuilder<'static>> = None;

    let _: Option<qpack::QpackEncoderInstruction<'static>> = None;
    let _: Option<qpack::QpackSetDynamicTableCapacity<'static>> = None;
    let _: Option<qpack::QpackInsertWithNameReference<'static>> = None;
    let _: Option<qpack::QpackInsertWithLiteralName<'static>> = None;
    let _: Option<qpack::QpackDuplicate<'static>> = None;
    let _: Option<qpack::QpackEncoderInstructions<'static>> = None;
    let _: Option<qpack::QpackEncoderInstructionIter<'static>> = None;
    let _: Option<qpack::QpackEncoderInstructionParseError> = None;
    let _: Option<qpack::QpackEncoderInstructionsParseError> = None;
    let _: Option<qpack::QpackEncoderInstructionBuildError> = None;
    let _: Option<qpack::QpackSetDynamicTableCapacityBuilder<'static>> = None;
    let _: Option<qpack::QpackInsertWithNameReferenceBuilder<'static, 'static>> = None;
    let _: Option<qpack::QpackInsertWithLiteralNameBuilder<'static, 'static, 'static>> = None;
    let _: Option<qpack::QpackDuplicateBuilder<'static>> = None;
}

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
fn qpack_encoder_stream_failures_classification_atomicity_and_facades_are_exact() {
    let _: Option<QpackEncoderInstructionApplier> = None;
    let _: Option<QpackEncoderInstructionApplyError> = None;
    let _: Option<QpackEncoderInstructionApplyOutcome> = None;
    let _: Option<qpack::QpackEncoderInstructionApplier> = None;
    let _: Option<qpack::QpackEncoderInstructionApplyError> = None;
    let _: Option<qpack::QpackEncoderInstructionApplyOutcome> = None;
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
fn qpack_encoder_stream_sequence_applies_appendix_b_empty_and_facades_exactly() {
    let _: Option<net_wire::QpackEncoderInstructionsApplyError> = None;
    let _: Option<QpackEncoderInstructionsApplyError> = None;
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

#[test]
fn qpack_field_section_prefix_rfc_vectors_and_raw_boundaries_are_exact() {
    for (wire, required_insert_count, negative, delta_base) in [
        (&[0x00, 0x00][..], 0, false, 0),
        (&[0x03, 0x81][..], 3, true, 1),
        (&[0x05, 0x00][..], 5, false, 0),
        (&[0x00, 0x80][..], 0, true, 0),
    ] {
        assert_eq!(
            QpackFieldSectionPrefix::parse(wire).map(|prefix| (
                prefix.as_bytes(),
                prefix.encoded_required_insert_count().value(),
                prefix.is_negative(),
                prefix.delta_base().value(),
            )),
            Ok((wire, required_insert_count, negative, delta_base))
        );
    }

    let with_field_line = [0x03, 0x81, 0xd1, 0xaa];
    let prefix = QpackFieldSectionPrefix::parse(&with_field_line).expect("complete prefix");
    assert_eq!(prefix.as_bytes(), &[0x03, 0x81]);
    assert_eq!(prefix.encoded_required_insert_count().as_bytes(), &[0x03]);
    assert_eq!(prefix.delta_base().as_bytes(), &[0x81]);

    let noncanonical = [0xff, 0x80, 0, 0xff, 0x80, 0, 0xd1];
    let prefix = QpackFieldSectionPrefix::parse(&noncanonical).expect("complete prefix");
    assert_eq!(prefix.as_bytes(), &noncanonical[..6]);
    assert_eq!(prefix.encoded_required_insert_count().value(), 255);
    assert_eq!(
        prefix.encoded_required_insert_count().as_bytes(),
        &noncanonical[..3]
    );
    assert!(prefix.is_negative());
    assert_eq!(prefix.delta_base().value(), 127);
    assert_eq!(prefix.delta_base().as_bytes(), &noncanonical[3..6]);

    assert_eq!(
        QpackFieldSectionPrefix::parse(&[]),
        Err(QpackFieldSectionPrefixParseError::RequiredInsertCount(
            QpackIntegerParseError::Incomplete {
                required: 1,
                available: 0,
            }
        ))
    );
    assert_eq!(
        QpackFieldSectionPrefix::parse(&[0xff]),
        Err(QpackFieldSectionPrefixParseError::RequiredInsertCount(
            QpackIntegerParseError::Incomplete {
                required: 2,
                available: 1,
            }
        ))
    );
    assert_eq!(
        QpackFieldSectionPrefix::parse(&[0x00]),
        Err(QpackFieldSectionPrefixParseError::DeltaBase(
            QpackIntegerParseError::Incomplete {
                required: 1,
                available: 0,
            }
        ))
    );
    assert_eq!(
        QpackFieldSectionPrefix::parse(&[0x00, 0xff]),
        Err(QpackFieldSectionPrefixParseError::DeltaBase(
            QpackIntegerParseError::Incomplete {
                required: 2,
                available: 1,
            }
        ))
    );
}

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
fn qpack_field_section_context_public_facades_are_complete() {
    let _: Option<QpackFieldSectionContext> = None;
    let _: Option<QpackFieldSectionContextError> = None;
    let _: Option<qpack::QpackFieldSectionContext> = None;
    let _: Option<qpack::QpackFieldSectionContextError> = None;

    let root: Result<QpackFieldSectionContext, QpackFieldSectionContextError> =
        match QpackFieldSectionPrefix::parse(&[0x04, 0x82]) {
            Ok(prefix) => QpackFieldSectionContext::decode(prefix, 10, 100),
            Err(error) => panic!("{error}"),
        };
    assert_eq!(
        root.map(|context| (context.required_insert_count(), context.base())),
        Ok((9, 6))
    );
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

#[test]
fn qpack_field_section_prefix_builder_is_canonical_atomic_and_destination_only() {
    for (required_insert_count, negative, delta_base, expected) in [
        (0, false, 0, &[0x00, 0x00][..]),
        (3, true, 1, &[0x03, 0x81][..]),
        (5, false, 0, &[0x05, 0x00][..]),
        (0, true, 0, &[0x00, 0x80][..]),
        (255, false, 127, &[0xff, 0x00, 0x7f, 0x00][..]),
        (255, true, 127, &[0xff, 0x00, 0xff, 0x00][..]),
    ] {
        let mut destination = [0xaa; 20];
        let prefix = QpackFieldSectionPrefixBuilder::new(
            &mut destination,
            required_insert_count,
            negative,
            delta_base,
        )
        .build()
        .expect("capacity");
        assert_eq!(prefix.as_bytes(), expected);
        assert_eq!(destination[expected.len()], 0xaa);
    }

    let mut exact = [0xaa; 2];
    assert_eq!(
        QpackFieldSectionPrefixBuilder::new(&mut exact, 3, true, 1)
            .build()
            .map(QpackFieldSectionPrefix::as_bytes),
        Ok(&[0x03, 0x81][..])
    );

    let mut short = [0xaa; 2];
    let before = short;
    assert_eq!(
        QpackFieldSectionPrefixBuilder::new(&mut short, 255, true, 127).build(),
        Err(QpackFieldSectionPrefixBuildError::BufferTooShort {
            required: 4,
            available: 2,
        })
    );
    assert_eq!(short, before);

    for (required_insert_count, negative, delta_base, error) in [
        (
            QPACK_INTEGER_MAX + 1,
            false,
            0,
            QpackFieldSectionPrefixBuildError::RequiredInsertCount(
                QpackIntegerBuildError::ValueTooLarge {
                    value: QPACK_INTEGER_MAX + 1,
                },
            ),
        ),
        (
            0,
            true,
            QPACK_INTEGER_MAX + 1,
            QpackFieldSectionPrefixBuildError::DeltaBase(QpackIntegerBuildError::ValueTooLarge {
                value: QPACK_INTEGER_MAX + 1,
            }),
        ),
    ] {
        let mut destination = [0xaa; 20];
        let before = destination;
        assert_eq!(
            QpackFieldSectionPrefixBuilder::new(
                &mut destination,
                required_insert_count,
                negative,
                delta_base,
            )
            .build(),
            Err(error)
        );
        assert_eq!(destination, before);
    }

    let mut maximum = [0xaa; 20];
    let prefix = QpackFieldSectionPrefixBuilder::new(
        &mut maximum,
        QPACK_INTEGER_MAX,
        true,
        QPACK_INTEGER_MAX,
    )
    .build()
    .expect("maximum capacity");
    assert_eq!(
        prefix.encoded_required_insert_count().value(),
        QPACK_INTEGER_MAX
    );
    assert_eq!(prefix.delta_base().value(), QPACK_INTEGER_MAX);
    assert!(prefix.is_negative());

    let _: Option<net_wire::QpackFieldSectionPrefix<'static>> = None;
    let _: Option<net_wire::QpackFieldSectionPrefixParseError> = None;
    let _: Option<net_wire::QpackFieldSectionPrefixBuildError> = None;
    let _: Option<net_wire::QpackFieldSectionPrefixBuilder<'static>> = None;
    let _: Option<qpack::QpackFieldSectionPrefix<'static>> = None;
    let _: Option<qpack::QpackFieldSectionPrefixParseError> = None;
    let _: Option<qpack::QpackFieldSectionPrefixBuildError> = None;
    let _: Option<qpack::QpackFieldSectionPrefixBuilder<'static>> = None;
}

fn controlled_mask(prefix_bits: u8) -> u8 {
    match prefix_bits {
        2..=7 => (1u8 << prefix_bits) - 1,
        8 => u8::MAX,
        _ => 0,
    }
}

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
        net_wire::QpackSectionAcknowledgmentBuilder::new(&mut acknowledgment, 4)
            .build()
            .map(|instruction| instruction.as_bytes()),
        Ok(&[0x84][..])
    );
    assert_eq!(acknowledgment[1], 0xaa);
    let mut cancellation = [0xaa; 2];
    assert_eq!(
        net_wire::QpackStreamCancellationBuilder::new(&mut cancellation, 8)
            .build()
            .map(|instruction| instruction.as_bytes()),
        Ok(&[0x48][..])
    );
    assert_eq!(cancellation[1], 0xaa);
    let mut increment = [0xaa; 2];
    assert_eq!(
        net_wire::QpackInsertCountIncrementBuilder::new(&mut increment, 1)
            .build()
            .map(|instruction| instruction.as_bytes()),
        Ok(&[0x01][..])
    );
    assert_eq!(increment[1], 0xaa);
    let mut zero = [0xaa; 1];
    assert_eq!(
        net_wire::QpackInsertCountIncrementBuilder::new(&mut zero, 0)
            .build()
            .map(|instruction| (instruction.increment().value(), instruction.as_bytes())),
        Ok((0, &[0][..]))
    );

    let mut acknowledgment_boundary = [0xaa; 2];
    assert_eq!(
        net_wire::QpackSectionAcknowledgmentBuilder::new(&mut acknowledgment_boundary, 127)
            .build()
            .map(|instruction| instruction.as_bytes()),
        Ok(&[0xff, 0][..])
    );
    let mut cancellation_boundary = [0xaa; 2];
    assert_eq!(
        net_wire::QpackStreamCancellationBuilder::new(&mut cancellation_boundary, 63)
            .build()
            .map(|instruction| instruction.as_bytes()),
        Ok(&[0x7f, 0][..])
    );
    let mut increment_boundary = [0xaa; 2];
    assert_eq!(
        net_wire::QpackInsertCountIncrementBuilder::new(&mut increment_boundary, 63)
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
        net_wire::QpackSectionAcknowledgmentBuilder::new(&mut section[..0], 4).build(),
        Err(error)
    );
    assert_eq!(section, before);
    let mut cancel = [0xaa; 1];
    let before = cancel;
    assert_eq!(
        net_wire::QpackStreamCancellationBuilder::new(&mut cancel[..0], 8).build(),
        Err(error)
    );
    assert_eq!(cancel, before);
    let mut count = [0xaa; 1];
    let before = count;
    assert_eq!(
        net_wire::QpackInsertCountIncrementBuilder::new(&mut count[..0], 0).build(),
        Err(error)
    );
    assert_eq!(count, before);

    let too_large = QPACK_INTEGER_MAX + 1;
    let mut section = [0xaa; 16];
    let before = section;
    assert_eq!(
        net_wire::QpackSectionAcknowledgmentBuilder::new(&mut section, too_large).build(),
        Err(QpackDecoderInstructionBuildError::SectionAcknowledgment(
            QpackIntegerBuildError::ValueTooLarge { value: too_large },
        ))
    );
    assert_eq!(section, before);
    let mut cancel = [0xaa; 16];
    let before = cancel;
    assert_eq!(
        net_wire::QpackStreamCancellationBuilder::new(&mut cancel, too_large).build(),
        Err(QpackDecoderInstructionBuildError::StreamCancellation(
            QpackIntegerBuildError::ValueTooLarge { value: too_large },
        ))
    );
    assert_eq!(cancel, before);
    let mut count = [0xaa; 16];
    let before = count;
    assert_eq!(
        net_wire::QpackInsertCountIncrementBuilder::new(&mut count, too_large).build(),
        Err(QpackDecoderInstructionBuildError::InsertCountIncrement(
            QpackIntegerBuildError::ValueTooLarge { value: too_large },
        ))
    );
    assert_eq!(count, before);
}

#[test]
fn qpack_decoder_instruction_all_public_facades_compile() {
    let _: Option<net_wire::QpackDecoderInstruction<'static>> = None;
    let _: Option<net_wire::QpackSectionAcknowledgment<'static>> = None;
    let _: Option<net_wire::QpackStreamCancellation<'static>> = None;
    let _: Option<net_wire::QpackInsertCountIncrement<'static>> = None;
    let _: Option<net_wire::QpackDecoderInstructions<'static>> = None;
    let _: Option<net_wire::QpackDecoderInstructionIter<'static>> = None;
    let _: Option<net_wire::QpackDecoderInstructionParseError> = None;
    let _: Option<net_wire::QpackDecoderInstructionsParseError> = None;
    let _: Option<net_wire::QpackDecoderInstructionBuildError> = None;
    let _: Option<net_wire::QpackSectionAcknowledgmentBuilder<'static>> = None;
    let _: Option<net_wire::QpackStreamCancellationBuilder<'static>> = None;
    let _: Option<net_wire::QpackInsertCountIncrementBuilder<'static>> = None;

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

#[test]
fn qpack_field_line_all_five_forms_flags_and_boundaries_are_exact() {
    let literal_ref = [
        0x51, 0x0b, b'/', b'i', b'n', b'd', b'e', b'x', b'.', b'h', b't', b'm', b'l', 0xaa,
    ];
    let line = QpackFieldLine::parse(&literal_ref).expect("literal name reference");
    assert_eq!(line.as_bytes(), &literal_ref[..13]);
    match line {
        QpackFieldLine::LiteralNameReference(field) => {
            assert!(!field.is_never_indexed());
            assert!(field.is_static());
            assert_eq!(field.name_index().value(), 1);
            assert_eq!(field.value().encoded_payload(), b"/index.html");
        }
        _ => panic!("wrong field-line form"),
    }

    for (wire, index) in [([0x10, 0xaa], 0), ([0x11, 0xaa], 1)] {
        let line = QpackFieldLine::parse(&wire).expect("indexed post-base");
        assert_eq!(line.as_bytes(), &wire[..1]);
        match line {
            QpackFieldLine::IndexedPostBase(field) => assert_eq!(field.index().value(), index),
            _ => panic!("wrong field-line form"),
        }
    }

    for (wire, is_static, index) in [
        ([0x80, 0xaa], false, 0),
        ([0xc1, 0xaa], true, 1),
        ([0x81, 0xaa], false, 1),
    ] {
        let line = QpackFieldLine::parse(&wire).expect("indexed");
        assert_eq!(line.as_bytes(), &wire[..1]);
        match line {
            QpackFieldLine::Indexed(field) => {
                assert_eq!(field.is_static(), is_static);
                assert_eq!(field.index().value(), index);
            }
            _ => panic!("wrong field-line form"),
        }
    }

    for (wire, never_indexed, value) in [
        ([0x00, 1, b'x', 0xaa], false, b"x".as_slice()),
        ([0x08, 1, b'y', 0xaa], true, b"y".as_slice()),
    ] {
        let line = QpackFieldLine::parse(&wire).expect("literal post-base name reference");
        assert_eq!(line.as_bytes(), &wire[..3]);
        match line {
            QpackFieldLine::LiteralPostBaseNameReference(field) => {
                assert_eq!(field.is_never_indexed(), never_indexed);
                assert_eq!(field.name_index().value(), 0);
                assert_eq!(field.value().encoded_payload(), value);
            }
            _ => panic!("wrong field-line form"),
        }
    }

    for (wire, never_indexed, huffman, name, value) in [
        (
            [0x21, b'n', 1, b'v', 0xaa],
            false,
            false,
            b"n".as_slice(),
            b"v".as_slice(),
        ),
        (
            [0x39, b'h', 1, b'w', 0xaa],
            true,
            true,
            b"h".as_slice(),
            b"w".as_slice(),
        ),
    ] {
        let line = QpackFieldLine::parse(&wire).expect("literal name");
        assert_eq!(line.as_bytes(), &wire[..4]);
        match line {
            QpackFieldLine::LiteralName(field) => {
                assert_eq!(field.is_never_indexed(), never_indexed);
                assert_eq!(field.name().is_huffman(), huffman);
                assert_eq!(field.name().encoded_payload(), name);
                assert_eq!(field.value().encoded_payload(), value);
            }
            _ => panic!("wrong field-line form"),
        }
    }

    for (first, never_indexed, is_static) in [
        (0x40, false, false),
        (0x50, false, true),
        (0x60, true, false),
        (0x70, true, true),
    ] {
        let wire = [first, 1, b'v', 0xaa];
        let line = QpackFieldLine::parse(&wire).expect("literal name reference");
        assert_eq!(line.as_bytes(), &wire[..3]);
        match line {
            QpackFieldLine::LiteralNameReference(field) => {
                assert_eq!(field.is_never_indexed(), never_indexed);
                assert_eq!(field.is_static(), is_static);
                assert_eq!(field.name_index().value(), 0);
                assert_eq!(field.value().encoded_payload(), b"v");
            }
            _ => panic!("wrong field-line form"),
        }
    }
}

#[test]
fn qpack_field_line_noncanonical_components_and_nested_errors_are_exact() {
    let indexed = [0xbf, 0x80, 0, 0xaa];
    let line = QpackFieldLine::parse(&indexed).expect("noncanonical indexed integer");
    assert_eq!(line.as_bytes(), &indexed[..3]);
    match line {
        QpackFieldLine::Indexed(field) => {
            assert_eq!(field.index().as_bytes(), &indexed[..3]);
            assert_eq!(field.index().value(), 63);
        }
        _ => panic!("wrong field-line form"),
    }

    let literal_ref = [0x4f, 0x80, 0, 1, b'v', 0xaa];
    let line = QpackFieldLine::parse(&literal_ref).expect("noncanonical literal reference integer");
    assert_eq!(line.as_bytes(), &literal_ref[..5]);
    match line {
        QpackFieldLine::LiteralNameReference(field) => {
            assert_eq!(field.name_index().as_bytes(), &literal_ref[..3]);
            assert_eq!(field.name_index().value(), 15);
        }
        _ => panic!("wrong field-line form"),
    }

    let literal_name = [
        0x27, 0x80, 0, b'a', b'b', b'c', b'd', b'e', b'f', b'g', 0, 0xaa,
    ];
    let line = QpackFieldLine::parse(&literal_name).expect("noncanonical literal name length");
    assert_eq!(line.as_bytes(), &literal_name[..11]);
    match line {
        QpackFieldLine::LiteralName(field) => {
            assert_eq!(field.name().as_bytes(), &literal_name[..10]);
            assert!(!field.name().is_huffman());
            assert_eq!(field.name().encoded_payload(), b"abcdefg");
            assert_eq!(field.value().as_bytes(), &[0]);
        }
        _ => panic!("wrong field-line form"),
    }

    assert_eq!(
        QpackFieldLine::parse(&[]),
        Err(QpackFieldLineParseError::DispatchIncomplete)
    );
    assert_eq!(
        QpackFieldLine::parse(&[0xbf]),
        Err(QpackFieldLineParseError::IndexedIndex(
            qpack::QpackIntegerParseError::Incomplete {
                required: 2,
                available: 1
            }
        ))
    );
    assert_eq!(
        QpackFieldLine::parse(&[0x40]),
        Err(QpackFieldLineParseError::LiteralNameReferenceValue(
            qpack::QpackStringLiteralParseError::Length(
                qpack::QpackIntegerParseError::Incomplete {
                    required: 1,
                    available: 0
                }
            )
        ))
    );
    assert_eq!(
        QpackFieldLine::parse(&[0x40, 2, b'a']),
        Err(QpackFieldLineParseError::LiteralNameReferenceValue(
            qpack::QpackStringLiteralParseError::Incomplete {
                required: 3,
                available: 2
            }
        ))
    );
    assert_eq!(
        QpackFieldLine::parse(&[0x22, b'a']),
        Err(QpackFieldLineParseError::LiteralNameName(
            qpack::QpackStringLiteralParseError::Incomplete {
                required: 3,
                available: 2
            }
        ))
    );
    assert_eq!(
        QpackFieldLine::parse(&[0x21, b'n']),
        Err(QpackFieldLineParseError::LiteralNameValue(
            qpack::QpackStringLiteralParseError::Length(
                qpack::QpackIntegerParseError::Incomplete {
                    required: 1,
                    available: 0
                }
            )
        ))
    );
    assert_eq!(
        QpackFieldLine::parse(&[0x00]),
        Err(QpackFieldLineParseError::LiteralPostBaseNameReferenceValue(
            qpack::QpackStringLiteralParseError::Length(
                qpack::QpackIntegerParseError::Incomplete {
                    required: 1,
                    available: 0
                }
            )
        ))
    );
}

#[test]
fn qpack_field_line_builders_are_canonical_exact_and_destination_only() {
    let mut indexed_static = [0xaa; 2];
    let indexed = QpackIndexedFieldLineBuilder::new(&mut indexed_static, true, 0)
        .build()
        .expect("capacity");
    assert!(indexed.is_static());
    assert_eq!(indexed.index().value(), 0);
    assert_eq!(indexed.as_bytes(), &[0xc0]);
    assert!(matches!(
        QpackFieldLine::parse(indexed.as_bytes()),
        Ok(QpackFieldLine::Indexed(field))
            if field.is_static() && field.index().value() == 0 && field.as_bytes() == [0xc0]
    ));
    assert_eq!(indexed_static[1], 0xaa);

    let mut indexed_dynamic = [0xaa; 3];
    let indexed = QpackIndexedFieldLineBuilder::new(&mut indexed_dynamic, false, 63)
        .build()
        .expect("capacity");
    assert!(!indexed.is_static());
    assert_eq!(indexed.index().value(), 63);
    assert_eq!(indexed.as_bytes(), &[0xbf, 0x00]);
    assert_eq!(indexed_dynamic[2], 0xaa);

    let mut indexed_post_base = [0xaa; 3];
    let indexed = QpackIndexedPostBaseFieldLineBuilder::new(&mut indexed_post_base, 15)
        .build()
        .expect("capacity");
    assert_eq!(indexed.index().value(), 15);
    assert_eq!(indexed.as_bytes(), &[0x1f, 0x00]);
    assert_eq!(indexed_post_base[2], 0xaa);

    let mut literal_reference = [0xaa; 6];
    let field = QpackLiteralNameReferenceFieldLineBuilder::new(
        &mut literal_reference,
        true,
        true,
        15,
        true,
        &[0xab, 0xcd],
    )
    .build()
    .expect("capacity");
    assert!(field.is_never_indexed());
    assert!(field.is_static());
    assert_eq!(field.name_index().value(), 15);
    assert!(field.value().is_huffman());
    assert_eq!(field.value().encoded_payload(), &[0xab, 0xcd]);
    assert_eq!(field.as_bytes(), &[0x7f, 0x00, 0x82, 0xab, 0xcd]);
    assert!(matches!(
        QpackFieldLine::parse(field.as_bytes()),
        Ok(QpackFieldLine::LiteralNameReference(parsed))
            if parsed.is_never_indexed()
                && parsed.is_static()
                && parsed.name_index().value() == 15
                && parsed.value().is_huffman()
                && parsed.value().encoded_payload() == [0xab, 0xcd]
    ));
    assert_eq!(literal_reference[5], 0xaa);

    let mut literal_reference_plain = [0xaa; 4];
    let field = QpackLiteralNameReferenceFieldLineBuilder::new(
        &mut literal_reference_plain,
        false,
        false,
        1,
        false,
        b"x",
    )
    .build()
    .expect("capacity");
    assert!(!field.is_never_indexed());
    assert!(!field.is_static());
    assert_eq!(field.name_index().value(), 1);
    assert!(!field.value().is_huffman());
    assert_eq!(field.value().encoded_payload(), b"x");
    assert_eq!(field.as_bytes(), &[0x41, 0x01, b'x']);
    assert_eq!(literal_reference_plain[3], 0xaa);

    let mut post_base_literal = [0xaa; 5];
    let field = QpackLiteralPostBaseNameReferenceFieldLineBuilder::new(
        &mut post_base_literal,
        true,
        7,
        false,
        b"x",
    )
    .build()
    .expect("capacity");
    assert!(field.is_never_indexed());
    assert_eq!(field.name_index().value(), 7);
    assert!(!field.value().is_huffman());
    assert_eq!(field.value().encoded_payload(), b"x");
    assert_eq!(field.as_bytes(), &[0x0f, 0x00, 0x01, b'x']);
    assert_eq!(post_base_literal[4], 0xaa);

    let mut literal_name = [0xaa; 5];
    let field =
        QpackLiteralNameFieldLineBuilder::new(&mut literal_name, true, true, b"n", false, b"v")
            .build()
            .expect("capacity");
    assert!(field.is_never_indexed());
    assert!(field.name().is_huffman());
    assert_eq!(field.name().encoded_payload(), b"n");
    assert!(!field.value().is_huffman());
    assert_eq!(field.value().encoded_payload(), b"v");
    assert_eq!(field.as_bytes(), &[0x39, b'n', 0x01, b'v']);
    assert_eq!(literal_name[4], 0xaa);

    let mut destination = [0xaa; 5];
    let field = {
        let name = *b"n";
        let value = *b"v";
        QpackLiteralNameFieldLineBuilder::new(&mut destination, false, false, &name, true, &value)
            .build()
            .expect("capacity")
    };
    assert_eq!(field.name().encoded_payload(), b"n");
    assert!(field.value().is_huffman());
    assert_eq!(field.value().encoded_payload(), b"v");
    assert_eq!(field.as_bytes(), &[0x21, b'n', 0x81, b'v']);
    assert_eq!(destination[4], 0xaa);
}

#[test]
fn qpack_field_line_builder_failures_are_atomic_and_facades_are_complete() {
    let mut short = [0xaa; 4];
    let before = short;
    assert_eq!(
        QpackLiteralNameReferenceFieldLineBuilder::new(
            &mut short,
            true,
            true,
            15,
            true,
            &[0xab, 0xcd],
        )
        .build(),
        Err(QpackFieldLineBuildError::BufferTooShort {
            required: 5,
            available: 4,
        })
    );
    assert_eq!(short, before);

    let too_large = QPACK_INTEGER_MAX + 1;
    let mut indexed = [0xaa; 16];
    let before = indexed;
    assert_eq!(
        QpackIndexedFieldLineBuilder::new(&mut indexed, false, too_large).build(),
        Err(QpackFieldLineBuildError::IndexedIndex(
            QpackIntegerBuildError::ValueTooLarge { value: too_large },
        ))
    );
    assert_eq!(indexed, before);

    let mut post_base = [0xaa; 16];
    let before = post_base;
    assert_eq!(
        QpackLiteralPostBaseNameReferenceFieldLineBuilder::new(
            &mut post_base,
            false,
            too_large,
            false,
            b"",
        )
        .build(),
        Err(
            QpackFieldLineBuildError::LiteralPostBaseNameReferenceNameIndex(
                QpackIntegerBuildError::ValueTooLarge { value: too_large },
            )
        )
    );
    assert_eq!(post_base, before);

    let _: Option<net_wire::QpackFieldLineBuildError> = None;
    let _: Option<net_wire::QpackIndexedFieldLineBuilder<'static>> = None;
    let _: Option<net_wire::QpackIndexedPostBaseFieldLineBuilder<'static>> = None;
    let _: Option<net_wire::QpackLiteralNameReferenceFieldLineBuilder<'static, 'static>> = None;
    let _: Option<net_wire::QpackLiteralPostBaseNameReferenceFieldLineBuilder<'static, 'static>> =
        None;
    let _: Option<net_wire::QpackLiteralNameFieldLineBuilder<'static, 'static, 'static>> = None;
    let _: Option<qpack::QpackFieldLineBuildError> = None;
    let _: Option<qpack::QpackIndexedFieldLineBuilder<'static>> = None;
    let _: Option<qpack::QpackIndexedPostBaseFieldLineBuilder<'static>> = None;
    let _: Option<qpack::QpackLiteralNameReferenceFieldLineBuilder<'static, 'static>> = None;
    let _: Option<qpack::QpackLiteralPostBaseNameReferenceFieldLineBuilder<'static, 'static>> =
        None;
    let _: Option<qpack::QpackLiteralNameFieldLineBuilder<'static, 'static, 'static>> = None;
}

#[test]
fn qpack_field_lines_sequence_iteration_and_public_facades_are_exact() {
    let bytes = [0x80, 0x10, 0x00, 1, b'x', 0x21, b'n', 1, b'v'];
    let lines = QpackFieldLines::parse(&bytes).expect("field-line sequence");
    assert_eq!(lines.as_bytes(), &bytes);
    let mut iter = lines.iter();
    assert_eq!(
        iter.next().expect("first").expect("indexed").as_bytes(),
        &[0x80]
    );
    assert_eq!(
        iter.next().expect("second").expect("post-base").as_bytes(),
        &[0x10]
    );
    assert_eq!(
        iter.next()
            .expect("third")
            .expect("post-base literal")
            .as_bytes(),
        &[0x00, 1, b'x']
    );
    assert_eq!(
        iter.next()
            .expect("fourth")
            .expect("literal name")
            .as_bytes(),
        &[0x21, b'n', 1, b'v']
    );
    assert_eq!(iter.next(), None);
    assert_eq!(iter.next(), None);

    let empty = QpackFieldLines::parse(&[]).expect("empty sequence");
    assert_eq!(empty.as_bytes(), &[]);
    assert_eq!(empty.iter().next(), None);

    let malformed = [0x80, 0x40];
    let expected = QpackFieldLineParseError::LiteralNameReferenceValue(
        qpack::QpackStringLiteralParseError::Length(qpack::QpackIntegerParseError::Incomplete {
            required: 1,
            available: 0,
        }),
    );
    let error = QpackFieldLines::parse(&malformed).expect_err("malformed sequence");
    assert_eq!(error.offset(), 1);
    assert_eq!(error.error(), expected);
    let mut iter = QpackFieldLineIter::new(&malformed);
    assert_eq!(
        iter.next().expect("first").expect("indexed").as_bytes(),
        &[0x80]
    );
    assert_eq!(iter.next(), Some(Err(expected)));
    assert_eq!(iter.next(), None);
    assert_eq!(iter.next(), None);

    let _: Option<net_wire::QpackFieldLine<'static>> = None;
    let _: Option<net_wire::QpackIndexedFieldLine<'static>> = None;
    let _: Option<net_wire::QpackIndexedPostBaseFieldLine<'static>> = None;
    let _: Option<net_wire::QpackLiteralNameReferenceFieldLine<'static>> = None;
    let _: Option<net_wire::QpackLiteralPostBaseNameReferenceFieldLine<'static>> = None;
    let _: Option<net_wire::QpackLiteralNameFieldLine<'static>> = None;
    let _: Option<net_wire::QpackFieldLineParseError> = None;
    let _: Option<net_wire::QpackFieldLines<'static>> = None;
    let _: Option<net_wire::QpackFieldLinesParseError> = None;
    let _: Option<net_wire::QpackFieldLineIter<'static>> = None;
    let _: Option<qpack::QpackFieldLine<'static>> = None;
    let _: Option<qpack::QpackIndexedFieldLine<'static>> = None;
    let _: Option<qpack::QpackIndexedPostBaseFieldLine<'static>> = None;
    let _: Option<qpack::QpackLiteralNameReferenceFieldLine<'static>> = None;
    let _: Option<qpack::QpackLiteralPostBaseNameReferenceFieldLine<'static>> = None;
    let _: Option<qpack::QpackLiteralNameFieldLine<'static>> = None;
    let _: Option<qpack::QpackFieldLineParseError> = None;
    let _: Option<qpack::QpackFieldLines<'static>> = None;
    let _: Option<qpack::QpackFieldLinesParseError> = None;
    let _: Option<qpack::QpackFieldLineIter<'static>> = None;
}

#[test]
fn qpack_field_section_decoder_all_forms_order_flags_and_facades_are_exact() {
    let _: Option<QpackDecodedFieldEntry> = None;
    let _: Option<QpackDecodedFieldRef<'static>> = None;
    let _: Option<QpackDecodedFieldIter<'static>> = None;
    let _: Option<QpackDecodedFieldSection<'static>> = None;
    let _: Option<QpackFieldSectionBlocked> = None;
    let _: Option<QpackFieldSectionDecodeError> = None;
    let _: Option<QpackFieldSectionDecodeOutcome<'static>> = None;
    let _: Option<QpackFieldSectionDecoder> = None;
    let _: Option<QpackFieldSectionOutput<'static, 'static>> = None;
    let _: Option<qpack::QpackDecodedFieldEntry> = None;
    let _: Option<qpack::QpackDecodedFieldRef<'static>> = None;
    let _: Option<qpack::QpackDecodedFieldIter<'static>> = None;
    let _: Option<qpack::QpackDecodedFieldSection<'static>> = None;
    let _: Option<qpack::QpackFieldSectionBlocked> = None;
    let _: Option<qpack::QpackFieldSectionDecodeError> = None;
    let _: Option<qpack::QpackFieldSectionDecodeOutcome<'static>> = None;
    let _: Option<qpack::QpackFieldSectionDecoder> = None;
    let _: Option<qpack::QpackFieldSectionOutput<'static, 'static>> = None;

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

#[test]
fn qpack_decoder_feedback_state_starts_empty_and_facades_are_complete() {
    let _: Option<net_wire::QpackDecoderState> = None;
    let _: Option<net_wire::QpackDecoderFeedbackError> = None;
    let _: Option<qpack::QpackDecoderState> = None;
    let _: Option<qpack::QpackDecoderFeedbackError> = None;

    assert_eq!(
        net_wire::QpackDecoderState::default().known_received_count(),
        0
    );
    assert_eq!(qpack::QpackDecoderState::new().known_received_count(), 0);
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

#[test]
fn qpack_encoder_state_initialization_zero_reference_and_facades_are_exact() {
    let _: Option<QpackEncoderOutstandingSection> = None;
    let _: Option<QpackEncoderState<'static, 'static>> = None;
    let _: Option<QpackEncoderStateError> = None;
    let _: Option<qpack::QpackEncoderOutstandingSection> = None;
    let _: Option<qpack::QpackEncoderState<'static, 'static>> = None;
    let _: Option<qpack::QpackEncoderStateError> = None;

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
fn qpack_encoder_state_insert_count_increment_errors_overflow_and_facades_are_exact() {
    let _: Option<QpackDecoderInstructionApplyError> = None;
    let _: Option<qpack::QpackDecoderInstructionApplyError> = None;

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
    let _: Option<net_wire::QpackDecoderInstructionsApplyError> = None;
    let _: Option<qpack::QpackDecoderInstructionsApplyError> = None;

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

#[test]
fn qpack_blocked_streams_limits_storage_and_facades_are_exact() {
    let _: Option<QpackBlockedStream> = None;
    let _: Option<QpackBlockedStreams<'static>> = None;
    let _: Option<QpackBlockedStreamsError> = None;
    let _: Option<QpackReadyBlockedStreamIter<'static>> = None;
    let _: Option<qpack::QpackBlockedStream> = None;
    let _: Option<qpack::QpackBlockedStreams<'static>> = None;
    let _: Option<qpack::QpackBlockedStreamsError> = None;
    let _: Option<qpack::QpackReadyBlockedStreamIter<'static>> = None;

    let blocked = |encoded: &[u8]| {
        let mut storage = [];
        let mut entries = [];
        let table = QpackDynamicTable::new(&mut storage, &mut entries);
        let mut bytes = [];
        let mut fields = [];
        let mut output = QpackFieldSectionOutput::new(&mut bytes, &mut fields);
        match QpackFieldSectionDecoder::new(128)
            .decode(encoded, &table, &mut output)
            .expect("blocked prefix")
        {
            QpackFieldSectionDecodeOutcome::Blocked(blocked) => blocked,
            QpackFieldSectionDecodeOutcome::Decoded(_) => panic!("blocked prefix"),
        }
    };
    let blocked_one = blocked(&[2, 0]);
    assert_eq!(blocked_one.required_insert_count(), 1);

    let mut records = [QpackBlockedStream::EMPTY; 2];
    {
        let mut seeded = QpackBlockedStreams::new(&mut records, 2).expect("storage fits maximum");
        assert_eq!(seeded.register(7, blocked_one), Ok(()));
        assert_eq!(seeded.register(8, blocked_one), Ok(()));
    }
    let before = records;
    let error = match QpackBlockedStreams::new(&mut records, 3) {
        Err(error) => error,
        Ok(_) => panic!("maximum exceeds storage"),
    };
    assert_eq!(
        error,
        QpackBlockedStreamsError::MaximumBlockedStreamsExceedsStorage {
            maximum: 3,
            storage_capacity: 2,
        }
    );
    assert!(error.is_provisioning_error());
    assert!(!error.is_decompression_failed());
    assert!(error.to_string().contains("3"));
    assert!(error.to_string().contains("2"));
    assert_eq!(records, before);

    #[cfg(target_pointer_width = "32")]
    {
        let before = records;
        let error = match QpackBlockedStreams::new(&mut records, u64::MAX) {
            Err(error) => error,
            Ok(_) => panic!("maximum is unrepresentable"),
        };
        assert_eq!(
            error,
            QpackBlockedStreamsError::MaximumBlockedStreamsExceedsStorage {
                maximum: u64::MAX,
                storage_capacity: 2,
            }
        );
        assert_eq!(records, before);
    }

    {
        let cleared = QpackBlockedStreams::new(&mut records, 2).expect("storage fits maximum");
        assert_eq!(
            (
                cleared.maximum_blocked_streams(),
                cleared.storage_capacity(),
                cleared.len(),
                cleared.is_empty(),
            ),
            (2, 2, 0, true)
        );
    }
    assert_eq!(records, [QpackBlockedStream::EMPTY; 2]);

    let mut no_records = [];
    let mut none = QpackBlockedStreams::new(&mut no_records, 0).expect("zero is valid");
    assert_eq!(
        (
            none.maximum_blocked_streams(),
            none.storage_capacity(),
            none.len(),
            none.is_empty(),
        ),
        (0, 0, 0, true)
    );
    let error = none.register(0, blocked_one).expect_err("maximum is zero");
    assert_eq!(
        error,
        QpackBlockedStreamsError::BlockedStreamsLimitExceeded { maximum: 0 }
    );
    assert!(error.is_decompression_failed());
    assert!(!error.is_provisioning_error());
    assert!(error.to_string().contains("0"));
}

#[test]
fn qpack_blocked_streams_distinct_count_aggregation_and_removal_are_exact() {
    let blocked = |encoded: &[u8]| {
        let mut storage = [];
        let mut entries = [];
        let table = QpackDynamicTable::new(&mut storage, &mut entries);
        let mut bytes = [];
        let mut fields = [];
        let mut output = QpackFieldSectionOutput::new(&mut bytes, &mut fields);
        match QpackFieldSectionDecoder::new(128)
            .decode(encoded, &table, &mut output)
            .expect("blocked prefix")
        {
            QpackFieldSectionDecodeOutcome::Blocked(blocked) => blocked,
            QpackFieldSectionDecodeOutcome::Decoded(_) => panic!("blocked prefix"),
        }
    };
    let one = blocked(&[2, 0]);
    let two = blocked(&[3, 0]);
    let three = blocked(&[4, 0]);
    assert_eq!(
        (
            one.required_insert_count(),
            two.required_insert_count(),
            three.required_insert_count(),
        ),
        (1, 2, 3)
    );

    let mut records = [QpackBlockedStream::EMPTY; 3];
    let mut streams = QpackBlockedStreams::new(&mut records, 2).expect("storage fits maximum");
    assert_eq!(streams.register(0, one), Ok(()));
    assert_eq!(streams.register(u64::MAX, two), Ok(()));
    assert_eq!((streams.len(), streams.is_empty()), (2, false));
    assert_eq!(streams.register(0, one), Ok(()));
    assert_eq!(streams.register(0, three), Ok(()));
    assert_eq!(streams.len(), 2);
    let mut ready = streams.ready(3);
    assert_eq!(
        ready
            .next()
            .map(|record| (record.stream_id(), record.required_insert_count())),
        Some((0, 3))
    );
    assert_eq!(
        ready
            .next()
            .map(|record| (record.stream_id(), record.required_insert_count())),
        Some((u64::MAX, 2))
    );
    assert_eq!(ready.next(), None);
    assert!(streams.contains(0));
    assert!(streams.contains(u64::MAX));
    assert!(streams.is_blocked(0, 2));
    assert!(!streams.is_blocked(0, 3));
    assert!(streams.is_blocked(u64::MAX, 1));
    assert!(!streams.is_blocked(u64::MAX, 2));

    let before = streams.len();
    let error = streams.register(9, one).expect_err("distinct maximum");
    assert_eq!(
        error,
        QpackBlockedStreamsError::BlockedStreamsLimitExceeded { maximum: 2 }
    );
    assert!(error.is_decompression_failed());
    assert_eq!(streams.len(), before);
    let mut ready = streams.ready(3);
    assert_eq!(ready.next().map(QpackBlockedStream::stream_id), Some(0));
    assert_eq!(
        ready.next().map(QpackBlockedStream::stream_id),
        Some(u64::MAX)
    );
    assert_eq!(ready.next(), None);
    assert!(!streams.contains(9));
    assert!(!streams.is_blocked(9, 0));

    assert!(streams.remove(0));
    assert_eq!(streams.len(), 1);
    assert!(!streams.contains(0));
    assert!(!streams.remove(0));
    assert_eq!(streams.len(), 1);
    assert_eq!(streams.register(5, one), Ok(()));
    let mut ready = streams.ready(3);
    assert_eq!(ready.next().map(QpackBlockedStream::stream_id), Some(5));
    assert_eq!(
        ready.next().map(QpackBlockedStream::stream_id),
        Some(u64::MAX)
    );
    assert_eq!(ready.next(), None);
}

#[test]
fn qpack_blocked_streams_ready_iteration_is_ordered_fused_and_non_mutating() {
    fn assert_fused<I: core::iter::FusedIterator>(_iterator: &I) {}

    let blocked = |encoded: &[u8]| {
        let mut storage = [];
        let mut entries = [];
        let table = QpackDynamicTable::new(&mut storage, &mut entries);
        let mut bytes = [];
        let mut fields = [];
        let mut output = QpackFieldSectionOutput::new(&mut bytes, &mut fields);
        match QpackFieldSectionDecoder::new(128)
            .decode(encoded, &table, &mut output)
            .expect("blocked prefix")
        {
            QpackFieldSectionDecodeOutcome::Blocked(blocked) => blocked,
            QpackFieldSectionDecodeOutcome::Decoded(_) => panic!("blocked prefix"),
        }
    };
    let one = blocked(&[2, 0]);
    let two = blocked(&[3, 0]);
    let three = blocked(&[4, 0]);
    let four = blocked(&[5, 0]);

    let mut records = [QpackBlockedStream::EMPTY; 4];
    let mut streams = QpackBlockedStreams::new(&mut records, 4).expect("storage fits maximum");
    assert_eq!(streams.register(10, three), Ok(()));
    assert_eq!(streams.register(20, one), Ok(()));
    assert_eq!(streams.register(30, four), Ok(()));
    assert!(streams.remove(20));
    assert_eq!(streams.register(40, two), Ok(()));

    let mut ready = streams.ready(2);
    assert_fused(&ready);
    let (lower, upper) = ready.size_hint();
    assert!(lower <= 1);
    if let Some(upper) = upper {
        assert!(upper >= 1);
    }
    assert_eq!(
        ready
            .next()
            .map(|record| (record.stream_id(), record.required_insert_count())),
        Some((40, 2))
    );
    assert_eq!(ready.next(), None);
    assert_eq!(ready.next(), None);
    let mut ready = streams.ready(3);
    assert_eq!(ready.next().map(QpackBlockedStream::stream_id), Some(10));
    assert_eq!(ready.next().map(QpackBlockedStream::stream_id), Some(40));
    assert_eq!(ready.next(), None);
    let mut ready = streams.ready(4);
    assert_eq!(ready.next().map(QpackBlockedStream::stream_id), Some(10));
    assert_eq!(ready.next().map(QpackBlockedStream::stream_id), Some(40));
    assert_eq!(ready.next().map(QpackBlockedStream::stream_id), Some(30));
    assert_eq!(ready.next(), None);
    assert_eq!(streams.len(), 3);
    for stream_id in [10, 30, 40] {
        assert!(streams.contains(stream_id));
    }

    let copied = {
        let mut ready = streams.ready(3);
        ready.next().expect("ready record")
    };
    assert_eq!(
        (copied.stream_id(), copied.required_insert_count()),
        (10, 3)
    );
    assert!(streams.remove(copied.stream_id()));
    assert_eq!(streams.len(), 2);
    assert!(!streams.contains(10));
}

#[test]
fn qpack_field_section_encoder_static_forms_are_exact_and_unregistered() {
    let _: Option<QpackFieldSectionEncoder> = None;
    let _: Option<QpackFieldPlan<'static>> = None;
    let _: Option<QpackFieldSectionBase> = None;
    let _: Option<QpackFieldSectionEncodeBuffers<'static, 'static, 'static>> = None;
    let _: Option<QpackFieldSectionPlanSlot<'static>> = None;
    let _: Option<QpackFieldSectionEncodeError> = None;
    let _: Option<QpackFieldSectionPlanError> = None;
    let _: Option<qpack::QpackFieldSectionEncoder> = None;
    let _: Option<qpack::QpackFieldPlan<'static>> = None;
    let _: Option<qpack::QpackFieldSectionEncodeBuffers<'static, 'static, 'static>> = None;

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
