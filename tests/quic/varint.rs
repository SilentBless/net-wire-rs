use net_wire::quic::*;

#[test]
fn parses_rfc_9000_appendix_a_1_values_and_exact_views() {
    let fixtures = [
        (37, &[0x25][..], QuicVarIntLen::One),
        (15_293, &[0x7b, 0xbd][..], QuicVarIntLen::Two),
        (
            494_878_333,
            &[0x9d, 0x7f, 0x3e, 0x7d][..],
            QuicVarIntLen::Four,
        ),
        (
            151_288_809_941_952_652,
            &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c][..],
            QuicVarIntLen::Eight,
        ),
    ];

    for (value, bytes, length) in fixtures {
        let mut input = [0xee; 9];
        input[..bytes.len()].copy_from_slice(bytes);
        let parsed = QuicVarInt::parse(&input).unwrap();
        assert_eq!(parsed.value(), value);
        assert_eq!(parsed.as_bytes(), bytes);
        assert_eq!(parsed.encoded_len(), length);
        assert_eq!(parsed.byte_len(), bytes.len());
        assert!(parsed.is_canonical());
    }
}

#[test]
fn parses_boundaries_noncanonical_values_and_all_truncations() {
    let boundaries = [
        (63, &[0x3f][..], QuicVarIntLen::One),
        (64, &[0x40, 0x40][..], QuicVarIntLen::Two),
        (16_383, &[0x7f, 0xff][..], QuicVarIntLen::Two),
        (16_384, &[0x80, 0x00, 0x40, 0x00][..], QuicVarIntLen::Four),
        (
            1_073_741_823,
            &[0xbf, 0xff, 0xff, 0xff][..],
            QuicVarIntLen::Four,
        ),
        (
            1_073_741_824,
            &[0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00][..],
            QuicVarIntLen::Eight,
        ),
        (
            (1u64 << 62) - 1,
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..],
            QuicVarIntLen::Eight,
        ),
    ];
    for (value, bytes, length) in boundaries {
        let parsed = QuicVarInt::parse(bytes).unwrap();
        assert_eq!((parsed.value(), parsed.encoded_len()), (value, length));
        assert!(parsed.is_canonical());
    }

    let noncanonical = QuicVarInt::parse(&[0x40, 0x25]).unwrap();
    assert_eq!(noncanonical.value(), 37);
    assert_eq!(noncanonical.encoded_len(), QuicVarIntLen::Two);
    assert!(!noncanonical.is_canonical());

    assert_eq!(
        QuicVarInt::parse(&[]),
        Err(QuicVarIntParseError::Incomplete {
            required: 1,
            available: 0
        })
    );
    for (input, required) in [
        (&[0x40][..], 2),
        (&[0x80, 0][..], 4),
        (&[0xc0, 0, 0][..], 8),
    ] {
        assert_eq!(
            QuicVarInt::parse(input),
            Err(QuicVarIntParseError::Incomplete {
                required,
                available: input.len()
            })
        );
    }
}

#[test]
fn builds_canonical_and_explicit_widths_atomically() {
    let fixtures = [
        (37, &[0x25][..]),
        (15_293, &[0x7b, 0xbd][..]),
        (494_878_333, &[0x9d, 0x7f, 0x3e, 0x7d][..]),
        (
            151_288_809_941_952_652,
            &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c][..],
        ),
    ];
    for (value, expected) in fixtures {
        let mut destination = [0xa5; 9];
        let built = QuicVarIntBuilder::new(&mut destination, value)
            .build()
            .unwrap();
        assert_eq!(built.as_bytes(), expected);
        assert_eq!(destination[expected.len()], 0xa5);
    }

    let mut destination = [0xa5; 3];
    let built = QuicVarIntBuilder::new(&mut destination, 37)
        .with_len(QuicVarIntLen::Two)
        .build()
        .unwrap();
    assert_eq!(built.as_bytes(), &[0x40, 0x25]);
    assert_eq!(destination[2], 0xa5);

    let mut failures = [0xa5; 8];
    let before = failures;
    assert_eq!(
        QuicVarIntBuilder::new(&mut failures, 1u64 << 62).build(),
        Err(QuicVarIntBuildError::ValueTooLarge { value: 1u64 << 62 })
    );
    assert_eq!(failures, before);
    assert_eq!(
        QuicVarIntBuilder::new(&mut failures, 64)
            .with_len(QuicVarIntLen::One)
            .build(),
        Err(QuicVarIntBuildError::WidthTooSmall {
            length: QuicVarIntLen::One,
            value: 64
        })
    );
    assert_eq!(failures, before);
    assert_eq!(
        QuicVarIntBuilder::new(&mut failures[..1], 64).build(),
        Err(QuicVarIntBuildError::BufferTooShort {
            required: 2,
            available: 1
        })
    );
    assert_eq!(failures, before);
}
