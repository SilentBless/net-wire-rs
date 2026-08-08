use net_wire::http2::hpack::{
    HpackInteger, HpackIntegerBuildError, HpackIntegerBuilder, HpackIntegerParseError,
};

#[test]
fn hpack_integer_parses_rfc_examples_and_exact_views() {
    let ten = HpackInteger::parse(&[0xea, 0xaa], 5).unwrap();
    assert_eq!(ten.value(), 10);
    assert_eq!(ten.as_bytes(), [0xea]);
    assert_eq!(ten.prefix_bits(), 5);
    assert_eq!(ten.high_bits(), 0xe0);

    let large = HpackInteger::parse(&[0xbf, 0x9a, 0x0a, 0xaa], 5).unwrap();
    assert_eq!(large.value(), 1337);
    assert_eq!(large.as_bytes(), [0xbf, 0x9a, 0x0a]);
    assert_eq!(large.high_bits(), 0xa0);

    let eight_bit = HpackInteger::parse(&[42, 0xaa], 8).unwrap();
    assert_eq!(eight_bit.value(), 42);
    assert_eq!(eight_bit.as_bytes(), [42]);
    assert_eq!(eight_bit.high_bits(), 0);
}

#[test]
fn hpack_integer_parses_saturated_and_overlong_representations() {
    let saturated = HpackInteger::parse(&[0x1f, 0x80, 0x01], 5).unwrap();
    assert_eq!(saturated.value(), 159);
    assert_eq!(saturated.as_bytes(), [0x1f, 0x80, 0x01]);

    let overlong = HpackInteger::parse(&[0x1f, 0x80, 0x00, 0xaa], 5).unwrap();
    assert_eq!(overlong.value(), 31);
    assert_eq!(overlong.as_bytes(), [0x1f, 0x80, 0x00]);
}

#[test]
fn hpack_integer_rejects_invalid_incomplete_and_overflow_representations() {
    assert_eq!(
        HpackInteger::parse(&[], 5),
        Err(HpackIntegerParseError::Incomplete {
            required: 1,
            available: 0,
        })
    );
    assert_eq!(
        HpackInteger::parse(&[0x1f], 5),
        Err(HpackIntegerParseError::Incomplete {
            required: 2,
            available: 1,
        })
    );
    assert_eq!(
        HpackInteger::parse(&[0], 0),
        Err(HpackIntegerParseError::InvalidPrefixBits { prefix_bits: 0 })
    );
    assert_eq!(
        HpackInteger::parse(&[0], 9),
        Err(HpackIntegerParseError::InvalidPrefixBits { prefix_bits: 9 })
    );
    assert_eq!(
        HpackInteger::parse(
            &[
                0x1f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02
            ],
            5,
        ),
        Err(HpackIntegerParseError::Overflow)
    );
    assert_eq!(
        HpackInteger::parse(
            &[
                0x1f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00
            ],
            5,
        ),
        Err(HpackIntegerParseError::Overflow)
    );
}

#[test]
fn hpack_integer_builder_writes_canonical_bytes_and_preserves_suffix() {
    let mut ten_destination = [0xaa; 4];
    let ten = HpackIntegerBuilder::new(&mut ten_destination, 5, 0xe0, 10)
        .build()
        .unwrap();
    assert_eq!(ten.as_bytes(), [0xea]);
    assert_eq!(ten_destination, [0xea, 0xaa, 0xaa, 0xaa]);

    let mut large_destination = [0xaa; 5];
    let large = HpackIntegerBuilder::new(&mut large_destination, 5, 0xa0, 1337)
        .build()
        .unwrap();
    assert_eq!(large.as_bytes(), [0xbf, 0x9a, 0x0a]);
    assert_eq!(large_destination, [0xbf, 0x9a, 0x0a, 0xaa, 0xaa]);

    let mut eight_bit_destination = [0xaa; 3];
    let eight_bit = HpackIntegerBuilder::new(&mut eight_bit_destination, 8, 0, 42)
        .build()
        .unwrap();
    assert_eq!(eight_bit.as_bytes(), [42]);
    assert_eq!(eight_bit_destination, [42, 0xaa, 0xaa]);
}

#[test]
fn hpack_integer_builder_is_atomic_and_round_trips_u64_max() {
    let mut invalid_prefix = [0xaa; 4];
    let before = invalid_prefix;
    assert_eq!(
        HpackIntegerBuilder::new(&mut invalid_prefix, 0, 0, 1).build(),
        Err(HpackIntegerBuildError::InvalidPrefixBits { prefix_bits: 0 })
    );
    assert_eq!(invalid_prefix, before);

    let mut invalid_high_bits = [0xaa; 4];
    let before = invalid_high_bits;
    assert_eq!(
        HpackIntegerBuilder::new(&mut invalid_high_bits, 5, 0xe1, 1).build(),
        Err(HpackIntegerBuildError::HighBitsOverlap {
            high_bits: 0xe1,
            prefix_bits: 5,
        })
    );
    assert_eq!(invalid_high_bits, before);

    let mut short = [0xaa; 2];
    let before = short;
    assert_eq!(
        HpackIntegerBuilder::new(&mut short, 5, 0xa0, 1337).build(),
        Err(HpackIntegerBuildError::BufferTooShort {
            required: 3,
            available: 2,
        })
    );
    assert_eq!(short, before);

    let mut maximum_destination = [0xaa; 12];
    let maximum = HpackIntegerBuilder::new(&mut maximum_destination, 5, 0xe0, u64::MAX)
        .build()
        .unwrap();
    assert_eq!(maximum.value(), u64::MAX);
    assert_eq!(maximum.high_bits(), 0xe0);
    assert_eq!(
        HpackInteger::parse(maximum.as_bytes(), 5).unwrap().value(),
        u64::MAX
    );
    let maximum_len = maximum.as_bytes().len();
    assert_eq!(maximum_destination[maximum_len..], [0xaa]);
}
