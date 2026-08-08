use net_wire::http2::hpack::{
    HpackIntegerParseError, HpackStringLiteral, HpackStringLiteralBuildError,
    HpackStringLiteralBuilder, HpackStringLiteralParseError,
};

#[test]
fn hpack_string_literal_parses_plain_and_huffman_opaque_payloads() {
    let plain_wire = b"\x0fwww.example.comsuffix";
    let plain = HpackStringLiteral::parse(plain_wire).unwrap();
    assert_eq!(plain.as_bytes(), b"\x0fwww.example.com");
    assert!(!plain.is_huffman());
    assert_eq!(plain.encoded_bytes(), b"www.example.com");
    assert_eq!(plain.length().as_bytes(), [0x0f]);
    assert_eq!(plain.length().value(), 15);

    let huffman_wire = [0x83, 0xff, 0x00, 0xa5, 0xde];
    let huffman = HpackStringLiteral::parse(&huffman_wire).unwrap();
    assert_eq!(huffman.as_bytes(), &huffman_wire[..4]);
    assert!(huffman.is_huffman());
    assert_eq!(huffman.encoded_bytes(), [0xff, 0x00, 0xa5]);
    assert_eq!(huffman.length().as_bytes(), [0x83]);
}

#[test]
fn hpack_string_literal_preserves_long_and_overlong_length_representations() {
    let long_payload = [0x5a; 127];
    let mut long_wire = vec![0x7f, 0x00];
    long_wire.extend_from_slice(&long_payload);
    long_wire.push(0xaa);
    let long = HpackStringLiteral::parse(&long_wire).unwrap();
    assert_eq!(long.as_bytes(), &long_wire[..129]);
    assert_eq!(long.length().as_bytes(), [0x7f, 0x00]);
    assert_eq!(long.encoded_bytes(), long_payload);

    let mut overlong_wire = vec![0x7f, 0x80, 0x00];
    overlong_wire.extend_from_slice(&long_payload);
    overlong_wire.push(0xaa);
    let overlong = HpackStringLiteral::parse(&overlong_wire).unwrap();
    assert_eq!(overlong.as_bytes(), &overlong_wire[..130]);
    assert_eq!(overlong.length().as_bytes(), [0x7f, 0x80, 0x00]);
    assert_eq!(overlong.length().value(), 127);
    assert_eq!(overlong.encoded_bytes(), long_payload);
}

#[test]
fn hpack_string_literal_propagates_length_errors_and_payload_truncation() {
    assert_eq!(
        HpackStringLiteral::parse(&[]),
        Err(HpackStringLiteralParseError::InvalidLength(
            HpackIntegerParseError::Incomplete {
                required: 1,
                available: 0,
            }
        ))
    );
    assert_eq!(
        HpackStringLiteral::parse(&[0x7f]),
        Err(HpackStringLiteralParseError::InvalidLength(
            HpackIntegerParseError::Incomplete {
                required: 2,
                available: 1,
            }
        ))
    );
    assert_eq!(
        HpackStringLiteral::parse(&[
            0x7f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02,
        ]),
        Err(HpackStringLiteralParseError::InvalidLength(
            HpackIntegerParseError::Overflow
        ))
    );
    assert_eq!(
        HpackStringLiteral::parse(&[0x03, 0xaa, 0xbb]),
        Err(HpackStringLiteralParseError::IncompleteEncodedPayload {
            required: 3,
            available: 2,
        })
    );
}

#[test]
fn hpack_string_literal_builder_writes_exact_bytes_and_preserves_suffix() {
    let mut plain_destination = [0xaa; 24];
    let plain =
        HpackStringLiteralBuilder::new_encoded(&mut plain_destination, false, b"www.example.com")
            .build()
            .unwrap();
    assert_eq!(plain.as_bytes(), b"\x0fwww.example.com");
    assert!(!plain.is_huffman());
    assert_eq!(plain_destination[16..], [0xaa; 8]);

    let mut huffman_destination = [0xaa; 8];
    let huffman =
        HpackStringLiteralBuilder::new_encoded(&mut huffman_destination, true, &[0xff, 0x00, 0xa5])
            .build()
            .unwrap();
    assert_eq!(huffman.as_bytes(), [0x83, 0xff, 0x00, 0xa5]);
    assert!(huffman.is_huffman());
    assert_eq!(huffman_destination[4..], [0xaa; 4]);

    let long_payload = [0x5a; 127];
    let mut long_destination = [0xaa; 132];
    let long = HpackStringLiteralBuilder::new_encoded(&mut long_destination, false, &long_payload)
        .build()
        .unwrap();
    assert_eq!(
        long.as_bytes(),
        [&[0x7f, 0x00][..], &long_payload[..]].concat()
    );
    assert_eq!(long_destination[129..], [0xaa; 3]);
}

#[test]
fn hpack_string_literal_builder_failures_are_atomic() {
    let mut destination = [0xaa; 3];
    let before = destination;
    assert_eq!(
        HpackStringLiteralBuilder::new_encoded(&mut destination, true, &[0xff, 0x00, 0xa5]).build(),
        Err(HpackStringLiteralBuildError::BufferTooShort {
            required: 4,
            available: 3,
        })
    );
    assert_eq!(destination, before);
}
