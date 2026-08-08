use net_wire::qpack::{
    QpackHuffmanDecoder, QpackIntegerParseError, QpackStringLiteral, QpackStringLiteralBuildError,
    QpackStringLiteralBuilder, QpackStringLiteralParseError,
};

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

fn controlled_mask(prefix_bits: u8) -> u8 {
    match prefix_bits {
        2..=7 => (1u8 << prefix_bits) - 1,
        8 => u8::MAX,
        _ => 0,
    }
}
