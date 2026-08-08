use net_wire::http2::hpack::{
    HpackHuffmanDecodeError, HpackHuffmanDecoder, HpackHuffmanEncodeError, HpackHuffmanEncoder,
};

#[test]
fn hpack_huffman_decodes_rfc_appendix_c_vectors() {
    for (encoded, expected) in [
        (
            &[
                0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
            ][..],
            b"www.example.com" as &[u8],
        ),
        (
            &[0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf][..],
            b"no-cache" as &[u8],
        ),
        (
            &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f][..],
            b"custom-key" as &[u8],
        ),
        (
            &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf][..],
            b"custom-value" as &[u8],
        ),
    ] {
        let mut destination = [0xaa; 32];
        let decoded = HpackHuffmanDecoder::new(encoded, &mut destination)
            .decode()
            .unwrap();
        assert_eq!(decoded, expected);
        assert!(
            destination[expected.len()..]
                .iter()
                .all(|byte| *byte == 0xaa)
        );
    }
}

#[test]
fn hpack_huffman_reports_validated_decoded_lengths() {
    for (encoded, expected) in [
        (
            &[
                0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
            ][..],
            15,
        ),
        (&[0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf][..], 8),
        (&[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f][..], 10),
        (
            &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf][..],
            12,
        ),
        (&[][..], 0),
        (&[0xff, 0xc7, 0xff, 0xff, 0xdd][..], 2),
    ] {
        assert_eq!(
            HpackHuffmanDecoder::required_decoded_len(encoded),
            Ok(expected)
        );
    }
}

#[test]
fn hpack_huffman_length_query_matches_decode_errors_and_exact_capacity() {
    for (encoded, error) in [
        (
            &[0xff, 0xff, 0xff, 0xff][..],
            HpackHuffmanDecodeError::EosSymbol,
        ),
        (&[0x00][..], HpackHuffmanDecodeError::InvalidPadding),
        (&[0xff][..], HpackHuffmanDecodeError::InvalidPadding),
    ] {
        let mut destination = [0xaa; 8];
        assert_eq!(
            HpackHuffmanDecoder::required_decoded_len(encoded),
            Err(error)
        );
        assert_eq!(
            HpackHuffmanDecoder::new(encoded, &mut destination).decode(),
            Err(error)
        );
    }

    let encoded = [
        0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
    ];
    let required = HpackHuffmanDecoder::required_decoded_len(&encoded).unwrap();
    let mut destination = [0xaa; 15];
    assert_eq!(destination.len(), required);
    assert_eq!(
        HpackHuffmanDecoder::new(&encoded, &mut destination).decode(),
        Ok(b"www.example.com" as &[u8])
    );
}

#[test]
fn hpack_huffman_handles_empty_and_binary_outputs() {
    let mut empty_destination = [0xaa; 3];
    assert_eq!(
        HpackHuffmanDecoder::new(&[], &mut empty_destination).decode(),
        Ok(&[][..])
    );
    assert_eq!(empty_destination, [0xaa; 3]);

    let mut binary_destination = [0xaa; 4];
    let decoded =
        HpackHuffmanDecoder::new(&[0xff, 0xc7, 0xff, 0xff, 0xdd], &mut binary_destination)
            .decode()
            .unwrap();
    assert_eq!(decoded, [0, 255]);
    assert_eq!(binary_destination, [0, 255, 0xaa, 0xaa]);
}

#[test]
fn hpack_huffman_rejects_malformed_data_atomically() {
    for (encoded, error) in [
        (
            &[0xff, 0xff, 0xff, 0xff][..],
            HpackHuffmanDecodeError::EosSymbol,
        ),
        (&[0x00][..], HpackHuffmanDecodeError::InvalidPadding),
        (&[0xff][..], HpackHuffmanDecodeError::InvalidPadding),
    ] {
        let mut destination = [0xaa; 8];
        let before = destination;
        assert_eq!(
            HpackHuffmanDecoder::new(encoded, &mut destination).decode(),
            Err(error)
        );
        assert_eq!(destination, before);
    }
}

#[test]
fn hpack_huffman_short_destination_is_atomic_and_reports_capacity() {
    let encoded = [
        0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
    ];
    let mut destination = [0xaa; 14];
    let before = destination;
    assert_eq!(
        HpackHuffmanDecoder::new(&encoded, &mut destination).decode(),
        Err(HpackHuffmanDecodeError::OutputTooShort {
            required: 15,
            available: 14,
        })
    );
    assert_eq!(destination, before);
}

#[test]
fn hpack_huffman_encodes_rfc_appendix_c_vectors() {
    for (decoded, expected) in [
        (
            b"www.example.com" as &[u8],
            &[
                0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
            ][..],
        ),
        (
            b"no-cache" as &[u8],
            &[0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf][..],
        ),
        (
            b"custom-key" as &[u8],
            &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f][..],
        ),
        (
            b"custom-value" as &[u8],
            &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf][..],
        ),
    ] {
        let mut destination = [0xaa; 32];
        let encoded = HpackHuffmanEncoder::new(decoded, &mut destination)
            .encode()
            .unwrap();
        assert_eq!(encoded, expected);
        let mut decoded_destination = [0; 32];
        assert_eq!(
            HpackHuffmanDecoder::new(encoded, &mut decoded_destination).decode(),
            Ok(decoded)
        );
    }
}

#[test]
fn hpack_huffman_encoder_handles_empty_and_binary_inputs() {
    let mut empty_destination = [0xaa; 3];
    assert_eq!(HpackHuffmanEncoder::required_encoded_len(&[]), Ok(0));
    assert_eq!(
        HpackHuffmanEncoder::new(&[], &mut empty_destination).encode(),
        Ok(&[][..])
    );
    assert_eq!(empty_destination, [0xaa; 3]);

    let mut binary_destination = [0xaa; 8];
    let encoded = HpackHuffmanEncoder::new(&[0, 255], &mut binary_destination)
        .encode()
        .unwrap();
    assert_eq!(encoded, [0xff, 0xc7, 0xff, 0xff, 0xdd]);
    assert_eq!(
        binary_destination,
        [0xff, 0xc7, 0xff, 0xff, 0xdd, 0xaa, 0xaa, 0xaa]
    );
}

#[test]
fn hpack_huffman_encoder_reports_exact_lengths_and_preserves_suffix() {
    assert_eq!(
        HpackHuffmanEncoder::required_encoded_len(b"www.example.com"),
        Ok(12)
    );
    assert_eq!(
        HpackHuffmanEncoder::required_encoded_len(b"no-cache"),
        Ok(6)
    );
    assert_eq!(
        HpackHuffmanEncoder::required_encoded_len(b"custom-key"),
        Ok(8)
    );
    assert_eq!(
        HpackHuffmanEncoder::required_encoded_len(b"custom-value"),
        Ok(9)
    );

    let mut destination = [0xaa; 16];
    let encoded = HpackHuffmanEncoder::new(b"no-cache", &mut destination)
        .encode()
        .unwrap();
    assert_eq!(encoded, [0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf]);
    assert_eq!(destination[6..], [0xaa; 10]);
}

#[test]
fn hpack_huffman_encoder_short_destination_is_atomic() {
    let mut destination = [0xaa; 11];
    let before = destination;
    assert_eq!(
        HpackHuffmanEncoder::new(b"www.example.com", &mut destination).encode(),
        Err(HpackHuffmanEncodeError::DestinationTooShort {
            required: 12,
            available: 11,
        })
    );
    assert_eq!(destination, before);
}

#[test]
fn hpack_huffman_encoder_round_trips_all_byte_values() {
    let input: Vec<u8> = (0..=255).collect();
    let required = HpackHuffmanEncoder::required_encoded_len(&input).unwrap();
    let mut encoded_destination = vec![0xaa; required + 3];
    let encoded = HpackHuffmanEncoder::new(&input, &mut encoded_destination)
        .encode()
        .unwrap();
    let mut decoded_destination = [0xaa; 256];
    let decoded = HpackHuffmanDecoder::new(encoded, &mut decoded_destination)
        .decode()
        .unwrap();
    assert_eq!(decoded, input);
    assert_eq!(encoded_destination[required..], [0xaa; 3]);
}
