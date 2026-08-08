use net_wire::qpack::{
    QpackHuffmanDecodeError, QpackHuffmanDecoder, QpackHuffmanEncodeError, QpackHuffmanEncoder,
};

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
