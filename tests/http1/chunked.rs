use net_wire::http1::{Http1ChunkedBody, Http1Field, Http1ParseError};

#[test]
fn chunked_body_preserves_chunks_extensions_trailers_and_suffix() {
    let wire = b"A;foo=bar\r\n0123456789\r\n3\r\nabc\r\n000; end=\"yes\"\r\nX-T: one\r\nX-T:\ttwo \t\r\n\r\nNEXT";
    let body = Http1ChunkedBody::parse(wire).unwrap();
    assert_eq!(body.as_bytes(), &wire[..71]);
    assert_eq!(body.decoded_len(), 13);
    assert_eq!(body.last_chunk_extensions(), b"; end=\"yes\"");

    let mut chunks = body.chunks();
    let first = chunks.next().unwrap();
    assert_eq!(first.size(), 10);
    assert_eq!(first.data(), b"0123456789");
    assert_eq!(first.extensions(), b";foo=bar");
    let second = chunks.next().unwrap();
    assert_eq!(second.size(), 3);
    assert_eq!(second.data(), b"abc");
    assert_eq!(second.extensions(), b"");
    assert!(chunks.next().is_none());

    let trailers: [Http1Field<'_>; 2] = body
        .trailers()
        .iter()
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    assert_eq!(trailers[0].value(), b"one");
    assert_eq!(trailers[1].raw_value(), b"\ttwo \t");
    assert_eq!(trailers[1].value(), b"two");

    let empty = Http1ChunkedBody::parse(b"0000\r\n\r\nrest").unwrap();
    assert_eq!(empty.as_bytes(), b"0000\r\n\r\n");
    assert_eq!(empty.decoded_len(), 0);
    assert!(empty.chunks().next().is_none());

    let escaped = Http1ChunkedBody::parse(b"1; q=\"a\\\"b\"\r\nx\r\n0\r\n\r\n").unwrap();
    assert_eq!(
        escaped.chunks().next().unwrap().extensions(),
        b"; q=\"a\\\"b\""
    );
}

#[test]
fn chunked_body_distinguishes_malformed_overflow_and_incomplete() {
    assert_eq!(
        Http1ChunkedBody::parse(b"g\r\n"),
        Err(Http1ParseError::InvalidChunkSize)
    );
    assert_eq!(
        Http1ChunkedBody::parse(b"1   \r\na\r\n0\r\n\r\n"),
        Err(Http1ParseError::InvalidChunkSize)
    );
    assert_eq!(
        Http1ChunkedBody::parse(b"1; q=\"bad\\\r\nx\r\n0\r\n\r\n"),
        Err(Http1ParseError::InvalidChunkSize)
    );
    if usize::BITS == 64 {
        assert_eq!(
            Http1ChunkedBody::parse(b"10000000000000000\r\n"),
            Err(Http1ParseError::ChunkSizeOverflow)
        );
    }
    assert!(matches!(
        Http1ChunkedBody::parse(b"3\r\nab"),
        Err(Http1ParseError::Incomplete {
            required: 8,
            available: 5
        })
    ));
    assert_eq!(
        Http1ChunkedBody::parse(b"1\r\naX\r\n0\r\n\r\n"),
        Err(Http1ParseError::InvalidChunkTerminator)
    );
    assert_eq!(
        Http1ChunkedBody::parse(b"0\r\nBad Field: x\r\n\r\n"),
        Err(Http1ParseError::InvalidTrailer)
    );
    assert_eq!(
        Http1ChunkedBody::parse(b"0\r\nX: y\n\n"),
        Err(Http1ParseError::InvalidTrailer)
    );
    assert!(matches!(
        Http1ChunkedBody::parse(b"0\r\nX: y\r\n"),
        Err(Http1ParseError::Incomplete { .. })
    ));

    for name in [
        b"Content-Length" as &[u8],
        b"Transfer-Encoding",
        b"Host",
        b"Trailer",
        b"TE",
    ] {
        let mut wire = [0u8; 64];
        wire[..3].copy_from_slice(b"0\r\n");
        wire[3..3 + name.len()].copy_from_slice(name);
        let end = 3 + name.len();
        wire[end..end + 9].copy_from_slice(b": value\r\n");
        wire[end + 9..end + 11].copy_from_slice(b"\r\n");
        assert_eq!(
            Http1ChunkedBody::parse(&wire[..end + 11]),
            Err(Http1ParseError::InvalidTrailer)
        );
    }
}
