use net_wire::*;

#[test]
fn request_head_is_strict_bounded_and_preserves_fields() {
    let wire = b"GET /a?b=1 HTTP/1.1\r\nHost: example.test\r\nX-A: one\r\nx-a:\ttwo \t\r\n\r\nBODY";
    let head = Http1RequestHead::parse(wire).unwrap();
    assert_eq!(head.as_bytes(), &wire[..65]);
    assert_eq!(head.head_len(), 65);
    assert_eq!(head.method(), b"GET");
    assert_eq!(head.target(), b"/a?b=1");
    assert_eq!(head.version(), Http1Version::Http11);

    let mut fields = head.fields().iter();
    let host = fields.next().unwrap();
    assert_eq!(host.raw_line(), b"Host: example.test");
    assert_eq!(host.name(), b"Host");
    assert_eq!(host.raw_value(), b" example.test");
    assert_eq!(host.value(), b"example.test");
    assert!(host.name_eq(b"HOST"));
    assert_eq!(fields.next().unwrap().value(), b"one");
    assert_eq!(fields.next().unwrap().value(), b"two");
    assert!(fields.next().is_none());
}

#[test]
fn response_head_preserves_version_status_reason_and_suffix() {
    let wire = b"HTTP/1.0 599 raw reason\x80\r\nX: y\r\n\r\nnext";
    let head = Http1ResponseHead::parse(wire).unwrap();
    assert_eq!(head.as_bytes(), &wire[..34]);
    assert_eq!(head.version(), Http1Version::Http10);
    assert_eq!(head.status(), 599);
    assert_eq!(head.reason(), b"raw reason\x80");
    assert_eq!(head.fields().iter().next().unwrap().value(), b"y");
}

#[test]
fn heads_reject_incomplete_and_noncanonical_lines() {
    assert!(matches!(
        Http1RequestHead::parse(b"GET / HTTP/1.1\r\nHost: x\r\n"),
        Err(Http1ParseError::Incomplete { .. })
    ));
    for wire in [
        b"GET / HTTP/1.1\n\n" as &[u8],
        b"GET  HTTP/1.1\r\n\r\n",
        b"G ET / HTTP/1.1\r\n\r\n",
        b"GET / HTTP/2.0\r\n\r\n",
        b"GET / HTTP/1.1 extra\r\n\r\n",
    ] {
        assert!(Http1RequestHead::parse(wire).is_err(), "{wire:?}");
    }
    for wire in [
        b"GET / HTTP/1.1\r\n Host: x\r\n\r\n" as &[u8],
        b"GET / HTTP/1.1\r\nHost : x\r\n\r\n",
        b"GET / HTTP/1.1\r\nBad\0:x\r\n\r\n",
        b"GET / HTTP/1.1\r\nX: a\x7f\r\n\r\n",
    ] {
        assert_eq!(
            Http1RequestHead::parse(wire),
            Err(Http1ParseError::InvalidField)
        );
    }
    assert_eq!(
        Http1ResponseHead::parse(b"HTTP/1.1 20 OK\r\n\r\n"),
        Err(Http1ParseError::InvalidStartLine)
    );
    assert_eq!(
        Http1ResponseHead::parse(b"HTTP/1.1 200 bad\nreason\r\n\r\n"),
        Err(Http1ParseError::InvalidStartLine)
    );
}

#[test]
fn content_length_uses_all_occurrences_and_comma_members() {
    let equal = Http1RequestHead::parse(
        b"POST / HTTP/1.1\r\nContent-Length: 42, 42\r\ncontent-length:\t42 \r\n\r\n",
    )
    .unwrap();
    assert_eq!(
        equal.body_framing(),
        Ok(Http1BodyFraming::ContentLength(42))
    );

    let conflicting = Http1RequestHead::parse(
        b"POST / HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\n",
    )
    .unwrap();
    assert_eq!(
        conflicting.body_framing(),
        Err(Http1ParseError::ConflictingContentLength)
    );

    for value in [b"" as &[u8], b"4,", b"+4", b"4 4"] {
        let mut wire = [0u8; 96];
        let prefix = b"POST / HTTP/1.1\r\nContent-Length:";
        wire[..prefix.len()].copy_from_slice(prefix);
        wire[prefix.len()..prefix.len() + value.len()].copy_from_slice(value);
        let end = prefix.len() + value.len();
        wire[end..end + 4].copy_from_slice(b"\r\n\r\n");
        let head = Http1RequestHead::parse(&wire[..end + 4]).unwrap();
        assert_eq!(
            head.body_framing(),
            Err(Http1ParseError::InvalidContentLength)
        );
    }

    let overflow =
        Http1RequestHead::parse(b"POST / HTTP/1.1\r\nContent-Length: 18446744073709551616\r\n\r\n")
            .unwrap();
    if usize::BITS == 64 {
        assert_eq!(
            overflow.body_framing(),
            Err(Http1ParseError::ContentLengthOverflow)
        );
    }
}

#[test]
fn transfer_encoding_is_ordered_and_security_strict() {
    let valid = Http1RequestHead::parse(
        b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip; level=\"a,b\", chunked\r\n\r\n",
    )
    .unwrap();
    assert_eq!(valid.body_framing(), Ok(Http1BodyFraming::Chunked));

    let split = Http1RequestHead::parse(
        b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n",
    )
    .unwrap();
    assert_eq!(split.body_framing(), Ok(Http1BodyFraming::Chunked));

    let escaped = Http1RequestHead::parse(
        b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip; note=\"a\\\"b\", chunked\r\n\r\n",
    )
    .unwrap();
    assert_eq!(escaped.body_framing(), Ok(Http1BodyFraming::Chunked));
    let dangling_escape = Http1RequestHead::parse(
        b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip; note=\"bad\\\r\n\r\n",
    )
    .unwrap();
    assert_eq!(
        dangling_escape.body_framing(),
        Err(Http1ParseError::InvalidTransferEncoding)
    );

    let response =
        Http1ResponseHead::parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip; level=fast\r\n\r\n")
            .unwrap();
    assert_eq!(
        response.body_framing(None),
        Ok(Http1BodyFraming::CloseDelimited)
    );

    let request =
        Http1RequestHead::parse(b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n").unwrap();
    assert_eq!(
        request.body_framing(),
        Err(Http1ParseError::InvalidTransferEncoding)
    );

    for value in [
        b"chunked, gzip" as &[u8],
        b"chunked; q=1",
        b"gzip, chunked, chunked",
        b"gzip,,chunked",
        b"gzip; q=\"unterminated",
    ] {
        let fields = [Http1FieldRef::new(b"Transfer-Encoding", value)];
        let mut output = [0u8; 128];
        let head =
            Http1RequestHeadBuilder::new(&mut output, b"POST", b"/", Http1Version::Http11, &fields)
                .build()
                .unwrap();
        assert!(head.body_framing().is_err(), "{value:?}");
    }

    let conflict = Http1RequestHead::parse(
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: bogus\r\n\r\n",
    )
    .unwrap();
    assert_eq!(
        conflict.body_framing(),
        Err(Http1ParseError::TransferEncodingWithContentLength)
    );
}

#[test]
fn response_framing_applies_rfc_precedence_and_context() {
    for status in [100, 199, 204, 304] {
        let mut wire = [0u8; 96];
        let status = [
            b'0' + (status / 100) as u8,
            b'0' + ((status / 10) % 10) as u8,
            b'0' + (status % 10) as u8,
        ];
        let fields = [
            Http1FieldRef::new(b"Transfer-Encoding", b"chunked"),
            Http1FieldRef::new(b"Content-Length", b"5"),
        ];
        let head = Http1ResponseHeadBuilder::new(
            &mut wire,
            Http1Version::Http11,
            u16::from(status[0] - b'0') * 100
                + u16::from(status[1] - b'0') * 10
                + u16::from(status[2] - b'0'),
            b"x",
            &fields,
        )
        .build()
        .unwrap();
        assert_eq!(head.body_framing(None), Ok(Http1BodyFraming::None));
    }

    let conflict = Http1ResponseHead::parse(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
    )
    .unwrap();
    assert_eq!(
        conflict.body_framing(Some(b"HEAD")),
        Ok(Http1BodyFraming::None)
    );
    assert_eq!(
        conflict.body_framing(Some(b"CONNECT")),
        Ok(Http1BodyFraming::Tunnel)
    );
    assert_eq!(
        conflict.body_framing(None),
        Err(Http1ParseError::TransferEncodingWithContentLength)
    );

    let connect_299 = Http1ResponseHead::parse(b"HTTP/1.1 299 x\r\n\r\n").unwrap();
    assert_eq!(
        connect_299.body_framing(Some(b"CONNECT")),
        Ok(Http1BodyFraming::Tunnel)
    );
    let connect_300 = Http1ResponseHead::parse(b"HTTP/1.1 300 x\r\n\r\n").unwrap();
    assert_eq!(
        connect_300.body_framing(Some(b"CONNECT")),
        Ok(Http1BodyFraming::CloseDelimited)
    );

    let no_fields = Http1ResponseHead::parse(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
    assert_eq!(
        no_fields.body_framing(None),
        Ok(Http1BodyFraming::CloseDelimited)
    );
    assert_eq!(
        Http1RequestHead::parse(b"GET / HTTP/1.1\r\n\r\n")
            .unwrap()
            .body_framing(),
        Ok(Http1BodyFraming::None)
    );
}

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

fn request_built_from_local(buffer: &mut [u8]) -> Http1RequestHead<'_> {
    let value = *b" one";
    let fields = [Http1FieldRef::new(b"X-A", &value)];
    Http1RequestHeadBuilder::new(buffer, b"GET", b"/local", Http1Version::Http11, &fields)
        .build()
        .unwrap()
}

#[test]
fn builders_copy_inputs_preserve_order_and_leave_suffix() {
    let mut request_output = [0xaa; 64];
    let request = request_built_from_local(&mut request_output);
    let expected = b"GET /local HTTP/1.1\r\nX-A: one\r\n\r\n";
    assert_eq!(request.as_bytes(), expected);
    let length = request.head_len();
    assert!(request_output[length..].iter().all(|byte| *byte == 0xaa));

    let fields = [
        Http1FieldRef::new(b"X-A", b" one"),
        Http1FieldRef::new(b"x-a", b" two"),
    ];
    let mut response_output = [0xaa; 96];
    let response = Http1ResponseHeadBuilder::new(
        &mut response_output,
        Http1Version::Http10,
        201,
        b"Created",
        &fields,
    )
    .build()
    .unwrap();
    assert_eq!(
        response.as_bytes(),
        b"HTTP/1.0 201 Created\r\nX-A: one\r\nx-a: two\r\n\r\n"
    );
    assert_eq!(response.fields().iter().count(), 2);
}

#[test]
fn builder_failures_are_atomic() {
    let fields = [Http1FieldRef::new(b"Bad Name", b" value")];
    let mut invalid = [0xaa; 64];
    let before = invalid;
    assert_eq!(
        Http1RequestHeadBuilder::new(&mut invalid, b"GET", b"/", Http1Version::Http11, &fields,)
            .build(),
        Err(Http1BuildError::InvalidValue)
    );
    assert_eq!(invalid, before);

    let injected = [Http1FieldRef::new(b"X", b" ok\r\nInjected: yes")];
    let mut injection = [0xaa; 64];
    let before = injection;
    assert_eq!(
        Http1ResponseHeadBuilder::new(&mut injection, Http1Version::Http11, 200, b"OK", &injected,)
            .build(),
        Err(Http1BuildError::InvalidValue)
    );
    assert_eq!(injection, before);

    let mut short = [0xaa; 8];
    let before = short;
    assert!(matches!(
        Http1RequestHeadBuilder::new(&mut short, b"GET", b"/", Http1Version::Http11, &[],).build(),
        Err(Http1BuildError::BufferTooShort { .. })
    ));
    assert_eq!(short, before);
}
