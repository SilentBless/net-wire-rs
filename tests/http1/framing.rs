use net_wire::http1::{
    Http1BodyFraming, Http1FieldRef, Http1ParseError, Http1RequestHead, Http1RequestHeadBuilder,
    Http1ResponseHead, Http1ResponseHeadBuilder, Http1Version,
};

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
