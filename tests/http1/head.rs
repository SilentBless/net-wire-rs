use net_wire::http1::{Http1ParseError, Http1RequestHead, Http1ResponseHead, Http1Version};

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
