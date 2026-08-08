use net_wire::http1::{
    Http1BuildError, Http1FieldRef, Http1RequestHead, Http1RequestHeadBuilder,
    Http1ResponseHeadBuilder, Http1Version,
};

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
