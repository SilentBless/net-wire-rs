use net_wire::tls::{
    ClientHello, HELLO_RETRY_REQUEST_RANDOM, ServerHello, TlsCipherSuite, TlsCompressionMethod,
    TlsProtocolVersion,
};

#[test]
fn client_hello_preserves_order_duplicates_unknowns_and_versions() {
    let mut body = [0u8; 68];
    body[..2].copy_from_slice(&[3, 3]);
    body[34] = 1;
    body[35] = 0x44;
    body[36..38].copy_from_slice(&[0, 4]);
    body[38..42].copy_from_slice(&[0x0a, 0x0a, 0x13, 0x01]);
    body[42..44].copy_from_slice(&[1, 0]);
    body[44..46].copy_from_slice(&[0, 22]);
    body[46..68].copy_from_slice(&[
        0x0a, 0x0a, 0, 0, // GREASE extension
        0, 43, 0, 5, 4, 0x0a, 0x0a, 3, 4, // supported_versions
        0, 43, 0, 1, 0, // duplicate malformed payload remains observable
        0xfe, 0xfe, 0, 0, // private/unknown
    ]);

    let hello = ClientHello::parse(&body).unwrap();
    assert_eq!(hello.legacy_version(), TlsProtocolVersion::TLS12);
    assert_eq!(hello.session_id(), &[0x44]);
    assert_eq!(hello.as_bytes(), &body);
    assert_eq!(
        hello
            .cipher_suites()
            .map(TlsCipherSuite::raw)
            .collect::<Vec<_>>(),
        [0x0a0a, 0x1301]
    );
    assert_eq!(
        hello
            .compression_methods()
            .map(TlsCompressionMethod::raw)
            .collect::<Vec<_>>(),
        [0]
    );
    assert!(hello.offers_tls13());
    assert_eq!(
        hello
            .extensions()
            .map(|extension| extension.unwrap().extension_type().raw())
            .collect::<Vec<_>>(),
        [0x0a0a, 43, 43, 0xfefe]
    );

    let mut future_offer = body;
    future_offer[55..57].copy_from_slice(&[4, 0]);
    assert!(ClientHello::parse(&future_offer).unwrap().offers_tls13());

    let tls12_without_extensions = [
        3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 2, 0xc0, 0x2f, 1, 0,
    ];
    let hello = ClientHello::parse(&tls12_without_extensions).unwrap();
    assert!(hello.extensions().next().is_none());
    assert!(!hello.offers_tls13());
}

#[test]
fn server_hello_exposes_selected_fields_and_hrr() {
    let mut body = [0u8; 46];
    body[..2].copy_from_slice(&[3, 3]);
    body[2..34].copy_from_slice(&HELLO_RETRY_REQUEST_RANDOM);
    body[34] = 0;
    body[35..37].copy_from_slice(&[0x13, 0x01]);
    body[37] = 0;
    body[38..40].copy_from_slice(&[0, 6]);
    body[40..46].copy_from_slice(&[0, 43, 0, 2, 3, 4]);

    let hello = ServerHello::parse(&body).unwrap();
    assert!(hello.is_hello_retry_request());
    assert_eq!(hello.session_id(), &[]);
    assert_eq!(hello.cipher_suite(), TlsCipherSuite::TLS_AES_128_GCM_SHA256);
    assert_eq!(hello.compression_method(), TlsCompressionMethod::NULL);
    assert_eq!(
        hello.selected_version().unwrap(),
        Some(TlsProtocolVersion::TLS13)
    );
    assert_eq!(hello.as_bytes(), &body);
}
