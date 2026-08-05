use net_wire::*;

fn only_extension(bytes: &[u8]) -> TlsExtension<'_> {
    let mut extensions = TlsExtensions::new(bytes);
    let extension = extensions.next().expect("fixture extension").unwrap();
    assert!(extensions.next().is_none());
    extension
}

#[test]
fn record_and_handshake_views_are_exactly_bounded() {
    let bytes = [22, 3, 3, 0, 2, 1, 2, 9];
    let record = TlsRecord::parse(&bytes).unwrap();
    assert_eq!(record.content_type(), TlsContentType::HANDSHAKE);
    assert_eq!(record.version(), TlsProtocolVersion::TLS12);
    assert_eq!(record.fragment(), &[1, 2]);
    assert_eq!(record.as_bytes(), &bytes[..7]);
    assert_eq!(
        TlsRecord::parse(&bytes[..6]),
        Err(TlsParseError::Incomplete {
            required: 7,
            available: 6,
        })
    );

    let mut mutable = bytes;
    let mut record = TlsRecordMut::parse(&mut mutable).unwrap();
    record.set_content_type(TlsContentType::APPLICATION_DATA);
    record.set_version(TlsProtocolVersion::TLS13);
    record.fragment_mut()[0] = 7;
    assert_eq!(record.fragment(), &[7, 2]);
    assert_eq!(record.as_bytes(), &[23, 3, 4, 0, 2, 7, 2]);

    let handshake_bytes = [1, 0, 0, 2, 3, 4, 99];
    let handshake = TlsHandshake::parse(&handshake_bytes).unwrap();
    assert_eq!(handshake.handshake_type(), TlsHandshakeType::CLIENT_HELLO);
    assert_eq!(handshake.body(), &[3, 4]);
    assert_eq!(handshake.as_bytes(), &handshake_bytes[..6]);
    assert!(handshake.client_hello().is_err());
    assert_eq!(
        TlsHandshake::parse(&handshake_bytes[..5]),
        Err(TlsParseError::Incomplete {
            required: 6,
            available: 5,
        })
    );

    let mut uint24 = [0u8; 260];
    uint24[..4].copy_from_slice(&[0xfe, 0, 1, 0]);
    let handshake = TlsHandshake::parse(&uint24).unwrap();
    assert_eq!(handshake.handshake_type().raw(), 0xfe);
    assert_eq!(handshake.body().len(), 256);
    assert_eq!(handshake.client_hello().unwrap(), None);

    let client_handshake = [
        1, 0, 0, 41, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0xc0, 0x2f, 1, 0,
    ];
    let client = TlsHandshake::parse(&client_handshake)
        .unwrap()
        .client_hello()
        .unwrap()
        .unwrap();
    assert_eq!(client.cipher_suites().next().unwrap().raw(), 0xc02f);
}

#[test]
fn registry_values_preserve_unknowns_and_classify_grease_exactly() {
    for value in (0x0a0a..=0xfafa).step_by(0x1010) {
        assert!(TlsExtensionType::new(value).is_grease());
        assert!(TlsCipherSuite::new(value).is_grease());
        assert!(TlsNamedGroup::new(value).is_grease());
        assert!(TlsSignatureScheme::new(value).is_grease());
        assert!(TlsProtocolVersion::new(value).is_grease());
    }
    assert!(!TlsExtensionType::new(0x0a1a).is_grease());
    assert_eq!(TlsExtensionType::new(0xfefe).raw(), 0xfefe);

    for value in [0x0b, 0x2a, 0x49, 0x68, 0x87, 0xa6, 0xc5, 0xe4] {
        assert!(TlsPskKeyExchangeMode::new(value).is_grease());
    }
    assert!(!TlsPskKeyExchangeMode::new(0x1b).is_grease());

    let grease_alpn = only_extension(&[0, 16, 0, 5, 0, 3, 2, 0x0a, 0x0a]);
    assert!(
        grease_alpn
            .alpn_protocol_list()
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .unwrap()
            .is_grease()
    );
}

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

#[test]
fn extension_iterator_reports_real_truncation_and_preserves_raw_data() {
    let mut short = TlsExtensions::new(&[0, 43, 0]);
    assert_eq!(
        short.next().unwrap(),
        Err(TlsParseError::Incomplete {
            required: 4,
            available: 3,
        })
    );
    assert!(short.next().is_none());

    let mut payload_short = TlsExtensions::new(&[0, 43, 0, 3, 2]);
    assert_eq!(
        payload_short.next().unwrap(),
        Err(TlsParseError::Incomplete {
            required: 7,
            available: 5,
        })
    );

    let unknown = only_extension(&[0xfe, 0xfe, 0, 3, 1, 2, 3]);
    assert_eq!(unknown.extension_type().raw(), 0xfefe);
    assert_eq!(unknown.data(), &[1, 2, 3]);
    assert_eq!(
        unknown.client_supported_versions(),
        Err(TlsParseError::InvalidValue)
    );
}

#[test]
fn sni_and_alpn_views_validate_context_specific_layouts() {
    let sni = only_extension(&[0, 0, 0, 10, 0, 8, 0, 0, 5, b'a', b'.', b'c', b'o', b'm']);
    let mut names = sni.client_server_name_list().unwrap().iter();
    let name = names.next().unwrap().unwrap();
    assert_eq!(name.name_type(), TlsServerNameType::HOST_NAME);
    assert_eq!(name.as_bytes(), b"a.com");
    assert!(names.next().is_none());
    assert_eq!(
        sni.server_name_acknowledgement(),
        Err(TlsParseError::TrailingBytes)
    );
    assert!(
        only_extension(&[0, 0, 0, 0])
            .server_name_acknowledgement()
            .is_ok()
    );

    let alpn = only_extension(&[0, 16, 0, 7, 0, 5, 2, b'h', b'2', 1, b'x']);
    assert_eq!(
        alpn.alpn_protocol_list()
            .unwrap()
            .iter()
            .map(|protocol| protocol.unwrap().as_bytes())
            .collect::<Vec<_>>(),
        [b"h2".as_slice(), b"x".as_slice()]
    );
    assert_eq!(
        alpn.server_selected_alpn(),
        Err(TlsParseError::TrailingBytes)
    );
    assert_eq!(
        only_extension(&[0, 16, 0, 5, 0, 3, 2, b'h', b'2'])
            .server_selected_alpn()
            .unwrap()
            .protocol()
            .as_bytes(),
        b"h2"
    );
    assert!(
        only_extension(&[0, 16, 0, 3, 0, 1, 0])
            .alpn_protocol_list()
            .is_err()
    );
}

#[test]
fn ordered_registry_extension_views_keep_wire_values() {
    let versions = only_extension(&[0, 43, 0, 5, 4, 0x0a, 0x0a, 3, 4]);
    let versions = versions.client_supported_versions().unwrap();
    assert_eq!(
        versions
            .iter()
            .map(TlsProtocolVersion::raw)
            .collect::<Vec<_>>(),
        [0x0a0a, 0x0304]
    );
    assert_eq!(versions.highest(), Some(TlsProtocolVersion::TLS13));
    assert!(
        only_extension(&[0, 43, 0, 4, 3, 3, 4, 0])
            .client_supported_versions()
            .is_err()
    );

    let groups = only_extension(&[0, 10, 0, 6, 0, 4, 0x0a, 0x0a, 0, 29]);
    assert_eq!(
        groups
            .supported_groups()
            .unwrap()
            .iter()
            .collect::<Vec<_>>(),
        [TlsNamedGroup::new(0x0a0a), TlsNamedGroup::X25519]
    );

    let signatures = only_extension(&[0, 13, 0, 6, 0, 4, 8, 4, 4, 3]);
    assert_eq!(
        signatures
            .signature_algorithms()
            .unwrap()
            .iter()
            .collect::<Vec<_>>(),
        [
            TlsSignatureScheme::RSA_PSS_RSAE_SHA256,
            TlsSignatureScheme::ECDSA_SECP256R1_SHA256,
        ]
    );

    let point_formats = only_extension(&[0, 11, 0, 3, 2, 0, 1]);
    assert_eq!(
        point_formats
            .ec_point_formats()
            .unwrap()
            .iter()
            .collect::<Vec<_>>(),
        [0, 1]
    );

    let compression = only_extension(&[0, 27, 0, 5, 4, 0, 1, 0, 2]);
    assert_eq!(
        compression
            .certificate_compression_algorithms()
            .unwrap()
            .iter()
            .collect::<Vec<_>>(),
        [
            TlsCertificateCompressionAlgorithm::ZLIB,
            TlsCertificateCompressionAlgorithm::BROTLI,
        ]
    );
}

#[test]
fn key_share_views_distinguish_client_server_and_hrr_layouts() {
    let client = only_extension(&[0, 51, 0, 9, 0, 7, 0, 29, 0, 3, 1, 2, 3]);
    let entry = client
        .client_key_share()
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(entry.group(), TlsNamedGroup::X25519);
    assert_eq!(entry.key_exchange(), &[1, 2, 3]);
    assert!(client.server_key_share().is_err());

    let empty_client = only_extension(&[0, 51, 0, 2, 0, 0]);
    assert!(
        empty_client
            .client_key_share()
            .unwrap()
            .iter()
            .next()
            .is_none()
    );

    let server = only_extension(&[0, 51, 0, 7, 0, 29, 0, 3, 1, 2, 3]);
    assert_eq!(server.server_key_share().unwrap().entry(), entry);
    assert!(server.client_key_share().is_err());

    let hrr = only_extension(&[0, 51, 0, 2, 0, 29]);
    assert_eq!(hrr.hrr_key_share().unwrap().group(), TlsNamedGroup::X25519);
    assert!(hrr.server_key_share().is_err());
}

#[test]
fn psk_views_validate_nested_vectors_and_identity_binder_count() {
    let modes = only_extension(&[0, 45, 0, 3, 2, 0x0b, 1]);
    assert_eq!(
        modes
            .psk_key_exchange_modes()
            .unwrap()
            .iter()
            .collect::<Vec<_>>(),
        [
            TlsPskKeyExchangeMode::new(0x0b),
            TlsPskKeyExchangeMode::PSK_DHE_KE
        ]
    );

    let psk = [
        0, 41, 0, 44, // extension header
        0, 7, 0, 1, 0xaa, 0, 0, 0, 5, // one identity
        0, 33, 32, // binder vector and binder length
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];
    let psk = only_extension(&psk).client_pre_shared_key().unwrap();
    let identity = psk.identities().next().unwrap().unwrap();
    assert_eq!(identity.identity(), &[0xaa]);
    assert_eq!(identity.obfuscated_ticket_age(), 5);
    assert_eq!(psk.binders().next().unwrap().unwrap().len(), 32);

    let selected = only_extension(&[0, 41, 0, 2, 0, 1]);
    assert_eq!(
        selected
            .server_pre_shared_key()
            .unwrap()
            .selected_identity(),
        1
    );

    let mismatched = [
        0, 41, 0, 45, 0, 7, 0, 1, 0xaa, 0, 0, 0, 5, 0, 34, 32, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0,
    ];
    assert!(only_extension(&mismatched).client_pre_shared_key().is_err());
}

#[test]
fn cookie_and_early_data_layouts_are_context_specific() {
    assert_eq!(
        only_extension(&[0, 44, 0, 4, 0, 2, 0xaa, 0xbb])
            .cookie()
            .unwrap()
            .as_bytes(),
        &[0xaa, 0xbb]
    );
    assert!(only_extension(&[0, 42, 0, 0]).early_data_marker().is_ok());
    assert_eq!(
        only_extension(&[0, 42, 0, 4, 0, 1, 0, 0])
            .early_data_max_size()
            .unwrap(),
        65_536
    );
    assert!(
        only_extension(&[0, 42, 0, 0])
            .early_data_max_size()
            .is_err()
    );
}

fn built_client_from_local<'a>(buffer: &'a mut [u8]) -> ClientHello<'a> {
    let random = [0x11; 32];
    let extensions = [0, 43, 0, 3, 2, 3, 4];
    ClientHelloBuilder::new(
        buffer,
        TlsProtocolVersion::TLS12,
        &random,
        &[0x22],
        &[0x13, 0x01],
        &[0],
        Some(&extensions),
    )
    .build()
    .unwrap()
}

#[test]
fn builders_copy_inputs_and_fail_atomically() {
    let mut record_output = [0xaa; 9];
    let record = TlsRecordBuilder::new(
        &mut record_output,
        TlsContentType::HANDSHAKE,
        TlsProtocolVersion::TLS12,
        &[1, 2],
    )
    .build()
    .unwrap();
    assert_eq!(record.as_bytes(), &[22, 3, 3, 0, 2, 1, 2]);

    let mut handshake_output = [0xaa; 8];
    let handshake = TlsHandshakeBuilder::new(
        &mut handshake_output,
        TlsHandshakeType::CLIENT_HELLO,
        &[1, 2],
    )
    .build()
    .unwrap();
    assert_eq!(handshake, &[1, 0, 0, 2, 1, 2]);

    let mut extension_output = [0xaa; 9];
    let extension = TlsExtensionBuilder::new(
        &mut extension_output,
        TlsExtensionType::SUPPORTED_VERSIONS,
        &[2, 3, 4],
    )
    .build()
    .unwrap();
    assert_eq!(extension.data(), &[2, 3, 4]);
    assert_eq!(extension_output[..7], [0, 43, 0, 3, 2, 3, 4]);
    assert_eq!(extension_output[7..], [0xaa, 0xaa]);

    let mut client_output = [0xaa; 64];
    let client = built_client_from_local(&mut client_output);
    assert_eq!(client.random(), &[0x11; 32]);
    assert_eq!(client.session_id(), &[0x22]);
    assert!(client.offers_tls13());
    let represented = client.as_bytes().len();
    assert!(
        client_output[represented..]
            .iter()
            .all(|byte| *byte == 0xaa)
    );

    let mut server_output = [0xaa; 48];
    let random = [0x33; 32];
    let server = ServerHelloBuilder::new(
        &mut server_output,
        TlsProtocolVersion::TLS12,
        &random,
        &[0x44],
        TlsCipherSuite::TLS_AES_128_GCM_SHA256,
        TlsCompressionMethod::NULL,
        None,
    )
    .build()
    .unwrap();
    assert_eq!(server.session_id(), &[0x44]);
    assert_eq!(
        server.cipher_suite(),
        TlsCipherSuite::TLS_AES_128_GCM_SHA256
    );

    let mut short = [0xaa; 6];
    let before = short;
    assert_eq!(
        TlsRecordBuilder::new(
            &mut short,
            TlsContentType::HANDSHAKE,
            TlsProtocolVersion::TLS12,
            &[1, 2],
        )
        .build(),
        Err(TlsBuildError::BufferTooShort {
            required: 7,
            available: 6,
        })
    );
    assert_eq!(short, before);

    let mut short_handshake = [0xaa; 5];
    let before = short_handshake;
    assert_eq!(
        TlsHandshakeBuilder::new(
            &mut short_handshake,
            TlsHandshakeType::CLIENT_HELLO,
            &[1, 2],
        )
        .build(),
        Err(TlsBuildError::BufferTooShort {
            required: 6,
            available: 5,
        })
    );
    assert_eq!(short_handshake, before);

    let mut invalid = [0xaa; 64];
    let before = invalid;
    assert_eq!(
        ClientHelloBuilder::new(
            &mut invalid,
            TlsProtocolVersion::TLS12,
            &[0; 32],
            &[],
            &[0x13],
            &[0],
            None,
        )
        .build(),
        Err(TlsBuildError::InvalidValue)
    );
    assert_eq!(invalid, before);

    let mut malformed_extensions = [0xaa; 64];
    let before = malformed_extensions;
    assert_eq!(
        ClientHelloBuilder::new(
            &mut malformed_extensions,
            TlsProtocolVersion::TLS12,
            &[0; 32],
            &[],
            &[0x13, 0x01],
            &[0],
            Some(&[0, 43, 0]),
        )
        .build(),
        Err(TlsBuildError::InvalidValue)
    );
    assert_eq!(malformed_extensions, before);

    let oversized = vec![0u8; usize::from(u16::MAX) + 1];
    let mut untouched = [0xaa; 8];
    let before = untouched;
    assert_eq!(
        TlsExtensionBuilder::new(&mut untouched, TlsExtensionType::COOKIE, &oversized).build(),
        Err(TlsBuildError::LengthTooLarge)
    );
    assert_eq!(untouched, before);

    let compression_methods = [0u8; 256];
    let mut compression_output = [0xaa; 64];
    let before = compression_output;
    assert_eq!(
        ClientHelloBuilder::new(
            &mut compression_output,
            TlsProtocolVersion::TLS12,
            &[0; 32],
            &[],
            &[0x13, 0x01],
            &compression_methods,
            None,
        )
        .build(),
        Err(TlsBuildError::LengthTooLarge)
    );
    assert_eq!(compression_output, before);
}

#[test]
fn encrypted_application_data_stays_opaque() {
    let bytes = [23, 3, 3, 0, 5, 1, 0, 0, 1, 0xff];
    let record = TlsRecord::parse(&bytes).unwrap();
    assert_eq!(record.content_type(), TlsContentType::APPLICATION_DATA);
    assert_eq!(record.fragment(), &[1, 0, 0, 1, 0xff]);
}
