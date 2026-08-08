use super::fixtures::only_extension;
use net_wire::tls::{
    TlsCertificateCompressionAlgorithm, TlsExtensions, TlsNamedGroup, TlsParseError,
    TlsProtocolVersion, TlsPskKeyExchangeMode, TlsServerNameType, TlsSignatureScheme,
};

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
