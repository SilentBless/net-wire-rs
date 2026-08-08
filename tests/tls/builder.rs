use net_wire::tls::{
    ClientHello, ClientHelloBuilder, ServerHelloBuilder, TlsBuildError, TlsCipherSuite,
    TlsCompressionMethod, TlsContentType, TlsExtensionBuilder, TlsExtensionType,
    TlsHandshakeBuilder, TlsHandshakeType, TlsProtocolVersion, TlsRecordBuilder,
};

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
