use net_wire::tls::{
    TlsContentType, TlsHandshake, TlsHandshakeType, TlsParseError, TlsProtocolVersion, TlsRecord,
    TlsRecordMut,
};

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
fn encrypted_application_data_stays_opaque() {
    let bytes = [23, 3, 3, 0, 5, 1, 0, 0, 1, 0xff];
    let record = TlsRecord::parse(&bytes).unwrap();
    assert_eq!(record.content_type(), TlsContentType::APPLICATION_DATA);
    assert_eq!(record.fragment(), &[1, 0, 0, 1, 0xff]);
}
