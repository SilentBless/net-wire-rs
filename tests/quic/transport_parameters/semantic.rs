use net_wire::quic::*;

#[test]
fn transport_parameter_v1_semantics_bound_present_integers_and_preserve_raw_views() {
    let bytes = [
        0x03, 0x02, 0x44, 0xb0, // max_udp_payload_size = 1200
        0x08, 0x08, 0xd0, 0, 0, 0, 0, 0, 0, 0, // initial_max_streams_bidi = 2^60
        0x09, 0x08, 0xd0, 0, 0, 0, 0, 0, 0, 0, // initial_max_streams_uni = 2^60
        0x0a, 0x01, 20, // ack_delay_exponent
        0x0b, 0x02, 0x7f, 0xff, // max_ack_delay = 2^14 - 1
        0x0e, 0x01, 2, // active_connection_id_limit
        0x01, 0x02, 0x40, 0x25, // max_idle_timeout = 37 in two-byte width
        0x04, 0x04, 0x80, 0, 0, 0x25, // initial_max_data = 37 in four-byte width
        0x05, 0x08, 0xc0, 0, 0, 0, 0, 0, 0,
        0x25, // initial_max_stream_data_bidi_local = 37 in eight-byte width
        0x1b, 0x03, 0xaa, 0xbb, 0xcc, // reserved opaque parameter
        0x20, 0x02, 0xdd, 0xee, // unknown opaque parameter
    ];
    let raw = QuicTransportParameters::parse(&bytes).unwrap();
    let checked: QuicTransportParametersV1<'_> = raw
        .validate_v1(QuicTransportParameterSender::Client)
        .unwrap();
    let _: QuicTransportParameterSender = QuicTransportParameterSender::Client;
    let _: QuicTransportParameterSemanticError =
        QuicTransportParameterSemanticError::ForbiddenSender {
            id: QuicTransportParameterId::ORIGINAL_DESTINATION_CONNECTION_ID,
            offset: 0,
        };
    assert_eq!(checked.as_bytes(), &bytes);
    assert_eq!(checked.sender(), QuicTransportParameterSender::Client);
    assert_eq!(
        checked.iter().nth(1).unwrap().unwrap().value(),
        &[0xd0, 0, 0, 0, 0, 0, 0, 0]
    );
    for (index, encoded) in [
        (6, &[0x40, 0x25][..]),
        (7, &[0x80, 0, 0, 0x25][..]),
        (8, &[0xc0, 0, 0, 0, 0, 0, 0, 0x25][..]),
    ] {
        let integer = checked
            .iter()
            .nth(index)
            .unwrap()
            .unwrap()
            .integer()
            .unwrap();
        assert_eq!(integer.as_bytes(), encoded);
        assert_eq!(integer.value(), 37);
        assert!(!integer.is_canonical());
    }
    let reserved = checked.iter().nth(9).unwrap().unwrap();
    assert_eq!(reserved.as_bytes(), &[0x1b, 0x03, 0xaa, 0xbb, 0xcc]);
    assert_eq!(reserved.parameter_id().raw(), 0x1b);
    let unknown = checked.iter().nth(10).unwrap().unwrap();
    assert_eq!(unknown.as_bytes(), &[0x20, 0x02, 0xdd, 0xee]);
    assert_eq!(unknown.parameter_id().raw(), 0x20);
    assert_eq!(raw.as_bytes(), &bytes);

    for (bytes, id, value, maximum) in [
        (
            &[0x08, 0x08, 0xd0, 0, 0, 0, 0, 0, 0, 1][..],
            0x08,
            (1u64 << 60) + 1,
            1u64 << 60,
        ),
        (
            &[0x09, 0x08, 0xd0, 0, 0, 0, 0, 0, 0, 1][..],
            0x09,
            (1u64 << 60) + 1,
            1u64 << 60,
        ),
        (&[0x0a, 0x01, 21][..], 0x0a, 21, 20),
        (
            &[0x0b, 0x04, 0x80, 0, 0x40, 0][..],
            0x0b,
            1 << 14,
            (1 << 14) - 1,
        ),
    ] {
        assert_eq!(
            QuicTransportParameters::parse(bytes)
                .unwrap()
                .validate_v1(QuicTransportParameterSender::Client),
            Err(QuicTransportParameterSemanticError::AboveMaximum {
                id: QuicTransportParameterId::new(id),
                offset: 0,
                value,
                maximum,
            })
        );
    }
    for (bytes, id, value, minimum) in [
        (&[0x03, 0x02, 0x44, 0xaf][..], 0x03, 1199, 1200),
        (&[0x0e, 0x01, 1][..], 0x0e, 1, 2),
    ] {
        assert_eq!(
            QuicTransportParameters::parse(bytes)
                .unwrap()
                .validate_v1(QuicTransportParameterSender::Client),
            Err(QuicTransportParameterSemanticError::BelowMinimum {
                id: QuicTransportParameterId::new(id),
                offset: 0,
                value,
                minimum,
            })
        );
    }
}

#[test]
fn transport_parameter_v1_semantics_enforce_roles_and_typed_layouts() {
    let prefix = [0x01, 0x01, 0];
    let mut malformed_original = [0u8; 26];
    malformed_original[..3].copy_from_slice(&prefix);
    malformed_original[3] = 0x00;
    malformed_original[4] = 21;
    let original = QuicTransportParameters::parse(&malformed_original).unwrap();
    assert_eq!(
        original.validate_v1(QuicTransportParameterSender::Client),
        Err(QuicTransportParameterSemanticError::ForbiddenSender {
            id: QuicTransportParameterId::ORIGINAL_DESTINATION_CONNECTION_ID,
            offset: 3,
        })
    );
    assert_eq!(original.as_bytes(), &malformed_original);
    assert_eq!(
        original.iter().nth(1).unwrap().unwrap().as_bytes(),
        &malformed_original[3..]
    );
    assert_eq!(
        original.validate_v1(QuicTransportParameterSender::Server),
        Err(QuicTransportParameterSemanticError::Value {
            id: QuicTransportParameterId::ORIGINAL_DESTINATION_CONNECTION_ID,
            offset: 3,
            error: QuicTransportParameterValueError::ConnectionIdTooLong {
                maximum: 20,
                actual: 21,
            },
        })
    );

    let mut malformed_retry = [0u8; 26];
    malformed_retry[..3].copy_from_slice(&prefix);
    malformed_retry[3] = 0x10;
    malformed_retry[4] = 21;
    for (bytes, id) in [
        (&[0x01, 0x01, 0, 0x02, 0][..], 0x02),
        (&[0x01, 0x01, 0, 0x0d, 0][..], 0x0d),
        (&malformed_retry[..], 0x10),
    ] {
        let parameters = QuicTransportParameters::parse(bytes).unwrap();
        assert_eq!(
            parameters.validate_v1(QuicTransportParameterSender::Client),
            Err(QuicTransportParameterSemanticError::ForbiddenSender {
                id: QuicTransportParameterId::new(id),
                offset: 3,
            })
        );
    }

    let mut original_connection_id = [0u8; 22];
    original_connection_id[1] = 20;
    assert!(
        QuicTransportParameters::parse(&original_connection_id)
            .unwrap()
            .validate_v1(QuicTransportParameterSender::Server)
            .is_ok()
    );
    let mut stateless_reset_token = [0u8; 18];
    stateless_reset_token[0] = 0x02;
    stateless_reset_token[1] = 16;
    assert!(
        QuicTransportParameters::parse(&stateless_reset_token)
            .unwrap()
            .validate_v1(QuicTransportParameterSender::Server)
            .is_ok()
    );
    let mut preferred_address = [0u8; 45];
    preferred_address[..3].copy_from_slice(&[0x0d, 0x40, 42]);
    preferred_address[27] = 1;
    assert!(
        QuicTransportParameters::parse(&preferred_address)
            .unwrap()
            .validate_v1(QuicTransportParameterSender::Server)
            .is_ok()
    );
    let mut retry_source_connection_id = [0u8; 22];
    retry_source_connection_id[0] = 0x10;
    retry_source_connection_id[1] = 20;
    assert!(
        QuicTransportParameters::parse(&retry_source_connection_id)
            .unwrap()
            .validate_v1(QuicTransportParameterSender::Server)
            .is_ok()
    );

    let mut malformed_token = [0u8; 20];
    malformed_token[..3].copy_from_slice(&prefix);
    malformed_token[3] = 0x02;
    malformed_token[4] = 15;
    assert_eq!(
        QuicTransportParameters::parse(&malformed_token)
            .unwrap()
            .validate_v1(QuicTransportParameterSender::Server),
        Err(QuicTransportParameterSemanticError::Value {
            id: QuicTransportParameterId::STATELESS_RESET_TOKEN,
            offset: 3,
            error: QuicTransportParameterValueError::WrongLength {
                kind: QuicTransportParameterValueKind::StatelessResetToken,
                expected: 16,
                actual: 15,
            },
        })
    );

    for (bytes, id, error) in [
        (
            &[0x04, 0x01, 0, 0x01, 0x02, 1, 0xaa][..],
            QuicTransportParameterId::MAX_IDLE_TIMEOUT,
            QuicTransportParameterValueError::TrailingIntegerBytes {
                parsed: 1,
                available: 2,
            },
        ),
        (
            &[0x01, 0x01, 0, 0x03, 0x01, 0x40][..],
            QuicTransportParameterId::MAX_UDP_PAYLOAD_SIZE,
            QuicTransportParameterValueError::MalformedInteger {
                error: QuicVarIntParseError::Incomplete {
                    required: 2,
                    available: 1,
                },
            },
        ),
        (
            &[0x01, 0x01, 0, 0x0c, 0x01, 0][..],
            QuicTransportParameterId::DISABLE_ACTIVE_MIGRATION,
            QuicTransportParameterValueError::WrongLength {
                kind: QuicTransportParameterValueKind::DisableActiveMigration,
                expected: 0,
                actual: 1,
            },
        ),
        (
            &[0x01, 0x01, 0, 0x0d, 0][..],
            QuicTransportParameterId::PREFERRED_ADDRESS,
            QuicTransportParameterValueError::PreferredAddressIncomplete {
                offset: 0,
                required: 4,
                available: 0,
            },
        ),
    ] {
        assert_eq!(
            QuicTransportParameters::parse(bytes)
                .unwrap()
                .validate_v1(QuicTransportParameterSender::Server),
            Err(QuicTransportParameterSemanticError::Value {
                id,
                offset: 3,
                error,
            })
        );
    }
}

#[test]
fn transport_parameter_handshake_client_cids_are_exact_and_reusable() {
    let _: QuicTransportParameterHandshakeContext<'_> =
        QuicTransportParameterHandshakeContext::Client {
            initial_source_connection_id: b"cid",
        };
    let _: QuicTransportParameterHandshakeError = QuicTransportParameterHandshakeError::Missing {
        id: QuicTransportParameterId::INITIAL_SOURCE_CONNECTION_ID,
    };
    let structural = QuicTransportParameterHandshakeError::Structural {
        error: QuicTransportParameterParseError::IncompleteValue {
            offset: 1,
            required: 2,
            available: 1,
        },
    };
    assert_eq!(
        structural.to_string(),
        "QUIC handshake transport parameters are not structural: QUIC transport parameter value at offset 1 is incomplete: need 2 bytes, have 1"
    );
    let zero = QuicTransportParameters::parse(&[0x0f, 0]).unwrap();
    let checked = zero
        .validate_v1(QuicTransportParameterSender::Client)
        .unwrap();
    assert_eq!(
        checked.validate_handshake(QuicTransportParameterHandshakeContext::Client {
            initial_source_connection_id: &[],
        }),
        Ok(())
    );

    let bytes = [0x01, 0x01, 0, 0x40, 0x0f, 0x40, 0x03, b'c', b'i', b'd'];
    let checked = QuicTransportParameters::parse(&bytes)
        .unwrap()
        .validate_v1(QuicTransportParameterSender::Client)
        .unwrap();
    assert_eq!(
        checked.validate_handshake(QuicTransportParameterHandshakeContext::Client {
            initial_source_connection_id: b"bad",
        }),
        Err(QuicTransportParameterHandshakeError::ConnectionIdMismatch {
            id: QuicTransportParameterId::INITIAL_SOURCE_CONNECTION_ID,
            offset: 3,
        })
    );
    assert_eq!(checked.as_bytes(), &bytes);
    assert_eq!(
        checked.validate_handshake(QuicTransportParameterHandshakeContext::Client {
            initial_source_connection_id: b"cid",
        }),
        Ok(())
    );
    assert_eq!(
        QuicTransportParameters::parse(&[])
            .unwrap()
            .validate_v1(QuicTransportParameterSender::Client)
            .unwrap()
            .validate_handshake(QuicTransportParameterHandshakeContext::Client {
                initial_source_connection_id: b"cid",
            }),
        Err(QuicTransportParameterHandshakeError::Missing {
            id: QuicTransportParameterId::INITIAL_SOURCE_CONNECTION_ID,
        })
    );
}

#[test]
fn transport_parameter_handshake_server_cids_retry_and_precedence_are_exact() {
    let no_retry = [0x0f, 0, 0x00, 0x02, b'o', b'd'];
    let checked = QuicTransportParameters::parse(&no_retry)
        .unwrap()
        .validate_v1(QuicTransportParameterSender::Server)
        .unwrap();
    let context = QuicTransportParameterHandshakeContext::Server {
        initial_source_connection_id: &[],
        original_destination_connection_id: b"od",
        retry_source_connection_id: None,
    };
    assert_eq!(checked.validate_handshake(context), Ok(()));

    let retry = [0x0f, 0x01, b'i', 0x00, 0, 0x10, 0x01, b'r'];
    let checked = QuicTransportParameters::parse(&retry)
        .unwrap()
        .validate_v1(QuicTransportParameterSender::Server)
        .unwrap();
    assert_eq!(
        checked.validate_handshake(QuicTransportParameterHandshakeContext::Server {
            initial_source_connection_id: b"i",
            original_destination_connection_id: &[],
            retry_source_connection_id: Some(b"r"),
        }),
        Ok(())
    );
    assert_eq!(
        checked.validate_handshake(QuicTransportParameterHandshakeContext::Server {
            initial_source_connection_id: b"i",
            original_destination_connection_id: &[],
            retry_source_connection_id: None,
        }),
        Err(QuicTransportParameterHandshakeError::Unexpected {
            id: QuicTransportParameterId::RETRY_SOURCE_CONNECTION_ID,
            offset: 5,
        })
    );
    for (initial, original, retry, id, offset) in [
        (b"x" as &[u8], &[][..], Some(b"r" as &[u8]), 0x0f, 0),
        (b"i" as &[u8], b"x" as &[u8], Some(b"r" as &[u8]), 0x00, 3),
        (b"i" as &[u8], &[][..], Some(b"x" as &[u8]), 0x10, 5),
    ] {
        assert_eq!(
            checked.validate_handshake(QuicTransportParameterHandshakeContext::Server {
                initial_source_connection_id: initial,
                original_destination_connection_id: original,
                retry_source_connection_id: retry,
            }),
            Err(QuicTransportParameterHandshakeError::ConnectionIdMismatch {
                id: QuicTransportParameterId::new(id),
                offset,
            })
        );
    }
    for (bytes, expected) in [
        (
            &[][..],
            QuicTransportParameterId::INITIAL_SOURCE_CONNECTION_ID,
        ),
        (
            &[0x0f, 0][..],
            QuicTransportParameterId::ORIGINAL_DESTINATION_CONNECTION_ID,
        ),
        (
            &[0x0f, 0, 0x00, 0][..],
            QuicTransportParameterId::RETRY_SOURCE_CONNECTION_ID,
        ),
    ] {
        assert_eq!(
            QuicTransportParameters::parse(bytes)
                .unwrap()
                .validate_v1(QuicTransportParameterSender::Server)
                .unwrap()
                .validate_handshake(QuicTransportParameterHandshakeContext::Server {
                    initial_source_connection_id: &[],
                    original_destination_connection_id: &[],
                    retry_source_connection_id: Some(b"r"),
                }),
            Err(QuicTransportParameterHandshakeError::Missing { id: expected })
        );
    }
}

#[test]
fn transport_parameter_handshake_context_sender_mismatch_precedes_tuple_scanning() {
    let client = QuicTransportParameters::parse(&[])
        .unwrap()
        .validate_v1(QuicTransportParameterSender::Client)
        .unwrap();
    assert_eq!(
        client.validate_handshake(QuicTransportParameterHandshakeContext::Server {
            initial_source_connection_id: &[],
            original_destination_connection_id: &[],
            retry_source_connection_id: None,
        }),
        Err(
            QuicTransportParameterHandshakeError::SenderContextMismatch {
                sender: QuicTransportParameterSender::Client,
                context_sender: QuicTransportParameterSender::Server,
            }
        )
    );
    let server = QuicTransportParameters::parse(&[])
        .unwrap()
        .validate_v1(QuicTransportParameterSender::Server)
        .unwrap();
    assert_eq!(
        server.validate_handshake(QuicTransportParameterHandshakeContext::Client {
            initial_source_connection_id: &[],
        }),
        Err(
            QuicTransportParameterHandshakeError::SenderContextMismatch {
                sender: QuicTransportParameterSender::Server,
                context_sender: QuicTransportParameterSender::Client,
            }
        )
    );
}
