use net_wire::quic::*;

#[test]
fn transport_parameter_typed_integer_views_preserve_width_and_reject_other_layouts() {
    for id in [
        0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0e,
    ] {
        let bytes = [id, 1, 2];
        let parameter = QuicTransportParameters::parse(&bytes)
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(parameter.integer().unwrap().value(), 2);
    }
    let parameters = QuicTransportParameters::parse(&[0x01, 0x02, 0x40, 0x25]).unwrap();
    let parameter = parameters.iter().next().unwrap().unwrap();
    let integer = parameter.integer().unwrap();
    assert_eq!(integer.as_bytes(), &[0x40, 0x25]);
    assert_eq!(integer.value(), 37);
    assert!(!integer.is_canonical());

    for (value, expected) in [
        (
            &[][..],
            QuicTransportParameterValueError::MalformedInteger {
                error: QuicVarIntParseError::Incomplete {
                    required: 1,
                    available: 0,
                },
            },
        ),
        (
            &[0x40][..],
            QuicTransportParameterValueError::MalformedInteger {
                error: QuicVarIntParseError::Incomplete {
                    required: 2,
                    available: 1,
                },
            },
        ),
        (
            &[0x01, 0xaa][..],
            QuicTransportParameterValueError::TrailingIntegerBytes {
                parsed: 1,
                available: 2,
            },
        ),
    ] {
        let mut bytes = [0u8; 4];
        bytes[0] = 0x01;
        bytes[1] = value.len() as u8;
        bytes[2..2 + value.len()].copy_from_slice(value);
        let parameter = QuicTransportParameters::parse(&bytes[..2 + value.len()])
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(parameter.integer(), Err(expected));
    }
    let parameter = QuicTransportParameters::parse(&[0x02, 0])
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(
        parameter.integer(),
        Err(QuicTransportParameterValueError::WrongId {
            kind: QuicTransportParameterValueKind::Integer,
            actual: QuicTransportParameterId::STATELESS_RESET_TOKEN,
        })
    );
}

#[test]
fn transport_parameter_typed_connection_token_and_empty_views_are_bounded() {
    for id in [0x00, 0x0f, 0x10] {
        let bytes = [id, 0];
        let parameter = QuicTransportParameters::parse(&bytes)
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .unwrap();
        assert!(parameter.connection_id().unwrap().is_empty());
    }
    let mut maximum_cid = [0u8; 22];
    maximum_cid[0] = 0x0f;
    maximum_cid[1] = 20;
    maximum_cid[2..].fill(0x33);
    assert_eq!(
        QuicTransportParameters::parse(&maximum_cid)
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .unwrap()
            .connection_id()
            .unwrap()
            .len(),
        20
    );
    let mut cid = [0u8; 23];
    cid[0] = 0x0f;
    cid[1] = 21;
    assert_eq!(
        QuicTransportParameters::parse(&cid)
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .unwrap()
            .connection_id(),
        Err(QuicTransportParameterValueError::ConnectionIdTooLong {
            maximum: 20,
            actual: 21
        })
    );
    let parameter = QuicTransportParameters::parse(&[0x02, 0])
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(
        parameter.connection_id(),
        Err(QuicTransportParameterValueError::WrongId {
            kind: QuicTransportParameterValueKind::ConnectionId,
            actual: QuicTransportParameterId::STATELESS_RESET_TOKEN,
        })
    );

    let token = [
        0x02, 16, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa,
    ];
    assert_eq!(
        QuicTransportParameters::parse(&token)
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .unwrap()
            .stateless_reset_token()
            .unwrap(),
        &[0xaa; 16]
    );
    for length in [15, 17] {
        let mut bytes = [0u8; 19];
        bytes[0] = 0x02;
        bytes[1] = length;
        let parameter = QuicTransportParameters::parse(&bytes[..2 + usize::from(length)])
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(
            parameter.stateless_reset_token(),
            Err(QuicTransportParameterValueError::WrongLength {
                kind: QuicTransportParameterValueKind::StatelessResetToken,
                expected: 16,
                actual: usize::from(length),
            })
        );
    }
    let parameter = QuicTransportParameters::parse(&[0x01, 0])
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(
        parameter.stateless_reset_token(),
        Err(QuicTransportParameterValueError::WrongId {
            kind: QuicTransportParameterValueKind::StatelessResetToken,
            actual: QuicTransportParameterId::MAX_IDLE_TIMEOUT,
        })
    );
    let parameter = QuicTransportParameters::parse(&[0x0c, 0])
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(parameter.disable_active_migration(), Ok(()));
    let parameter = QuicTransportParameters::parse(&[0x0c, 1, 0])
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(
        parameter.disable_active_migration(),
        Err(QuicTransportParameterValueError::WrongLength {
            kind: QuicTransportParameterValueKind::DisableActiveMigration,
            expected: 0,
            actual: 1,
        })
    );
    let parameter = QuicTransportParameters::parse(&[0x01, 0])
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(
        parameter.disable_active_migration(),
        Err(QuicTransportParameterValueError::WrongId {
            kind: QuicTransportParameterValueKind::DisableActiveMigration,
            actual: QuicTransportParameterId::MAX_IDLE_TIMEOUT,
        })
    );
}

#[test]
fn transport_parameter_preferred_address_exposes_exact_borrowed_fields() {
    let _: Option<QuicPreferredAddress<'_>> = None;
    let _: QuicTransportParameterValueError = QuicTransportParameterValueError::WrongLength {
        kind: QuicTransportParameterValueKind::PreferredAddress,
        expected: 0,
        actual: 0,
    };
    let mut bytes = [0u8; 45];
    bytes[..3].copy_from_slice(&[0x0d, 0x40, 42]);
    bytes[3..7].copy_from_slice(&[192, 0, 2, 1]);
    bytes[7..9].copy_from_slice(&443u16.to_be_bytes());
    bytes[9..25].copy_from_slice(&[0x20; 16]);
    bytes[25..27].copy_from_slice(&8443u16.to_be_bytes());
    bytes[27] = 1;
    bytes[28] = 0x44;
    bytes[29..].copy_from_slice(&[0x55; 16]);
    let parameter = QuicTransportParameters::parse(&bytes)
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .unwrap();
    let preferred = parameter.preferred_address().unwrap();
    assert_eq!(preferred.as_bytes(), &bytes[3..]);
    assert_eq!(preferred.ipv4_address(), &[192, 0, 2, 1]);
    assert_eq!(preferred.ipv4_port(), 443);
    assert_eq!(preferred.ipv6_address(), &[0x20; 16]);
    assert_eq!(preferred.ipv6_port(), 8443);
    assert_eq!(preferred.connection_id().as_bytes(), &[0x44]);
    assert_eq!(preferred.stateless_reset_token(), &[0x55; 16]);

    let mut twenty = [0u8; 64];
    twenty[0] = 0x0d;
    twenty[1] = 61;
    twenty[26] = 20;
    twenty[27..47].fill(0x66);
    twenty[47..63].fill(0x77);
    assert_eq!(
        QuicTransportParameters::parse(&twenty[..63])
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .unwrap()
            .preferred_address()
            .unwrap()
            .connection_id()
            .len(),
        20
    );
}

#[test]
fn transport_parameter_preferred_address_reports_value_relative_bounds() {
    for (length, offset, required) in [
        (0usize, 0, 4),
        (3, 0, 4),
        (5, 4, 6),
        (21, 6, 22),
        (23, 22, 24),
        (24, 24, 25),
        (25, 25, 26),
        (40, 26, 42),
    ] {
        let mut bytes = [0u8; 65];
        bytes[0] = 0x0d;
        bytes[1] = length as u8;
        if length > 24 {
            bytes[26] = 1;
        }
        let parameter = QuicTransportParameters::parse(&bytes[..2 + length])
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(
            parameter.preferred_address(),
            Err(
                QuicTransportParameterValueError::PreferredAddressIncomplete {
                    offset,
                    required,
                    available: length,
                }
            )
        );
    }
    for connection_id_length in [0u8, 21] {
        let mut bytes = [0u8; 63];
        bytes[0] = 0x0d;
        bytes[1] = 61;
        bytes[26] = connection_id_length;
        let parameter = QuicTransportParameters::parse(&bytes)
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(
            parameter.preferred_address(),
            Err(
                QuicTransportParameterValueError::PreferredAddressConnectionIdLength {
                    actual: connection_id_length,
                }
            )
        );
    }
    let mut token_truncated = [0u8; 43];
    token_truncated[0] = 0x0d;
    token_truncated[1] = 41;
    token_truncated[26] = 1;
    let parameter = QuicTransportParameters::parse(&token_truncated)
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(
        parameter.preferred_address(),
        Err(
            QuicTransportParameterValueError::PreferredAddressIncomplete {
                offset: 26,
                required: 42,
                available: 41,
            }
        )
    );
    let mut trailing = [0u8; 45];
    trailing[0] = 0x0d;
    trailing[1] = 43;
    trailing[26] = 1;
    let parameter = QuicTransportParameters::parse(&trailing)
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(
        parameter.preferred_address(),
        Err(
            QuicTransportParameterValueError::PreferredAddressTrailingBytes {
                offset: 42,
                available: 1,
            }
        )
    );
    let parameter = QuicTransportParameters::parse(&[0x01, 0])
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(
        parameter.preferred_address(),
        Err(QuicTransportParameterValueError::WrongId {
            kind: QuicTransportParameterValueKind::PreferredAddress,
            actual: QuicTransportParameterId::MAX_IDLE_TIMEOUT,
        })
    );
}
