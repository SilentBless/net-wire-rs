use net_wire::{quic::*, tls::*};

fn only_extension(bytes: &[u8]) -> TlsExtension<'_> {
    let mut extensions = TlsExtensions::new(bytes);
    let extension = extensions.next().expect("fixture extension").unwrap();
    assert!(extensions.next().is_none());
    extension
}

#[test]
fn quic_transport_parameter_extension_constant_and_canonical_namespace_are_available() {
    assert_eq!(TlsExtensionType::QUIC_TRANSPORT_PARAMETERS.raw(), 0x0039);

    let _: Option<net_wire::quic::QuicTransportParametersTlsExtensionError> = None;
}

#[test]
fn quic_tls_extension_preserves_valid_payloads_and_empty_payloads() {
    let bytes = [
        0, 0x39, 0, 11, 1, 0, 0x40, 0x25, 0x40, 2, 0xaa, 0xbb, 0x1b, 1, 0xcc,
    ];
    let parameters = only_extension(&bytes).quic_transport_parameters().unwrap();
    assert_eq!(parameters.as_bytes(), &bytes[4..]);
    let mut tuples = parameters.iter();
    assert_eq!(tuples.next().unwrap().unwrap().as_bytes(), &[1, 0]);
    let noncanonical = tuples.next().unwrap().unwrap();
    assert_eq!(noncanonical.id().as_bytes(), &[0x40, 0x25]);
    assert_eq!(noncanonical.length().as_bytes(), &[0x40, 2]);
    assert_eq!(noncanonical.value(), &[0xaa, 0xbb]);
    let reserved = tuples.next().unwrap().unwrap();
    assert_eq!(reserved.as_bytes(), &[0x1b, 1, 0xcc]);
    assert!(reserved.parameter_id().is_reserved());
    assert_eq!(tuples.next(), None);

    let empty = only_extension(&[0, 0x39, 0, 0])
        .quic_transport_parameters()
        .unwrap();
    assert_eq!(empty.as_bytes(), &[]);
}

#[test]
fn quic_tls_extension_reports_wrong_type_and_payload_failures_exactly() {
    assert_eq!(
        only_extension(&[0, 44, 0, 0]).quic_transport_parameters(),
        Err(
            QuicTransportParametersTlsExtensionError::WrongExtensionType {
                actual: TlsExtensionType::COOKIE,
            }
        )
    );
    assert_eq!(
        only_extension(&[0, 0x39, 0, 1, 0x40]).quic_transport_parameters(),
        Err(QuicTransportParametersTlsExtensionError::Parse(
            QuicTransportParameterParseError::IncompleteVarInt {
                field: QuicTransportParameterField::Id,
                offset: 0,
                error: QuicVarIntParseError::Incomplete {
                    required: 2,
                    available: 1,
                },
            }
        ))
    );
    assert_eq!(
        only_extension(&[0, 0x39, 0, 6, 1, 0, 2, 0, 1, 0]).quic_transport_parameters(),
        Err(QuicTransportParametersTlsExtensionError::Parse(
            QuicTransportParameterParseError::DuplicateId {
                id: QuicTransportParameterId::new(1),
                first_offset: 0,
                duplicate_offset: 4,
            }
        ))
    );
}
