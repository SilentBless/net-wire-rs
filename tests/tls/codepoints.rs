use super::fixtures::only_extension;
use net_wire::tls::{
    TlsCipherSuite, TlsExtensionType, TlsNamedGroup, TlsProtocolVersion, TlsPskKeyExchangeMode,
    TlsSignatureScheme,
};

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
