//! Typed, ordered TLS extension views.
#[path = "extensions/views.rs"]
mod views;

pub use views::{
    AlpnProtocol, AlpnProtocolIter, AlpnProtocolList, CertificateCompressionAlgorithms,
    ClientKeyShare, ClientPreSharedKey, ClientServerNameList, ClientSupportedVersions, Cookie,
    EcPointFormats, HrrKeyShare, KeyShareEntry, KeyShareIter, PskBinderIter, PskIdentity,
    PskIdentityIter, PskKeyExchangeModes, ServerKeyShare, ServerName, ServerNameIter,
    ServerPreSharedKey, ServerSelectedAlpn, ServerSupportedVersion, SignatureAlgorithms,
    SupportedGroups, SupportedVersions, TlsExtension, TlsExtensions,
};
