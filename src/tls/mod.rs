//! Standalone allocation-free TLS record and handshake wire views.
mod builder;
mod error;
pub(crate) mod extensions;
mod handshake;
mod hello;
mod record;
pub(crate) mod types;
pub use builder::{ClientHelloBuilder, ServerHelloBuilder, TlsExtensionBuilder};
pub use error::{TlsBuildError, TlsParseError, TlsRecordMutationError};
pub use extensions::{
    AlpnProtocol, AlpnProtocolIter, AlpnProtocolList, CertificateCompressionAlgorithms,
    ClientKeyShare, ClientPreSharedKey, ClientServerNameList, ClientSupportedVersions, Cookie,
    EcPointFormats, HrrKeyShare, KeyShareEntry, KeyShareIter, PskBinderIter, PskIdentity,
    PskIdentityIter, PskKeyExchangeModes, ServerKeyShare, ServerName, ServerNameIter,
    ServerPreSharedKey, ServerSelectedAlpn, ServerSupportedVersion, SignatureAlgorithms,
    SupportedGroups, TlsExtension, TlsExtensions,
};
pub use handshake::{TlsHandshake, TlsHandshakeBuilder};
pub use hello::{ClientHello, HELLO_RETRY_REQUEST_RANDOM, ServerHello};
pub use record::{TlsRecord, TlsRecordBuilder, TlsRecordMut};
pub use types::{
    TlsCertificateCompressionAlgorithm, TlsCipherSuite, TlsCompressionMethod, TlsContentType,
    TlsExtensionType, TlsHandshakeType, TlsNamedGroup, TlsProtocolVersion, TlsPskKeyExchangeMode,
    TlsServerNameType, TlsSignatureScheme,
};
