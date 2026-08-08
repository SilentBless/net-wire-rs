//! Typed, ordered TLS extension views.

pub(super) mod alpn;
pub(crate) mod extension;
pub(super) mod key_share;
pub(super) mod layout;
pub(super) mod psk;
pub(super) mod scalar_lists;
pub(super) mod server_name;
pub(super) mod versions;

pub use alpn::{AlpnProtocol, AlpnProtocolIter, AlpnProtocolList, ServerSelectedAlpn};
pub use extension::{Cookie, TlsExtension, TlsExtensions};
pub use key_share::{ClientKeyShare, HrrKeyShare, KeyShareEntry, KeyShareIter, ServerKeyShare};
pub use psk::{
    ClientPreSharedKey, PskBinderIter, PskIdentity, PskIdentityIter, PskKeyExchangeModes,
    ServerPreSharedKey,
};
pub use scalar_lists::{
    CertificateCompressionAlgorithms, EcPointFormats, SignatureAlgorithms, SupportedGroups,
};
pub use server_name::{ClientServerNameList, ServerName, ServerNameIter};
pub use versions::{ClientSupportedVersions, ServerSupportedVersion};
