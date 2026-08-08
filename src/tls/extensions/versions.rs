use super::layout::{len, v8};
use crate::tls::{error::TlsParseError, types::TlsProtocolVersion};

/// Ordered protocol versions from a ClientHello supported_versions extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientSupportedVersions<'a> {
    bytes: &'a [u8],
}
/// Backward-compatible name for client supported protocol versions.
pub type SupportedVersions<'a> = ClientSupportedVersions<'a>;
impl<'a> ClientSupportedVersions<'a> {
    pub(super) fn parse(b: &'a [u8]) -> Result<Self, TlsParseError> {
        let bytes = v8(b, 2)?;
        if !bytes.len().is_multiple_of(2) {
            return Err(TlsParseError::InvalidValue);
        }
        Ok(Self { bytes })
    }
    /// Returns versions in their original wire order.
    pub fn iter(&self) -> impl Iterator<Item = TlsProtocolVersion> + 'a {
        self.bytes
            .chunks_exact(2)
            .map(|x| TlsProtocolVersion::new(u16::from_be_bytes([x[0], x[1]])))
    }
    /// Returns the numerically highest non-GREASE offered version.
    pub fn highest(&self) -> Option<TlsProtocolVersion> {
        self.iter().filter(|x| !x.is_grease()).max()
    }
}
/// A protocol version selected by a server or HelloRetryRequest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerSupportedVersion(TlsProtocolVersion);
impl ServerSupportedVersion {
    pub(super) fn parse(b: &[u8]) -> Result<Self, TlsParseError> {
        if b.len() != 2 {
            return Err(len(2, b.len()));
        }
        Ok(Self(TlsProtocolVersion::new(u16::from_be_bytes([
            b[0], b[1],
        ]))))
    }
    /// Returns the selected raw-preserving version.
    pub const fn version(self) -> TlsProtocolVersion {
        self.0
    }
}
