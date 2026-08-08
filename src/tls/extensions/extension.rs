use super::{
    alpn::{AlpnProtocolList, ServerSelectedAlpn},
    key_share::{ClientKeyShare, HrrKeyShare, ServerKeyShare},
    layout::{empty, len, v16},
    psk::{ClientPreSharedKey, PskKeyExchangeModes, ServerPreSharedKey},
    scalar_lists::{
        CertificateCompressionAlgorithms, EcPointFormats, SignatureAlgorithms, SupportedGroups,
    },
    server_name::ClientServerNameList,
    versions::{ClientSupportedVersions, ServerSupportedVersion},
};
use crate::tls::{
    error::TlsParseError,
    types::{TlsExtensionType, TlsProtocolVersion},
};

/// A raw TLS extension preserving its type and opaque payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsExtension<'a> {
    extension_type: TlsExtensionType,
    data: &'a [u8],
}
impl<'a> TlsExtension<'a> {
    /// Returns the raw extension type.
    pub const fn extension_type(&self) -> TlsExtensionType {
        self.extension_type
    }
    /// Returns the exact extension payload.
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }
    fn ty(&self, t: TlsExtensionType) -> Result<(), TlsParseError> {
        if self.extension_type == t {
            Ok(())
        } else {
            Err(TlsParseError::InvalidValue)
        }
    }
    /// Parses the ClientHello server_name list layout.
    pub fn client_server_name_list(&self) -> Result<ClientServerNameList<'a>, TlsParseError> {
        self.ty(TlsExtensionType::SERVER_NAME)?;
        ClientServerNameList::parse(self.data)
    }
    /// Validates the empty ServerHello server_name acknowledgement.
    pub fn server_name_acknowledgement(&self) -> Result<(), TlsParseError> {
        self.ty(TlsExtensionType::SERVER_NAME)?;
        empty(self.data)
    }
    /// Parses an ordered ALPN protocol-name list.
    pub fn alpn_protocol_list(&self) -> Result<AlpnProtocolList<'a>, TlsParseError> {
        self.ty(TlsExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION)?;
        AlpnProtocolList::parse(self.data)
    }
    /// Parses the single protocol selected by a server ALPN extension.
    pub fn server_selected_alpn(&self) -> Result<ServerSelectedAlpn<'a>, TlsParseError> {
        self.ty(TlsExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION)?;
        ServerSelectedAlpn::parse(self.data)
    }
    /// Parses the ClientHello supported_versions vector.
    pub fn client_supported_versions(&self) -> Result<ClientSupportedVersions<'a>, TlsParseError> {
        self.ty(TlsExtensionType::SUPPORTED_VERSIONS)?;
        ClientSupportedVersions::parse(self.data)
    }
    /// Returns the selected server or HelloRetryRequest protocol version.
    pub fn server_supported_version(&self) -> Result<TlsProtocolVersion, TlsParseError> {
        Ok(self.server_supported_version_view()?.version())
    }
    /// Parses the server or HelloRetryRequest supported_versions layout.
    pub fn server_supported_version_view(&self) -> Result<ServerSupportedVersion, TlsParseError> {
        self.ty(TlsExtensionType::SUPPORTED_VERSIONS)?;
        ServerSupportedVersion::parse(self.data)
    }
    /// Parses the ordered supported named groups.
    pub fn supported_groups(&self) -> Result<SupportedGroups<'a>, TlsParseError> {
        self.ty(TlsExtensionType::SUPPORTED_GROUPS)?;
        SupportedGroups::parse(self.data)
    }
    /// Parses the signature_algorithms scheme list.
    pub fn signature_algorithms(&self) -> Result<SignatureAlgorithms<'a>, TlsParseError> {
        self.ty(TlsExtensionType::SIGNATURE_ALGORITHMS)?;
        SignatureAlgorithms::parse(self.data)
    }
    /// Parses the signature_algorithms_cert scheme list.
    pub fn signature_algorithms_cert(&self) -> Result<SignatureAlgorithms<'a>, TlsParseError> {
        self.ty(TlsExtensionType::SIGNATURE_ALGORITHMS_CERT)?;
        SignatureAlgorithms::parse(self.data)
    }
    /// Parses the legacy EC point-format list.
    pub fn ec_point_formats(&self) -> Result<EcPointFormats<'a>, TlsParseError> {
        self.ty(TlsExtensionType::EC_POINT_FORMATS)?;
        EcPointFormats::parse(self.data)
    }
    /// Parses the ClientHello key-share entry vector.
    pub fn client_key_share(&self) -> Result<ClientKeyShare<'a>, TlsParseError> {
        self.ty(TlsExtensionType::KEY_SHARE)?;
        ClientKeyShare::parse(self.data)
    }
    /// Parses the single ServerHello key-share entry.
    pub fn server_key_share(&self) -> Result<ServerKeyShare<'a>, TlsParseError> {
        self.ty(TlsExtensionType::KEY_SHARE)?;
        ServerKeyShare::parse(self.data)
    }
    /// Parses the selected HelloRetryRequest key-share group.
    pub fn hrr_key_share(&self) -> Result<HrrKeyShare, TlsParseError> {
        self.ty(TlsExtensionType::KEY_SHARE)?;
        HrrKeyShare::parse(self.data)
    }
    /// Parses the ordered PSK key-exchange modes.
    pub fn psk_key_exchange_modes(&self) -> Result<PskKeyExchangeModes<'a>, TlsParseError> {
        self.ty(TlsExtensionType::PSK_KEY_EXCHANGE_MODES)?;
        PskKeyExchangeModes::parse(self.data)
    }
    /// Parses ClientHello PSK identities and binders.
    pub fn client_pre_shared_key(&self) -> Result<ClientPreSharedKey<'a>, TlsParseError> {
        self.ty(TlsExtensionType::PRE_SHARED_KEY)?;
        ClientPreSharedKey::parse(self.data)
    }
    /// Parses the ServerHello selected PSK identity.
    pub fn server_pre_shared_key(&self) -> Result<ServerPreSharedKey, TlsParseError> {
        self.ty(TlsExtensionType::PRE_SHARED_KEY)?;
        ServerPreSharedKey::parse(self.data)
    }
    /// Parses the offered certificate-compression algorithms.
    pub fn certificate_compression_algorithms(
        &self,
    ) -> Result<CertificateCompressionAlgorithms<'a>, TlsParseError> {
        self.ty(TlsExtensionType::COMPRESS_CERTIFICATE)?;
        CertificateCompressionAlgorithms::parse(self.data)
    }
    /// Parses the nonempty cookie vector.
    pub fn cookie(&self) -> Result<Cookie<'a>, TlsParseError> {
        self.ty(TlsExtensionType::COOKIE)?;
        Cookie::parse(self.data)
    }
    /// Validates an empty ClientHello or EncryptedExtensions early_data marker.
    pub fn early_data_marker(&self) -> Result<(), TlsParseError> {
        self.ty(TlsExtensionType::EARLY_DATA)?;
        empty(self.data)
    }
    /// Parses a NewSessionTicket maximum early-data size.
    pub fn early_data_max_size(&self) -> Result<u32, TlsParseError> {
        self.ty(TlsExtensionType::EARLY_DATA)?;
        if self.data.len() != 4 {
            return Err(len(4, self.data.len()));
        }
        Ok(u32::from_be_bytes(self.data.try_into().expect("checked")))
    }
}
/// A fallible iterator over ordered TLS extension TLVs.
#[derive(Clone, Debug)]
pub struct TlsExtensions<'a> {
    bytes: &'a [u8],
}
impl<'a> TlsExtensions<'a> {
    /// Creates an iterator over a caller-supplied extension block.
    ///
    /// Individual malformed or truncated TLVs are reported by iteration.
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}
impl<'a> Iterator for TlsExtensions<'a> {
    type Item = Result<TlsExtension<'a>, TlsParseError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return None;
        }
        let a = self.bytes.len();
        if a < 4 {
            self.bytes = &[];
            return Some(Err(TlsParseError::Incomplete {
                required: 4,
                available: a,
            }));
        }
        let n = usize::from(u16::from_be_bytes([self.bytes[2], self.bytes[3]]));
        let total = 4 + n;
        if a < total {
            self.bytes = &[];
            return Some(Err(TlsParseError::Incomplete {
                required: total,
                available: a,
            }));
        }
        let x = TlsExtension {
            extension_type: TlsExtensionType::new(u16::from_be_bytes([
                self.bytes[0],
                self.bytes[1],
            ])),
            data: &self.bytes[4..total],
        };
        self.bytes = &self.bytes[total..];
        Some(Ok(x))
    }
}
/// A nonempty opaque TLS cookie.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cookie<'a>(&'a [u8]);
impl<'a> Cookie<'a> {
    pub(super) fn parse(b: &'a [u8]) -> Result<Self, TlsParseError> {
        Ok(Self(v16(b, 1, false)?))
    }
    /// Returns the cookie bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.0
    }
}
