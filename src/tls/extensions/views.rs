//! Context-specific borrowed views of TLS extension payloads.
use crate::tls::{
    TlsCertificateCompressionAlgorithm, TlsExtensionType, TlsNamedGroup, TlsParseError,
    TlsProtocolVersion, TlsPskKeyExchangeMode, TlsServerNameType, TlsSignatureScheme,
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
fn len(r: usize, a: usize) -> TlsParseError {
    if a < r {
        TlsParseError::Incomplete {
            required: r,
            available: a,
        }
    } else {
        TlsParseError::TrailingBytes
    }
}
fn empty(b: &[u8]) -> Result<(), TlsParseError> {
    if b.is_empty() {
        Ok(())
    } else {
        Err(TlsParseError::TrailingBytes)
    }
}
fn v16(b: &[u8], min: usize, even: bool) -> Result<&[u8], TlsParseError> {
    if b.len() < 2 {
        return Err(TlsParseError::Incomplete {
            required: 2,
            available: b.len(),
        });
    }
    let n = usize::from(u16::from_be_bytes([b[0], b[1]]));
    if n < min || (even && !n.is_multiple_of(2)) {
        return Err(TlsParseError::InvalidValue);
    }
    if b.len() != n + 2 {
        return Err(len(n + 2, b.len()));
    }
    Ok(&b[2..])
}
fn v8(b: &[u8], min: usize) -> Result<&[u8], TlsParseError> {
    if b.is_empty() {
        return Err(TlsParseError::Incomplete {
            required: 1,
            available: 0,
        });
    }
    let n = usize::from(b[0]);
    if n < min {
        return Err(TlsParseError::InvalidValue);
    }
    if b.len() != n + 1 {
        return Err(len(n + 1, b.len()));
    }
    Ok(&b[1..])
}
/// Ordered protocol versions from a ClientHello supported_versions extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientSupportedVersions<'a> {
    bytes: &'a [u8],
}
/// Backward-compatible name for client supported protocol versions.
pub type SupportedVersions<'a> = ClientSupportedVersions<'a>;
impl<'a> ClientSupportedVersions<'a> {
    fn parse(b: &'a [u8]) -> Result<Self, TlsParseError> {
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
    fn parse(b: &[u8]) -> Result<Self, TlsParseError> {
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
/// An ordered ClientHello server-name list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientServerNameList<'a> {
    bytes: &'a [u8],
}
impl<'a> ClientServerNameList<'a> {
    fn parse(b: &'a [u8]) -> Result<Self, TlsParseError> {
        let x = v16(b, 1, false)?;
        names_ok(x)?;
        Ok(Self { bytes: x })
    }
    /// Returns server names in their original wire order.
    pub fn iter(&self) -> ServerNameIter<'a> {
        ServerNameIter { bytes: self.bytes }
    }
}
/// One raw-preserving server-name entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerName<'a> {
    name_type: TlsServerNameType,
    name: &'a [u8],
}
impl<'a> ServerName<'a> {
    /// Returns the raw server-name type.
    pub const fn name_type(self) -> TlsServerNameType {
        self.name_type
    }
    /// Returns the encoded name bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.name
    }
}
/// A fallible iterator over server-name entries.
#[derive(Clone, Debug)]
pub struct ServerNameIter<'a> {
    bytes: &'a [u8],
}
impl<'a> Iterator for ServerNameIter<'a> {
    type Item = Result<ServerName<'a>, TlsParseError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return None;
        }
        match name(self.bytes) {
            Ok((x, n)) => {
                self.bytes = &self.bytes[n..];
                Some(Ok(x))
            }
            Err(e) => {
                self.bytes = &[];
                Some(Err(e))
            }
        }
    }
}
fn name(b: &[u8]) -> Result<(ServerName<'_>, usize), TlsParseError> {
    if b.len() < 3 {
        return Err(TlsParseError::Incomplete {
            required: 3,
            available: b.len(),
        });
    }
    let n = usize::from(u16::from_be_bytes([b[1], b[2]]));
    if n == 0 {
        return Err(TlsParseError::InvalidValue);
    }
    if b.len() < 3 + n {
        return Err(TlsParseError::Incomplete {
            required: 3 + n,
            available: b.len(),
        });
    }
    Ok((
        ServerName {
            name_type: TlsServerNameType::new(b[0]),
            name: &b[3..3 + n],
        },
        3 + n,
    ))
}
fn names_ok(mut b: &[u8]) -> Result<(), TlsParseError> {
    while !b.is_empty() {
        let (_, n) = name(b)?;
        b = &b[n..]
    }
    Ok(())
}
/// One opaque ALPN protocol identification sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlpnProtocol<'a>(&'a [u8]);
impl<'a> AlpnProtocol<'a> {
    /// Returns the opaque protocol-name bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.0
    }
    /// Returns whether this is the RFC 8701 two-byte GREASE ALPN value.
    pub const fn is_grease(self) -> bool {
        self.0.len() == 2 && self.0[0] == self.0[1] && self.0[0] & 15 == 10
    }
}
/// An ordered ALPN protocol-name list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlpnProtocolList<'a> {
    bytes: &'a [u8],
}
impl<'a> AlpnProtocolList<'a> {
    fn parse(b: &'a [u8]) -> Result<Self, TlsParseError> {
        let x = v16(b, 1, false)?;
        protocols_ok(x)?;
        Ok(Self { bytes: x })
    }
    /// Returns ALPN protocols in their original wire order.
    pub fn iter(&self) -> AlpnProtocolIter<'a> {
        AlpnProtocolIter { bytes: self.bytes }
    }
}
/// A fallible iterator over ALPN protocol names.
#[derive(Clone, Debug)]
pub struct AlpnProtocolIter<'a> {
    bytes: &'a [u8],
}
impl<'a> Iterator for AlpnProtocolIter<'a> {
    type Item = Result<AlpnProtocol<'a>, TlsParseError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return None;
        }
        let n = usize::from(self.bytes[0]);
        if n == 0 {
            return Some(Err(TlsParseError::InvalidValue));
        }
        if self.bytes.len() < n + 1 {
            let a = self.bytes.len();
            self.bytes = &[];
            return Some(Err(TlsParseError::Incomplete {
                required: n + 1,
                available: a,
            }));
        }
        let x = AlpnProtocol(&self.bytes[1..n + 1]);
        self.bytes = &self.bytes[n + 1..];
        Some(Ok(x))
    }
}
fn protocols_ok(mut b: &[u8]) -> Result<(), TlsParseError> {
    while !b.is_empty() {
        let n = usize::from(b[0]);
        if n == 0 {
            return Err(TlsParseError::InvalidValue);
        }
        if b.len() < n + 1 {
            return Err(TlsParseError::Incomplete {
                required: n + 1,
                available: b.len(),
            });
        }
        b = &b[n + 1..]
    }
    Ok(())
}
/// The single ALPN protocol selected by a server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerSelectedAlpn<'a>(AlpnProtocol<'a>);
impl<'a> ServerSelectedAlpn<'a> {
    fn parse(b: &'a [u8]) -> Result<Self, TlsParseError> {
        let x = AlpnProtocolList::parse(b)?;
        let mut i = x.iter();
        let p = i.next().expect("nonempty")?;
        if i.next().is_some() {
            return Err(TlsParseError::TrailingBytes);
        }
        Ok(Self(p))
    }
    /// Returns the selected opaque protocol name.
    pub const fn protocol(self) -> AlpnProtocol<'a> {
        self.0
    }
}
macro_rules! list {
    ($n:ident,$t:ty) => {
        #[doc = concat!("An ordered TLS ", stringify!($n), " vector.")]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $n<'a> {
            bytes: &'a [u8],
        }
        impl<'a> $n<'a> {
            fn parse(b: &'a [u8]) -> Result<Self, TlsParseError> {
                Ok(Self {
                    bytes: v16(b, 2, true)?,
                })
            }
            /// Returns values in their original wire order.
            pub fn iter(&self) -> impl Iterator<Item = $t> + 'a {
                self.bytes
                    .chunks_exact(2)
                    .map(|x| <$t>::new(u16::from_be_bytes([x[0], x[1]])))
            }
        }
    };
}
list!(SupportedGroups, TlsNamedGroup);
list!(SignatureAlgorithms, TlsSignatureScheme);
/// Ordered certificate-compression algorithm identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificateCompressionAlgorithms<'a> {
    bytes: &'a [u8],
}
impl<'a> CertificateCompressionAlgorithms<'a> {
    fn parse(b: &'a [u8]) -> Result<Self, TlsParseError> {
        let bytes = v8(b, 2)?;
        if !bytes.len().is_multiple_of(2) {
            return Err(TlsParseError::InvalidValue);
        }
        Ok(Self { bytes })
    }
    /// Returns algorithms in their original wire order.
    pub fn iter(&self) -> impl Iterator<Item = TlsCertificateCompressionAlgorithm> + 'a {
        self.bytes.chunks_exact(2).map(|bytes| {
            TlsCertificateCompressionAlgorithm::new(u16::from_be_bytes([bytes[0], bytes[1]]))
        })
    }
}
/// Ordered legacy EC point-format identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EcPointFormats<'a> {
    bytes: &'a [u8],
}
impl<'a> EcPointFormats<'a> {
    fn parse(b: &'a [u8]) -> Result<Self, TlsParseError> {
        Ok(Self { bytes: v8(b, 1)? })
    }
    /// Returns raw point-format values in wire order.
    pub fn iter(&self) -> impl Iterator<Item = u8> + 'a {
        self.bytes.iter().copied()
    }
}
/// Ordered ClientHello key-share entries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientKeyShare<'a> {
    bytes: &'a [u8],
}
impl<'a> ClientKeyShare<'a> {
    fn parse(b: &'a [u8]) -> Result<Self, TlsParseError> {
        let x = v16(b, 0, false)?;
        shares_ok(x)?;
        Ok(Self { bytes: x })
    }
    /// Returns key shares in their original wire order.
    pub fn iter(&self) -> KeyShareIter<'a> {
        KeyShareIter { bytes: self.bytes }
    }
}
/// One named-group key-share entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyShareEntry<'a> {
    group: TlsNamedGroup,
    key_exchange: &'a [u8],
}
impl<'a> KeyShareEntry<'a> {
    /// Returns the raw named group.
    pub const fn group(self) -> TlsNamedGroup {
        self.group
    }
    /// Returns the opaque key-exchange bytes.
    pub const fn key_exchange(self) -> &'a [u8] {
        self.key_exchange
    }
}
/// A fallible iterator over key-share entries.
#[derive(Clone, Debug)]
pub struct KeyShareIter<'a> {
    bytes: &'a [u8],
}
impl<'a> Iterator for KeyShareIter<'a> {
    type Item = Result<KeyShareEntry<'a>, TlsParseError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return None;
        }
        match share(self.bytes) {
            Ok((x, n)) => {
                self.bytes = &self.bytes[n..];
                Some(Ok(x))
            }
            Err(e) => {
                self.bytes = &[];
                Some(Err(e))
            }
        }
    }
}
fn share(b: &[u8]) -> Result<(KeyShareEntry<'_>, usize), TlsParseError> {
    if b.len() < 4 {
        return Err(TlsParseError::Incomplete {
            required: 4,
            available: b.len(),
        });
    }
    let n = usize::from(u16::from_be_bytes([b[2], b[3]]));
    if n == 0 {
        return Err(TlsParseError::InvalidValue);
    }
    if b.len() < n + 4 {
        return Err(TlsParseError::Incomplete {
            required: n + 4,
            available: b.len(),
        });
    }
    Ok((
        KeyShareEntry {
            group: TlsNamedGroup::new(u16::from_be_bytes([b[0], b[1]])),
            key_exchange: &b[4..n + 4],
        },
        n + 4,
    ))
}
fn shares_ok(mut b: &[u8]) -> Result<(), TlsParseError> {
    while !b.is_empty() {
        let (_, n) = share(b)?;
        b = &b[n..]
    }
    Ok(())
}
/// The single key share carried by a ServerHello.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerKeyShare<'a>(KeyShareEntry<'a>);
impl<'a> ServerKeyShare<'a> {
    fn parse(b: &'a [u8]) -> Result<Self, TlsParseError> {
        let (x, n) = share(b)?;
        if n != b.len() {
            return Err(TlsParseError::TrailingBytes);
        }
        Ok(Self(x))
    }
    /// Returns the selected key-share entry.
    pub const fn entry(self) -> KeyShareEntry<'a> {
        self.0
    }
}
/// The named group selected by a HelloRetryRequest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HrrKeyShare(TlsNamedGroup);
impl HrrKeyShare {
    fn parse(b: &[u8]) -> Result<Self, TlsParseError> {
        if b.len() != 2 {
            return Err(len(2, b.len()));
        }
        Ok(Self(TlsNamedGroup::new(u16::from_be_bytes([b[0], b[1]]))))
    }
    /// Returns the selected named group.
    pub const fn group(self) -> TlsNamedGroup {
        self.0
    }
}
/// Ordered PSK key-exchange modes from a ClientHello.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PskKeyExchangeModes<'a> {
    bytes: &'a [u8],
}
impl<'a> PskKeyExchangeModes<'a> {
    fn parse(b: &'a [u8]) -> Result<Self, TlsParseError> {
        Ok(Self { bytes: v8(b, 1)? })
    }
    /// Returns modes in their original wire order.
    pub fn iter(&self) -> impl Iterator<Item = TlsPskKeyExchangeMode> + 'a {
        self.bytes.iter().copied().map(TlsPskKeyExchangeMode::new)
    }
}
/// Borrowed ClientHello PSK identities and binders.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientPreSharedKey<'a> {
    identities: &'a [u8],
    binders: &'a [u8],
}
impl<'a> ClientPreSharedKey<'a> {
    fn parse(b: &'a [u8]) -> Result<Self, TlsParseError> {
        let (i, rest) = take_v16(b, 7)?;
        let (x, rest) = take_v16(rest, 33)?;
        if !rest.is_empty() {
            return Err(TlsParseError::TrailingBytes);
        }
        let identity_count = ids_ok(i)?;
        let binder_count = binders_ok(x)?;
        if identity_count != binder_count {
            return Err(TlsParseError::InvalidValue);
        }
        Ok(Self {
            identities: i,
            binders: x,
        })
    }
    /// Returns offered PSK identities in wire order.
    pub fn identities(&self) -> PskIdentityIter<'a> {
        PskIdentityIter {
            bytes: self.identities,
        }
    }
    /// Returns PSK binders in wire order.
    pub fn binders(&self) -> PskBinderIter<'a> {
        PskBinderIter {
            bytes: self.binders,
        }
    }
}
/// One PSK identity and its obfuscated ticket age.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PskIdentity<'a> {
    identity: &'a [u8],
    age: u32,
}
impl<'a> PskIdentity<'a> {
    /// Returns the opaque identity bytes.
    pub const fn identity(self) -> &'a [u8] {
        self.identity
    }
    /// Returns the obfuscated ticket age.
    pub const fn obfuscated_ticket_age(self) -> u32 {
        self.age
    }
}
/// A fallible iterator over PSK identities.
#[derive(Clone, Debug)]
pub struct PskIdentityIter<'a> {
    bytes: &'a [u8],
}
impl<'a> Iterator for PskIdentityIter<'a> {
    type Item = Result<PskIdentity<'a>, TlsParseError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return None;
        }
        match id(self.bytes) {
            Ok((x, n)) => {
                self.bytes = &self.bytes[n..];
                Some(Ok(x))
            }
            Err(e) => {
                self.bytes = &[];
                Some(Err(e))
            }
        }
    }
}
fn id(b: &[u8]) -> Result<(PskIdentity<'_>, usize), TlsParseError> {
    if b.len() < 6 {
        return Err(TlsParseError::Incomplete {
            required: 6,
            available: b.len(),
        });
    }
    let n = usize::from(u16::from_be_bytes([b[0], b[1]]));
    if n == 0 {
        return Err(TlsParseError::InvalidValue);
    }
    if b.len() < n + 6 {
        return Err(TlsParseError::Incomplete {
            required: n + 6,
            available: b.len(),
        });
    }
    Ok((
        PskIdentity {
            identity: &b[2..n + 2],
            age: u32::from_be_bytes([b[n + 2], b[n + 3], b[n + 4], b[n + 5]]),
        },
        n + 6,
    ))
}
fn ids_ok(mut b: &[u8]) -> Result<usize, TlsParseError> {
    let mut count = 0usize;
    while !b.is_empty() {
        let (_, n) = id(b)?;
        b = &b[n..];
        count += 1;
    }
    Ok(count)
}
/// A fallible iterator over PSK binder byte strings.
#[derive(Clone, Debug)]
pub struct PskBinderIter<'a> {
    bytes: &'a [u8],
}
impl<'a> Iterator for PskBinderIter<'a> {
    type Item = Result<&'a [u8], TlsParseError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return None;
        }
        let n = usize::from(self.bytes[0]);
        if n < 32 {
            self.bytes = &[];
            return Some(Err(TlsParseError::InvalidValue));
        }
        if self.bytes.len() < n + 1 {
            let available = self.bytes.len();
            self.bytes = &[];
            return Some(Err(TlsParseError::Incomplete {
                required: n + 1,
                available,
            }));
        }
        let x = &self.bytes[1..n + 1];
        self.bytes = &self.bytes[n + 1..];
        Some(Ok(x))
    }
}
fn binders_ok(mut b: &[u8]) -> Result<usize, TlsParseError> {
    let mut count = 0usize;
    while !b.is_empty() {
        let n = usize::from(b[0]);
        if n < 32 {
            return Err(TlsParseError::InvalidValue);
        }
        if b.len() < n + 1 {
            return Err(TlsParseError::Incomplete {
                required: n + 1,
                available: b.len(),
            });
        }
        b = &b[n + 1..];
        count += 1;
    }
    Ok(count)
}
/// The PSK identity index selected by a server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerPreSharedKey(u16);
impl ServerPreSharedKey {
    fn parse(b: &[u8]) -> Result<Self, TlsParseError> {
        if b.len() != 2 {
            return Err(len(2, b.len()));
        }
        Ok(Self(u16::from_be_bytes([b[0], b[1]])))
    }
    /// Returns the selected client identity index.
    pub const fn selected_identity(self) -> u16 {
        self.0
    }
}
/// A nonempty opaque TLS cookie.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cookie<'a>(&'a [u8]);
impl<'a> Cookie<'a> {
    fn parse(b: &'a [u8]) -> Result<Self, TlsParseError> {
        Ok(Self(v16(b, 1, false)?))
    }
    /// Returns the cookie bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.0
    }
}

fn take_v16(b: &[u8], minimum: usize) -> Result<(&[u8], &[u8]), TlsParseError> {
    if b.len() < 2 {
        return Err(TlsParseError::Incomplete {
            required: 2,
            available: b.len(),
        });
    }
    let length = usize::from(u16::from_be_bytes([b[0], b[1]]));
    if length < minimum {
        return Err(TlsParseError::InvalidValue);
    }
    let total = 2usize
        .checked_add(length)
        .ok_or(TlsParseError::InvalidValue)?;
    if b.len() < total {
        return Err(TlsParseError::Incomplete {
            required: total,
            available: b.len(),
        });
    }
    Ok((&b[2..total], &b[total..]))
}
