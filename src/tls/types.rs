//! TLS scalar wire values.

macro_rules! wire_type {
    ($name:ident, $raw:ty, $grease:expr) => {
        #[doc = concat!("A raw TLS ", stringify!($name), " value.")]
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct $name($raw);
        impl $name {
            /// Creates a value without restricting private or unknown assignments.
            #[inline]
            pub const fn new(raw: $raw) -> Self {
                Self(raw)
            }
            /// Returns the encoded wire value.
            #[inline]
            pub const fn raw(self) -> $raw {
                self.0
            }
            /// Returns whether this value is an RFC 8701 GREASE value.
            #[inline]
            pub const fn is_grease(self) -> bool {
                $grease(self.0)
            }
        }
    };
}

const fn grease_u16(value: u16) -> bool {
    let high = (value >> 8) as u8;
    let low = value as u8;
    high == low && high & 0x0f == 0x0a
}
const fn grease_u8(value: u8) -> bool {
    matches!(value, 0x0b | 0x2a | 0x49 | 0x68 | 0x87 | 0xa6 | 0xc5 | 0xe4)
}

const fn never_u8(_: u8) -> bool {
    false
}

const fn never_u16(_: u16) -> bool {
    false
}

wire_type!(TlsContentType, u8, never_u8);
wire_type!(TlsProtocolVersion, u16, grease_u16);
wire_type!(TlsHandshakeType, u8, never_u8);
wire_type!(TlsCipherSuite, u16, grease_u16);
wire_type!(TlsCompressionMethod, u8, never_u8);
wire_type!(TlsExtensionType, u16, grease_u16);
wire_type!(TlsNamedGroup, u16, grease_u16);
wire_type!(TlsSignatureScheme, u16, grease_u16);
wire_type!(TlsPskKeyExchangeMode, u8, grease_u8);
wire_type!(TlsServerNameType, u8, never_u8);
wire_type!(TlsCertificateCompressionAlgorithm, u16, never_u16);

impl TlsContentType {
    /// The change_cipher_spec record content type.
    pub const CHANGE_CIPHER_SPEC: Self = Self(20);
    /// The alert record content type.
    pub const ALERT: Self = Self(21);
    /// The handshake record content type.
    pub const HANDSHAKE: Self = Self(22);
    /// The application_data record content type.
    pub const APPLICATION_DATA: Self = Self(23);
}
impl TlsProtocolVersion {
    /// TLS 1.2.
    pub const TLS12: Self = Self(0x0303);
    /// TLS 1.3.
    pub const TLS13: Self = Self(0x0304);
}
impl TlsHandshakeType {
    /// ClientHello.
    pub const CLIENT_HELLO: Self = Self(1);
    /// ServerHello.
    pub const SERVER_HELLO: Self = Self(2);
}
impl TlsExtensionType {
    /// Server name indication.
    pub const SERVER_NAME: Self = Self(0);
    /// Supported groups.
    pub const SUPPORTED_GROUPS: Self = Self(10);
    /// EC point formats.
    pub const EC_POINT_FORMATS: Self = Self(11);
    /// Signature algorithms.
    pub const SIGNATURE_ALGORITHMS: Self = Self(13);
    /// ALPN.
    pub const APPLICATION_LAYER_PROTOCOL_NEGOTIATION: Self = Self(16);
    /// Certificate compression algorithms.
    pub const COMPRESS_CERTIFICATE: Self = Self(27);
    /// Pre-shared key extension.
    pub const PRE_SHARED_KEY: Self = Self(41);
    /// Early data.
    pub const EARLY_DATA: Self = Self(42);
    /// Cookie.
    pub const COOKIE: Self = Self(44);
    /// Certificate signature algorithms.
    pub const SIGNATURE_ALGORITHMS_CERT: Self = Self(50);
    /// Supported versions.
    pub const SUPPORTED_VERSIONS: Self = Self(43);
    /// PSK key exchange modes.
    pub const PSK_KEY_EXCHANGE_MODES: Self = Self(45);
    /// Key share.
    pub const KEY_SHARE: Self = Self(51);
}

impl TlsCipherSuite {
    /// TLS_AES_128_GCM_SHA256.
    pub const TLS_AES_128_GCM_SHA256: Self = Self(0x1301);
    /// TLS_AES_256_GCM_SHA384.
    pub const TLS_AES_256_GCM_SHA384: Self = Self(0x1302);
    /// TLS_CHACHA20_POLY1305_SHA256.
    pub const TLS_CHACHA20_POLY1305_SHA256: Self = Self(0x1303);
}

impl TlsCompressionMethod {
    /// The null legacy compression method.
    pub const NULL: Self = Self(0);
}

impl TlsNamedGroup {
    /// The secp256r1 named group.
    pub const SECP256R1: Self = Self(23);
    /// The secp384r1 named group.
    pub const SECP384R1: Self = Self(24);
    /// The X25519 named group.
    pub const X25519: Self = Self(29);
}

impl TlsSignatureScheme {
    /// rsa_pss_rsae_sha256.
    pub const RSA_PSS_RSAE_SHA256: Self = Self(0x0804);
    /// ecdsa_secp256r1_sha256.
    pub const ECDSA_SECP256R1_SHA256: Self = Self(0x0403);
    /// ed25519.
    pub const ED25519: Self = Self(0x0807);
}

impl TlsPskKeyExchangeMode {
    /// PSK-only key establishment.
    pub const PSK_KE: Self = Self(0);
    /// PSK with an ephemeral Diffie-Hellman key exchange.
    pub const PSK_DHE_KE: Self = Self(1);
}

impl TlsServerNameType {
    /// A DNS hostname.
    pub const HOST_NAME: Self = Self(0);
}

impl TlsCertificateCompressionAlgorithm {
    /// The zlib certificate-compression algorithm.
    pub const ZLIB: Self = Self(1);
    /// The Brotli certificate-compression algorithm.
    pub const BROTLI: Self = Self(2);
    /// The Zstandard certificate-compression algorithm.
    pub const ZSTD: Self = Self(3);
}
