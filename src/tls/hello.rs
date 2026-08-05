//! ClientHello and ServerHello wire views.

use super::{
    TlsCipherSuite, TlsCompressionMethod, TlsExtensionType, TlsExtensions, TlsParseError,
    TlsProtocolVersion,
};

/// TLS HelloRetryRequest random value.
pub const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// A structurally validated ClientHello body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientHello<'a> {
    bytes: &'a [u8],
    session_id: &'a [u8],
    cipher_suites: &'a [u8],
    compression_methods: &'a [u8],
    extensions: &'a [u8],
}

impl<'a> ClientHello<'a> {
    /// Parses an exact ClientHello body.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, TlsParseError> {
        need(bytes, 34)?;
        let mut offset = 34;

        let session_id = take_u8_vector(bytes, &mut offset)?;
        if session_id.len() > 32 {
            return Err(TlsParseError::InvalidValue);
        }

        let cipher_suites = take_u16_vector(bytes, &mut offset)?;
        if cipher_suites.is_empty() || !cipher_suites.len().is_multiple_of(2) {
            return Err(TlsParseError::InvalidValue);
        }

        let compression_methods = take_u8_vector(bytes, &mut offset)?;
        if compression_methods.is_empty() {
            return Err(TlsParseError::InvalidValue);
        }

        let extensions = if offset == bytes.len() {
            &[]
        } else {
            take_u16_vector(bytes, &mut offset)?
        };
        if offset != bytes.len() {
            return Err(TlsParseError::TrailingBytes);
        }

        Ok(Self {
            bytes,
            session_id,
            cipher_suites,
            compression_methods,
            extensions,
        })
    }

    /// Returns the legacy ClientHello version.
    pub fn legacy_version(&self) -> TlsProtocolVersion {
        TlsProtocolVersion::new(u16::from_be_bytes([self.bytes[0], self.bytes[1]]))
    }

    /// Returns the 32-byte client random.
    pub fn random(&self) -> &'a [u8; 32] {
        self.bytes[2..34]
            .try_into()
            .expect("validated ClientHello random")
    }

    /// Returns the legacy session identifier.
    pub fn session_id(&self) -> &'a [u8] {
        self.session_id
    }

    /// Returns ordered offered cipher suites.
    pub fn cipher_suites(&self) -> impl Iterator<Item = TlsCipherSuite> + 'a {
        self.cipher_suites
            .chunks_exact(2)
            .map(|bytes| TlsCipherSuite::new(u16::from_be_bytes([bytes[0], bytes[1]])))
    }

    /// Returns ordered legacy compression methods.
    pub fn compression_methods(&self) -> impl Iterator<Item = TlsCompressionMethod> + 'a {
        self.compression_methods
            .iter()
            .copied()
            .map(TlsCompressionMethod::new)
    }

    /// Returns ordered extension TLVs.
    pub fn extensions(&self) -> TlsExtensions<'a> {
        TlsExtensions::new(self.extensions)
    }

    /// Returns whether a valid supported_versions extension includes TLS 1.3.
    pub fn offers_tls13(&self) -> bool {
        self.extensions()
            .filter_map(Result::ok)
            .filter(|extension| extension.extension_type() == TlsExtensionType::SUPPORTED_VERSIONS)
            .filter_map(|extension| extension.client_supported_versions().ok())
            .any(|versions| {
                versions
                    .iter()
                    .any(|version| version == TlsProtocolVersion::TLS13)
            })
    }

    /// Returns the complete represented ClientHello body.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

/// A structurally validated ServerHello body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerHello<'a> {
    bytes: &'a [u8],
    session_id: &'a [u8],
    cipher_suite: TlsCipherSuite,
    compression_method: TlsCompressionMethod,
    extensions: &'a [u8],
}

impl<'a> ServerHello<'a> {
    /// Parses an exact ServerHello body.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, TlsParseError> {
        need(bytes, 38)?;
        let mut offset = 34;

        let session_id = take_u8_vector(bytes, &mut offset)?;
        if session_id.len() > 32 {
            return Err(TlsParseError::InvalidValue);
        }

        need(&bytes[offset..], 3)?;
        let cipher_suite =
            TlsCipherSuite::new(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]));
        let compression_method = TlsCompressionMethod::new(bytes[offset + 2]);
        offset += 3;

        let extensions = if offset == bytes.len() {
            &[]
        } else {
            take_u16_vector(bytes, &mut offset)?
        };
        if offset != bytes.len() {
            return Err(TlsParseError::TrailingBytes);
        }

        Ok(Self {
            bytes,
            session_id,
            cipher_suite,
            compression_method,
            extensions,
        })
    }

    /// Returns the legacy ServerHello version.
    pub fn legacy_version(&self) -> TlsProtocolVersion {
        TlsProtocolVersion::new(u16::from_be_bytes([self.bytes[0], self.bytes[1]]))
    }

    /// Returns the 32-byte server random.
    pub fn random(&self) -> &'a [u8; 32] {
        self.bytes[2..34]
            .try_into()
            .expect("validated ServerHello random")
    }

    /// Returns the echoed legacy session identifier.
    pub fn session_id(&self) -> &'a [u8] {
        self.session_id
    }

    /// Returns the selected cipher suite as its raw-preserving value.
    pub fn cipher_suite(&self) -> TlsCipherSuite {
        self.cipher_suite
    }

    /// Returns the selected legacy compression method.
    pub fn compression_method(&self) -> TlsCompressionMethod {
        self.compression_method
    }

    /// Returns whether this ServerHello is a HelloRetryRequest.
    pub fn is_hello_retry_request(&self) -> bool {
        self.random() == &HELLO_RETRY_REQUEST_RANDOM
    }

    /// Returns ordered extension TLVs.
    pub fn extensions(&self) -> TlsExtensions<'a> {
        TlsExtensions::new(self.extensions)
    }

    /// Returns the selected supported version when a valid server extension is present.
    pub fn selected_version(&self) -> Result<Option<TlsProtocolVersion>, TlsParseError> {
        for extension in self.extensions() {
            let extension = extension?;
            if extension.extension_type() == TlsExtensionType::SUPPORTED_VERSIONS {
                return extension.server_supported_version().map(Some);
            }
        }
        Ok(None)
    }

    /// Returns the complete represented ServerHello body.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

fn need(bytes: &[u8], required: usize) -> Result<(), TlsParseError> {
    if bytes.len() < required {
        Err(TlsParseError::Incomplete {
            required,
            available: bytes.len(),
        })
    } else {
        Ok(())
    }
}

fn take_u8_vector<'a>(bytes: &'a [u8], offset: &mut usize) -> Result<&'a [u8], TlsParseError> {
    need(&bytes[*offset..], 1)?;
    let length = usize::from(bytes[*offset]);
    *offset += 1;
    take(bytes, offset, length)
}

fn take_u16_vector<'a>(bytes: &'a [u8], offset: &mut usize) -> Result<&'a [u8], TlsParseError> {
    need(&bytes[*offset..], 2)?;
    let length = usize::from(u16::from_be_bytes([bytes[*offset], bytes[*offset + 1]]));
    *offset += 2;
    take(bytes, offset, length)
}

fn take<'a>(bytes: &'a [u8], offset: &mut usize, length: usize) -> Result<&'a [u8], TlsParseError> {
    let end = offset
        .checked_add(length)
        .ok_or(TlsParseError::InvalidValue)?;
    need(&bytes[*offset..], length)?;
    let result = &bytes[*offset..end];
    *offset = end;
    Ok(result)
}
