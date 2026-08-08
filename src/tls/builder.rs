//! Caller-buffer TLS extension and hello construction.

use super::{
    error::TlsBuildError,
    extensions::extension::{TlsExtension, TlsExtensions},
    hello::{ClientHello, ServerHello},
    types::{TlsCipherSuite, TlsCompressionMethod, TlsExtensionType, TlsProtocolVersion},
};

/// Builds one TLS extension TLV in caller-owned storage.
pub struct TlsExtensionBuilder<'a, 'b> {
    buffer: &'a mut [u8],
    extension_type: TlsExtensionType,
    data: &'b [u8],
}

impl<'a, 'b> TlsExtensionBuilder<'a, 'b> {
    /// Creates a builder that copies the supplied extension payload.
    pub fn new(buffer: &'a mut [u8], extension_type: TlsExtensionType, data: &'b [u8]) -> Self {
        Self {
            buffer,
            extension_type,
            data,
        }
    }

    /// Validates all inputs before writing the extension.
    pub fn build(self) -> Result<TlsExtension<'a>, TlsBuildError> {
        let data_length =
            u16::try_from(self.data.len()).map_err(|_| TlsBuildError::LengthTooLarge)?;
        let required = 4usize
            .checked_add(self.data.len())
            .ok_or(TlsBuildError::LengthTooLarge)?;
        ensure_capacity(self.buffer.len(), required)?;

        let bytes = &mut self.buffer[..required];
        bytes[..2].copy_from_slice(&self.extension_type.raw().to_be_bytes());
        bytes[2..4].copy_from_slice(&data_length.to_be_bytes());
        bytes[4..].copy_from_slice(self.data);

        Ok(TlsExtensions::new(bytes)
            .next()
            .expect("built extension is present")
            .expect("validated extension encoding"))
    }
}

/// Builds a ClientHello body in caller-owned storage.
pub struct ClientHelloBuilder<'a, 'b> {
    buffer: &'a mut [u8],
    legacy_version: TlsProtocolVersion,
    random: &'b [u8; 32],
    session_id: &'b [u8],
    cipher_suites: &'b [u8],
    compression_methods: &'b [u8],
    extensions: Option<&'b [u8]>,
}

impl<'a, 'b> ClientHelloBuilder<'a, 'b> {
    /// Creates a builder from ordered, already encoded variable-length fields.
    pub fn new(
        buffer: &'a mut [u8],
        legacy_version: TlsProtocolVersion,
        random: &'b [u8; 32],
        session_id: &'b [u8],
        cipher_suites: &'b [u8],
        compression_methods: &'b [u8],
        extensions: Option<&'b [u8]>,
    ) -> Self {
        Self {
            buffer,
            legacy_version,
            random,
            session_id,
            cipher_suites,
            compression_methods,
            extensions,
        }
    }

    /// Validates all fields and capacity before writing the ClientHello body.
    pub fn build(self) -> Result<ClientHello<'a>, TlsBuildError> {
        let session_length = validate_u8_vector(self.session_id, 0, 32)?;
        let cipher_length = validate_u16_vector(self.cipher_suites, 2, true)?;
        let compression_length = validate_u8_vector(self.compression_methods, 1, u8::MAX as usize)?;
        let extension_length = validate_extensions(self.extensions)?;

        let required = 34usize
            .checked_add(1 + self.session_id.len())
            .and_then(|value| value.checked_add(2 + self.cipher_suites.len()))
            .and_then(|value| value.checked_add(1 + self.compression_methods.len()))
            .and_then(|value| {
                value.checked_add(self.extensions.map_or(0, |extensions| 2 + extensions.len()))
            })
            .ok_or(TlsBuildError::LengthTooLarge)?;
        ensure_capacity(self.buffer.len(), required)?;

        let bytes = &mut self.buffer[..required];
        bytes[..2].copy_from_slice(&self.legacy_version.raw().to_be_bytes());
        bytes[2..34].copy_from_slice(self.random);
        let mut offset = 34;
        bytes[offset] = session_length;
        offset += 1;
        bytes[offset..offset + self.session_id.len()].copy_from_slice(self.session_id);
        offset += self.session_id.len();
        bytes[offset..offset + 2].copy_from_slice(&cipher_length.to_be_bytes());
        offset += 2;
        bytes[offset..offset + self.cipher_suites.len()].copy_from_slice(self.cipher_suites);
        offset += self.cipher_suites.len();
        bytes[offset] = compression_length;
        offset += 1;
        bytes[offset..offset + self.compression_methods.len()]
            .copy_from_slice(self.compression_methods);
        offset += self.compression_methods.len();
        if let (Some(extensions), Some(length)) = (self.extensions, extension_length) {
            bytes[offset..offset + 2].copy_from_slice(&length.to_be_bytes());
            offset += 2;
            bytes[offset..offset + extensions.len()].copy_from_slice(extensions);
        }

        Ok(ClientHello::parse(bytes).expect("validated ClientHello builder fields"))
    }
}

/// Builds a ServerHello body in caller-owned storage.
pub struct ServerHelloBuilder<'a, 'b> {
    buffer: &'a mut [u8],
    legacy_version: TlsProtocolVersion,
    random: &'b [u8; 32],
    session_id: &'b [u8],
    cipher_suite: TlsCipherSuite,
    compression_method: TlsCompressionMethod,
    extensions: Option<&'b [u8]>,
}

impl<'a, 'b> ServerHelloBuilder<'a, 'b> {
    /// Creates a builder from fixed fields and ordered encoded extension TLVs.
    pub fn new(
        buffer: &'a mut [u8],
        legacy_version: TlsProtocolVersion,
        random: &'b [u8; 32],
        session_id: &'b [u8],
        cipher_suite: TlsCipherSuite,
        compression_method: TlsCompressionMethod,
        extensions: Option<&'b [u8]>,
    ) -> Self {
        Self {
            buffer,
            legacy_version,
            random,
            session_id,
            cipher_suite,
            compression_method,
            extensions,
        }
    }

    /// Validates all fields and capacity before writing the ServerHello body.
    pub fn build(self) -> Result<ServerHello<'a>, TlsBuildError> {
        let session_length = validate_u8_vector(self.session_id, 0, 32)?;
        let extension_length = validate_extensions(self.extensions)?;
        let required = 38usize
            .checked_add(self.session_id.len())
            .and_then(|value| {
                value.checked_add(self.extensions.map_or(0, |extensions| 2 + extensions.len()))
            })
            .ok_or(TlsBuildError::LengthTooLarge)?;
        ensure_capacity(self.buffer.len(), required)?;

        let bytes = &mut self.buffer[..required];
        bytes[..2].copy_from_slice(&self.legacy_version.raw().to_be_bytes());
        bytes[2..34].copy_from_slice(self.random);
        let mut offset = 34;
        bytes[offset] = session_length;
        offset += 1;
        bytes[offset..offset + self.session_id.len()].copy_from_slice(self.session_id);
        offset += self.session_id.len();
        bytes[offset..offset + 2].copy_from_slice(&self.cipher_suite.raw().to_be_bytes());
        offset += 2;
        bytes[offset] = self.compression_method.raw();
        offset += 1;
        if let (Some(extensions), Some(length)) = (self.extensions, extension_length) {
            bytes[offset..offset + 2].copy_from_slice(&length.to_be_bytes());
            offset += 2;
            bytes[offset..offset + extensions.len()].copy_from_slice(extensions);
        }

        Ok(ServerHello::parse(bytes).expect("validated ServerHello builder fields"))
    }
}

fn validate_u8_vector(bytes: &[u8], minimum: usize, maximum: usize) -> Result<u8, TlsBuildError> {
    if bytes.len() > u8::MAX as usize {
        return Err(TlsBuildError::LengthTooLarge);
    }
    if bytes.len() < minimum || bytes.len() > maximum {
        return Err(TlsBuildError::InvalidValue);
    }
    Ok(bytes.len() as u8)
}

fn validate_u16_vector(bytes: &[u8], minimum: usize, even: bool) -> Result<u16, TlsBuildError> {
    if bytes.len() < minimum || (even && !bytes.len().is_multiple_of(2)) {
        return Err(TlsBuildError::InvalidValue);
    }
    u16::try_from(bytes.len()).map_err(|_| TlsBuildError::LengthTooLarge)
}

fn validate_extensions(extensions: Option<&[u8]>) -> Result<Option<u16>, TlsBuildError> {
    let Some(extensions) = extensions else {
        return Ok(None);
    };
    let length = u16::try_from(extensions.len()).map_err(|_| TlsBuildError::LengthTooLarge)?;
    for extension in TlsExtensions::new(extensions) {
        extension.map_err(|_| TlsBuildError::InvalidValue)?;
    }
    Ok(Some(length))
}

fn ensure_capacity(available: usize, required: usize) -> Result<(), TlsBuildError> {
    if available < required {
        Err(TlsBuildError::BufferTooShort {
            required,
            available,
        })
    } else {
        Ok(())
    }
}
