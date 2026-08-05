//! TLS record views and caller-buffer construction.
use super::{TlsBuildError, TlsContentType, TlsParseError, TlsProtocolVersion};
/// A single structurally bounded TLS record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsRecord<'a> {
    bytes: &'a [u8],
}
impl<'a> TlsRecord<'a> {
    /// Parses the first complete record and excludes any coalesced suffix.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, TlsParseError> {
        let length = declared(bytes, 5)?;
        Ok(Self {
            bytes: &bytes[..length],
        })
    }
    /// Returns the content type.
    pub fn content_type(&self) -> TlsContentType {
        TlsContentType::new(self.bytes[0])
    }
    /// Returns the legacy record version.
    pub fn version(&self) -> TlsProtocolVersion {
        TlsProtocolVersion::new(u16::from_be_bytes([self.bytes[1], self.bytes[2]]))
    }
    /// Returns the fragment.
    pub fn fragment(&self) -> &'a [u8] {
        &self.bytes[5..]
    }
    /// Returns the represented record bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}
/// A mutable structurally bounded TLS record.
#[derive(Debug, Eq, PartialEq)]
pub struct TlsRecordMut<'a> {
    bytes: &'a mut [u8],
}
impl<'a> TlsRecordMut<'a> {
    /// Parses the first complete record and excludes any coalesced suffix.
    pub fn parse(bytes: &'a mut [u8]) -> Result<Self, TlsParseError> {
        let length = declared(bytes, 5)?;
        Ok(Self {
            bytes: &mut bytes[..length],
        })
    }
    pub(crate) fn from_validated(bytes: &'a mut [u8]) -> Self {
        Self { bytes }
    }
    /// Returns the content type.
    pub fn content_type(&self) -> TlsContentType {
        TlsContentType::new(self.bytes[0])
    }
    /// Replaces the content type.
    pub fn set_content_type(&mut self, value: TlsContentType) {
        self.bytes[0] = value.raw();
    }
    /// Returns the legacy record version.
    pub fn version(&self) -> TlsProtocolVersion {
        TlsProtocolVersion::new(u16::from_be_bytes([self.bytes[1], self.bytes[2]]))
    }
    /// Replaces the legacy record version.
    pub fn set_version(&mut self, value: TlsProtocolVersion) {
        self.bytes[1..3].copy_from_slice(&value.raw().to_be_bytes());
    }
    /// Returns the fragment.
    pub fn fragment(&self) -> &[u8] {
        &self.bytes[5..]
    }
    /// Returns the fragment mutably without changing its encoded length.
    pub fn fragment_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[5..]
    }
    /// Returns represented record bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }
}
/// Builds a TLS record in caller-owned storage.
pub struct TlsRecordBuilder<'a, 'b> {
    buffer: &'a mut [u8],
    content_type: TlsContentType,
    version: TlsProtocolVersion,
    fragment: &'b [u8],
}
impl<'a, 'b> TlsRecordBuilder<'a, 'b> {
    /// Starts a record builder with a copied fragment input.
    pub fn new(
        buffer: &'a mut [u8],
        content_type: TlsContentType,
        version: TlsProtocolVersion,
        fragment: &'b [u8],
    ) -> Self {
        Self {
            buffer,
            content_type,
            version,
            fragment,
        }
    }
    /// Validates all inputs before writing the record.
    pub fn build(self) -> Result<TlsRecordMut<'a>, TlsBuildError> {
        if self.fragment.len() > u16::MAX as usize {
            return Err(TlsBuildError::LengthTooLarge);
        }
        let length = 5usize
            .checked_add(self.fragment.len())
            .ok_or(TlsBuildError::LengthTooLarge)?;
        if self.buffer.len() < length {
            return Err(TlsBuildError::BufferTooShort {
                required: length,
                available: self.buffer.len(),
            });
        }
        let bytes = &mut self.buffer[..length];
        bytes[0] = self.content_type.raw();
        bytes[1..3].copy_from_slice(&self.version.raw().to_be_bytes());
        bytes[3..5].copy_from_slice(&(self.fragment.len() as u16).to_be_bytes());
        bytes[5..].copy_from_slice(self.fragment);
        Ok(TlsRecordMut::from_validated(bytes))
    }
}
fn declared(bytes: &[u8], header: usize) -> Result<usize, TlsParseError> {
    if bytes.len() < header {
        return Err(TlsParseError::Incomplete {
            required: header,
            available: bytes.len(),
        });
    }
    let length = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
    let total = header + length;
    if bytes.len() < total {
        return Err(TlsParseError::Incomplete {
            required: total,
            available: bytes.len(),
        });
    }
    Ok(total)
}
