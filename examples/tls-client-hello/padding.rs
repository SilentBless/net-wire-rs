use net_wire::tls::{TlsExtensionType, TlsParseError};

pub const PADDING_EXTENSION_TYPE: TlsExtensionType = TlsExtensionType::new(21);

/// Borrowed RFC 7685 padding whose payload contains only zero bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PaddingExtension<'a>(&'a [u8]);

impl<'a> PaddingExtension<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, TlsParseError> {
        if bytes.iter().any(|byte| *byte != 0) {
            return Err(TlsParseError::InvalidValue);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(self) -> &'a [u8] {
        self.0
    }
}
