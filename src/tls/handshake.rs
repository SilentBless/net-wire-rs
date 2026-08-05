//! TLS handshake framing views.
use super::{ClientHello, ServerHello, TlsBuildError, TlsHandshakeType, TlsParseError};
/// A single structurally bounded TLS handshake message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsHandshake<'a> {
    bytes: &'a [u8],
}
impl<'a> TlsHandshake<'a> {
    /// Parses the first complete handshake and excludes any suffix.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, TlsParseError> {
        let total = declared(bytes)?;
        Ok(Self {
            bytes: &bytes[..total],
        })
    }
    /// Returns the handshake type.
    pub fn handshake_type(&self) -> TlsHandshakeType {
        TlsHandshakeType::new(self.bytes[0])
    }
    /// Returns the handshake body.
    pub fn body(&self) -> &'a [u8] {
        &self.bytes[4..]
    }
    /// Returns the represented handshake bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
    /// Parses a ClientHello when this message has that type.
    pub fn client_hello(&self) -> Result<Option<ClientHello<'a>>, TlsParseError> {
        if self.handshake_type() == TlsHandshakeType::CLIENT_HELLO {
            ClientHello::parse(self.body()).map(Some)
        } else {
            Ok(None)
        }
    }
    /// Parses a ServerHello when this message has that type.
    pub fn server_hello(&self) -> Result<Option<ServerHello<'a>>, TlsParseError> {
        if self.handshake_type() == TlsHandshakeType::SERVER_HELLO {
            ServerHello::parse(self.body()).map(Some)
        } else {
            Ok(None)
        }
    }
}
/// Builds a TLS handshake frame in caller-owned storage.
pub struct TlsHandshakeBuilder<'a, 'b> {
    buffer: &'a mut [u8],
    handshake_type: TlsHandshakeType,
    body: &'b [u8],
}
impl<'a, 'b> TlsHandshakeBuilder<'a, 'b> {
    /// Starts a handshake builder with a copied body input.
    pub fn new(buffer: &'a mut [u8], handshake_type: TlsHandshakeType, body: &'b [u8]) -> Self {
        Self {
            buffer,
            handshake_type,
            body,
        }
    }
    /// Validates all inputs before writing the handshake.
    pub fn build(self) -> Result<&'a mut [u8], TlsBuildError> {
        if self.body.len() > 0x00ff_ffff {
            return Err(TlsBuildError::LengthTooLarge);
        }
        let total = 4usize
            .checked_add(self.body.len())
            .ok_or(TlsBuildError::LengthTooLarge)?;
        if self.buffer.len() < total {
            return Err(TlsBuildError::BufferTooShort {
                required: total,
                available: self.buffer.len(),
            });
        }
        let bytes = &mut self.buffer[..total];
        bytes[0] = self.handshake_type.raw();
        let len = self.body.len() as u32;
        bytes[1] = (len >> 16) as u8;
        bytes[2] = (len >> 8) as u8;
        bytes[3] = len as u8;
        bytes[4..].copy_from_slice(self.body);
        Ok(bytes)
    }
}
fn declared(bytes: &[u8]) -> Result<usize, TlsParseError> {
    if bytes.len() < 4 {
        return Err(TlsParseError::Incomplete {
            required: 4,
            available: bytes.len(),
        });
    }
    let body = (usize::from(bytes[1]) << 16) | (usize::from(bytes[2]) << 8) | usize::from(bytes[3]);
    let total = 4 + body;
    if bytes.len() < total {
        return Err(TlsParseError::Incomplete {
            required: total,
            available: bytes.len(),
        });
    }
    Ok(total)
}
