use super::layout::v16;
use crate::tls::error::TlsParseError;

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
    pub(super) fn parse(b: &'a [u8]) -> Result<Self, TlsParseError> {
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
            self.bytes = &[];
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
    pub(super) fn parse(b: &'a [u8]) -> Result<Self, TlsParseError> {
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
