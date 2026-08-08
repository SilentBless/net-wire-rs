use super::layout::{len, take_v16, v8};
use crate::tls::{error::TlsParseError, types::TlsPskKeyExchangeMode};

/// Ordered PSK key-exchange modes from a ClientHello.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PskKeyExchangeModes<'a> {
    bytes: &'a [u8],
}
impl<'a> PskKeyExchangeModes<'a> {
    pub(super) fn parse(b: &'a [u8]) -> Result<Self, TlsParseError> {
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
    pub(super) fn parse(b: &'a [u8]) -> Result<Self, TlsParseError> {
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
    pub(super) fn parse(b: &[u8]) -> Result<Self, TlsParseError> {
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
