use super::layout::{len, v16};
use crate::tls::{error::TlsParseError, types::TlsNamedGroup};

/// Ordered ClientHello key-share entries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientKeyShare<'a> {
    bytes: &'a [u8],
}
impl<'a> ClientKeyShare<'a> {
    pub(super) fn parse(b: &'a [u8]) -> Result<Self, TlsParseError> {
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
    pub(super) fn parse(b: &'a [u8]) -> Result<Self, TlsParseError> {
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
    pub(super) fn parse(b: &[u8]) -> Result<Self, TlsParseError> {
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
