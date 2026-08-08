use super::layout::v16;
use crate::tls::{error::TlsParseError, types::TlsServerNameType};

/// An ordered ClientHello server-name list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientServerNameList<'a> {
    bytes: &'a [u8],
}
impl<'a> ClientServerNameList<'a> {
    pub(super) fn parse(b: &'a [u8]) -> Result<Self, TlsParseError> {
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
