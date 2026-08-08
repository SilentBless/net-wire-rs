use super::layout::{v8, v16};
use crate::tls::{
    error::TlsParseError,
    types::{TlsCertificateCompressionAlgorithm, TlsNamedGroup, TlsSignatureScheme},
};

macro_rules! list {
    ($n:ident,$t:ty) => {
        #[doc = concat!("An ordered TLS ", stringify!($n), " vector.")]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $n<'a> {
            bytes: &'a [u8],
        }
        impl<'a> $n<'a> {
            pub(super) fn parse(b: &'a [u8]) -> Result<Self, TlsParseError> {
                Ok(Self {
                    bytes: v16(b, 2, true)?,
                })
            }
            /// Returns values in their original wire order.
            pub fn iter(&self) -> impl Iterator<Item = $t> + 'a {
                self.bytes
                    .chunks_exact(2)
                    .map(|x| <$t>::new(u16::from_be_bytes([x[0], x[1]])))
            }
        }
    };
}
list!(SupportedGroups, TlsNamedGroup);
list!(SignatureAlgorithms, TlsSignatureScheme);
/// Ordered certificate-compression algorithm identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificateCompressionAlgorithms<'a> {
    bytes: &'a [u8],
}
impl<'a> CertificateCompressionAlgorithms<'a> {
    pub(super) fn parse(b: &'a [u8]) -> Result<Self, TlsParseError> {
        let bytes = v8(b, 2)?;
        if !bytes.len().is_multiple_of(2) {
            return Err(TlsParseError::InvalidValue);
        }
        Ok(Self { bytes })
    }
    /// Returns algorithms in their original wire order.
    pub fn iter(&self) -> impl Iterator<Item = TlsCertificateCompressionAlgorithm> + 'a {
        self.bytes.chunks_exact(2).map(|bytes| {
            TlsCertificateCompressionAlgorithm::new(u16::from_be_bytes([bytes[0], bytes[1]]))
        })
    }
}
/// Ordered legacy EC point-format identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EcPointFormats<'a> {
    bytes: &'a [u8],
}
impl<'a> EcPointFormats<'a> {
    pub(super) fn parse(b: &'a [u8]) -> Result<Self, TlsParseError> {
        Ok(Self { bytes: v8(b, 1)? })
    }
    /// Returns raw point-format values in wire order.
    pub fn iter(&self) -> impl Iterator<Item = u8> + 'a {
        self.bytes.iter().copied()
    }
}
