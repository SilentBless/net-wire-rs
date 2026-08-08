//! IPv6 extension traversal and upper-layer dispatch errors.

use core::fmt;

use crate::error::ParseError;

/// Failure while traversing IPv6 extension headers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv6ExtensionTraversalError {
    /// A shared structural parse failure occurred during traversal.
    Parse(ParseError),
    /// An extension header encodes a length below that header's format minimum.
    InvalidExtensionHeaderLength {
        /// Next Header value identifying the invalid extension header.
        next_header: u8,
        /// Minimum valid extension-header length.
        minimum: usize,
        /// Encoded extension-header length.
        actual: usize,
    },
    /// A nonempty IPv6 tail cannot be resolved when the base Payload Length is zero.
    UnresolvedPayloadLength,
}

impl fmt::Display for Ipv6ExtensionTraversalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => write!(formatter, "IPv6 extension traversal failed: {error}"),
            Self::InvalidExtensionHeaderLength {
                next_header,
                minimum,
                actual,
            } => write!(
                formatter,
                "invalid IPv6 extension header length for next header {next_header}: minimum {minimum}, got {actual}"
            ),
            Self::UnresolvedPayloadLength => {
                formatter.write_str("IPv6 payload length is unresolved")
            }
        }
    }
}

/// Failure while dispatching an IPv6 payload to a concrete upper-layer parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv6DispatchError {
    /// IPv6 extension-header traversal failed.
    Traversal(Ipv6ExtensionTraversalError),
    /// The selected upper-layer parser failed.
    UpperLayer(ParseError),
}

impl fmt::Display for Ipv6DispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Traversal(error) => write!(formatter, "IPv6 dispatch traversal failed: {error}"),
            Self::UpperLayer(error) => {
                write!(formatter, "IPv6 upper-layer parsing failed: {error}")
            }
        }
    }
}
