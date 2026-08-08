//! Shared HTTP/3 stream vocabulary.

use super::super::codepoints::Http3StreamType;
use super::super::ids::Http3PushId;

/// The local endpoint role used to interpret control-stream frame semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3EndpointRole {
    /// The local endpoint is an HTTP/3 client.
    Client,
    /// The local endpoint is an HTTP/3 server.
    Server,
}

/// Classifies an HTTP/3 unidirectional stream header without discarding extension types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3UniStreamKind {
    /// The HTTP/3 control stream.
    Control,
    /// A server push stream and its Push ID.
    Push(Http3PushId),
    /// The QPACK encoder stream.
    QpackEncoder,
    /// The QPACK decoder stream.
    QpackDecoder,
    /// An extension, unknown, or grease stream type.
    Unknown(Http3StreamType),
}
