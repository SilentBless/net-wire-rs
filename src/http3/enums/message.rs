//! Shared HTTP/3 message vocabulary.

/// The intended HTTP/3 role of a decoded HEADERS field section.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3HeadersContext {
    /// A request field section, with the negotiated Extended CONNECT capability.
    Request {
        /// Whether the peer enabled Extended CONNECT.
        extended_connect_enabled: bool,
    },
    /// A response field section.
    Response,
    /// A trailer field section.
    Trailers,
}

/// The semantic role assigned to a QPACK-decoded HTTP/3 header section.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3HeadersKind {
    /// The initial header section of a request.
    Request,
    /// A non-final response header section.
    InformationalResponse,
    /// The final response header section.
    FinalResponse,
    /// A trailing header section following message content.
    Trailers,
}
