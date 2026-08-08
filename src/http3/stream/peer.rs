//! Bounded lifecycle state for incoming HTTP/3 peer unidirectional streams.

use core::fmt;

use crate::quic::varint::QuicVarIntLen;

use super::super::codepoints::{Http3ErrorCode, Http3StreamType};
use super::super::enums::stream::{Http3EndpointRole, Http3UniStreamKind};
use super::super::ids::{Http3PushId, Http3StreamId};
use super::uni::Http3UniStreamHeader;

/// A peer unidirectional stream kind that HTTP/3 requires exactly once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3CriticalUniStreamKind {
    /// The HTTP/3 control stream.
    Control,
    /// The peer's QPACK encoder stream.
    QpackEncoder,
    /// The peer's QPACK decoder stream.
    QpackDecoder,
}

/// The outcome of accepting an incoming peer unidirectional stream header.
///
/// Critical events hand the stream remainder to its existing owner. Push events hand the Push ID
/// to future push-lifecycle state; unknown events preserve the extension stream type for caller
/// policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3PeerUniStreamEvent {
    /// The peer's unique HTTP/3 control stream.
    Control {
        /// QUIC stream identifier.
        stream_id: Http3StreamId,
    },
    /// A server push stream received by a client.
    Push {
        /// QUIC stream identifier.
        stream_id: Http3StreamId,
        /// Push ID carried by the stream header.
        push_id: Http3PushId,
    },
    /// The peer's unique QPACK encoder stream.
    QpackEncoder {
        /// QUIC stream identifier.
        stream_id: Http3StreamId,
    },
    /// The peer's unique QPACK decoder stream.
    QpackDecoder {
        /// QUIC stream identifier.
        stream_id: Http3StreamId,
    },
    /// An extension, unknown, or GREASE stream that remains caller-owned.
    Unknown {
        /// QUIC stream identifier.
        stream_id: Http3StreamId,
        /// Raw HTTP/3 unidirectional stream type.
        stream_type: Http3StreamType,
    },
}

/// Failure while registering or closing a peer HTTP/3 unidirectional stream.
///
/// [`Self::InvalidPeerUnidirectionalStream`] is a local integration error. The remaining
/// variants are peer-caused HTTP/3 connection errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3PeerUniStreamError {
    /// The supplied stream ID is not a valid peer-initiated unidirectional QUIC stream ID.
    InvalidPeerUnidirectionalStream {
        /// Invalid raw QUIC stream identifier.
        stream_id: Http3StreamId,
    },
    /// The peer opened a second stream for a required unique critical-stream kind.
    DuplicateCriticalStream {
        /// Duplicated critical-stream kind.
        kind: Http3CriticalUniStreamKind,
        /// Previously registered peer stream identifier.
        existing: Http3StreamId,
        /// Newly received duplicate peer stream identifier.
        received: Http3StreamId,
    },
    /// A client opened a server-only push stream.
    ClientInitiatedPushStream {
        /// Client-initiated QUIC stream identifier.
        stream_id: Http3StreamId,
        /// Push ID carried by the invalid stream header.
        push_id: Http3PushId,
    },
    /// A peer closed or reset a registered critical stream.
    ClosedCriticalStream {
        /// Closed critical-stream kind.
        kind: Http3CriticalUniStreamKind,
        /// Closed peer stream identifier.
        stream_id: Http3StreamId,
    },
}

impl Http3PeerUniStreamError {
    /// Returns the HTTP/3 application error code for a peer-caused failure.
    pub const fn error_code(self) -> Option<Http3ErrorCode> {
        match self {
            Self::InvalidPeerUnidirectionalStream { .. } => None,
            Self::DuplicateCriticalStream { .. } | Self::ClientInitiatedPushStream { .. } => {
                Some(Http3ErrorCode::STREAM_CREATION_ERROR)
            }
            Self::ClosedCriticalStream { .. } => Some(Http3ErrorCode::CLOSED_CRITICAL_STREAM),
        }
    }
}

impl fmt::Display for Http3PeerUniStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPeerUnidirectionalStream { stream_id } => write!(
                f,
                "stream ID {} is not a peer-initiated unidirectional QUIC stream",
                stream_id.value()
            ),
            Self::DuplicateCriticalStream {
                kind,
                existing,
                received,
            } => write!(
                f,
                "HTTP/3 {kind:?} critical stream {} duplicates stream {}",
                received.value(),
                existing.value()
            ),
            Self::ClientInitiatedPushStream { stream_id, push_id } => write!(
                f,
                "client-initiated HTTP/3 push stream {} carries Push ID {}",
                stream_id.value(),
                push_id.value()
            ),
            Self::ClosedCriticalStream { kind, stream_id } => write!(
                f,
                "HTTP/3 {kind:?} critical stream {} was closed",
                stream_id.value()
            ),
        }
    }
}

impl core::error::Error for Http3PeerUniStreamError {}

/// Bounded state for incoming peer HTTP/3 unidirectional critical streams.
///
/// It records only the three unique critical stream IDs. Header parsing, stream I/O and
/// reassembly, critical-stream frame sequencing, QPACK application, push lifecycle, locally
/// opened streams, and extension policy remain owned by their respective callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3PeerUniStreamState {
    local_role: Http3EndpointRole,
    control: Option<Http3StreamId>,
    qpack_encoder: Option<Http3StreamId>,
    qpack_decoder: Option<Http3StreamId>,
}

impl Http3PeerUniStreamState {
    /// Creates empty incoming peer unidirectional-stream state for an endpoint role.
    pub const fn new(local_role: Http3EndpointRole) -> Self {
        Self {
            local_role,
            control: None,
            qpack_encoder: None,
            qpack_decoder: None,
        }
    }

    /// Returns the local endpoint role used to validate peer stream identifiers.
    pub const fn role(self) -> Http3EndpointRole {
        self.local_role
    }

    /// Returns the registered peer control stream identifier.
    pub const fn control_stream_id(self) -> Option<Http3StreamId> {
        self.control
    }

    /// Returns the registered peer QPACK encoder stream identifier.
    pub const fn qpack_encoder_stream_id(self) -> Option<Http3StreamId> {
        self.qpack_encoder
    }

    /// Returns the registered peer QPACK decoder stream identifier.
    pub const fn qpack_decoder_stream_id(self) -> Option<Http3StreamId> {
        self.qpack_decoder
    }

    /// Receives a parsed HTTP/3 unidirectional stream header from a peer stream.
    ///
    /// Errors leave state unchanged. A successful critical event registers exactly its matching
    /// critical stream; push and unknown streams are deliberately not retained.
    pub fn receive_header(
        &mut self,
        stream_id: Http3StreamId,
        header: Http3UniStreamHeader<'_>,
    ) -> Result<Http3PeerUniStreamEvent, Http3PeerUniStreamError> {
        self.validate_peer_unidirectional_stream_id(stream_id)?;

        match header.kind() {
            Http3UniStreamKind::Control => {
                self.receive_critical(stream_id, Http3CriticalUniStreamKind::Control)
            }
            Http3UniStreamKind::QpackEncoder => {
                self.receive_critical(stream_id, Http3CriticalUniStreamKind::QpackEncoder)
            }
            Http3UniStreamKind::QpackDecoder => {
                self.receive_critical(stream_id, Http3CriticalUniStreamKind::QpackDecoder)
            }
            Http3UniStreamKind::Push(push_id) => {
                if self.local_role == Http3EndpointRole::Server {
                    return Err(Http3PeerUniStreamError::ClientInitiatedPushStream {
                        stream_id,
                        push_id,
                    });
                }
                Ok(Http3PeerUniStreamEvent::Push { stream_id, push_id })
            }
            Http3UniStreamKind::Unknown(stream_type) => Ok(Http3PeerUniStreamEvent::Unknown {
                stream_id,
                stream_type,
            }),
        }
    }

    /// Reports a close or reset of a retained peer critical stream.
    ///
    /// Closing a critical stream is terminal for the connection, so this method intentionally
    /// takes `self` and does not perform a recoverable state transition. Closing an unregistered,
    /// push, or extension stream is ignored, including a close received before its header.
    pub fn receive_closed(self, stream_id: Http3StreamId) -> Result<(), Http3PeerUniStreamError> {
        if self.control == Some(stream_id) {
            return Err(Http3PeerUniStreamError::ClosedCriticalStream {
                kind: Http3CriticalUniStreamKind::Control,
                stream_id,
            });
        }
        if self.qpack_encoder == Some(stream_id) {
            return Err(Http3PeerUniStreamError::ClosedCriticalStream {
                kind: Http3CriticalUniStreamKind::QpackEncoder,
                stream_id,
            });
        }
        if self.qpack_decoder == Some(stream_id) {
            return Err(Http3PeerUniStreamError::ClosedCriticalStream {
                kind: Http3CriticalUniStreamKind::QpackDecoder,
                stream_id,
            });
        }
        Ok(())
    }

    fn validate_peer_unidirectional_stream_id(
        self,
        stream_id: Http3StreamId,
    ) -> Result<(), Http3PeerUniStreamError> {
        let value = stream_id.value();
        let expected_low_bits = match self.local_role {
            Http3EndpointRole::Client => 0x03,
            Http3EndpointRole::Server => 0x02,
        };
        if value > QuicVarIntLen::Eight.max_value() || value & 0x03 != expected_low_bits {
            return Err(Http3PeerUniStreamError::InvalidPeerUnidirectionalStream { stream_id });
        }
        Ok(())
    }

    fn receive_critical(
        &mut self,
        stream_id: Http3StreamId,
        kind: Http3CriticalUniStreamKind,
    ) -> Result<Http3PeerUniStreamEvent, Http3PeerUniStreamError> {
        let existing = match kind {
            Http3CriticalUniStreamKind::Control => self.control,
            Http3CriticalUniStreamKind::QpackEncoder => self.qpack_encoder,
            Http3CriticalUniStreamKind::QpackDecoder => self.qpack_decoder,
        };
        if let Some(existing) = existing {
            return Err(Http3PeerUniStreamError::DuplicateCriticalStream {
                kind,
                existing,
                received: stream_id,
            });
        }

        match kind {
            Http3CriticalUniStreamKind::Control => {
                self.control = Some(stream_id);
                Ok(Http3PeerUniStreamEvent::Control { stream_id })
            }
            Http3CriticalUniStreamKind::QpackEncoder => {
                self.qpack_encoder = Some(stream_id);
                Ok(Http3PeerUniStreamEvent::QpackEncoder { stream_id })
            }
            Http3CriticalUniStreamKind::QpackDecoder => {
                self.qpack_decoder = Some(stream_id);
                Ok(Http3PeerUniStreamEvent::QpackDecoder { stream_id })
            }
        }
    }
}
