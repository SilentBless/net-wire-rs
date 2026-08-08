//! Incoming HTTP/3 request, response, and push-message frame sequencing.

use core::fmt;

use super::super::codepoints::{Http3ErrorCode, Http3FrameType};
use super::super::enums::message::Http3HeadersKind;
use super::super::frame::Http3Frame;
use super::super::frame::Http3FramePayloadParseError;
use super::super::frame::{Http3Data, Http3Headers, Http3PushPromise};
use super::super::headers::Http3DecodedHeaderSection;

/// The direction and message role of an incoming HTTP/3 stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3MessageStreamKind {
    /// An inbound client request on a server's request stream.
    Request,
    /// An inbound server response on a client's request stream.
    Response,
    /// An inbound server response on a client's push stream.
    Push,
}

/// The current position in an incoming HTTP/3 message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3MessagePosition {
    /// A request has not yet received its initial header section.
    BeforeHeaders,
    /// A response has not yet received its final response header section.
    BeforeFinalResponse,
    /// The initial or final header section was accepted and content may follow.
    Content,
    /// A trailing header section was accepted.
    Trailers,
}

/// Failure to sequence a received frame on an HTTP/3 message stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3MessageStreamError {
    /// A frame is forbidden in the current message position or stream kind.
    UnexpectedFrame {
        /// Forbidden frame type.
        frame_type: Http3FrameType,
        /// Message position at which the frame was received.
        position: Http3MessagePosition,
    },
    /// An allowed known frame has a malformed intrinsic payload.
    FramePayload {
        /// Type of the frame with the malformed payload.
        frame_type: Http3FrameType,
        /// Intrinsic payload parsing failure.
        error: Http3FramePayloadParseError,
    },
    /// A QPACK-decoded header section is invalid for the current message position.
    InvalidHeaderSection {
        /// Incoming message stream kind.
        stream_kind: Http3MessageStreamKind,
        /// Message position at which HEADERS was received.
        position: Http3MessagePosition,
        /// Validated QPACK-decoded header-section role.
        section_kind: Http3HeadersKind,
    },
    /// The stream ended before its initial or final response header section was accepted.
    IncompleteMessage {
        /// Incoming message stream kind.
        stream_kind: Http3MessageStreamKind,
        /// Message position at stream end.
        position: Http3MessagePosition,
    },
}

impl Http3MessageStreamError {
    /// Returns the HTTP/3 application error code required by this failure.
    pub const fn error_code(self) -> Http3ErrorCode {
        match self {
            Self::UnexpectedFrame { .. } => Http3ErrorCode::FRAME_UNEXPECTED,
            Self::FramePayload { .. } => Http3ErrorCode::FRAME_ERROR,
            Self::InvalidHeaderSection { .. } => Http3ErrorCode::MESSAGE_ERROR,
            Self::IncompleteMessage {
                stream_kind: Http3MessageStreamKind::Request,
                ..
            } => Http3ErrorCode::REQUEST_INCOMPLETE,
            Self::IncompleteMessage {
                stream_kind: Http3MessageStreamKind::Response | Http3MessageStreamKind::Push,
                ..
            } => Http3ErrorCode::MESSAGE_ERROR,
        }
    }
}

impl fmt::Display for Http3MessageStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedFrame {
                frame_type,
                position,
            } => write!(
                f,
                "HTTP/3 frame type {} is unexpected at message position {position:?}",
                frame_type.value()
            ),
            Self::FramePayload { frame_type, error } => write!(
                f,
                "HTTP/3 message frame type {} payload: {error}",
                frame_type.value()
            ),
            Self::InvalidHeaderSection {
                stream_kind,
                position,
                section_kind,
            } => write!(
                f,
                "HTTP/3 {section_kind:?} header section is invalid for {stream_kind:?} at message position {position:?}"
            ),
            Self::IncompleteMessage {
                stream_kind,
                position,
            } => write!(
                f,
                "HTTP/3 {stream_kind:?} message is incomplete at message position {position:?}"
            ),
        }
    }
}

impl core::error::Error for Http3MessageStreamError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::FramePayload { error, .. } => Some(error),
            Self::UnexpectedFrame { .. }
            | Self::InvalidHeaderSection { .. }
            | Self::IncompleteMessage { .. } => None,
        }
    }
}

/// Bounded state for receiving one incoming HTTP/3 request, response, or push message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3MessageStreamState {
    kind: Http3MessageStreamKind,
    position: Http3MessagePosition,
}

impl Http3MessageStreamState {
    /// Creates state for an incoming stream of the supplied message kind.
    pub const fn new(kind: Http3MessageStreamKind) -> Self {
        let position = match kind {
            Http3MessageStreamKind::Request => Http3MessagePosition::BeforeHeaders,
            Http3MessageStreamKind::Response | Http3MessageStreamKind::Push => {
                Http3MessagePosition::BeforeFinalResponse
            }
        };
        Self { kind, position }
    }

    /// Returns this stream's incoming message kind.
    pub const fn kind(self) -> Http3MessageStreamKind {
        self.kind
    }

    /// Returns the current message position.
    pub const fn position(self) -> Http3MessagePosition {
        self.position
    }

    /// Receives a structurally bounded frame from this message stream.
    ///
    /// A HEADERS event retains the mutable state borrow until its QPACK-decoded semantic role is
    /// accepted. On every error, state is unchanged.
    pub fn receive<'state, 'wire>(
        &'state mut self,
        frame: Http3Frame<'wire>,
    ) -> Result<Http3MessageFrame<'state, 'wire>, Http3MessageStreamError> {
        let frame_type = frame.frame_type();
        let position = self.position;

        match frame_type {
            Http3FrameType::HEADERS => {
                if position == Http3MessagePosition::Trailers {
                    return Err(unexpected_frame(frame_type, position));
                }
                let headers = Http3Headers::from_frame(frame)
                    .map_err(|error| frame_payload_error(frame_type, error))?;
                Ok(Http3MessageFrame::Headers(Http3PendingHeaders {
                    state: self,
                    headers,
                }))
            }
            Http3FrameType::DATA => {
                if position != Http3MessagePosition::Content {
                    return Err(unexpected_frame(frame_type, position));
                }
                Http3Data::from_frame(frame)
                    .map(Http3MessageFrame::Data)
                    .map_err(|error| frame_payload_error(frame_type, error))
            }
            Http3FrameType::PUSH_PROMISE => {
                if self.kind != Http3MessageStreamKind::Response {
                    return Err(unexpected_frame(frame_type, position));
                }
                Http3PushPromise::from_frame(frame)
                    .map(Http3MessageFrame::PushPromise)
                    .map_err(|error| frame_payload_error(frame_type, error))
            }
            Http3FrameType::CANCEL_PUSH
            | Http3FrameType::SETTINGS
            | Http3FrameType::GOAWAY
            | Http3FrameType::MAX_PUSH_ID => Err(unexpected_frame(frame_type, position)),
            frame_type if is_http2_reserved_frame_type(frame_type) => {
                Err(unexpected_frame(frame_type, position))
            }
            _ => Ok(Http3MessageFrame::Unknown(frame)),
        }
    }

    /// Validates that this message ended after its complete header and optional content sequence.
    pub const fn finish(&self) -> Result<(), Http3MessageStreamError> {
        match self.position {
            Http3MessagePosition::Content | Http3MessagePosition::Trailers => Ok(()),
            Http3MessagePosition::BeforeHeaders | Http3MessagePosition::BeforeFinalResponse => {
                Err(Http3MessageStreamError::IncompleteMessage {
                    stream_kind: self.kind,
                    position: self.position,
                })
            }
        }
    }
}

/// An accepted incoming HTTP/3 message frame.
#[derive(Debug)]
pub enum Http3MessageFrame<'state, 'wire> {
    /// An opaque DATA payload following the initial or final header section.
    Data(Http3Data<'wire>),
    /// A HEADERS frame awaiting QPACK-driven semantic classification.
    Headers(Http3PendingHeaders<'state, 'wire>),
    /// A PUSH_PROMISE on an incoming response request stream.
    PushPromise(Http3PushPromise<'wire>),
    /// An unknown extension or GREASE frame preserved exactly.
    Unknown(Http3Frame<'wire>),
}

/// A HEADERS frame whose QPACK-decoded semantic role must be accepted before state advances.
#[derive(Debug)]
pub struct Http3PendingHeaders<'state, 'wire> {
    state: &'state mut Http3MessageStreamState,
    headers: Http3Headers<'wire>,
}

impl<'state, 'wire> Http3PendingHeaders<'state, 'wire> {
    /// Returns the typed, raw-preserving HEADERS frame for QPACK decoding.
    pub const fn headers(&self) -> Http3Headers<'wire> {
        self.headers
    }

    /// Accepts a validated QPACK-decoded header section and commits the corresponding transition.
    ///
    /// The section is consumed semantically but remains caller-owned for message-content handling.
    /// Invalid classifications leave the stream state unchanged.
    pub fn accept(
        self,
        section: &Http3DecodedHeaderSection<'_>,
    ) -> Result<Http3Headers<'wire>, Http3MessageStreamError> {
        let section_kind = section.kind();
        let next_position = next_position(self.state.kind, self.state.position, section_kind)?;
        self.state.position = next_position;
        Ok(self.headers)
    }
}

const fn next_position(
    stream_kind: Http3MessageStreamKind,
    position: Http3MessagePosition,
    section_kind: Http3HeadersKind,
) -> Result<Http3MessagePosition, Http3MessageStreamError> {
    match (stream_kind, position, section_kind) {
        (
            Http3MessageStreamKind::Request,
            Http3MessagePosition::BeforeHeaders,
            Http3HeadersKind::Request,
        ) => Ok(Http3MessagePosition::Content),
        (
            Http3MessageStreamKind::Request,
            Http3MessagePosition::Content,
            Http3HeadersKind::Trailers,
        ) => Ok(Http3MessagePosition::Trailers),
        (
            Http3MessageStreamKind::Response | Http3MessageStreamKind::Push,
            Http3MessagePosition::BeforeFinalResponse,
            Http3HeadersKind::InformationalResponse,
        ) => Ok(Http3MessagePosition::BeforeFinalResponse),
        (
            Http3MessageStreamKind::Response | Http3MessageStreamKind::Push,
            Http3MessagePosition::BeforeFinalResponse,
            Http3HeadersKind::FinalResponse,
        ) => Ok(Http3MessagePosition::Content),
        (
            Http3MessageStreamKind::Response | Http3MessageStreamKind::Push,
            Http3MessagePosition::Content,
            Http3HeadersKind::Trailers,
        ) => Ok(Http3MessagePosition::Trailers),
        _ => Err(Http3MessageStreamError::InvalidHeaderSection {
            stream_kind,
            position,
            section_kind,
        }),
    }
}

const fn unexpected_frame(
    frame_type: Http3FrameType,
    position: Http3MessagePosition,
) -> Http3MessageStreamError {
    Http3MessageStreamError::UnexpectedFrame {
        frame_type,
        position,
    }
}

const fn frame_payload_error(
    frame_type: Http3FrameType,
    error: Http3FramePayloadParseError,
) -> Http3MessageStreamError {
    Http3MessageStreamError::FramePayload { frame_type, error }
}

const fn is_http2_reserved_frame_type(frame_type: Http3FrameType) -> bool {
    matches!(frame_type.value(), 0x02 | 0x06 | 0x08 | 0x09)
}
