//! Incoming HTTP/3 control-stream frame sequencing.

use super::{
    Http3CancelPush, Http3ControlStreamError, Http3Frame, Http3FramePayloadParseError,
    Http3FrameType, Http3Goaway, Http3MaxPushId, Http3PeerSettings, Http3PushId, Http3Settings,
};

/// A validated incoming HTTP/3 control-stream frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3ControlFrame<'a> {
    /// A SETTINGS frame and its semantically validated peer settings.
    Settings {
        /// The typed, raw-preserving SETTINGS frame.
        frame: Http3Settings<'a>,
        /// Effective known settings received from the peer.
        peer_settings: Http3PeerSettings,
    },
    /// A CANCEL_PUSH frame received by a server.
    CancelPush(Http3CancelPush<'a>),
    /// A GOAWAY frame.
    Goaway(Http3Goaway<'a>),
    /// A MAX_PUSH_ID frame received by a server.
    MaxPushId(Http3MaxPushId<'a>),
    /// An unknown extension or GREASE frame.
    Unknown(Http3Frame<'a>),
}

/// The local endpoint role used to interpret control-stream frame semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3EndpointRole {
    /// The local endpoint is an HTTP/3 client.
    Client,
    /// The local endpoint is an HTTP/3 server.
    Server,
}

/// Bounded state for receiving frames on one HTTP/3 control stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3ControlStreamState {
    local_role: Http3EndpointRole,
    settings: Option<Http3PeerSettings>,
    last_goaway_identifier: Option<u64>,
    maximum_push_id: Option<Http3PushId>,
}

impl Http3ControlStreamState {
    /// Creates empty incoming control-stream state for an endpoint role.
    pub const fn new(local_role: Http3EndpointRole) -> Self {
        Self {
            local_role,
            settings: None,
            last_goaway_identifier: None,
            maximum_push_id: None,
        }
    }

    /// Returns the local endpoint role used for incoming frame semantics.
    pub const fn role(self) -> Http3EndpointRole {
        self.local_role
    }

    /// Returns the peer SETTINGS after a valid SETTINGS frame is received.
    pub const fn settings(self) -> Option<Http3PeerSettings> {
        self.settings
    }

    /// Returns the last accepted GOAWAY identifier.
    pub const fn last_goaway_identifier(self) -> Option<u64> {
        self.last_goaway_identifier
    }

    /// Returns the largest accepted MAX_PUSH_ID.
    pub const fn maximum_push_id(self) -> Option<Http3PushId> {
        self.maximum_push_id
    }

    /// Receives a structurally bounded frame from this control stream.
    ///
    /// On error, no state is changed.
    pub fn receive<'a>(
        &mut self,
        frame: Http3Frame<'a>,
    ) -> Result<Http3ControlFrame<'a>, Http3ControlStreamError> {
        let frame_type = frame.frame_type();

        if self.settings.is_none() {
            if frame_type != Http3FrameType::SETTINGS {
                return Err(Http3ControlStreamError::MissingSettings { actual: frame_type });
            }
            return self.receive_settings(frame);
        }

        match frame_type {
            Http3FrameType::SETTINGS
            | Http3FrameType::DATA
            | Http3FrameType::HEADERS
            | Http3FrameType::PUSH_PROMISE => {
                Err(Http3ControlStreamError::UnexpectedFrame { frame_type })
            }
            frame_type if is_http2_reserved_frame_type(frame_type) => {
                Err(Http3ControlStreamError::UnexpectedFrame { frame_type })
            }
            Http3FrameType::CANCEL_PUSH => self.receive_cancel_push(frame),
            Http3FrameType::GOAWAY => self.receive_goaway(frame),
            Http3FrameType::MAX_PUSH_ID => self.receive_max_push_id(frame),
            _ => Ok(Http3ControlFrame::Unknown(frame)),
        }
    }

    fn receive_settings<'a>(
        &mut self,
        frame: Http3Frame<'a>,
    ) -> Result<Http3ControlFrame<'a>, Http3ControlStreamError> {
        let settings = Http3Settings::from_frame(frame).map_err(|error| {
            Http3ControlStreamError::FramePayload {
                frame_type: Http3FrameType::SETTINGS,
                error,
            }
        })?;
        let peer_settings = settings
            .validate_semantics()
            .map_err(Http3ControlStreamError::Settings)?;

        self.settings = Some(peer_settings);
        Ok(Http3ControlFrame::Settings {
            frame: settings,
            peer_settings,
        })
    }

    fn receive_cancel_push<'a>(
        &mut self,
        frame: Http3Frame<'a>,
    ) -> Result<Http3ControlFrame<'a>, Http3ControlStreamError> {
        if self.local_role == Http3EndpointRole::Client {
            return Err(Http3ControlStreamError::UnexpectedFrame {
                frame_type: Http3FrameType::CANCEL_PUSH,
            });
        }
        Http3CancelPush::from_frame(frame)
            .map(Http3ControlFrame::CancelPush)
            .map_err(|error| frame_payload_error(Http3FrameType::CANCEL_PUSH, error))
    }

    fn receive_goaway<'a>(
        &mut self,
        frame: Http3Frame<'a>,
    ) -> Result<Http3ControlFrame<'a>, Http3ControlStreamError> {
        let goaway = Http3Goaway::from_frame(frame)
            .map_err(|error| frame_payload_error(Http3FrameType::GOAWAY, error))?;
        let identifier = goaway.identifier();

        if self.local_role == Http3EndpointRole::Client && identifier & 0x03 != 0 {
            return Err(Http3ControlStreamError::InvalidGoawayStreamId { identifier });
        }
        if let Some(previous) = self.last_goaway_identifier
            && identifier > previous
        {
            return Err(Http3ControlStreamError::IncreasedGoawayIdentifier {
                previous,
                current: identifier,
            });
        }

        self.last_goaway_identifier = Some(identifier);
        Ok(Http3ControlFrame::Goaway(goaway))
    }

    fn receive_max_push_id<'a>(
        &mut self,
        frame: Http3Frame<'a>,
    ) -> Result<Http3ControlFrame<'a>, Http3ControlStreamError> {
        if self.local_role == Http3EndpointRole::Client {
            return Err(Http3ControlStreamError::UnexpectedFrame {
                frame_type: Http3FrameType::MAX_PUSH_ID,
            });
        }
        let maximum_push_id = Http3MaxPushId::from_frame(frame)
            .map_err(|error| frame_payload_error(Http3FrameType::MAX_PUSH_ID, error))?;
        let current = maximum_push_id.push_id();

        if let Some(previous) = self.maximum_push_id
            && current.value() < previous.value()
        {
            return Err(Http3ControlStreamError::ReducedMaximumPushId { previous, current });
        }

        self.maximum_push_id = Some(current);
        Ok(Http3ControlFrame::MaxPushId(maximum_push_id))
    }
}

fn frame_payload_error(
    frame_type: Http3FrameType,
    error: Http3FramePayloadParseError,
) -> Http3ControlStreamError {
    Http3ControlStreamError::FramePayload { frame_type, error }
}

const fn is_http2_reserved_frame_type(frame_type: Http3FrameType) -> bool {
    matches!(frame_type.value(), 0x02 | 0x06 | 0x08 | 0x09)
}
