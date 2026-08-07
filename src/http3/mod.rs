//! Raw, allocation-free HTTP/3 wire views and caller-buffer construction.

mod builder;
mod control;
mod error;
mod frame;
mod header_section;
mod message;
mod message_content;
mod qpack;
mod settings;
mod standard;
mod standard_builder;
mod stream;
mod stream_builder;
mod types;
mod uni_stream_state;

pub use builder::Http3FrameBuilder;
pub use control::{Http3ControlFrame, Http3ControlStreamState, Http3EndpointRole};
pub use error::{
    Http3ControlStreamError, Http3FrameBuildError, Http3FrameParseError,
    Http3FramePayloadBuildError, Http3FramePayloadField, Http3FramePayloadParseError,
    Http3HeaderSectionError, Http3MessageContentError, Http3MessageStreamError,
    Http3PeerUniStreamError, Http3QpackFieldSectionError, Http3SettingsSemanticError,
    Http3UniStreamBuildError, Http3UniStreamField, Http3UniStreamParseError,
};
pub use frame::{Http3Frame, Http3FrameMut};
pub use header_section::{
    Http3DecodedHeaderSection, Http3DecodedPushPromise, Http3HeaderSectionContext,
    analyze_decoded_header_section, analyze_decoded_push_promise,
};
pub use message::{
    Http3HeaderSectionKind, Http3MessageFrame, Http3MessagePosition, Http3MessageStreamKind,
    Http3MessageStreamState, Http3PendingHeaders,
};
pub use message_content::{
    Http3MessageContentDisposition, Http3MessageContentKind, Http3MessageContentOperation,
    Http3MessageContentState, Http3ResponseRequestContext,
};
pub use settings::Http3PeerSettings;
pub use standard::{
    Http3CancelPush, Http3Data, Http3Goaway, Http3Headers, Http3MaxPushId, Http3PushPromise,
    Http3Setting, Http3Settings, Http3SettingsIter,
};
pub use standard_builder::{
    Http3CancelPushBuilder, Http3DataBuilder, Http3GoawayBuilder, Http3HeadersBuilder,
    Http3MaxPushIdBuilder, Http3PushPromiseBuilder, Http3SettingValue, Http3SettingsBuilder,
};
pub use stream::{Http3UniStreamHeader, Http3UniStreamKind};
pub use stream_builder::Http3UniStreamHeaderBuilder;
pub use types::{
    Http3ErrorCode, Http3FrameType, Http3PushId, Http3SettingId, Http3StreamId, Http3StreamType,
};
pub use uni_stream_state::{
    Http3CriticalUniStreamKind, Http3PeerUniStreamEvent, Http3PeerUniStreamState,
};
